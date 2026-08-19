# `fp_soundness_poc` — frame-pointer under-constraint exploit

A working proof-of-concept for **audit finding F-2**: leanVM's deployed execution AIR never
constrains the frame pointer `fp` to the memory range. The malicious prover in this crate
makes the **canonical, unmodified verifier** (`lean_prover::verify_execution`) accept a proof
of a statement that is false under leanVM's own semantics.

## The gap

In `crates/lean_vm/src/tables/execution/air.rs` the frame pointer is committed column 1, but:

- it is **never itself a memory-lookup address** — only the sums `fp + operand` are pulled,
  and only for `mem`-mode operands (`execution/mod.rs` emits three memory pulls A/B/C, no
  `fp` pull);
- there is **no boundary constraint** on `fp` (only `pc` is pinned, `stacked_pcs.rs`);
- `fp` updates are range-unchecked: a taken `JUMP` sets `next(fp) = ν_C`, and when
  `updated_fp` is a `mem` operand, `ν_C` is an arbitrary memory *value*.

The Lean formalization hit this as a counterexample and **patched** it by adding an
unconditional per-row `(fp, value_fp)` memory pull (`Leanth/LeanVM/Arith/Glue.lean`,
decision log `docs/formalization/decisions.md`). The deployed Rust binary has no such
mechanism, so the only machine-checked soundness statement is about a *stronger* VM than the
one that ships.

Because address arithmetic is over `KoalaBear` (`p = 2^31 - 2^24 + 1`), an out-of-range
`fp ≈ p` makes `fp + operand` **wrap** back into a valid in-range address. The exploit uses
this to redirect a checked memory read.

## Why the exploit needs hand-written ISA

The zkDSL compiler *accidentally* constrains `fp`: a function call/return lowers to
`write_call_frame` dereferences that assert `m[callee+1] == caller_fp` (pinning the saved fp)
and read through the callee base (range-checking it via the memory lookup). That is a
property of the **compiler**, not of the **AIR**. `src/guest.rs` (a zkDSL fibonacci-verify)
therefore *cannot* be hijacked through its return — see the discussion below.

`src/isa_guest.rs` writes the **same** `fib(N) == public_input[0]` check directly in leanISA,
omitting the incidental pin: the one jump that reloads `fp` takes its new value from a
`hint_witness` cell the AIR never constrains. This exposes the raw gap.

## The exploit chain (`isa_guest` + `forge::forge_isa`)

1. The program computes `fib(N)` into `m[fp+RES]`, then a `JUMP` reloads `fp <- m[fp+H]`
   (`H` is a hint cell), then reads the public claim `m[0]` and asserts
   `m[fp+RES] == claim`.
2. **Honest** (`fp = 10` throughout): the hint is `10`, the jump is a no-op, the assert reads
   the genuine fib result — the proof exists iff `public_input[0] == fib(N)`.
3. **Forged**: the malicious prover sets the hint cell to the **out-of-range**
   `fp = p - RES`. The AIR accepts it (values are not range-checked; `fp` is not pulled; the
   addresses `fp + operand` all wrap in-range). At the assert, the result read `m[fp+RES]`
   wraps to `m[(p-RES)+RES] = m[0]` — the public claim itself — so `assert claim == claim`
   passes for **any** claim.
4. The real prover commits this trace; the **canonical** `verify_execution` accepts a proof
   that `fib(10) == 999`.

The honest runner can never produce this: there `fp` is a `usize` bounded by the memory size,
and `p - RES ≈ 2^31` faults as an index.

## What is and isn't modified

- **The verifier is untouched.** `verify_execution` and everything it calls run byte-for-byte
  as they ship. Every test ends in an unmodified `verify_execution` call.
- The only edit to `lean_prover` is a behavior-preserving refactor of `prove_execution` into
  `prove_from_execution_result` (the PoC's forged-trace entry point) + a private helper; the
  honest `prove_execution` is unchanged. The forged trace is turned into committed columns by
  the same `get_execution_trace` the honest path uses.

## Tests (`tests/exploit.rs`)

Run with `--release` (the trace is tiny; a `debug_assert` in the packing code trips only in
debug, which is why the repo's own alias runs tests in release):

```
cargo test -p fp_soundness_poc --release
```

| test | shows |
| --- | --- |
| `isa_honest_true_verifies` | canonical verifier accepts the TRUE claim |
| `isa_false_is_honestly_unprovable` | the FALSE claim is honestly unprovable (runner rejects) |
| `isa_forged_false_statement_is_accepted` | **THE BREAK**: canonical verifier accepts `fib(10)==999` |
| `probe_relocate_fib_frame_in_range` | the zkDSL callee frame base is unconstrained (relocating fib's frame still verifies) |
| `honest_true_statement_verifies` / `false_statement_is_honestly_unprovable` | the zkDSL guest controls |

`dump_isa_layout` / `dump_honest_layout` (`--ignored --nocapture`) print the per-cycle trace.

## Note on the zkDSL guest

`probe_relocate_fib_frame_in_range` confirms the freedom is real even in compiled code: the
callee frame base is prover-chosen, and relocating fib's whole frame still verifies. But the
compiler's `write_call_frame` pin + the write-once same-cell assert make the *compiled*
fibonacci non-exploitable for a false statement — the falsehood cannot escape the pinned
convention. The hand-written ISA version removes that incidental defense, which is the point:
the soundness bug is in the **AIR**, and any bytecode (compiler-emitted or not) that reloads
`fp` from an unconstrained source inherits it.

## Remediation

Add the frame-pointer range pull the Lean model already specifies: an unconditional per-row
memory lookup `(fp, value_fp)` in the execution table's `bus_interactions`. That forces `fp`
in-range every row and rejects the forged trace. (Pinning only the initial `fp` via a
boundary constraint is **not** sufficient — taken jumps re-load `fp` from unconstrained
values.)
