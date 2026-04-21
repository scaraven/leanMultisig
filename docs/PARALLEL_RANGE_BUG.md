# parallel_range Stride Bug - Final Debug Notes

## Symptom

Running SPHINCS batch verification with `n_sigs >= 2` failed while `n_sigs = 1` worked:

```text
ParallelSegmentFailed(1, UndefinedMemory(...))
```

After one partial fix, the crash moved to a different address, proving the first issue was real but not the only one.

## VM Behavior That Matters

In `parallel_range`, the VM:

1. Executes iteration 0 sequentially.
2. Computes per-iteration segment size from the iteration-0 fp stride:
   - `stride = fp_after_iter0 - batch_fp`
3. Runs later iterations in fixed `SegmentMemory` slices of length `stride`.
4. Fails on out-of-slice reads (`UndefinedMemory`), and defers out-of-slice writes.

This only works if each iteration has the same total frame footprint.

## What Actually Went Wrong

The main issue was not just dynamic array sizes. The deeper issue was frame-size variance across match specializations.

`iterate_hash` is implemented via:

- `match_range(n, range(0, SPX_WOTS_W), lambda k: _iterate_hash_const(..., k, ...))`

This creates separate specialized functions for each constant `k`.

Even after removing obvious dynamic allocations, specialized `_iterate_hash_const_k=*` functions still had different compiled frame sizes. Diagnostic output showed function sizes increasing with `k`.

Result:

- Iteration 0 can hit a smaller-k call path and define `stride` from that smaller footprint.
- Another signer in parallel can hit larger-k path, exceed the segment, and crash or produce deferred writes.

## Why the VM-side "AP stride" workaround was rejected

A temporary runner change used AP footprint instead of fp stride for segment sizing.

That avoided immediate `UndefinedMemory`, but it changed memory behavior and broke proof consistency and regression expectations:

- `lean_compiler` regression `test_parallel_loop` failed memory-size equality checks.
- SPHINCS proving path could complete execution but fail verification (`InvalidProof`) with non-zero deferred writes.

Conclusion: VM/prover semantics should remain unchanged; fix the program footprint instead.

## Final Fix

Keep VM stride logic fp-based, and make SPHINCS per-k specialization frames truly uniform.

In `crates/rec_aggregation/sphincs_utils.py`:

- `_iterate_hash_const` now uses fixed-size workspace:
  - `states = Array(SPX_WOTS_W * DIGEST_LEN)`
- Uses fixed unroll bounds for all k:
  - `for i in unroll(0, SPX_WOTS_W - 1): ...`
- Writes output from `states + k * DIGEST_LEN`.
- `iterate_hash` continues to dispatch through `match_range`, but every target specialization now has the same effective frame structure.

This resolves the per-iteration footprint mismatch without changing VM proof semantics.

## Validation Summary

- Parallel runner no longer requires VM semantic changes.
- SPHINCS run with `n-signatures = 2` succeeds in current workspace state.
- The issue was a program-level footprint-uniformity violation under `parallel_range`, not a prover bug.

## Extra Diagnostics Added During Debugging

Temporary diagnostics were added in:

- `crates/lean_vm/src/execution/runner.rs` (`[parallel-diag] ...` lines)
- SPHINCS Python verifier flow (`print(1000)`, etc.)

These were useful to localize divergence and measure overflows/deferred writes. Remove them when no longer needed.
