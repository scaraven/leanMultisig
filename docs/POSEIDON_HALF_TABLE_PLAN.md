# Architecture Plan: Splitting the Poseidon Table to Shrink the Result Lookup

**Status:** Design only — no code changes made.
**Goal:** Reduce the logup-GKR cost (§5.8 of `misc/minimal_zkVM.tex`) of short-output
poseidon calls by giving them their own table whose **result memory lookup is 4 cells**
instead of the current unconditional **16 cells**.
**Decisions locked with the user:** Split **by AIR output width** into three poseidon
tables — out4 (4 cells), out8 (8 cells), and permute (16 cells) — each with a result memory
lookup matching its true width. Optimise generally across signature schemes.

> **Revised after call-site analysis (see §1e).** The earlier "split off the 4-cell case"
> decision was based on a wrong premise: that almost all calls are 4-FE. Static call-site
> counts in the XMSS-like zkDSL (`crates/rec_aggregation/zkdsl_implem/*.py`) show the
> dominant output width is **8 cells**, not 4. The 4-cell (`quarter*`) family is real but
> secondary. Hence a 3-way split keyed on output width, with the **out8 table** as the
> high-value target.

This branch has **no SPHINCS+ implementation**; XMSS (in `rec_aggregation/zkdsl_implem`) is
the representative workload used for the analysis below.

> **Code-base note (verified on branch `feature/poseidon-compress-only-table`,
> commit 2d4148a6).** The poseidon/bus layer was substantially refactored upstream since the
> first draft of this plan. All code anchors below reflect the *current* code. The branch
> name suggests upstream may already be moving toward this split; this plan should be
> reconciled with any upstream WIP before implementation. The key facts the plan relies on
> were re-verified and **still hold**: the result memory lookup is hardcoded to 16 cells for
> every output mode, and that lookup count dominates `N` for short-output calls.

All `tex` line references are to `misc/minimal_zkVM.tex` unless stated otherwise.

---

## 0. What the upstream refactor changed (vs. the original draft)

| Original anchor | Current state |
|---|---|
| `crates/lean_vm/src/tables/poseidon_16/mod.rs` | renamed → `crates/lean_vm/src/tables/poseidon/mod.rs` |
| `POSEIDON_16_COL_*` columns | renamed → `POSEIDON_COL_*` |
| separate `fn bus()` + `fn lookups()` | **unified** into `fn bus_interactions() -> Vec<BusInteraction>` (`poseidon/mod.rs:149`) |
| precompile-bus tuple `(PRECOMPILE_DATA, ν_A, ν_B, ν_C)` (mode packed into `PRECOMPILE_DATA`) | data is now `[ν_A, ν_B, ν_C]` (3 cells) with a **separate `domainsep` field** carrying the mode (`poseidon/mod.rs:149-159`) |
| `MAX_PRECOMPILE_BUS_WIDTH = 4` | replaced by `MAX_BUS_WIDTH = N_INSTRUCTION_COLUMNS + 2` (`table_enum.rs:8`) |
| single `flag_half_output` + `POSEIDON_HALF_OUTPUT_SHIFT` | two flags `flag_out4` / `flag_out8` (4/8/16-cell output) + `POSEIDON_FLAG_OUT8_SHIFT` (`poseidon/mod.rs:101-102, 370-371`) |
| tweaks "not yet implemented" | chopped-output + hardcoded-left **implemented**, plus new `quarter` and `permute_half` variants (`poseidon/mod.rs:115-130`) |

These are renames/restructurings — they change *where* the plan applies, not *whether* it
applies. Two of them actively help (see §3).

---

## 1. Where the cost lives

### 1a. The precompile bus is small and is not the target

When a poseidon precompile runs, the execution table pushes pointer data over the precompile
bus and the poseidon table pulls it. In the current code the bus *data* is just the three
pointers `[ν_A, ν_B, ν_C]`, with the mode carried in a **separate** `domainsep` field rather
than packed into the data:

- Poseidon pull: `crates/lean_vm/src/tables/poseidon/mod.rs:149-159`
  (`BusInteraction { direction: Pull, multiplicity: Column(MULTIPLICITY),
  domainsep: Column(DOMAINSEP), data: [NU_A, NU_B, NU_C] }`)
- Execution side pointer columns: `EXEC_COL_NU_A/B/C = 21/22/23`
  (`crates/lean_vm/src/tables/execution/air.rs:35-37`)

This is already minimal. **There is nothing to shrink on the cross-table bus.** (This
corrects the original framing that "16 FE are written into the execution table per poseidon
call" — the bus is 3 data cells + 1 domainsep.)

### 1b. The 16 lives in the *result memory lookup* (§5.8, lines 813–839)

Memory lookups are now expressed as bus interactions too. The poseidon table emits four
groups of consecutive memory lookups via `memory_lookups_consecutive`
(`crates/lean_vm/src/tables/table_trait.rs:64-76`), one `BusInteraction` per cell:

| Group | index column | values | count |
|---|---|---|---|
| left lo  | `POSEIDON_COL_ADDR_LEFT_LO` | `input[0..4]`  | 4 |
| left hi  | `POSEIDON_COL_ADDR_LEFT_HI` | `input[4..8]`  | 4 |
| right    | `POSEIDON_COL_NU_B`         | `input[8..16]` | 8 |
| **result** | `POSEIDON_COL_NU_C`       | `out[0..16]`   | **16** |

`poseidon/mod.rs:175-179`:
```rust
buses.extend(memory_lookups_consecutive(
    POSEIDON_COL_NU_C,
    POSEIDON_COL_OUT_LO,
    DIGEST_LEN * 2,        // = 16, UNCONDITIONAL — independent of flag_out4 / flag_out8
));
```

Each cell is a distinct `BusInteraction` (`table_trait.rs:65-75`), and logup spends one GKR
fraction per memory-lookup bus per row (`crates/sub_protocols/src/logup.rs:133-160`, which
expands `bus_interactions()` and groups them via `memory_lookup_groups`). This matches the
spec cost `N = Σ_T n_T·H_T` (line 835): the result group alone contributes `16·H_T`.

### 1c. The result lookup ignores the output mode — that is the inefficiency

The runtime writes only the meaningful cells (`poseidon/mod.rs:250-259`): `out4` ⇒ 4 cells,
`out8` ⇒ 8, permute ⇒ 16. The spec's "Chopped output" optimization intends exactly this
(lines 600–602: "only the first `n` … the remaining `8 − n` are ignored"). **But the result
*memory lookup* is hardcoded to 16 cells regardless** (`poseidon/mod.rs:178`). So a 4-FE
output still contributes `16·H_T` fractions to `N` when only 4 are meaningful. Removing the
unneeded 12 is the optimization.

### 1d. Clarification: "compress" is not "permute then chop" — the short table needs no permute op

Every poseidon row runs the permutation exactly once → `s = poseidon(left‖right) ∈ 𝔽^16`
(line 571). The mode only selects what is exposed to memory (line 567). Compression already
*contains* a full permutation internally — there is no separate permute step preceding it.

The current flags make this explicit (`poseidon/mod.rs:370-371`): `flag_out4` (compression,
4 cells), `flag_out8` (8 cells), neither ⇒ 16 (permutation). The AIR enforces the mode is
well-formed and that out4 is compression-only (`poseidon/mod.rs:346-355`):
```rust
builder.assert_zero(cols.flag_permute * cols.flag_out4);            // no out4 permute
builder.assert_zero(cols.flag_out8 * cols.flag_out4);               // out4 / out8 mutually exclusive
builder.assert_zero((1 - flag_permute)(1 - flag_out8)(1 - flag_out4)); // some mode must be set
```
So a 4-cell output is compression-only by construction. A 4-cell permute is forbidden
(matches spec line 592: chopped output "is incompatible with the *permutation* mode").

### 1e. The three real output widths, the counterintuitive DSL names, and the call-site mix

There are exactly **three memory-write widths**, set by the runtime
(`poseidon/mod.rs:251-258`):
```rust
if permute { out_len = half_output ? DIGEST_LEN (8) : DIGEST_LEN*2 (16) }
else       { out_len = half_output ? HALF_DIGEST_LEN (4) : DIGEST_LEN (8) }
```
The DSL names are **counterintuitive** — "half"/"quarter" refer to the fraction of the
16-wide *state* written, not "half of 8". The full mapping (verified via the compiler
`a_simplify_lang/mod.rs:1701-1719` and the `Display` impl `instruction.rs:266-292`):

| DSL function | `(half_output, permute)` | AIR mode | **cells written** |
|---|---|---|---|
| `compress_half`, `compress_half_hardcoded_left` | (false, false) | out8 | **8** |
| `quarter`, `quarter_hardcoded_left` | (true, false) | out4 | **4** |
| `permute` | (false, true) | (neither flag) | **16** |
| `permute_half`, `permute_half_hardcoded_left` | (true, true) | out8 | **8** |

Note the AIR `flag_out4`/`flag_out8` columns gate the output *constraints*; the
memory-*write* width above is what the result lookup must match. The three correspond
exactly: `out4` ⇒ 4, `out8` ⇒ 8, neither ⇒ 16.

**Static call-site counts** in the XMSS-like zkDSL
(`crates/rec_aggregation/zkdsl_implem/*.py`, mostly `hashing.py`):

| Variant | call sites | cells written |
|---|---|---|
| `compress_half` | 28 | 8 |
| `permute_half` | 13 | 8 |
| `quarter_hardcoded_left` | 11 | **4** |
| `permute` | 8 | **16** |
| `permute_half_hardcoded_left` | 1 | 8 |

Bucketed by write width: **8-cell ≈ 42 sites, 4-cell = 11, 16-cell = 8.** The 8-cell case
dominates. (These are *static* sites; loop/unroll multiplicity will skew dynamic counts —
see §5 caveat. They suffice to reject the "almost all 4-cell" premise.)

---

## 2. Why "separate tables" is the spec-clean mechanism

The indexed-lookup rule (line 823) quantifies `∀i < n_T, ∀j < H_T`: the number of memory
lookups `n_T` is a **per-table** property, uniform across that table's rows. The code mirrors
this — `bus_interactions()` is built once per table (`poseidon/mod.rs:149`), not per row, so
the result-lookup width cannot vary by row within one table.

Splitting into distinct tables is natively supported: `𝒯` is "the set of all tables"
(line 818) and `N = Σ_T n_T·H_T` (line 835) sums over however many tables exist. Split into
**three tables keyed on output width**, each with a result lookup matching its true write
width:

| Table | mode (`half_output, permute`) | result lookup | XMSS sites (§1e) | maps to |
|---|---|---|---|---|
| `Poseidon16Out4` (new)    | out4 — (true, false)  | **4**  | 11 | lines 600–602 (`n=4`) |
| `Poseidon16Out8` (new)    | out8 — (false,false) / (true,true) | **8** | ≈42 | line 577 |
| `Poseidon16Permute` (keep)| 16 — (false, true)    | 16 | 8 | line 584 |

All three run the identical permutation AIR (`eval_poseidon1_16`, `poseidon/mod.rs:386`);
only the `bus_interactions()` result group width differs (the `DIGEST_LEN * 2` argument at
`poseidon/mod.rs:178` becomes `HALF_DIGEST_LEN`=4, `DIGEST_LEN`=8, or `DIGEST_LEN*2`=16
respectively). Per line 835, each call then contributes `width·H_T` instead of `16·H_T`:

- out8 (the bulk): `8·H_T` instead of `16·H_T` — **halves** the result-lookup cost for the
  dominant case. This is the primary win.
- out4: `4·H_T` instead of `16·H_T` — a 12-fraction-per-row saving on its (smaller) table.
- permute: unchanged at 16 (genuine 16-cell writes), but now isolated to a small table.

> **Constraint-gating caveat.** The AIR output constraints (`poseidon/mod.rs:495-512`) gate
> `out_lo[4..8]` by `(1 - flag_out4)` and `out_hi` by `(1 - flag_out8 - flag_out4)`. When a
> table is specialised to a single mode, the corresponding flag column becomes a compile-time
> constant, so these gates simplify (and the unused `out_hi`/`out_lo[4..8]` committed columns
> may be droppable in the out4/out8 tables — a further column-count saving worth checking).

---

## 3. Routing the modes to the right table

The refactor makes routing easy because the mode lives in a dedicated `domainsep` field
rather than packed inside the bus data.

`domainsep` is reconstructed in the AIR from the flag columns (`poseidon/mod.rs:322-326`):
```rust
let domainsep_reconstructed = POSEIDON_DOMAINSEP_BASE
    + cols.flag_permute * POSEIDON_FLAG_PERMUTE_SHIFT
    + cols.flag_out8    * POSEIDON_FLAG_OUT8_SHIFT
    + cols.flag_left    * POSEIDON_FLAG_LEFT_SHIFT
    + cols.flag_left * cols.offset_left * POSEIDON_OFFSET_LEFT_SHIFT;
```
and set identically in the trace (`poseidon/mod.rs:278-283`). Each output mode already carries
a distinct `domainsep` value (out4 = neither `flag_out8` nor `flag_permute`; out8 = `flag_out8`
set; permute = `flag_permute` set). The execution table pushes a matching `domainsep`, so
**routing each mode to its table requires no new bus data** — each table pulls only the
`domainsep` values for its mode. Injectivity of the `domainsep` encoding (spec lines 618–623)
carries the soundness argument across the three pull-tables.

The routing decision is made in `PrecompileCompTimeArgs::table()`
(`crates/lean_vm/src/isa/instruction.rs:83-88`), which currently maps **all** Poseidon16 to a
single `Table::poseidon16()`; it would branch on `(half_output, permute)` to one of three
table constructors.

---

## 4. Files affected (mechanical, multi-site)

`Table` is a fixed enum with a `const`-discriminant index used for logup domain separation.
Adding two variants touches several wiring sites; none require new cryptographic design.

| File | Change |
|---|---|
| `crates/lean_vm/src/tables/table_enum.rs` | `N_TABLES 3→5`; add `Poseidon16Out4`, `Poseidon16Out8`, `Poseidon16Permute` to `ALL_TABLES`, the `Table` enum, both `delegate_to_inner!` arms, and constructors (`table_enum.rs:6,7,12-16,19-36,45-47` region). (Replace the single `Poseidon16` variant with the three; or keep one and add two.) |
| `crates/lean_vm/src/tables/poseidon/mod.rs` | Parameterise the result-lookup width (const generic `RES_WIDTH` ∈ {4,8,16}); `bus_interactions()` (`:175-179`) emits `RES_WIDTH` result cells; `table()` (`:141`) and the `execute` routing `ctx.traces.get_mut(&self.table())` (`:228`) return the right variant. Optionally drop the now-constant flag columns / unused `out_hi` per specialised table. |
| `crates/lean_vm/src/isa/instruction.rs` | `PrecompileCompTimeArgs::table()` (`:83-88`) currently maps **all** Poseidon16 to one table; branch on `(half_output, permute)` → out4 / out8 / permute constructor. |
| `crates/lean_prover/src/trace_gen.rs` | Fill all three poseidon traces (currently fills the single `Table::poseidon16()`). |
| `crates/lean_vm/src/execution/runner.rs` | `tables` map auto-includes the new tables via `ALL_TABLES`/`N_TABLES`; the `n_poseidons` stat may want to sum the three. |

The AIR constraint body (`eval` / `eval_poseidon1_16`, `poseidon/mod.rs:312-361, 386`) is
**shared** — all three tables run the identical permutation. Only the declared result-lookup
width (and possibly the specialised flag columns) differ.

---

## 5. Cost trade-off (spec line 429)

> Tables are padded to the next power of two (with a minimum of `2^8` rows).

Each table pays its own padding `H_T` (next power of two, min `2^8`). The split is a net win
when the result-lookup saving outweighs the extra padding. Per the §1e call-site mix:

| Table | typical population | result width | net effect |
|---|---|---|---|
| `Poseidon16Out8` | the bulk (≈42 sites; the hot loops) | 8 (was 16) | **halves** the dominant result-lookup cost — primary win |
| `Poseidon16Out4` | the `quarter*` family (11 sites) | 4 (was 16) | `12·H_T` saved on a smaller table |
| `Poseidon16Permute` | genuine 16-cell (8 sites) | 16 (unchanged) | isolates 16-cell calls; may sit near the `2^8` floor |

The dominant out8 table is well above the floor in any real XMSS run, so its 16→8 halving is
unambiguous. The out4 and permute tables are smaller; if either is so sparse that its `2^8`
floor erodes its own saving, it can be merged back (e.g. fold permute’s 8 calls into a 16-cell
table shared with out8 — but that re-inflates out8 to 16, defeating the point, so prefer
keeping permute separate only if it clears the floor).

**Caveat on the numbers:** §1e counts are *static call sites*, not dynamic row counts. Loops,
`unroll`, and `dynamic_unroll` will change the real per-mode populations substantially. A
one-off instrumented XMSS run (count `flag_out4`/`flag_out8`/`flag_permute` rows after
execution) should confirm the populations — especially that out8 dominates and that permute
clears `2^8` — before committing to three tables vs. two (out4+out8, folding permute into the
16-cell table).

---

## 6. Summary

- The cross-table bus is small (`[ν_A, ν_B, ν_C]` + separate `domainsep`,
  `poseidon/mod.rs:149-159`) — not the target. (Original "16 FE on the bus" framing was
  wrong.)
- The **16** is the *result memory lookup* width, hardcoded for every output mode
  (`poseidon/mod.rs:178`), and it dominates `N` (line 835) even though no call writes more
  than its mode’s width (4 / 8 / 16, `poseidon/mod.rs:251-258`).
- **DSL names are counterintuitive** (§1e): `compress_half` and `permute_half` write **8**
  cells; only `quarter*` writes 4; plain `permute` writes 16. Call-site data (XMSS-like
  zkDSL) shows **8-cell is the dominant width**, not 4 — overturning the earlier premise.
- "Compress" already contains a full permutation (line 571); out4 is compression-only and a
  4-cell permute is forbidden by the AIR (`poseidon/mod.rs:346-355`, spec line 592).
- The spec-clean fix is **three tables keyed on output width** (out4 / out8 / permute): `𝒯`
  and `N` (lines 818, 835) sum cleanly over tables. Routing needs **no new bus data** — each
  mode already carries a distinct `domainsep` (`poseidon/mod.rs:322-326`).
- The **out8 table is the high-value target** (≈80% of static call sites; 16→8 halves its
  result lookup). out4 captures the `quarter*` family; permute isolates the rare 16-cell case.
- Implementation is mechanical wiring across ~5 files; the AIR body is shared.
- **Verify dynamic per-mode row counts** (not just static sites) and **reconcile with
  upstream** (`feature/poseidon-compress-only-table`, whose `out4`/`out8`/`domainsep` design
  looks like scaffolding for exactly this split) before coding.
