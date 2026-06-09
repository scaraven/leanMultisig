# Architecture Plan: Splitting the Poseidon Table to Shrink the Result Lookup

**Status:** Design only — no code changes made.
**Goal:** Reduce the logup-GKR cost (§5.8 of `misc/minimal_zkVM.tex`) of short-output
poseidon calls by giving them their own table whose **result memory lookup is 4 cells**
instead of the current unconditional **16 cells**.
**Decisions locked with the user:** Split off **only the 4-cell (out4 / `quarter*`) case**
into its own poseidon table with a 4-cell result memory lookup. Keep the 8-cell (out8) and
16-cell (permute) calls together in the **existing** table (result lookup stays 16). Optimise
generally across signature schemes.

> **Revised twice.** (1) Static call-site counts in the XMSS-like zkDSL
> (`crates/rec_aggregation/zkdsl_implem/*.py`) show the dominant *static* output width is
> 8 cells, not 4. (2) **But dynamic execution is dominated by the 4-cell (`quarter*`) case**:
> Merkle-tree verification performs one hash *per tree layer*, and WOTS performs several hashes
> *per chain*, and these are the 4-cell calls — multiplied across all signers/layers/chains
> they dwarf the statically-larger `compress_half`/`permute_half` sites. So the high-value
> target by *dynamic row count* is **out4**. The decision is therefore to peel **out4** into
> its own table (4-cell result lookup) and leave out8 + permute in the existing 16-cell table.
> A future second split (out8 → 8-cell) remains possible but is deferred; isolating out4 is the
> single-table change with the largest dynamic payoff.

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
dominates *statically*.

**But static counts mislead here — dynamic row counts invert the picture.** The 4-cell
(`quarter*`) calls sit in the hottest loops:
- **Merkle verification** runs one hash *per tree layer* (`hashing.py:328+`), repeated for
  every authentication path.
- **WOTS** runs several hashes *per chain*, across all chains in a signature.

These per-layer / per-chain hashes are the 4-cell calls, and their multiplicity (signers ×
layers × chains) makes out4 the **dominant table by executed rows**, even though
`compress_half`/`permute_half` have more *static* call sites. This is why the split peels off
out4 specifically: it is the highest-multiplicity width. (Static site counts above remain
useful only for reasoning about the rarer widths; confirm the dynamic populations with an
instrumented run — see §5.)

---

## 2. Why "separate tables" is the spec-clean mechanism

The indexed-lookup rule (line 823) quantifies `∀i < n_T, ∀j < H_T`: the number of memory
lookups `n_T` is a **per-table** property, uniform across that table's rows. The code mirrors
this — `bus_interactions()` is built once per table (`poseidon/mod.rs:149`), not per row, so
the result-lookup width cannot vary by row within one table.

Splitting into distinct tables is natively supported: `𝒯` is "the set of all tables"
(line 818) and `N = Σ_T n_T·H_T` (line 835) sums over however many tables exist. Peel off
**out4 into its own table**; keep out8 and permute together in the existing table:

| Table | modes (`half_output, permute`) | result lookup | dominant by | maps to |
|---|---|---|---|---|
| `Poseidon16Out4` (new)      | out4 — (true, false)                          | **4**  | **executed rows** (Merkle layers + WOTS chains) | lines 600–602 (`n=4`) |
| `Poseidon16` (keep, unchanged) | out8 — (false,false)/(true,true) **and** permute — (false,true) | 16 | static sites | lines 577, 584 |

Both tables run the identical permutation AIR (`eval_poseidon1_16`, `poseidon/mod.rs:386`);
only the new out4 table's `bus_interactions()` result group width differs (the `DIGEST_LEN * 2`
argument at `poseidon/mod.rs:178` becomes `HALF_DIGEST_LEN` = 4 in the out4 table; the kept
table stays at `DIGEST_LEN * 2` = 16). Per line 835:

- out4 (the dynamic bulk): `4·H_T` instead of `16·H_T` — a **12-fraction-per-row saving on the
  highest-multiplicity table**. This is the primary win.
- out8 + permute (kept table): unchanged at 16. The out8 calls still over-declare (8 written,
  16 looked up), but they are left as-is in this iteration — a later out8 split could recover
  another 8→ -saving if its dynamic population justifies a second table past the `2^8` floor.

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
and set identically in the trace (`poseidon/mod.rs:278-283`). out4 carries a distinct
`domainsep` value (neither `flag_out8` nor `flag_permute` set), so **routing out4 to its table
requires no new bus data** — the out4 table pulls only its `domainsep` values; the kept table
pulls the out8 and permute `domainsep` values as before. Injectivity of the `domainsep`
encoding (spec lines 618–623) carries the soundness argument across the two pull-tables.

The routing decision is made in `PrecompileCompTimeArgs::table()`
(`crates/lean_vm/src/isa/instruction.rs:83-88`), which currently maps **all** Poseidon16 to a
single `Table::poseidon16()`; it would branch: out4 — `(half_output=true, permute=false)` —
to the new out4 table constructor, everything else to the existing `Table::poseidon16()`.

---

## 4. Files affected (mechanical, multi-site)

`Table` is a fixed enum with a `const`-discriminant index used for logup domain separation.
Adding **one** variant touches several wiring sites; none require new cryptographic design.

| File | Change |
|---|---|
| `crates/lean_vm/src/tables/table_enum.rs` | `N_TABLES 3→4`; add **one** `Poseidon16Out4` variant to `ALL_TABLES`, the `Table` enum, both `delegate_to_inner!` arms, and a constructor (`table_enum.rs:6,7,12-16,19-36,45-47` region). The existing `Poseidon16` variant stays. |
| `crates/lean_vm/src/tables/poseidon/mod.rs` | Parameterise the result-lookup width (const generic `RES_WIDTH` ∈ {4,16}, or a bool); `bus_interactions()` (`:175-179`) emits `RES_WIDTH` result cells (4 for the out4 table, 16 otherwise); `table()` (`:141`) and the `execute` routing `ctx.traces.get_mut(&self.table())` (`:228`) return the out4 variant when `(half_output=true, permute=false)`. Optionally drop the now-constant `flag_out4`=1 column / unused `out_hi` and `out_lo[4..8]` in the out4 table. |
| `crates/lean_vm/src/isa/instruction.rs` | `PrecompileCompTimeArgs::table()` (`:83-88`) currently maps **all** Poseidon16 to one table; branch out4 → new constructor, everything else → existing `Table::poseidon16()`. |
| `crates/lean_prover/src/trace_gen.rs` | Fill both poseidon traces (currently fills the single `Table::poseidon16()`). |
| `crates/lean_vm/src/execution/runner.rs` | `tables` map auto-includes the new table via `ALL_TABLES`/`N_TABLES`; the `n_poseidons` stat may want to sum the two. |

The AIR constraint body (`eval` / `eval_poseidon1_16`, `poseidon/mod.rs:312-361, 386`) is
**shared** — both tables run the identical permutation. Only the declared result-lookup
width (and possibly the specialised flag column in the out4 table) differs.

---

## 5. Cost trade-off (spec line 429)

> Tables are padded to the next power of two (with a minimum of `2^8` rows).

Each table pays its own padding `H_T` (next power of two, min `2^8`). The split is a net win
when the result-lookup saving outweighs the extra padding:

| Table | typical population | result width | net effect |
|---|---|---|---|
| `Poseidon16Out4` (new) | the **dynamic bulk** — one hash per Merkle layer, several per WOTS chain, × all signers | 4 (was 16) | `12·H_T` saved on the **highest-multiplicity** table — primary win |
| `Poseidon16` (kept) | out8 + permute | 16 (unchanged) | no change this iteration |

The out4 table is well above the `2^8` floor in any real XMSS run (Merkle + WOTS hashes scale
with the workload), so peeling it off — even just the `12·H_T` saving per row — is the largest
single-table win available. The kept table is unchanged, so there is no risk of a sparse new
table eroding its own saving via the floor.

**Confirm dynamic populations before coding.** §1e counts are *static call sites* and
*understate* out4's true weight — loops, `unroll`, and `dynamic_unroll` blow up the per-layer /
per-chain 4-cell calls. A one-off instrumented XMSS run (count `flag_out4` /
`flag_out8`/`flag_permute` rows after execution) should confirm out4 is the dominant executed
width and that it clears `2^8`. If a later iteration also wants to peel out8 (8-cell) into a
third table, gate that on its own dynamic count clearing the floor.

---

## 5b. Future work (out of scope for this iteration)

Once the out4 functionality lives in its own table, the **kept** `Poseidon16` table no longer
emits any out4 rows. Its `flag_out4` column and all related machinery become dead weight and
can be removed in a **follow-up** (explicitly *not* part of this iteration):

- Drop the `flag_out4` committed column (`POSEIDON_COL_FLAG_OUT4`, `poseidon/mod.rs:101`) and
  the `flag_out4` field from `Poseidon1Cols16`.
- Drop the now-vacuous AIR constraints that mention `flag_out4`: `assert_bool(flag_out4)`
  (`:347`), `flag_permute * flag_out4` (`:351`), `flag_out8 * flag_out4` (`:352`), and the
  `flag_out4` term in the mode-coverage check (`:353-355`). The output gates simplify:
  `gate_lo_8 = 1 - flag_out4` → `1` (out_lo[4..8] always constrained), and `gate_hi =
  1 - flag_out8 - flag_out4` → `1 - flag_out8`.
- This also drops `degree_air` back below 10 for the kept table (the `(1 - flag_out4)` gating
  factor disappears) and reduces its `n_constraints`.

Deferred because it touches the *shared* AIR body / `Poseidon1Cols16` layout that the kept
table still uses during this iteration; doing it now would entangle the two changes. Land the
out4 split first, confirm it green, then prune `flag_out4` from the base table separately.

---

## 6. Summary

- The cross-table bus is small (`[ν_A, ν_B, ν_C]` + separate `domainsep`,
  `poseidon/mod.rs:149-159`) — not the target. (Original "16 FE on the bus" framing was
  wrong.)
- The **16** is the *result memory lookup* width, hardcoded for every output mode
  (`poseidon/mod.rs:178`), and it dominates `N` (line 835) even though no call writes more
  than its mode’s width (4 / 8 / 16, `poseidon/mod.rs:251-258`).
- **DSL names are counterintuitive** (§1e): `compress_half` and `permute_half` write **8**
  cells; only `quarter*` writes 4; plain `permute` writes 16. Static call-site data shows
  8-cell is the most common width, but **dynamic execution is dominated by the 4-cell
  (`quarter*`) case** — one hash per Merkle layer plus several per WOTS chain, multiplied
  across all signers/layers/chains.
- "Compress" already contains a full permutation (line 571); out4 is compression-only and a
  4-cell permute is forbidden by the AIR (`poseidon/mod.rs:346-355`, spec line 592).
- The chosen fix is **peel out4 into its own table** (4-cell result lookup); keep out8 +
  permute in the existing 16-cell table. `𝒯` and `N` (lines 818, 835) sum cleanly over tables.
  Routing needs **no new bus data** — out4 already carries a distinct `domainsep`
  (`poseidon/mod.rs:322-326`).
- The **out4 table is the high-value target by dynamic row count** (16→4 saves `12·H_T` per row
  on the highest-multiplicity table). A later out8 split (8-cell) is deferred — gate it on its
  own dynamic count.
- Implementation is mechanical wiring across ~5 files for **one** new table variant; the AIR
  body is shared.
- **Verify dynamic per-mode row counts** (not just static sites — they understate out4) and
  **reconcile with upstream** (`feature/poseidon-compress-only-table`, whose
  `out4`/`out8`/`domainsep` design looks like scaffolding for exactly this split) before coding.
