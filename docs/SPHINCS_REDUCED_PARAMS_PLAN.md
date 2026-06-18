# SPHINCS+ Reduced-Parameter Redesign Plan

Status: **design / scoping**. No implementation until approved.

This document designs the Rust signer and the zkDSL guest verifier for a **reduced
SPHINCS+ parameter set** with a **2^24 signature limit** (governed by the FORS
security analysis, not the tree height). It pays special attention to ADRS tweaks,
the count and shape of Poseidon calls, and how data is packed to minimise guest-program
constraints.

It supersedes the parameter choices in `docs/SPHINCS_ZKDSL_PLAN.md` (that document
describes the *current* d=3 / V=32 / w=16 scheme). The architecture, address binding
rules, and test infrastructure from that plan still apply; only the parameters and the
hypertree→single-tree collapse change here.

---

## 1. New Parameter Set

| Parameter | Old (current code) | **New** | Notes |
|---|---|---|---|
| `SPX_D` (hypertree layers) | 3 | **1** | Single XMSS tree — no inter-layer re-hashing |
| `SPX_TREE_HEIGHT` | 11 | **22** | One tree, 2^22 leaves |
| `SPX_FULL_HEIGHT` | 33 | **22** | `= SPX_D * SPX_TREE_HEIGHT` |
| `SPX_FORS_TREES` (k) | 9 | **6** | FORS trees |
| `SPX_FORS_HEIGHT` (a) | 15 | **24** | FORS tree height |
| `SPX_WOTS_LEN` (V) | 32 | **64** | WOTS+ chains |
| `SPX_WOTS_LOGW` | 4 | **2** | bits per chain index (`w = 2^LOGW`) |
| `SPX_WOTS_W` (chain length) | 16 | **4** | hashes per chain |
| `TARGET_SUM` | 304 | **112** | fixed sum of the 64 indices (see §4) |
| `NUM_CHAIN_HASHES` | 176 | **80** | `V*(w-1) - TARGET_SUM = 192 - 112` |
| `DIGEST_SIZE` | 8 | 8 | unchanged (KoalaBear FE) |
| `HALF_DIGEST_SIZE` | 4 | 4 | unchanged |

**Signature limit.** The single Merkle tree addresses `2^22` leaves. The advertised
`2^24` figure comes from the FORS few-times security analysis (k=6 trees of height
24); it is a property of the security argument, **not** the tree's leaf count. The
design does not need to reconcile these — the tree is height 22.

### 1.1 Derived bit-widths (ADRS)

```
SPX_LEAF_BITS  = SPX_TREE_HEIGHT          = 22   (leaf within the single tree)
SPX_TREE_BITS  = SPX_FULL_HEIGHT - SPX_TREE_HEIGHT = 0   (only one tree → no idx_tree!)
SPX_KP_ADDR_BITS  = 22                            (key-pair address == leaf index)
SPX_CHAIN_ADDR_BITS = ceil(log2(V)) = ceil(log2(64)) = 6
SPX_HASH_ADDR_BITS  = SPX_WOTS_LOGW       = 2     (one step per chain level, max step w-2=2)
```

**Major simplification from d=1:** `SPX_TREE_BITS = 0`. There is no hypertree subtree
addressing — `idx_tree` vanishes everywhere. This removes one runtime field from every
FORS ADRS and from the digest decomposition. (See §5 and §7.)

---

## 2. Poseidon-call Budget (per signature)

This is the quantity the whole design optimises. All hashes are Poseidon-16
compressions over KoalaBear; "half" = truncating 8→4 output, "out8" = full 8-FE output.

| Component | Calls | Derivation |
|---|---|---|
| `prf_msg` (R) | 1 | one compression |
| `hmsg` + decompose (fused) | **2** | `permute` (carry 16-FE state) + `compress` out8 whose output IS the index slots (§7) |
| **WOTS encoding** | 1 | `poseidon(message, [r0..r5, adrs0, adrs1])` |
| **WOTS chain completion** | **80** | `V*(w-1) - TARGET_SUM = 192-112` (avg, summed across 64 chains) |
| **WOTS pubkey fold** (T-Sponge) | **32** | `V/2 = 64/2` |
| **Merkle path** (22 levels, single tree) | **22** | one compression per level |
| FORS leaf hashes | **6** | one per tree (k=6) |
| **FORS auth paths** | **144** | `k * a = 6 * 24` |
| **FORS root fold** (T-Sponge) | **3** | `ceil(k/2) = ceil(6/2)` |
| **Total (dominant terms)** | **≈ 295** | vs ≈ 1019 in the old d=3/V=32 scheme |

The big structural wins vs the old scheme: **d=1 removes ~2 layers of WOTS (≈ 600
calls)**; V=64/w=4 makes each WOTS instance cheaper per chain but there are more chains
(net: chain completion 80 vs ~720 across 3 layers). FORS grows (k·a = 144 vs 135) but
stays comparable.

> The *constraint* cost is not only Poseidon rows: every compression also builds its
> 8-FE left input in memory. The `make_tweak5` approach (§6) hoists the `pk_seed` copy
> per scope; no tweak table is used.

---

## 3. Single-Tree Hypertree → `sphincs_tree`

With `SPX_D = 1` the `sphincs_hypertree.py` module collapses. There is exactly one
XMSS tree of height 22:

```
sphincs_tree_verify(pk_seed, message, leaf_index, expected_root):
    # message = half_to_full(fors_pubkey)
    wots_leaf = wots_encode_and_complete(message, adrs0, adrs1, randomness, chain_tips, pk_seed, ...)
    # one 22-level Merkle path → root
    merkle_verify(leaf_index, wots_leaf, auth_path)  →  root
    assert root == expected_root   # == pk_root
```

Removed relative to the current hypertree:
- the `for l in unroll(0, SPX_D)` layer loop;
- the inter-layer `current_message = poseidon(layer_root, [l+1, 0...])` re-hash (saves
  `SPX_D - 1` compressions and removes the layer domain separator entirely);
- `idx_tree` / `layer_tree_address` plumbing (d=1 ⇒ `tree_address ≡ 0`).

**ADRS for the tree.** With one tree, `tree_address = 0` and `layer = 0` are fixed
constants, so `adrs0` for `TREE`/`WOTS_HASH`/`WOTS_PK` reduces to just the `type` field
(plus the now-zero tree bits). This means the `adrs0` part of the tweak is a pure
compile-time literal, fed into `make_tweak5` (§6).

### 3.1 Merkle path grouping: 22 = 6 + 6 + 6 + 4

The copy-free Merkle block helper processes a fixed number of levels with one
`match_range` dispatch (the direction bits select left/right placement at each level
with no runtime arithmetic). 22 is not a multiple of any single clean step, so the tree
uses **three `do_6` groups + one `do_4` tail**:

```
do_6_merkle_level(bits[0],  ht_start=0,  state_in=leaf, ...)   # levels 0..5
do_6_merkle_level(bits[1],  ht_start=6,  ...)                  # levels 6..11
do_6_merkle_level(bits[2],  ht_start=12, ...)                  # levels 12..17
do_4_merkle_level(bits[3],  ht_start=18, ..., state_out=root) # levels 18..21
```

`do_6` is a new block (6 explicit levels, `match_range(k, range(0, 2**6))`); `do_4`
mirrors the XMSS `do_4_merkle_levels` shape. Both reuse the existing copy-free
state-half placement (`state_half_offset` / `sibling_half_offset`) and stream siblings
from the `tree_auth` hint queue.

> **`match_range` cost note.** A `do_6` group expands to `2**6 = 64` compile-time
> branch bodies (one per direction-bit pattern), only one of which executes at runtime.
> `do_4` expands to 16. This is the same mechanism the current `do_5` uses (32 bodies);
> `do_6` is a 2× larger expansion but still well within the bounds the compiler handles
> for the existing FORS/XMSS code. If program size becomes a concern, fall back to
> 5+5+6+6 or 2 × (do_6) + 2 × (do_5) — all reuse the same primitives.

---

## 4. WOTS+ Encoding (V=64, w=4, TARGET_SUM=112)

### 4.1 Index distribution and target choice

Each of the 64 indices is ~uniform on `{0,1,2,3}` (mean 1.5). The sum of 64 indices has
mean `96`, range `[0,192]`, σ ≈ 8.9.

- **TARGET_SUM = 112** sits ≈ +1.8σ above the mean.
- **Signer grinding** ≈ 2^13 attempts to find randomness whose encoding sums to exactly
  112. This is a one-time, *off-circuit* Rust cost (microseconds) — negligible.
- **Verifier chain hashes** = `V*(w-1) - TARGET_SUM = 192 - 112 = 80` in-circuit Poseidon
  calls. This is the cost we actually pay in the proof.

The asymmetry justifies pushing above the mean: 96→112 trades free signer grinding
(2^10→2^13) for **16 fewer in-circuit Poseidon calls per signature**. Pushing past ~112
gives diminishing returns (super-exponential grinding for ~8 more saved calls).

### 4.2 Encoding computation and decomposition

```
# right input packs 6 randomness FEs + adrs0/adrs1 (compile-time constants for d=1):
encoding_fe = poseidon16_compress(message, [r0..r5, adrs0, adrs1])      # 8 FEs out

# Decompose: w=4 ⇒ LOGW=2 bits per index ⇒ 12 indices per FE (24 usable bits / 2).
# 64 indices need ceil(64/12) = 6 FEs. The 6th FE yields 12 chunks but only 4 are used
# (6*12 = 72 slots, 64 needed) → 8 unused chunks + the high "remaining" bits.
encoding[0..64], remaining[0..6] = hint_decompose_wots(encoding_fe, num_chunks=12, chunk_bits=2)

for fe in 0..6:
    for j in 0..12:           # only the first 64 chunks are range/sum-checked
        if fe*12 + j < 64: assert encoding[fe*12+j] < SPX_WOTS_W   # < 4
    assert remaining[fe] < 2**(31 - 12*2)                          # < 2**7
    # reconstruction binding: encoding_fe[fe] == sum(chunk_j * 4**j) + remaining*2**24
assert sum(encoding[0..64]) == TARGET_SUM                          # == 112
```

**Packing note.** The existing `hint_decompose_wots` already decomposes per-FE into
`num_chunks` chunks of `chunk_bits` each plus a `remaining`. For w=4 we set
`num_chunks=12, chunk_bits=2`. The only new wrinkle vs the current code (4 chunks/FE) is
that the **last FE is partially used** (4 of its 12 chunks). The design handles this by
range/sum-checking only the first 64 chunks and still binding all 6 `encoding_fe[fe]`
values fully (so the unused high chunks are constrained as part of `remaining`/the
reconstruction, never left free).

### 4.3 Chain completion and pubkey fold

- **8-FE internal chain state** (the existing `iterate_hash_full_from_full` technique)
  is *kept*: each chain carries the full 8-FE Poseidon output between steps; only the
  chain-final value truncates to 4 FE. Revealed mid-chain tips stay 8-FE so split
  sign/verify composes with unsplit keygen. With w=4 chains are short (≤3 steps), so the
  per-chain staging buffers are tiny.
- **Pubkey fold**: V=64 is even → 32 T-Sponge absorb blocks (each absorbs two 4-FE
  tips), no padding. Producer writes each completed chain tip directly into its
  contiguous fold-buffer slot (`tip i @ fold_buf + i*HALF_DIGEST_LEN`) so the fold reads
  copy-free 8-FE blocks — same pattern as today.

---

## 5. FORS (k=6, height 24)

### 5.1 Grouping: 24 = 6 + 6 + 6 + 6 (four `do_6` groups)

24 divides cleanly by 6, so each FORS tree's 24-level auth path is exactly **four
`do_6` groups** — the same `do_6` block introduced for the Merkle tree (§3.1) is reused
here. This is the reason to standardise on step = 6.

```
MERKLE_LEVEL_STEP = 6
FORS:  N_GROUPS = SPX_FORS_HEIGHT / 6 = 4   (clean)
TREE:  6 + 6 + 6 + 4                        (tail group)
```

### 5.2 ADRS simplification under d=1

Because `SPX_TREE_BITS = 0`, FORS ADRS loses `idx_tree`:
- `adrs0 = FORS_TREE | (tree_index << ADRS0_FORS_TREE_SHIFT)` — only the FORS-internal
  tree number remains above the type field (no `idx_tree` term). With `tree_index`
  compile-time (unrolled per tree), `adrs0` is a **compile-time constant per tree**.
- `adrs1 = idx_leaf` (the 22-bit leaf, runtime).
- `adrs2 = (tree_height, tree_index_in_tree)` Merkle coordinate (runtime, per level),
  hinted + range-checked via the existing `hint_fors_node_adrs` (which already takes a
  `tree_ht_start` and is height-agnostic).

> **CRITICAL — position binding (see `feedback_fors_position_binding`).** FORS keys MUST
> remain domain-separated by the hypertree leaf position. Under d=1 there is no
> `idx_tree`, so the *only* position binder is `idx_leaf` (the 22-bit leaf). The design
> must keep `idx_leaf` in `adrs1` for the leaf hash, every Merkle level, and the root
> fold. The Rust `test_fors_key_is_position_dependent` regression must be retained and
> updated to vary `idx_leaf` only (idx_tree no longer exists).

### 5.3 Root fold

k=6 is **even** → `ceil(6/2) = 3` T-Sponge blocks, **no zero-pad tip** (unlike the old
odd k=9 which needed a 10th padded tip). The fold buffer holds exactly 6 contiguous
root slots. `adrs0 = pack(layer=0, FORS_ROOTS, tree_addr=0)` is a compile-time constant;
`adrs1 = idx_leaf`.

---

## 6. Tweaking strategy: `make_tweak5`, no tweak table

All tweaked compressions keep the existing `make_tweak5` approach — **no preamble tweak
table, no compile-time Poseidon offsets, no `poseidon16_compress_half_hardcoded_left`.**

- `adrs0` is a **compile-time literal** computed inline (e.g.
  `FORS_ADRS0 = ADRS_FORS_TREE<<2 | fors_tree<<27` under d=1, where `layer=0` and
  `tree_address=0` so they drop out — see §1.1, §5.2).
- `tweak5 = make_tweak5(pk_seed, adrs0) = [pk_seed(4) | adrs0]` is built **once per
  constant-`adrs0` scope** (a WOTS chain, a `do_6`/`do_4` Merkle group, a fold), hoisting
  the `pk_seed` copy out of the inner loop.
- Each compression's left input is assembled per call as
  `[pk_seed | adrs0 | adrs1 | adrs2 | 0]` via `copy_5(tweak5, left)` +
  `left[5]=adrs1; left[6]=adrs2; left[7]=0`, then a plain
  `poseidon16_compress` / `poseidon16_compress_half`.

This is exactly the current `sphincs_utils.py` mechanism (`adrs_compress_pair_t5*`),
retuned for the new parameters. **No precompile change, no new committed table, no
recursion/capacity ripple** from this axis.

> Rationale for not pursuing the XMSS-style hardcoded-left tweak table: under d=1 the
> only fully-compile-time tweak field is `adrs0`; `adrs1` carries the runtime
> `idx_leaf`/`kp_addr` (and per-level node coordinates), and `pk_seed` is runtime
> (per-signature). No call site has a *fully* compile-time 4-FE tweak half, so the
> compile-time-offset precompile does not fit. The `make_tweak5` path already hoists the
> only sizeable repeated cost (the `pk_seed` copy).

---

## 7. `hmsg` + Digest Decomposition — fused into 2 compressions

### 7.1 hmsg as a true sponge (`permute` then `compress`-out8)

`H_msg(R, PK.seed, PK.root, M)` must absorb **20 FE** (R·4 + pk_seed·4 + pk_root·4 +
message·8) and squeeze an 8-FE digest. 20 > 16, so **2 compressions is the
information-theoretic floor** — it cannot shrink (all four inputs are security-required:
R for interleaved-target resistance, pk_seed/pk_root for per-key domain separation, M
for the message).

The current code does `compress → truncate_half → compress`, which throws away 4 FE of
the first call's output. The redesign uses a **proper rate-8/capacity-8 sponge**:

```
# Call 1 — poseidon16_permute (NOT compress): carry the FULL 16-FE permuted state.
state16 = poseidon16_permute([R | pk_seed], [pk_root | message[0:4]])   # 16-FE out

# Call 2 — compress (out8): absorb the last message block; output IS the index slots.
expanded = poseidon16_compress(state16[8:16], [message[4:8] | 0,0,0,0])  # 8-FE out
```

- **Call 1 must be `permute`, not `compress`.** `compress` applies the feed-forward and
  yields a compressed digest; `permute` returns the raw 16-FE permuted state
  (verified: `flag_permute=1 ⇒ out_lo[i]=state[i], out_hi[i]=state[i+8]`, no
  feed-forward). The sponge needs the full permuted state carried into block 2, so
  `permute` is the correct primitive. This also *strengthens* the construction vs the
  old 4-FE `truncate_half` carry — the capacity is carried at full width.
- **Call 2 carries the capacity** `state16[8:16]` as its left input and overwrites the
  rate with the final message block `[message[4:8] | 0,0,0,0]`, producing the 8-FE
  squeeze via a standard out8 compression.

### 7.2 Extract indices directly from the hmsg output (no separate expand)

The 8-FE `expanded` from call 2 is a uniform Poseidon output that already commits to all
20 input FE — i.e. it *is* the message digest. Under d=1 we need only **7 index slots**,
which fit in 8 FE, so the **separate domain-separated expand call is removed entirely**:
indices are sliced directly from `expanded`.

```
N_SLOTS = SPX_D + SPX_FORS_TREES = 1 + 6 = 7   (≤ 8 → one 8-FE output, 1 slot spare)
```

- **Slot 0 — `leaf_idx`:** the **22-bit** tree leaf. `index < 2**22`,
  `upper < 2**(31-22) = 2**9`, binding `expanded[0] == index + upper * 2**22`.
- **Slots 1..6 — the 6 FORS indices:** each **24 bits**. `index < 2**24`,
  `upper < 2**(31-24) = 2**7`, binding `expanded[1+t] == index + upper * 2**24`.
- `idx_tree` is **gone** (`tree_address ≡ 0`); the FORS keypair is bound to `idx_leaf`
  alone (§5.2). So there is no `idx_tree = lli1 | lli2<<...` reconstruction.

**Pipeline: 3 compressions → 2.** Old: `hmsg`(2) + `expand`(1). New: `permute` +
`compress`-out8, with extraction off the second output. The old separate expand existed
only as a slot-count workaround (12 slots needed 2 outputs); it is not a security
requirement — indices are still `f(H_msg(R, pk_seed, pk_root, M))`.

**Why 7 FE suffice (KoalaBear `p = 2³¹ − 2²⁴ + 1`).** Each slot extracts the low `N`
bits of one FE via a hinted `(index, upper)` pair plus the field-equality binding. The
binding `expanded[i] == index + upper·2^N` holds **over the field**, and because
`expanded[i]` is a genuine canonical element (`< p`), any in-range `(index, upper)`
satisfying it is forced to be the true low-bit decomposition — a wrapped representative
(`index + upper·2^N ≥ p`) cannot equal `expanded[i] < p`. So the loose
`upper < 2**(31-N)` range check is sound (it is a superset that the equality
disambiguates), exactly as the current code already relies on. No tighter
`upper < ceil(p/2^N)` bound is required for soundness, though it is also valid.

Total extracted entropy: `22 + 6·24 = 166 bits` across the 8-FE hmsg output (8·~31 ≈ 248
usable bits ≫ 166).

### 7.3 Rust side must match

`core.rs` must mirror the fused construction exactly: `hmsg` becomes
`permute → compress`-out8, and `extract_digest_hash` slices indices directly from that
output (no `expand_digest`). Drop `expand_digest` / the `expanded_a, expanded_b` pair
entirely. The guest `decompose_message_digest` and the Rust extraction must agree on slot
order (leaf at 0, FORS at 1..6) and masks (22-bit leaf, 24-bit FORS). The
sign-side `extract_digest_parts` (hint generation) follows the same single-output layout.

---

## 8. Rust Signer Changes (`crates/sphincs/`)

| File | Change |
|---|---|
| `lib.rs` | New constants (§1). `SPX_D=1`, `SPX_TREE_HEIGHT=22`, `SPX_FORS_TREES=6`, `SPX_FORS_HEIGHT=24`, `SPX_WOTS_LEN=64`, `SPX_WOTS_LOGW=2`, `SPX_WOTS_W=4`, `TARGET_SUM=112`, `NUM_CHAIN_HASHES=80`. `SPX_TREE_BITS=0`, `SPX_CHAIN_ADDR_BITS=6`, `SPX_HASH_ADDR_BITS=2`. |
| `address.rs` | `pack_adrs0` tree_address field is 0-width (assert tree_addr==0). `pack_adrs1_wots` chain shift = 22, hash shift = 28. FORS `adrs0` drops the idx_tree term. Bump `MAX_*` bounds. Re-run all roundtrip tests. |
| `wots.rs` | V=64, w(=LOGW)=2, CHAIN_LENGTH=4, TARGET_SUM=112. `wots_encode` extracts 12 × 2-bit chunks from the bottom 24 bits of each of 6 FEs (then 64 indices). `is_valid_encoding` checks sum==112. Fold over 64 tips (32 blocks). |
| `fors.rs` | k=6, a=24. `fold_roots` over 6 roots (even → 3 blocks, no pad). `extract_fors_indices` reads 6 × 24-bit indices. Update `FORS_SIG_SIZE_FE`. Keep + update the position-binding regression (idx_leaf-only). |
| `hypertree.rs` → rename concept | Collapse to single-tree (`SPX_D=1`). Remove the layer loop and inter-layer re-hash. `tree_address` constant 0. Keep WOTS leaf + 22-level path. |
| `core.rs` | **Rework `hmsg` to `permute → compress`-out8** (true sponge; call 1 = `poseidon16_permute` carrying the full 16-FE state). **Delete `expand_digest`**; `extract_digest_hash` / `extract_digest_parts` slice indices directly from the hmsg output: 22-bit leaf at slot 0, 6 × 24-bit FORS at slots 1..6, no idx_tree. `MSG_RANDOMNESS_LEN_FE`, `prf_msg` unchanged. |
| `signers_cache.rs` | Adjust any cached sizes to the new tree/FORS dims. |

All `poseidon16_compress_pair` tweak layouts (`[pk_seed | adrs0, adrs1, adrs2, 0]`)
stay the same shape; only the packed field widths change. The 8-FE-internal WOTS chain
and the T-Sponge folds are preserved.

---

## 9. zkDSL Guest Changes (`crates/rec_aggregation/zkdsl_implem/`)

| File | Change |
|---|---|
| `sphincs_utils.py` | Update params. `MERKLE_LEVEL_STEP = 6`. Add `do_6_*_merkle_block` (FORS + tree variants) and a `do_4_*` tail (tree). Merkle/FORS/fold keep `make_tweak5` + `adrs_compress_pair_t5_block`. New hint-queue sizes. |
| `sphincs_wots.py` | V=64, LOGW=2 decomposition (`hint_decompose_wots(..., 12, 2)`); range/sum-check first 64 of 72 chunks; sum==112; fold 64 tips. Short chains (≤3 steps) shrink the `match_range(n, range(0, 4))` dispatch. Chain steps keep `make_tweak5` + `poseidon16_compress` (no tweak table). |
| `sphincs_fors.py` | k=6, a=24 = 4 × do_6 groups. Drop `idx_tree` from FORS adrs0. Even-k fold (no pad tip). |
| `sphincs_hypertree.py` → `sphincs_tree.py` | Single-tree verify: one WOTS + 22-level path (6+6+6+4). No layer loop, no inter-layer re-hash. |
| `sphincs_aggregate.py` | **Fuse hmsg + decompose**: `sphincs_verify` builds the digest via `poseidon16_permute([R\|pk_seed],[pk_root\|msg_lo])` then `poseidon16_compress(state[8:16],[msg_hi\|0000])`-out8; `decompose_message_digest` extracts off that output (no separate expand, no `domain_sep`). N_SLOTS=7: 22-bit leaf at 0, 6 × 24-bit FORS at 1..6; no idx_tree. |
| `main_sphincs.py` | Hint-stream sizes follow the new `FORS_SIG_SIZE_FE` / `*_AUTH_SIZE_FE` / `TREE_SIG_SIZE_FE`. |

### 9.1 New hint-queue / blob sizes

```
FORS_SIG_SIZE_FE     = SPX_FORS_TREES * HALF_DIGEST_LEN          = 6 * 4   = 24
FORS_AUTH_SIZE_FE    = SPX_FORS_TREES * SPX_FORS_HEIGHT * HALF   = 6*24*4  = 576
TREE_SIG_SIZE_FE     = RANDOMNESS_LEN+2 + SPX_WOTS_LEN*DIGEST    = 8 + 64*8 = 520   (single tree, no layer loop)
TREE_AUTH_SIZE_FE    = SPX_TREE_HEIGHT * HALF_DIGEST_LEN         = 22*4    = 88
```

---

## 10. VM / Recursion Ripple Effects (must check)

From prior hard-won lessons (memory index), changing committed table shapes or counts
ripples into the in-circuit verifier:

- **`do_6` `match_range` expansion** (64 branch bodies) and **w=4 chain dispatch** stay
  within compiler limits but should be smoke-tested early
  (`feedback_parallel_range_compile_time`, `project_inline_cost_model`).
- **No new Poseidon variant or committed table** is introduced (the design keeps
  `make_tweak5` + the existing `poseidon16_compress` / `_half`). So `N_TABLES` and the
  in-circuit AIR dispatch are **unaffected** by this redesign. (For context, if a future
  change *does* add a Poseidon variant or committed table, it would require bumping
  `N_TABLES`, updating `compilation.rs` + `recursion.py case N`, updating
  `instruction_encoder.rs` push side AND `eval()` pull side together, and raising the
  hardcoded `400` capacity ceilings in `utils.py` — see
  `project_adding_vm_table_recursion_dispatch`,
  `project_poseidon_table_domainsep_push_side`,
  `project_adding_table_recursion_capacity_ceilings`. These fail *deep* in prove/verify;
  reproduce fast with `test_zk_vm_all_precompiles`.)
- **No preamble extension for one-off constants** (`feedback_preamble_memory`): `adrs0`
  values are compile-time literals fed to `make_tweak5`, not a materialised table.

---

## 11. Open Questions for Review

1. **`do_6` program-size budget.** 64-body expansion per group × (4 FORS groups × 6
   trees + 3 tree groups) — validate this doesn't blow the AST / OOM in the unrolled
   per-signature loop (`feedback_const_arg_vs_inline_scaling`). Fallback groupings noted
   in §3.1.
2. **Partial last WOTS FE (§4.2).** Confirm the chosen handling (constrain all 6
   `encoding_fe`, range/sum-check only the 64 live chunks, fold unused chunks into the
   `remaining` reconstruction) matches the Rust `wots_encode` extraction exactly.
3. **TARGET_SUM = 112** locked (signer grind ≈ 2^13, verifier 80 chain hashes). Revisit
   only if the security analysis wants a different few-times margin.

---

## 12. Milestones

1. Rust params + `address.rs` widths + roundtrip tests (no zkDSL yet).
2. Rust `wots.rs` / `fors.rs` / single-tree / `core.rs`; full `sign`/`verify` roundtrip
   test green.
3. zkDSL params + `do_6`/`do_4` blocks using `make_tweak5` everywhere — get the verifier
   correct first.
4. End-to-end batch verify + aggregation tests.
```
