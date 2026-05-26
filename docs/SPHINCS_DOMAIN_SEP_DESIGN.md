# SPHINCS+ Condensed Address Domain Separation — Architecture Design

## Motivation

The current Rust SPHINCS+ signer achieves domain separation through positional encoding:
seed-derivation marker bytes (`0x00` for WOTS+, `0x02` for FORS), a layer index threaded
through the WOTS encoding hash, and implicit structural position in the Merkle tree.

This works for a standalone signer, but creates two problems as we move toward the zkDSL
verifier:

1. **No SK.prf / PK.seed abstraction.** The current signer derives all keying material
   from a raw 20-byte seed via ad-hoc Poseidon calls with marker bytes. There is no
   stable public key seeding value (PK.seed) that a verifier can treat as a compact
   canonical domain context, and no secret PRF value (SK.prf) that separates signing
   randomness from key material.

2. **Hash inputs are not self-describing.** In the FORS leaf derivation and WOTS pre-image
   derivation, the domain context is embedded by convention rather than by a well-defined
   address field. Adding a new hash operation risks collisions if its input layout happens
   to match an existing one.

The fix is a **condensed address structure** — two field elements that pack all ADRS bits
required for our concrete parameters — replacing the ad-hoc positional encoding while
keeping the circuit cost near zero.

---

## Parameter Analysis

| Parameter | Value | Bits needed |
|---|---|---|
| Layer address | 3 layers (0–2) | 2 bits |
| Tree address | up to 2^22 subtrees | 22 bits |
| Type | 7 types (0–6), see below | 3 bits |
| Key pair address | up to 2^22 leaves | 22 bits |
| Chain address | 0–31 (SPX_WOTS_LEN-1) | 5 bits |
| Hash address | 0–14 (SPX_WOTS_W-1) | 4 bits |
| Tree height | 0–15 (max of FORS_HEIGHT, TREE_HEIGHT) | 4 bits |
| Tree index | up to 2^15 leaves per tree | 15 bits |

**Total ADRS content:** 2+22+3+22+5+4 = 58 bits for the widest layout (WOTS_HASH).
This fits in two 31-bit KoalaBear field elements (62 bits available, 4 spare).

We pack the ADRS into exactly **two field elements** `adrs0` and `adrs1`:

```
adrs0 [bits 0–30]:
  bits  1.. 0 : layer        (2 bits)
  bits  4.. 2 : type         (3 bits)
  bits 26.. 5 : tree_address (22 bits)
  bits 30..27 : (unused)

adrs1 [bits 0–30]:
  bits  0–21 : key_pair_address (22 bits)  — or (tree_index for TREE/FORS_TREE)
  bits 22–26 : chain_address    (5 bits)   — or (tree_height for TREE/FORS_TREE)
  bits 27–30 : hash_address     (4 bits)   — zero for non-WOTS_HASH types
```

For the TREE and FORS_TREE types, the second field element is reused as:
```
adrs1 [TREE / FORS_TREE]:
  bits  0–14 : tree_index   (15 bits)
  bits 15–18 : tree_height  (4 bits)
  bits 19–30 : (unused)
```

This single two-element representation covers all 7 ADRS types with no type-specific
overflow.

### ADRS Type Encoding

| Type name | type value | Rust context |
|---|---|---|
| WOTS_HASH | 0 | WOTS+ chain hashing (F function) |
| WOTS_PK   | 1 | WOTS+ pubkey compression (T_l function) |
| TREE      | 2 | XMSS Merkle tree nodes (H function) |
| FORS_TREE | 3 | FORS Merkle tree nodes (H function) |
| FORS_ROOTS| 4 | FORS root folding (T_l function) |
| WOTS_PRF  | 5 | WOTS+ secret key generation (PRF function) |
| FORS_PRF  | 6 | FORS secret key generation (PRF function) |

---

## SK.prf and PK.seed

The reference SPHINCS+ standard defines two keying values:

- **SK.seed** — master secret for deterministic key material. Equivalent to our current
  20-byte seed.
- **SK.prf** — PRF key for randomised message nonce `R`. In the current implementation
  this is replaced by `rand::random()` at signing time; in the domain-separated design
  it becomes a deterministic PRF keyed off SK.prf.
- **PK.seed** — public parameter threaded through every hash call, providing multi-user
  domain separation. All hash calls gain a free extra context word.

### Concrete representation in our field

We represent SK.seed and SK.prf as `[F; HALF_DIGEST_SIZE]` = 4 KoalaBear field elements
(~124 bits of entropy) each. PK.seed is similarly 4 field elements, derived as:

```
PK.seed = poseidon16_compress([SK.seed | zeros], [SK.prf | zeros])[0..4]
```

This is computed once at key generation. PK.seed is part of the public key alongside
the hypertree root.

**zkDSL benefit:** PK.seed is known to the verifier (it is in the public key). Including
it in every hash call is a single pre-loaded constant slot in the verifier — zero extra
dynamic reads.

---

## Updated Hash Functions

All hash primitives now take `(pk_seed: HalfDigest, adrs: Adrs, ...)` as their first
two arguments. In practice we pass them as the first 8 field elements of the Poseidon
left half, with data in the right half (or lower left slots for small inputs). This
matches the existing Poseidon16 compression call convention.

### Hash input layout conventions

**F — single-input compression (WOTS chain step, FORS leaf hash):**
```
left  = [pk_seed[0..4] | adrs.adrs0, adrs.adrs1, 0, 0]
right = [data[0..8]]
output = poseidon16_compress(left, right)[0..4]  // half-digest
```

**H — two-input compression (XMSS/FORS internal nodes):**
```
left  = [pk_seed[0..4] | adrs.adrs0, adrs.adrs1, 0, 0]
right = [left_child[0..4] | right_child[0..4]]
output = poseidon16_compress(left, right)[0..4]  // half-digest
```

**T_l — multi-input compression (WOTS+ pubkey fold, FORS root fold):**
For our parameters, T_l is always either T_32 (WOTS) or T_9 (FORS roots). Rather than
a general T_l, we keep the sequential left-fold convention but thread the ADRS through
every step:

```
// WOTS_PK fold: adrs has type=WOTS_PK, key_pair_address=leaf_index
acc = F(pk_seed, adrs, chain_pub_keys[0], chain_pub_keys[1])
for i in 2..32:
    acc = F(pk_seed, adrs, acc, chain_pub_keys[i])

// FORS_ROOTS fold: adrs has type=FORS_ROOTS, key_pair_address=fors_tree_index
acc = F(pk_seed, adrs, roots[0], roots[1])
for i in 2..9:
    acc = F(pk_seed, adrs, acc, roots[i])
```

**PRF — pseudo-random key derivation:**
```
left  = [pk_seed[0..4] | adrs.adrs0, adrs.adrs1, 0, 0]
right = [sk_seed[0..4] | zeros]
output = poseidon16_compress(left, right)[0..4]
```

**PRFmsg — message nonce generation:**
```
left  = [sk_prf[0..4] | opt_rand[0..4]]   // opt_rand = per-message randomness
right = [message[0..8]]
R = poseidon16_compress(left, right)[0..4]
```

**Hmsg — message digest generation:**
```
left  = [R[0..4] | pk_seed[0..4]]
right = [pk_root[0..4] | message[0..4]]   // first half of message

// If message is longer than 4 FEs, chain:
left2  = [prev_output[0..4] | 0,0,0,0]
right2 = [message[4..8]]
output = poseidon16_compress(left2, right2)
```

For our 8-FE message, two Poseidon calls produce the full digest.

---

## Updated Seed Derivation

Replace the ad-hoc marker-byte approach with structured PRF calls.

### WOTS+ pre-image derivation (was: derive_wots_preimages)

```rust
// adrs: layer=l, type=WOTS_PRF, key_pair_address=global_leaf, chain_address=chain_i
let adrs = Adrs::wots_prf(layer, tree_address, key_pair_address, chain_i);
let pre_image: HalfDigest = prf(pk_seed, sk_seed, adrs);  // 4 FEs
```

One PRF call per chain (32 per WOTS key). The pre-image is a `HalfDigest` (4 FEs).
Every subsequent chain step — including the first — uses `iterate_hash_half_from_half`,
giving a single unified chain function. Replaces the current `derive_wots_preimages`
which constructs a custom Poseidon input layout and returns a full `Digest`.

### FORS leaf derivation (was: derive_leaf_secret)

Producing a FORS leaf node is a two-step operation (matching the spec's distinction
between `FORS_PRF` for key derivation and `FORS_TREE` at height 0 for leaf hashing):

```rust
// Step 1 — PRF: derive the secret value (FORS_PRF type)
// adrs: layer=0, type=FORS_PRF, tree_index=leaf_index (kp_addr unused, captured via tree_addr)
let adrs_prf = Adrs::fors_prf(tree_address, 0, leaf_index);
let sk: HalfDigest = prf(pk_seed, sk_seed, adrs_prf);

// Step 2 — F: hash the secret into the public leaf node (FORS_TREE type, height=0)
// adrs: layer=0, type=FORS_TREE, tree_height=0, tree_index=leaf_index
let adrs_f = Adrs::fors_tree(tree_address, 0, leaf_index);
let leaf_node: HalfDigest = hash_leaf(sk, pk_seed, tree_address, leaf_index);
```

The signature reveals `sk` (the raw PRF output) as `leaf_secret` in `ForsTreeSig`.
The verifier recomputes `leaf_node = hash_leaf(sk, pk_seed, tree, leaf)` and then
walks the auth path — `sk` itself is never used directly as a Merkle input.

---

## Condensed Adrs Struct (Rust)

```rust
/// Two-field-element ADRS for SPHINCS+ with our concrete parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Adrs {
    /// adrs0: bits 0-1 = layer, bits 4-6 = type, bits 7-28 = tree_address
    pub adrs0: F,
    /// adrs1: layout depends on type (see above)
    pub adrs1: F,
}

impl Adrs {
    pub fn wots_hash(layer: u32, tree_addr: u32, kp_addr: u32, chain: u32, hash: u32) -> Self { ... }
    pub fn wots_pk(layer: u32, tree_addr: u32, kp_addr: u32) -> Self { ... }
    pub fn tree(layer: u32, tree_addr: u32, tree_height: u32, tree_index: u32) -> Self { ... }
    pub fn fors_tree(tree_addr: u32, tree_height: u32, tree_index: u32) -> Self { ... }  // kp_addr unused, captured via tree_addr
    pub fn fors_roots(tree_addr: u32, kp_addr: u32) -> Self { ... }
    pub fn wots_prf(layer: u32, tree_addr: u32, kp_addr: u32, chain: u32) -> Self { ... }
    pub fn fors_prf(tree_addr: u32, kp_addr: u32, leaf_index: u32) -> Self { ... }

    /// Clear and set type field; mirrors ADRS.setTypeAndClear from the spec.
    pub fn set_type_and_clear(&mut self, adrs_type: u32) { ... }
}
```

Construction of each variant is a pure integer pack/shift with no heap allocation.

---

## Updated Key Structures

```rust
pub struct SphincsSecretKey {
    pub sk_seed: HalfDigest,   // 4 FEs (~124 bits)
    pub sk_prf:  HalfDigest,   // 4 FEs, used only for message nonce
    pub pk_seed: HalfDigest,   // public, reproduced in SphincsPublicKey
    pub pk_root: HalfDigest,   // hypertree root, reproduced in SphincsPublicKey
}

pub struct SphincsPublicKey {
    pub pk_seed: HalfDigest,
    pub pk_root: HalfDigest,
}
```

`SphincsPublicKey` is now 8 field elements total (was 4). The zkDSL verifier reads both
`pk_seed` and `pk_root` from the hint, threads `pk_seed` through every hash call as
a compile-time-constant left-half prefix.

---

## Impact on zkDSL Verifier

### What changes

1. **Every Poseidon call gains `pk_seed` and `adrs` in its left half.** The left half
   becomes `[pk_seed[0..4] | adrs.adrs0, adrs.adrs1, 0, 0]`. Since `pk_seed` is a
   per-signer constant loaded once from `expected_pk`, it is free to embed.

2. **ADRS values are compile-time constants in the unrolled loops.** Inside
   `for l in unroll(0, SPX_D)`, the layer `l` is a compile-time integer, so
   `adrs.adrs0 = pack(layer=l, type=WOTS_HASH, tree_addr=...)` reduces to a constant
   expression evaluated by the compiler. Chain address and hash address are also
   constants within `iterate_hash_pair` since `_chain_hash_pair_const` already receives
   a compile-time `n`.

3. **`adrs1` changes per chain and per step within a chain.** Per Algorithm 5, each
   hash step `j` within chain `i` sets `chain_address = i` and `hash_address = j`.
   In our `adrs1` encoding: `chain_address` (bits 26..22) is fixed for the whole chain;
   `hash_address` (bits 30..27) increments with each step. Since `_chain_hash_pair_const`
   already receives compile-time `n` (encoding both `chain_i` and step `j`), every
   combination of `(chain_address, hash_address)` is a distinct compile-time constant —
   the unrolled branches each get a different literal `adrs1` value at zero runtime cost.

4. **`wots_encode_and_complete` receives full ADRS as compile-time constants.**
   The layer `l` is already compile-time, so both `adrs0` and `adrs1` for the encoding
   calls are constants. `RANDOMNESS_LEN_FE` drops from 7 to 6 random FEs; slots 6 and 7
   of the right half carry `adrs0` and `adrs1` respectively. The two-call encoding
   structure is preserved:
   ```
   Call A: poseidon(message[0..8],  [r0, r1, r2, r3, r4, r5, adrs0, adrs1])
   Call B: poseidon(call_A_output,  [adrs0, adrs1, 0, 0, 0, 0, 0, 0])
   ```
   The verifier asserts `randomness[6] == adrs0` and `randomness[7] == adrs1` rather than
   the current `randomness[7] == layer_index`. Signature size decreases by one FE per
   WOTS layer (3 FEs total per SPHINCS+ signature).

5. **PRFmsg in the verifier.** The message randomness derivation
   `poseidon([r[0..4] | pk_seed], [message])` replaces the current
   `poseidon(message, [r[0..4] | zeros])`. The verifier already calls
   `poseidon16_compress` for message hashing; this is a fixed reordering of inputs.

6. **`sk_prf` is not needed by the verifier.** Verification uses only `pk_seed` and
   `pk_root`. The SK fields are signing-only.

### zkDSL ADRS constants

Since all ADRS values are compile-time constants in the verifier, they are not loaded
from hints or memory — they are emitted as literal FE values inside each `if` branch of
the compile-time-unrolled loops. This costs zero proof rows and zero memory accesses.

### Poseidon left-half template

Define a helper in `sphincs_utils.py`:

```python
@inline
def adrs_compress(pk_seed, adrs0, adrs1, data_left, data_right, out):
    # Build left half: [pk_seed[0..4] | adrs0, adrs1, 0, 0]
    left = Array(DIGEST_LEN)
    copy_4(pk_seed, left)
    left[4] = adrs0
    left[5] = adrs1
    left[6] = 0
    left[7] = 0
    poseidon16_compress(left, data_right if data_right else data_left, out)
    return
```

When `adrs0` and `adrs1` are compile-time constants (the common case), the compiler
eliminates the `Array` and `copy_4` entirely — the left half is just a literal 8-element
vector. In the rare case where tree_index or chain_address are runtime values (auth path
traversal where `bit` is runtime), the ADRS term containing them will be a runtime slot,
but `pk_seed` remains a constant and only the ADRS slot changes.

---

## Migration Plan

### Phase 1 — Rust signer ✅ COMPLETE

All Rust signer files have been updated. Every `cargo test --release -p sphincs` test
passes (17 unit tests + 1 integration test). The legacy `[u8; 20]` seed and all temporary
shims have been removed.

**`crates/sphincs/src/address.rs`** ✅
- `Adrs` struct with two `F` fields.
- All 7 constructor functions (`wots_hash`, `wots_pk`, `tree`, `fors_tree`, `fors_roots`,
  `wots_prf`, `fors_prf`) and `set_type_and_clear`.
- 9 unit tests covering every constructor and type-distinctness.
- Key implementation note: `MAX_HASH = SPX_WOTS_W - 2 = 14` (not 15) because the
  verifier completes the remaining steps; `hash_address=15` would overflow the KoalaBear
  prime when packed into `adrs1`.

**`crates/sphincs/src/lib.rs`** ✅
- `pub mod address; pub use address::*;`
- `RANDOMNESS_LEN_FE = 6` (was 7).
- New constants: `SPX_KP_ADDR_BITS`, `SPX_CHAIN_ADDR_BITS`, `SPX_HASH_ADDR_BITS`.

**`crates/sphincs/src/wots.rs`** ✅
- `WotsSecretKey::pre_images` is `[HalfDigest; V]` (was `[Digest; V]`).
- `iterate_hash_half` (full-Digest variant) removed; all chain steps use
  `iterate_hash_half_from_half`.
- `wots_encode(message, adrs0, adrs1, randomness)` — right half is
  `[r[0..6], adrs0, adrs1]`. `RANDOMNESS_LEN_FE = 6`.
- `find_randomness_for_wots_encoding`, `sign_with_randomness`, `recover_public_key` all
  take `(adrs0: F, adrs1: F)`.
- `WotsPublicKey::hash(pk_seed: HalfDigest, adrs: Adrs)` — uniform tweak layout:
  `left = [pk_seed | adrs0, adrs1, 0, 0]`, fold with `right = [acc | next_tip]`.

**`crates/sphincs/src/fors.rs`** ✅
- `ForsSecretKey` holds `sk_seed: HalfDigest` and `pk_seed: HalfDigest` (no `[u8; 20]`).
- `derive_leaf_secret` → `prf(pk_seed, sk_seed, Adrs::fors_prf(tree, 0, leaf))`.
- `hash_leaf(secret, pk_seed, tree_index, leaf_index)` uses `Adrs::fors_tree(tree, 0, leaf)`.
- `hash_merkle_node(left, right, pk_seed, tree, height, node_idx)` uses `Adrs::fors_tree`.
- `fold_roots(pk_seed, roots)` — each step `i` uses `Adrs::fors_roots(0, i)`.
- `fors_key_gen(sk_seed, pk_seed)`, `fors_verify(sig, indices, pk_seed)`.

**`crates/sphincs/src/hypertree.rs`** ✅
- `HypertreeSecretKey::new(sk_seed: HalfDigest, pk_seed: HalfDigest)` (no `[u8; 20]`).
- `derive_wots_preimages` removed; pre-images derived inline via
  `prf(pk_seed, sk_seed, Adrs::wots_prf(layer, tree_addr, local_leaf, chain))`.
- `hash_xmss_node(l, r, pk_seed, layer, tree_addr, height, node_idx)` uses `Adrs::tree`.
- `build_layer_tree(sk_seed, pk_seed, layer, tree_address)`.
- `hash_inter_layer_message` removed; layers pass `half_to_full(root)` directly.
- `hypertree_verify` takes `pk_seed: HalfDigest`; all hashing is tweaked.
- WOTS signing uses `Adrs::wots_hash` for `find_randomness_for_wots_encoding` and
  `sign_with_randomness`; WOTS verify uses same ADRS for `recover_public_key`.
- WOTS PK compression uses `Adrs::wots_pk` for `WotsPublicKey::hash`.

**`crates/sphincs/src/core.rs`** ✅
- `SphincsSecretKey { sk_seed, sk_prf, pk_seed, pk_root }` (was `seed: [u8; 20]`).
- `SphincsPublicKey { pk_seed, pk_root }` (was single `pk_root: HalfDigest`).
- `prf`, `prf_msg`, `hmsg` free functions implemented.
- `half_digest_to_legacy_seed` shim removed.
- `sign()` uses `fors_key_gen(sk_seed, pk_seed)` and `HypertreeSecretKey::new(sk_seed, pk_seed)`.
- `verify()` passes `self.pk_seed` to `fors_verify` and `hypertree_verify`.

**`crates/sphincs/src/signers_cache.rs`** ✅ (no code changes needed)
- Already uses `[F; 4]` sk_seed/sk_prf after a previous update.
- Cache fingerprint will change (pk now includes pk_seed). Delete
  `target/signers-cache/benchmark_sphincs_cache_*.bin` before the first benchmark run.

### Phase 2 — zkDSL verifier updates

Work is done **module by module, testing after each**. Run tests with:
```bash
cargo test --release -p rec_aggregation <test_name>
```

#### Status overview

| Module | zkDSL file | Rust test | Status |
|---|---|---|---|
| utils | `sphincs_utils.py` | — | ✅ complete |
| WOTS | `sphincs_wots.py` | `test_sphincs_wots_encode_complete` | ✅ complete |
| FORS | `sphincs_fors.py` | `test_sphincs_fors_merkle_verify`, `test_sphincs_fors_verify` | ✅ complete |
| Hypertree | `sphincs_hypertree.py` | `test_sphincs_hypertree_merkle_verify`, `test_sphincs_hypertree_verify` | ⬜ not started |
| Aggregate | `sphincs_aggregate.py` | `test_sphincs_aggregate` | ⬜ not started |

---

#### ✅ `sphincs_utils.py` — COMPLETE

`adrs_compress(pk_seed, adrs0, adrs1, data_right, out)` is implemented. It builds
`left = [pk_seed[0..4] | adrs0, adrs1, 0, 0]` and calls `poseidon16_compress_half`.
When `adrs0`/`adrs1` are compile-time integers the compiler folds this to zero runtime cost.

New helpers added:
- `do_5_fors_merkle_level_const(k, pk_seed, tree_index, tree_ht_start, adrs1_ptr, rem_ptr, leaf_index, state_in, sibling, state_out)` — 5 tweaked half-digest Merkle levels for FORS trees.
- `do_5_fors_merkle_level(...)` — `match_range` wrapper to make `k` compile-time.
- `fold_wots_pubkey(pk_seed, adrs0, adrs1, chain_pub_keys, out)` — 31-step tweaked fold with WOTS_PK tweak. All nodes are `HALF_DIGEST_LEN` (4 FEs).
- `fold_roots(pk_seed, roots, out)` — 8-step tweaked fold with FORS_ROOTS tweak.

Constants: `RANDOMNESS_LEN = 6`, `FORS_SIG_SIZE_FE = 576`, `HYPERTREE_SIG_SIZE_FE = 534`.

**Key design pattern for runtime floor division (`leaf_index >> H`):** zkDSL `/` is
field (modular inverse) division, not integer division. For every Merkle level h, the
`adrs1` value encodes `node_index = leaf_index >> H` where `H = tree_ht_start + h + 1`.
This is solved by a VM-level custom hint `hint_fors_node_adrs(adrs1_ptr, rem_ptr, leaf_index, tree_ht_start)`
that fills `MERKLE_LEVEL_STEP` slots with:
```
adrs1[h] = (leaf_index >> H) | (H << SPX_FORS_HEIGHT)
rem[h]   = leaf_index % (1 << H)
```
The zkDSL then range-checks `rem[h] < 2^H` and asserts
`leaf_index == (adrs1[h] - H * 2^ADRS1_TREE_HT_SHIFT) * 2^H + rem[h]`.
This custom hint is implemented as `CustomHint::ForsNodeAdrs` in
`crates/lean_vm/src/isa/hint.rs` (name: `"hint_fors_node_adrs"`, 4 args).

---

#### ✅ `sphincs_wots.py` — COMPLETE

`wots_encode_and_complete(message, adrs0, adrs1, randomness, chain_tips, pk_seed, wots_pk_adrs0, wots_pk_adrs1, wots_pubkey)`:
- Asserts `randomness[RANDOMNESS_LEN] == adrs0` and `randomness[RANDOMNESS_LEN+1] == adrs1`.
- All WOTS chain hashing uses `adrs_compress` with WOTS_HASH tweak (compile-time adrs0/adrs1 per step).
- WOTS PK fold uses `fold_wots_pubkey` with WOTS_PK tweak.
- Output `wots_pubkey` is `HALF_DIGEST_LEN` (4 FEs).

Rust test `test_sphincs_wots_encode_complete` passes. Hint layout for that test:
`pk_seed` (4), `message` (8), `adrs0` (1), `adrs1` (1), `wots_pk_adrs0` (1), `wots_pk_adrs1` (1),
`randomness` (8 = 6 random FEs + adrs0 + adrs1), `chain_tips` (128), `expected` (4).

---

#### ✅ `sphincs_fors.py` — COMPLETE

`fors_merkle_verify(pk_seed, tree_index, leaf_index, leaf_secret, auth_path, out)`:
- `match_range(tree_index, range(0, SPX_FORS_TREES), lambda t: _fors_merkle_verify_const(t, ...))` makes `tree_index` compile-time.
- `_fors_merkle_verify_const` hashes `leaf_secret` → `leaf_node` as step 0 with `FORS_TREE` tweak at height=0: `adrs_compress(pk_seed, FORS_LEAF_ADRS0, leaf_index, leaf_right, leaf_node)`.
- Uses `hint_decompose_bits_fors` to split `leaf_index` into `N_GROUPS = 3` five-bit sub-indices, then calls `hint_fors_node_adrs` per group.
- Walks 3 groups of 5 levels via `do_5_fors_merkle_level`.
- All nodes are `HALF_DIGEST_LEN` (4 FEs). `auth_path` is `SPX_FORS_HEIGHT * HALF_DIGEST_LEN` = 60 FEs.

`fors_verify(pk_seed, fors_indices, fors_pk)`:
- Hints `fors_sig` (576 FEs): `SPX_FORS_TREES * (1 + SPX_FORS_HEIGHT) * HALF_DIGEST_LEN`.
  Layout per tree `t`: `[leaf_secret (4 FEs) | auth_path (60 FEs)]`.
- Calls `fors_merkle_verify` for each tree, then `fold_roots`.
- Output `fors_pk` is `HALF_DIGEST_LEN` (4 FEs).

Rust helper `fors_sig_to_flat` in `crates/sphincs/src/fors.rs` emits:
`leaf_secret (4) + auth_path (4×15 = 60)` per tree = 64 FEs × 9 trees = 576 FEs. ✅ matches.

Rust tests `test_sphincs_fors_merkle_verify` and `test_sphincs_fors_verify` both pass.
No external hint data needed for adrs1 — the VM hint handles it entirely.

---

#### ⬜ `sphincs_hypertree.py` — NOT STARTED

**What needs to change:**

The current implementation uses untweaked `poseidon16_compress` (full 8-FE nodes) for
Merkle verification and an explicit `poseidon16_compress` inter-layer message hash.
Both are wrong — the Rust signer uses `hash_xmss_node` (TREE tweak, HalfDigest output)
and passes `half_to_full(layer_root)` directly between layers (no hash, just zero-pad).

**`HYPERTREE_SIG_SIZE_FE`** is already correct in `sphincs_utils.py`:
`3 * (6 + 32*4 + 11*4) = 3 * 178 = 534`. But `flatten_hypertree_sig` in
`crates/sphincs/src/hypertree.rs` currently pushes `F::from_usize(layer_idx)` as an
**extra FE** per layer (line 61: `out.push(F::from_usize(layer_idx))`), making the flat
sig 537 FEs. **This must be removed** before the zkDSL test can pass — `layer` is now
baked into `adrs0`, not stored in the signature.

**Required changes in `sphincs_hypertree.py`:**

1. **`hypertree_merkle_verify` new signature:**
   ```python
   def hypertree_merkle_verify(pk_seed, layer, layer_tree_address, layer_leaf_index, leaf_node, auth_path, root_out):
   ```
   - `layer` and `layer_tree_address` are compile-time (from the unrolled loop in `hypertree_verify`).
   - `leaf_node` and `root_out` are `HALF_DIGEST_LEN` (4 FEs), not `DIGEST_LEN` (8 FEs).
   - `auth_path` is `SPX_TREE_HEIGHT * HALF_DIGEST_LEN` = 44 FEs.
   - Replace `do_1_merkle_level` + `do_5_merkle_level` (untweaked, full-digest) with a new
     `do_5_hypertree_merkle_level` using the TREE tweak and `HALF_DIGEST_LEN` nodes.

2. **New `do_5_hypertree_merkle_level_const` helper in `sphincs_utils.py`:**

   This follows the same pattern as `do_5_fors_merkle_level_const` exactly, with two differences:
   - `TREE_ADRS0 = ADRS_TREE * (2 ** ADRS0_TYPE_SHIFT) + layer * (2 ** ADRS0_LAYER_SHIFT) + layer_tree_address * (2 ** ADRS0_TREE_SHIFT)` — where `ADRS0_LAYER_SHIFT = 0` (layer is bits 1..0).
     Actually: `adrs0 = layer | (ADRS_TREE << ADRS0_TYPE_SHIFT) | (layer_tree_address << ADRS0_TREE_SHIFT)`.
   - `ADRS1_TREE_HT_SHIFT = SPX_FORS_HEIGHT = 15` is the same shift (reused for TREE type).
   - The `hint_fors_node_adrs` VM hint computes `(leaf_index >> H) | (H << 15)` — this is
     identical for TREE nodes since TREE and FORS_TREE share the same `adrs1` layout.
     **Reuse `hint_fors_node_adrs` directly** for hypertree Merkle levels; no new VM hint needed.

   Signature:
   ```python
   def do_5_hypertree_merkle_level_const(k, pk_seed, layer, layer_tree_address, tree_ht_start,
                                          adrs1_ptr, rem_ptr, leaf_index,
                                          state_in, sibling, state_out):
   ```
   And the `match_range` wrapper `do_5_hypertree_merkle_level(...)`.

   **Note on decomposition:** `SPX_TREE_HEIGHT = 11`, which is not divisible by `MERKLE_LEVEL_STEP = 5`.
   11 = 1 + 5 + 5. The current code handles this with `do_1_merkle_level` (1 level) followed
   by two `do_5_merkle_level` calls. The new tweaked version must follow the same structure:
   - One tweaked single-level step (level 1): new `do_1_hypertree_merkle_level` or inline it.
   - Two `do_5_hypertree_merkle_level` calls (levels 2–6 and 7–11).

   For the single level: use `adrs_compress` with `adrs1 = (leaf_index >> 1) | (1 << 15)`,
   hinted via `hint_fors_node_adrs(adrs1_ptr, rem_ptr, leaf_index, 0)` taking only index 0.

3. **`hypertree_verify` new implementation:**
   ```python
   def hypertree_verify(pk_seed, fors_pubkey, layer_leaf_indices, expected_pk):
   ```
   - Remove `messages` array and all `poseidon16_compress` between-layer calls.
   - Between-layer message is `half_to_full(layer_root)` = `[layer_root[0..4] | 0, 0, 0, 0]`.
     In zkDSL: allocate `msg = Array(DIGEST_LEN)`, `copy_4(layer_root, msg)`, `msg[4]=0; ...; msg[7]=0`.
   - Layer 0 initial message: `half_to_full(fors_pubkey)` (same pattern: 4 FEs + 4 zeros).
   - `wots_leaf = Array(HALF_DIGEST_LEN)` (not `DIGEST_LEN`).
   - `layer_root = Array(HALF_DIGEST_LEN)` (not `DIGEST_LEN`).
   - `expected_pk` is `HALF_DIGEST_LEN` (4 FEs, the hypertree root).
   - The `wots_encode_and_complete` call keeps its current compile-time `adrs0`/`adrs1`
     derivation. ADRS for layer `l`, tree `layer_tree_address`, leaf `layer_leaf_index`:
     - `WOTS_HASH_ADRS0 = layer | (ADRS_WOTS_HASH << ADRS0_TYPE_SHIFT) | (layer_tree_address << ADRS0_TREE_SHIFT)` — compile-time for each unrolled `l`.
     - `WOTS_HASH_ADRS1 = layer_leaf_index` — runtime (from `layer_leaf_indices[l]`).
     - `WOTS_PK_ADRS0 = layer | (ADRS_WOTS_PK << ADRS0_TYPE_SHIFT) | (layer_tree_address << ADRS0_TREE_SHIFT)` — compile-time.
     - `WOTS_PK_ADRS1 = layer_leaf_index` — runtime.

     **Critical:** `layer_tree_address` is runtime (derived from `layer_leaf_indices`).
     The current `hypertree_verify` uses `match_range` on `tree_index`? No — it doesn't.
     The layer is compile-time (unroll), but `layer_tree_address` is runtime. Therefore
     `WOTS_HASH_ADRS0` is **runtime** (because `layer_tree_address` shifts into it).
     Follow the same `match_range` dispatch used in FORS if a compile-time tree address
     is needed, OR accept that `adrs0` is runtime for the hypertree — which is fine since
     `adrs_compress` supports runtime `adrs0/adrs1` scalars (no `match_range` required for
     correctness, only for compile-time optimisation).

   - `hypertree_sig` layout per layer `l`:
     `randomness (6 FEs) | chain_tips (SPX_WOTS_LEN * HALF_DIGEST_LEN = 128 FEs) | auth_path (SPX_TREE_HEIGHT * HALF_DIGEST_LEN = 44 FEs)` = 178 FEs.
     Layer offset: `l * 178`.

**Required changes in `crates/sphincs/src/hypertree.rs`:**

- Remove `out.push(F::from_usize(layer_idx));` from `flatten_hypertree_sig` (line 61).
  After this removal the flat sig is `3 * (6 + 128 + 44) = 534` FEs = `HYPERTREE_SIG_SIZE_FE`. ✅

**Required changes in test files:**

`tests/test_hypertree_merkle_verify.py`:
- Add `pk_seed` hint (4 FEs).
- Add `layer` hint (1 FE scalar).
- Add `layer_tree_address` hint (1 FE scalar).
- Change `leaf_node` to `HALF_DIGEST_LEN` (4 FEs).
- Change `auth_path` to `SPX_TREE_HEIGHT * HALF_DIGEST_LEN` = 44 FEs.
- Change `expected_root` and `root_out` to `HALF_DIGEST_LEN`.
- Call: `hypertree_merkle_verify(pk_seed, layer, layer_tree_address, layer_leaf_index, leaf_node, auth_path, out)`.

`tests/test_hypertree_verify.py`:
- Add `pk_seed` hint (4 FEs).
- Change `fors_pubkey` hint to `HALF_DIGEST_LEN` (4 FEs).
- Change `expected_pk` hint to `HALF_DIGEST_LEN` (4 FEs).
- Call: `hypertree_verify(pk_seed, fors_pubkey, layer_leaf_indices, expected_pk)`.

`tests/test_sphincs_utils.rs` — add two new test functions:

`test_sphincs_hypertree_merkle_verify`:
```rust
// Build a single-layer tree, extract leaf/auth_path, call zkDSL
let layer = 0usize;
let layer_tree_address = 0usize;
let layer_leaf_index: usize = rng.random_range(..(1 << SPX_TREE_HEIGHT));
// Build tree via hypertree internals (build_layer_tree is pub in hypertree.rs).
// Need: leaf_node = WOTS pk hash; auth_path = SPX_TREE_HEIGHT HalfDigests; root.
HashMap::from([
    ("pk_seed", vec![pk_seed.to_vec()]),
    ("layer", vec![vec![F::from_usize(layer)]]),
    ("layer_tree_address", vec![vec![F::from_usize(layer_tree_address)]]),
    ("layer_leaf_index", vec![vec![F::from_usize(layer_leaf_index)]]),
    ("leaf_node", vec![leaf_node.to_vec()]),  // HalfDigest
    ("auth_path", vec![auth_path.iter().flatten().copied().collect()]),  // 44 FEs
    ("expected_root", vec![root.to_vec()]),  // HalfDigest
])
```

`test_sphincs_hypertree_verify`:
```rust
// Sign with hypertree_sign, call hypertree_verify, flatten sig (without layer_idx).
let sig = hypertree_sign(&sk, &half_to_full(fors_pk), leaf_idx, tree_address);
let sig_flat = sig.flatten_hypertree_sig();  // 534 FEs after fix
HashMap::from([
    ("pk_seed", vec![pk_seed.to_vec()]),
    ("fors_pubkey", vec![fors_pk.to_vec()]),  // HalfDigest (4 FEs)
    ("layer_leaf_indices", vec![layer_leaf_indices_as_fe]),  // 3 FEs
    ("expected_pk", vec![pk_root.to_vec()]),  // HalfDigest (4 FEs)
    ("hypertree_sig", vec![sig_flat]),
])
```

Note: `build_layer_tree` and `extract_auth_path` may need to be made `pub` in `hypertree.rs`
for the merkle test, or the test can use a full `hypertree_sign` call and extract the
auth path from the resulting `HypertreeLayerSig`.

**Verification commands:**
```bash
cargo test --release -p rec_aggregation test_sphincs_hypertree_merkle_verify
cargo test --release -p rec_aggregation test_sphincs_hypertree_verify
```

---

#### ⬜ `sphincs_aggregate.py` — NOT STARTED

The public key hint is now 8 FEs: `[pk_seed[0..4] | pk_root[0..4]]`.

Required changes:
- Load `pk_seed = hint[0..4]`, `pk_root = hint[4..8]` from the public key hint.
- Pass `pk_seed` into `hypertree_verify` and all other functions that need it.
- `fors_verify(pk_seed, fors_indices, fors_pk)` already takes `pk_seed`.
- `hypertree_verify(pk_seed, fors_pubkey, layer_leaf_indices, expected_pk)` will take `pk_seed` after the hypertree update.

The `test_sphincs_aggregate` suite was previously hitting a SIGKILL (OOM/stack overflow)
before any of these changes. That is a pre-existing issue unrelated to domain separation.

---

### Key invariant

All ADRS values that depend only on compile-time loop indices (layer `l`, chain `i`,
encoding step) remain compile-time constants → zero runtime overhead.

ADRS values that depend on runtime Merkle path bits (tree_height + tree_index during
auth path traversal) become a single runtime field element (`adrs1`) per Poseidon call.
`adrs1` is not computed via field division — it is filled by `hint_fors_node_adrs` (or
the same hint reused for hypertree) and proved correct via range-check + linear constraint.

At 15 levels × 9 FORS trees + 11 levels × 3 hypertree layers = 135 + 33 = 168 affected
Poseidon calls, this is 168 extra multiplications and 168 extra additions in the trace —
a negligible overhead compared to the ~1000 Poseidon calls.

---

## Concrete Adrs Bit-Packing Reference

### adrs0

```
adrs0 = layer | (type << 2) | (tree_address << 5)
      // layer: bits  1.. 0  (2 bits,  0–2)
      // type:  bits  4.. 2  (3 bits,  0–6)
      // tree:  bits 26.. 5  (22 bits, tree_address ≤ 2^22 - 1)
      // spare: bits 30..27
```

### adrs1 — WOTS_HASH / WOTS_PRF / WOTS_PK

```
adrs1 = key_pair_address | (chain_address << 22) | (hash_address << 27)
      // kp_addr:    bits 21..0  (22 bits, leaf global index ≤ 2^22)
      // chain_addr: bits 26..22 (5 bits, 0..31)
      // hash_addr:  bits 30..27 (4 bits, 0..15)
```

For WOTS_PK and WOTS_PRF, `chain_addr` and `hash_addr` are zero.

### adrs1 — TREE / FORS_TREE

```
adrs1 = tree_index | (tree_height << 15)
      // tree_index:  bits 14..0  (15 bits, leaf ≤ 2^15)
      // tree_height: bits 18..15 (4 bits, 0..15)
      // spare:       bits 30..19
```

For FORS_ROOTS, `adrs1 = key_pair_address` (22 bits, same as WOTS layout slot 0).

---

## Intentional Deviations from FIPS 205

These are deliberate differences from the reference algorithms. They are not bugs.

### 1. Fixed-sum encoding replaces the checksum

The spec (Algorithms 7 and 8) appends `len2` checksum chains to the `len1` message
chains. Our implementation uses a **fixed-sum encoding** (`TARGET_SUM = 304`) over
exactly `SPX_WOTS_LEN = 32` chains, with no checksum chains. The fixed-sum constraint
binds all chains together — an attacker who changes any encoding index must decrease
another — providing the same unforgeability guarantee the checksum provides, at lower
cost and without the need for `len2` extra chains.

### 2. Randomised WOTS encoding via two Poseidon calls

The spec derives encoding indices directly via `base_2b(M)` (bit extraction from the
message with no hash). Our encoding uses:
```
Call A: poseidon(message[0..8], [r0..r5, adrs0, adrs1])
Call B: poseidon(call_A_output, [adrs0, adrs1, 0, 0, 0, 0, 0, 0])
```
The per-signature randomness `r` is mixed into the encoding to prevent grinding attacks:
an attacker who can choose `r` freely can try many encodings, but since `r` is committed
to in `R` (via PRFmsg) before the message is known, it cannot be adapted post-message.

### 3. No `hash_inter_layer_message` between hypertree layers

The spec (Algorithm 12) passes the raw `root` output of `xmss_pkFromSig` directly as
the message into the next layer's WOTS signing call. Our current signer wraps this in an
extra Poseidon call with a layer index. With the ADRS scheme this wrapper is removed:
the `layer` field in `adrs0` already distinguishes layers, so the raw root is passed
directly, matching the spec.

---

## Security Notes

1. **PK.seed size.** We use 4 KoalaBear field elements (4 × 31 = 124 bits) for PK.seed.
   This matches our existing half-digest size convention and provides multi-user domain
   separation at the same security level as the hash output. Using fewer bits would
   weaken multi-user security.

2. **ADRS collision resistance.** With 62 bits of ADRS space (two 31-bit FEs), two
   distinct (type, positional) tuples always produce distinct bit patterns, as long as no
   two of our 7 type codes + their positional fields collide — which they cannot since
   the type field is disjoint from all positional fields and all positional fields are
   bounded by the parameter sizes above.

3. **PRF vs bare hash for key derivation.** Using `prf(pk_seed, sk_seed, adrs)` rather
   than a bare hash with a marker byte adds PK.seed as a second independent key input.
   This ensures that two signers with different PK.seeds but the same SK.seed produce
   independent key material, closing a related-key attack surface that the current
   marker-byte approach does not address.

4. **Keeping SK.prf separate from SK.seed.** The PRFmsg call for message nonce uses only
   SK.prf, never SK.seed. This means leaking `R` from a nonce collision does not directly
   leak SK.seed, preserving standard separation between signing randomness and key material.

---

## Resolved Design Decisions

1. **RANDOMNESS_LEN drops from 7 to 6.** The signature stores 6 random FEs per WOTS
   layer. Slots 6 and 7 of the Poseidon right half carry `adrs0` and `adrs1`,
   both reconstructed at verification time as compile-time constants. The two-call
   encoding structure is:
   ```
   Call A: poseidon(message[0..8],  [r0..r5, adrs0, adrs1])
   Call B: poseidon(call_A_output,  [adrs0, adrs1, 0, 0, 0, 0, 0, 0])
   ```
   The verifier asserts `randomness[6] == adrs0` and `randomness[7] == adrs1`.
   Full ADRS coverage across both calls; signature shrinks by 3 FEs total (1 per layer).

2. **All PRF outputs are half-digests (4 FEs).** WOTS pre-images are `HalfDigest`,
   not full `Digest`. This means the first chain step calls `iterate_hash_half_from_half`
   rather than `iterate_hash_half` — a single unified function handles all chain steps
   including the initial one. The 4-FE entropy is sufficient; truncating an 8-FE output
   to 4 FEs at the start of every chain wastes one Poseidon call per chain with no
   security benefit.

3. **PK.seed is part of `SphincsPublicKey`.** Public key grows from 4 to 8 FEs
   (`pk_seed: HalfDigest` + `pk_root: HalfDigest`). The verifier reads both from the
   hint and uses `pk_seed` as a per-signer constant threaded through every hash call.

4. **Cache must be invalidated manually.** Delete
   `target/signers-cache/benchmark_sphincs_cache_*.bin` before the first run after
   the update. The footprint check will regenerate automatically.
