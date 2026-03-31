# SPHINCS+ Architecture Plan

## Project Goal

Implement SPHINCS+ signature aggregation using the leanMultisig zkVM, mirroring the
existing XMSS crate. Final deliverables:
1. `crates/sphincs/` — native Rust implementation for key gen, sign, verify, and benchmark cache
2. `crates/rec_aggregation/sphincs_aggregate.py` — zkDSL verification circuit for proof aggregation

The Rust crate comes first. It generates test vectors and benchmark witnesses. The zkDSL
cannot be meaningfully written or debugged without a working native implementation to
validate against.

---

## Parameters

| Constant | Value | Notes |
|---|---|---|
| `DIGEST_SIZE` | 8 | KoalaBear field elements per hash output (inherited from XMSS) |
| `SPX_N` | 16 | Hash output bytes (reference only) |
| `SPX_FULL_HEIGHT` | 33 | Total hypertree depth |
| `SPX_D` | 3 | Number of XMSS layers in hypertree |
| `SPX_TREE_HEIGHT` | 11 | Height of each individual XMSS tree (33/3) |
| `SPX_FORS_HEIGHT` | 15 | Height of each FORS binary tree |
| `SPX_FORS_TREES` | 9 | Number of FORS trees (k) |
| `SPX_WOTS_W` | 16 | WOTS+ chain length |
| `SPX_WOTS_LOGW` | 4 | Bits per chain index (log2(16)) |
| `SPX_WOTS_LEN` | 32 | WOTS+ chains per key (8 * N * 8 / LOGW = 8*16/4) |
| `TARGET_SUM` | 240 | Fixed sum of all 32 encoding indices |
| `NUM_CHAIN_HASHES` | 240 | Verifier chain steps (= V*(w-1) - TARGET_SUM = 32*15 - 240) |
| `V_GRINDING` | 0 | No grinding chains |
| `LOG_LIFETIME` | 30 | Total signatures supported = 2^30 |
| `RANDOMNESS_LEN_FE` | 7 | Field elements of per-signature randomness (inherited) |
| `MESSAGE_LEN_FE` | 9 | Field elements per message input |

**Derived values:**
- Each XMSS layer manages `2^(SPX_TREE_HEIGHT) = 2^11 = 2048` leaves
- FORS selects `k=9` trees, each contributing `a=15` auth path nodes
- `SPX_FORS_MSG_BYTES = (15*9 + 7) / 8 = 17` bytes to index into FORS trees

---

## Poseidon Hash Count Per Verification

| Step | Count | Notes |
|---|---|---|
| FORS leaf hashing | 9 | One per tree |
| FORS auth paths | 9 × 15 = 135 | One per level per tree |
| FORS root combination | 8 | Sequential fold of 9 roots |
| Inter-layer message hash | 3 | FORS→layer0, layer0→layer1, layer1→layer2 |
| WOTS encoding (per layer) | 2 × 3 = 6 | Two Poseidon calls per encoding |
| WOTS chain completion (per layer) | 240 × 3 = 720 | Fixed by TARGET_SUM |
| WOTS pubkey collapse (per layer) | 31 × 3 = 93 | Sequential fold of 32 tips |
| Merkle path (per layer) | 11 × 3 = 33 | One per tree level |
| **Total** | **~1004** | ~5.4× XMSS (185 hashes) |

Chain completion (720/1004 = 72%) dominates. This drives proof size and aggregation cost.

---

## Domain Separation Strategy

Uses **positional encoding** — the same approach as the existing XMSS crate. No explicit
address struct. Context is folded directly into hash inputs and seed derivation.

**Why not address structs:** The reference implementation uses a 252-bit STARK field where
5 field elements cover the full address cheaply. In KoalaBear (31-bit), an address struct
costs 2 field elements per hash call (~2000 extra elements per verification). Since the
two field representations are incompatible anyway, cross-implementation test vectors cannot
be directly reused regardless of approach. Positional encoding has zero overhead and is
consistent with the existing codebase.

### Seed derivation marker bytes

All keys and pseudo-random nodes are derived deterministically from a master seed using
`StdRng::from_seed`. Marker bytes prevent collisions between different derivation contexts:

| Marker | Context |
|---|---|
| `0x00` | WOTS+ pre-images (layer index + leaf index) |
| `0x01` | FORS secret values (FORS tree index + leaf index) |

Each derivation also includes all positional fields (layer index, tree index, leaf index)
to ensure uniqueness across the full hypertree.

Note: unlike XMSS, SPHINCS+ has no sparse tree / out-of-range node problem. Each XMSS
layer tree (height 11, 2048 leaves) and each FORS tree (height 15, 32768 leaves) is fully
materialised during key generation. There are no pseudo-random out-of-range nodes.

### Hash input domain separation

| Hash call | Positional context included |
|---|---|
| WOTS encoding (A) | message + randomness |
| WOTS encoding (B) | A + leaf index + truncated Merkle root of current layer's tree |
| Inter-layer message | child Merkle root + layer index + randomness counter |
| FORS leaf | secret value (derivation already position-specific) |
| FORS tree nodes | bare compression of children (position implicit via tree structure) |
| FORS root combination | sequential fold (order encodes position) |

---

## Crate Structure

```
crates/sphincs/
├── src/
│   ├── lib.rs            — constants, type aliases, module exports
│   ├── wots.rs           — WOTS+ (self-contained, not shared with xmss crate)
│   ├── fors.rs           — FORS key gen, sign, verify
│   ├── hypertree.rs      — d-layer XMSS hypertree (layer signing + Merkle paths)
│   ├── sphincs.rs        — top-level keygen, sign, verify
│   └── signers_cache.rs  — benchmark cache (mirrors xmss/signers_cache.rs pattern)
├── tests/
│   └── sphincs_tests.rs
└── Cargo.toml
```

No `address.rs` — positional encoding means there is no address struct.

---

## Module Responsibilities

### `lib.rs`
- All constants from the parameters table above
- `type F = KoalaBear` and `type Digest = [F; DIGEST_SIZE]`
- Re-exports from all sub-modules

### `wots.rs`
Self-contained WOTS+ adapted for `V=32, w=16, TARGET_SUM=240, V_GRINDING=0`.
Differs from `xmss/wots.rs` in:
- No grinding indices
- Longer chains (w=16 vs w=8)
- Different TARGET_SUM
- Encoding must include layer index in the B compression (domain separation)

Key types: `WotsSecretKey`, `WotsPublicKey`, `WotsSignature`
Key functions: `wots_encode`, `find_randomness_for_wots_encoding`, `iterate_hash`

### `fors.rs`
FORS (Few-Times Signature Scheme). Signs a message by:
1. Splitting the message into `k=9` indices, each selecting a leaf in one of 9 binary trees of height 15
2. Revealing the selected leaf's secret value and its 15-node auth path
3. Verifier recomputes each tree root from (leaf, auth path) and hashes the k roots together

Key types: `ForsSecretKey`, `ForsPublicKey`, `ForsSignature`
Key functions: `fors_key_gen`, `fors_sign`, `fors_verify`

FORS secret values are derived from the master seed using marker `0x02`:
```
rng_seed = seed ‖ 0x02 ‖ fors_tree_index as u8 ‖ leaf_index.to_le_bytes()
```

### `hypertree.rs`
Manages the `d=3` layer XMSS hypertree. Each layer is an XMSS tree of height 11.
Layer 0 signs messages (FORS output hash). Layers 1 and 2 each sign the Merkle root
of the layer below.

Inter-layer message hashing:
```
message_for_layer_i = hash(child_merkle_root, layer=i, randomness_counter)
```
The randomness counter serves the same role as in WOTS encoding — ensures the
resulting digest achieves TARGET_SUM with bounded retries.

Key types: `HypertreeSecretKey`, `HypertreePublicKey`, `HypertreeSignature`
Key functions: `hypertree_key_gen`, `hypertree_sign`, `hypertree_verify`

### `sphincs.rs`
Top-level composition. Ties FORS and hypertree together.

Sign:
1. Hash message to get FORS indices
2. FORS sign → FORS signature + FORS public key
3. Hash FORS public key (with layer=0, randomness counter) → hypertree message
4. Hypertree sign → hypertree signature

Verify:
1. FORS verify → recover FORS public key
2. Hash FORS public key → hypertree message
3. Hypertree verify → check against SPHINCS+ public key

Key types: `SphincsSecretKey`, `SphincsPublicKey`, `SphincsSignature`
Key functions: `sphincs_key_gen`, `sphincs_sign`, `sphincs_verify`

### `signers_cache.rs`
Mirrors `xmss/signers_cache.rs` exactly. Pre-computes WOTS randomness for benchmark
signers and persists to `test_data/benchmark_signers.json`. SPHINCS+ signing is
significantly more expensive than XMSS (3 WOTS layers + FORS), making pre-computation
even more important for benchmarks.

---

## Key Design Decisions (Locked)

1. **Positional encoding for domain separation** — no address struct
2. **Self-contained `wots.rs`** — not shared with or refactored from `xmss/wots.rs`
3. **No grinding** (`V_GRINDING=0`) — TARGET_SUM constraint alone is sufficient
4. **FORS root is hashed before passing to WOTS layer 0** — the hash includes layer
   index and randomness counter to bind it to a specific position in the hypertree
5. **Inter-layer messages are hashed** with layer index + randomness counter (same
   pattern as FORS→WOTS transition)
6. **Randomness counter retry loop** — same pattern as `find_randomness_for_wots_encoding`
   in XMSS; retry until the hash yields indices summing to TARGET_SUM

---

## Relationship to Existing Crates

| This crate uses | From |
|---|---|
| `KoalaBear`, `EF` | `backend/koala-bear` |
| `poseidon16_compress_pair` | `utils` |
| `compress` (bare, for Merkle trees) | `backend/symetric` |
| `default_koalabear_poseidon2_16` | `backend/koala-bear` |
| `rayon::into_par_iter` | `rayon` (already in workspace) |

Does **not** depend on `xmss` crate — fully independent.

---

## Open Questions

- [ ] Exact layout of FORS message derivation: how are the 9 tree indices extracted
      from the hashed message? (bit decomposition of `SPX_FORS_MSG_BYTES = 17 bytes`)
- [ ] Whether `poseidon16_compress_pair` or bare `compress` is used for FORS tree
      node hashing (affects zkDSL circuit design later)
- [ ] Exact Poseidon input layout for the inter-layer message hash (which fields go
      in left half vs right half of the 16-element state)
