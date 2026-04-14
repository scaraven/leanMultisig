# SPHINCS+ zkDSL Planning Document

## Scope

Provable verification of raw SPHINCS+ signatures only. No recursive aggregation.
The circuit proves: given `(pk, message, sig)` for each signer, all signatures are valid
and all public keys hash to the committed `pubkeys_hash`.

---

## File Structure

```
crates/rec_aggregation/
  sphincs_utils.py       # Shared helpers: do_1_merkle_level, iterate_hash, fold helpers
  sphincs_wots.py        # WOTS+ chain hashing and public key recovery (imports sphincs_utils)
  sphincs_fors.py        # FORS tree verification (imports sphincs_wots, sphincs_utils)
  sphincs_hypertree.py   # Hypertree verification (imports sphincs_wots, sphincs_utils)
  sphincs_aggregate.py   # Digest decomposition + top-level verify
  main_sphincs.py        # Main entry point (no recursion)
```

---

## Parameters (from lib.rs)

```python
DIGEST_LEN     = 8
SPX_WOTS_LEN   = 32     # V — chains per WOTS instance
SPX_WOTS_LOGW  = 4      # W — bits per encoding index
SPX_WOTS_W     = 16     # CHAIN_LENGTH
TARGET_SUM     = 240    # sum of all 32 encoding indices
V_GRINDING     = 0      # no grinding
SPX_D          = 3      # hypertree layers
SPX_TREE_HEIGHT = 11    # leaves per hypertree layer = 2^11 = 2048
SPX_FORS_HEIGHT = 15    # leaves per FORS tree = 2^15 = 32768
SPX_FORS_TREES  = 9     # k
RANDOMNESS_LEN  = 7     # FEs
MESSAGE_LEN     = 9     # FEs
```

---

## Signature Flat Layout (for `hint_sphincs`)

Analogous to `hint_xmss`, one flat `Vec<F>` per signature fed out-of-band.

```
FORS_SIG_SIZE_FE      = SPX_FORS_TREES * (1 + SPX_FORS_HEIGHT) * DIGEST_LEN
                       = 9 * (1 + 15) * 8 = 1152 FEs

HYPERTREE_SIG_SIZE_FE = SPX_D * (RANDOMNESS_LEN + SPX_WOTS_LEN * DIGEST_LEN + SPX_TREE_HEIGHT * DIGEST_LEN)
                       = 3 * (7 + 32*8 + 11*8) = 3 * 351 = 1053 FEs

SIG_SIZE_FE           = FORS_SIG_SIZE_FE + HYPERTREE_SIG_SIZE_FE = 2205 FEs

Layout:
  [ FORS section ]
  for tree t in 0..9:
    leaf_secret:  DIGEST_LEN FEs  (8)
    auth_path:    SPX_FORS_HEIGHT * DIGEST_LEN FEs  (15 * 8 = 120)
  -- 9 * 128 = 1152 FEs total

  [ Hypertree section ]
  for layer l in 0..3:
    randomness:   RANDOMNESS_LEN FEs  (7)
    chain_tips:   SPX_WOTS_LEN * DIGEST_LEN FEs  (32 * 8 = 256)
    auth_path:    SPX_TREE_HEIGHT * DIGEST_LEN FEs  (11 * 8 = 88)
  -- 3 * 351 = 1053 FEs total
```

---

## Module: `sphincs_wots.py`

Implements WOTS+ for SPHINCS+. Different from the XMSS WOTS in these ways:
- V=32 individual chains (not paired)
- W=4, CHAIN_LENGTH=16 (not 16^2=256 as in XMSS pairs)
- No grinding (V_GRINDING=0)
- Encoding uses two separate Poseidon calls with a `layer_index` domain separator

### `wots_encode_and_complete(message, layer_index, randomness, chain_tips) -> wots_pubkey`

```
# Step 1: compute encoding
a_right = [randomness[0..7], 0]           # 8 FEs
A = poseidon16_compress(message, a_right)
b_right = [layer_index, 0, 0, 0, 0, 0, 0, 0]
B = poseidon16_compress(A, b_right)

# Step 2: decompose B into 32 4-bit encoding indices
# B has 8 FEs. Extract 4-bit chunks from each FE (little-endian, 24 bits per FE → 6 chunks per FE).
# Take first 32 chunks total.
encoding[0..32] = decompose_into_4bit_chunks(B)  # via hint + range check
assert sum(encoding) == TARGET_SUM

# Step 3: chain completion
# For each chain i: complete (CHAIN_LENGTH - 1 - encoding[i]) hashes
wots_pubkey_elems[i] = iterate_hash(chain_tips[i], CHAIN_LENGTH - 1 - encoding[i])

# Step 4: fold public key
# hash(chain_tips[0], chain_tips[1]), then fold remaining 30
wots_pubkey_hash = fold_wots_pubkey(wots_pubkey_elems)  # 31 poseidon calls
```

**See: Open Question 3 — encoding decomposition and TARGET_SUM check.**

### `fold_wots_pubkey(chain_pub_keys) -> Digest`

Sequential left-fold of 32 digests (same pattern as FORS root folding):
```
acc = poseidon16_compress(chain_pub_keys[0], chain_pub_keys[1])
for i in 2..32:
    acc = poseidon16_compress(acc, chain_pub_keys[i])
```
31 Poseidon calls per invocation.

### `iterate_hash(input, n) -> Digest`

Same helper as XMSS: iterate `poseidon16_compress(state, zero_buf)` n times.
Uses `match_range(n, range(0, CHAIN_LENGTH), ...)`.

---

## Module: `sphincs_fors.py`

Implements FORS multi-tree verification.

### `fors_verify(fors_sig, fors_indices) -> fors_pubkey`

```
roots = Array(SPX_FORS_TREES * DIGEST_LEN)  # 9 roots

for t in unroll(0, SPX_FORS_TREES):         # 9 iterations
    leaf_secret = fors_sig + t * (1 + SPX_FORS_HEIGHT) * DIGEST_LEN
    auth_path   = leaf_secret + DIGEST_LEN

    # leaf_secret is already the level-0 node digest in the flat signature format
    leaf_node = leaf_secret

    # Walk 15-level auth path
    # leaf_index for tree t comes from fors_indices[t]  (15-bit value, dynamic)
    fors_merkle_verify(fors_indices[t], leaf_node, auth_path, roots + t * DIGEST_LEN)

# Fold 9 roots → FORS public key  (8 Poseidon calls)
fors_pubkey = fold_roots(roots)
```

### `fors_merkle_verify(leaf_index, leaf_node, auth_path, expected_root)`

Walks a 15-level binary Merkle tree. At each level `lv`, the bit `(leaf_index >> lv) & 1`
is extracted from the hinted `leaf_index` value and passed to `do_1_merkle_level`.
Since `leaf_index` is already range-checked < 2^15 by the FORS index hint, each bit
is implicitly bounded and the `match_range(bit, range(0,2), ...)` dispatch is safe.

### `fold_roots(roots) -> Digest`

Sequential left-fold of 9 roots:
```
acc = poseidon16_compress(roots[0], roots[1])
for i in 2..9:
    acc = poseidon16_compress(acc, roots[i])
```
8 Poseidon calls.

---

## Module: `sphincs_hypertree.py`

Implements the 3-layer XMSS hypertree.

### `hypertree_verify(hypertree_sig, fors_pubkey, layer_leaf_indices, expected_pk)`

Accepts the three precomputed `layer_leaf_indices[3]` from `decompose_message_digest`
rather than computing them in-loop. Since `l` is compile-time-unrolled, each
`layer_leaf_indices[l]` access resolves to a constant index with no dynamic shift
logic inside the loop body.

```
# Initial message: hash FORS pubkey with domain separator for layer 0
current_message = poseidon16_compress(fors_pubkey, [0, 0, 0, 0, 0, 0, 0, 0])

for l in unroll(0, SPX_D):    # 3 layers (compile-time unroll)
    wots_sig_ptr   = hypertree_sig + l * RANDOMNESS_LEN + l * (SPX_WOTS_LEN + SPX_TREE_HEIGHT) * DIGEST_LEN
    randomness_ptr = wots_sig_ptr
    chain_tips_ptr = wots_sig_ptr + RANDOMNESS_LEN
    auth_path_ptr  = chain_tips_ptr + SPX_WOTS_LEN * DIGEST_LEN

    # 1. Recover WOTS pubkey + hash it to leaf node
    wots_leaf = wots_encode_and_complete(current_message, l, randomness_ptr, chain_tips_ptr)

    # 2. layer_leaf_indices[l] already computed; no dynamic shift needed here
    # 3. Walk 11-level auth path → recover layer root
    if l < SPX_D - 1:
        layer_root = Array(DIGEST_LEN)
        hypertree_merkle_verify(layer_leaf_indices[l], wots_leaf, auth_path_ptr, layer_root)
        # Prepare next message: hash layer root with domain separator
        current_message = poseidon16_compress(layer_root, [l+1, 0, 0, 0, 0, 0, 0, 0])
    else:
        # Final layer: check root == expected_pk
        hypertree_merkle_verify(layer_leaf_indices[l], wots_leaf, auth_path_ptr, expected_pk)
```

### `hypertree_merkle_verify(layer_leaf_index, leaf_node, auth_path, expected_root)`

11-level auth path traversal. At each level `lv`, extracts bit `(layer_leaf_index >> lv) & 1`
and dispatches via `do_1_merkle_level`. Identical structure to `fors_merkle_verify`.
`layer_leaf_index` is already range-checked < 2^11 from the digest hint decomposition.

---

## Module: `sphincs_aggregate.py`

Top-level SPHINCS+ verifier. Handles message digest decomposition and calls FORS + hypertree.

### `decompose_message_digest(message_digest) -> (fors_indices, layer_leaf_indices)`

Single-pass decomposition: one hint path, one check path. Outputs only the indices
needed by Merkle routing and FORS; does not materialise full mhash bytes. The 3 layer
leaf indices are precomputed here and passed directly into `hypertree_verify`.

```
# Hint all values in a single pass
leaf_idx        = hint_val()              # 11-bit: FE[0] bits 0–10
tree_address    = hint_val()              # 22-bit: FE[0] bits 16–31 + FE[1] bits 0–5
fors_indices[9] = [hint_val() for 0..9]  # each 15-bit; 9×15 = 135 bits total

# Range checks
range_check(leaf_idx,     2**11)
range_check(tree_address, 2**22)
for i in 0..9: range_check(fors_indices[i], 2**15)

# Verify FE[0]: leaf_idx at bits 0–10; lower 16 bits of tree_address at bits 16–31
#   (bits 11–15 are 0 by the digest layout)
tree_address_lo = tree_address & 0xFFFF
assert message_digest[0] == leaf_idx + (tree_address_lo << 16)

# Verify FE[1..5]: tree_address_hi (bits 16–21) at FE[1] bits 0–5;
#   fors_indices bit-packed LE into 135 contiguous bits starting at FE[1] bit 8.
#   Assert each reconstructed FE slice == message_digest[1..5].
#   The 136th mhash bit is left unconstrained (unused per fors.rs:187).
tree_address_hi = tree_address >> 16
# ... reconstruct FE[1..5] from tree_address_hi + fors_indices bit-pack;
#     assert vs message_digest[1..5]  (mechanical field arithmetic, one expression per FE)

# Precompute Merkle routing indices once; no repeated shift logic inside hypertree loop
layer_leaf_indices = [
    leaf_idx,                       # layer 0: leaf within bottom XMSS tree
    tree_address & 0x7FF,           # layer 1: bits  0–10 of tree_address
    (tree_address >> 11) & 0x7FF,   # layer 2: bits 11–21 of tree_address
]

return fors_indices, layer_leaf_indices
```

The `...` marks mechanical but verbose bit-packing arithmetic; the pattern is
identical for each FE and follows directly from the OQ2 layout table.

### `sphincs_verify(pk, message, fors_sig, hypertree_sig)`

```
# 1. Hash message to 8-FE digest
right = Array(DIGEST_LEN)
right[0] = message[8]
message_digest = poseidon16_compress(message, right)   # 1 Poseidon call

# 2. Decompose digest once — single hint pass, single check path
fors_indices, layer_leaf_indices = decompose_message_digest(message_digest)

# 3. Verify FORS
fors_pubkey = fors_verify(fors_sig, fors_indices)

# 4. Verify hypertree (layer_leaf_indices already computed; no repeated shifts)
hypertree_verify(hypertree_sig, fors_pubkey, layer_leaf_indices, pk)
```

---

## Module: `main_sphincs.py`

Simple main — no recursion, no slot, no bytecode claim reduction.

### Public input layout

```
[ n_sigs(1) | pubkeys_hash(8) | message(9) ]
Total: 18 FEs
```

No slot, no merkle chunks for slot (those are XMSS-specific). Message is shared.

### Private input layout

```
[ ptr_pubkeys(1) | pubkeys(n_sigs × DIGEST_LEN) ]
```

No `source_0` / `n_raw` indexing structure. Signature data arrives entirely through
the two dedicated hint streams (`hint_sphincs_fors` and `hint_sphincs_hypertree`),
one pair of calls per signer inside the loop.

### `main()`

```python
pub_mem = NONRESERVED_PROGRAM_INPUT_START
n_sigs = pub_mem[0]
pubkeys_hash_expected = pub_mem + 1
message = pub_mem + 1 + DIGEST_LEN

priv_start: Imu
hint_private_input_start(priv_start)

# priv_start layout: [ptr_pubkeys | pubkeys]
all_pubkeys = priv_start[0]

# Hash all pubkeys to check pubkeys_hash
computed_hash = slice_hash_pubkeys(all_pubkeys, n_sigs)
copy_8(computed_hash, pubkeys_hash_expected)

# Verify each signature
for i in parallel_range(0, n_sigs):
    pk = all_pubkeys + i * DIGEST_LEN
    fors_sig = Array(FORS_SIG_SIZE_FE)
    hint_sphincs_fors(fors_sig)                     # loads 1152 FEs
    hypertree_sig = Array(HYPERTREE_SIG_SIZE_FE)
    hint_sphincs_hypertree(hypertree_sig)            # loads 1053 FEs
    sphincs_verify(pk, message, fors_sig, hypertree_sig)
```

---

## Estimated Circuit Cost

| Component                          | Poseidon calls (per sig) |
|------------------------------------|--------------------------|
| Message hash                       | 1                        |
| WOTS encoding (2 calls × 3 layers) | 6                        |
| WOTS chain completion (avg ~240/layer × 3) | ~720             |
| WOTS pubkey fold (31 × 3 layers)   | 93                       |
| Hypertree Merkle paths (11 × 3)    | 33                       |
| FORS: hash leaf secrets (9)        | 0                        |
| FORS: auth paths (15 × 9)          | 135                      |
| FORS root fold (8)                 | 8                        |
| Bit decomposition overhead         | ~20 (estimated)          |
| **Total**                          | **~1019**                |

---

## Open Questions

These need answers before implementation begins.

---

### OQ1 — Merkle path chunking for non-power-of-4 heights

**Decision: 1 level per step using `match_range(bit, range(0, 2), ...)`.**

The VM has a real conditional `Jump` instruction — only the taken branch executes.
`match_range` compiles to a `match` statement which lowers to conditional jumps, so
the non-taken Poseidon call is never executed. This makes it cheaper than a
field-arithmetic conditional select (which would require 32 multiplications + 16
additions regardless of the bit value, on top of the Poseidon call).

Cost per level: 1 conditional jump + 1 Poseidon call.

```python
@inline
def do_1_merkle_level(bit, state_in, sibling, state_out):
    # bit == 0: current is left child  → poseidon(state_in, sibling)
    # bit == 1: current is right child → poseidon(sibling,   state_in)
    match_range(bit, range(0, 2), lambda b:
        poseidon16_compress(state_in, sibling, state_out) if b == 0
        else poseidon16_compress(sibling, state_in, state_out)
    )
```

This function is defined **once** in `sphincs_utils.py` and imported by both
`sphincs_fors.py` and `sphincs_hypertree.py`. A single shared implementation
eliminates the risk of divergence between the FORS and hypertree path traversals.

The bits fed here come from `decompose_message_digest` (see `sphincs_aggregate.py`)
and are already constrained to be binary as part of the reconstruction check — no
separate boolean assertion needed.

Total path costs:
- FORS: 15 levels × 9 trees = 135 `do_1_merkle_level` calls
- Hypertree: 11 levels × 3 layers = 33 `do_1_merkle_level` calls

---

### OQ2 — Bit extraction from the message digest

`extract_digest_hash` serialises the 8-FE message digest as 8 × LE u32 bytes, then
reads bit ranges:

| Field         | Byte range | FE range           | Bit layout                          |
|---------------|------------|--------------------|-------------------------------------|
| `leaf_idx`    | bytes 0–1  | FE[0] bits 0–10    | `FE[0] & 0x7FF`                    |
| `tree_address`| bytes 2–4  | FE[0] bits 16–31 + FE[1] bits 0–5 | spans two FEs |
| `mhash`       | bytes 5–21 | FE[1] bits 8–31 + FE[2..4] + FE[5] bits 0–15 | spans five FEs |

KoalaBear field elements have a maximum value of 2^31 - 2^24 + 1 < 2^31, so bit 31
of the u32 serialisation is always 0. This means the layout is well-defined, but
**the extraction crosses field element boundaries**.

**Decision: hint all three values directly and reconstruct the original field elements.**

The prover provides `leaf_idx` (11-bit), `tree_address` (22-bit), and the 9 FORS
indices (9 × 15-bit) as hints. The circuit verifies correctness by repacking them
into the expected bit positions and asserting equality with the corresponding slices
of `message_digest`. Range checks enforce the bit widths. No in-circuit shifting needed.

---

### OQ3 — WOTS encoding decomposition and TARGET_SUM check

In `wots.rs::wots_encode`, the compressed value B (8 FEs) is decomposed as follows:
```
for each FE in B:
    extract 6 consecutive 4-bit chunks from bits 0–23 (little-endian)
take first 32 chunks as encoding indices
```

This is very similar to the XMSS `hint_decompose_bits_xmss` mechanism.

However there are differences from XMSS:
- XMSS uses paired chains (`V/2 = 20` pairs, range 0..256) to check the combined sum
- SPHINCS+ uses 32 individual chains, each in `range(0, 16)`, and checks `sum == 240`

The `is_valid_encoding` check also rejects any FE that equals `-F::ONE` (the
`compressed.iter().any(|&kb| kb == -F::ONE)` guard in `wots_encode`). This is an edge
case that may or may not need an explicit in-circuit check.

**Decision:**
1. The circuit must explicitly assert `sum(encoding) == TARGET_SUM`. Relying on
   downstream Merkle failure is insufficient — the TARGET_SUM constraint is part of
   the signature validity definition and must be enforced directly.
2. The `-F::ONE` guard is **not** needed in the verifier circuit. That guard exists
   in the signer to reject bad randomness; a verifier never produces an encoding from
   scratch and should not need it.

---

### OQ4 — FORS index extraction across field element boundaries

`extract_fors_indices` reads `mhash` (17 bytes = 136 bits) as 9 × 15-bit little-endian
chunks. Each chunk spans at most 3 consecutive bytes and the byte boundaries do not
align with field element boundaries.

For example:
- Index 0: bits  0–14 of mhash
- Index 1: bits 15–29 of mhash
- Index 5: bits 75–89 of mhash — this crosses from byte 9 into byte 10–11

Since mhash itself spans parts of FE[1] through FE[5] (with bit offsets that aren't
multiples of 8), the in-circuit extraction is non-trivial.

**Proposed approach:** Hint the 9 fors indices directly. Verify each is in `range(0,
2^15)`. Then reconstruct the mhash bit-vector from the indices and check it matches
the bit-slice of the message digest. This requires expressing the bit-packing
relationship as field arithmetic, which is verbose but straightforward.

**Decision: acceptable.** Hint the 9 indices directly. Range-check each < 2^15.
Reconstruct and verify against the message digest bit-slice. The 136th mhash bit is
unused by the FORS scheme and does not need to be constrained.

---

### OQ5 — `hint_sphincs` vs inline private input

For XMSS, `hint_xmss` loads the flat signature from `ExecutionWitness.xmss_signatures`
(a separate out-of-band channel, not part of `private_input` memory). This avoids
placing the large signature in the addressable private memory.

SPHINCS+ signatures are ~2205 FEs each (vs ~567 for XMSS). Loading them via a
dedicated `hint_sphincs` call is strongly preferable.

**Decision: use two separate hints.**
- `hint_sphincs_fors(fors_sig)` — loads 1152 FEs (9 trees × 128 FEs each)
- `hint_sphincs_hypertree(hypertree_sig)` — loads 1053 FEs (3 layers × 351 FEs each)

The Rust witness builder will split the flat `SphincsSig` into the two channels when
constructing `ExecutionWitness`.

---

### OQ6 — `tree_address` use in the circuit

In `hypertree.rs`, `layer_tree_address` is computed in `calculate_address_info` but is
marked `let _ = layer_tree_address` — it is **unused** during verification. Only
`layer_leaf_index` is needed for the auth path traversal.

This means for `l=0`, `layer_leaf_index = leaf_idx` (the 11-bit value from the message
digest). For `l=1`, `layer_leaf_index = tree_address & 0x7FF`. For `l=2`,
`layer_leaf_index = (tree_address >> 11) & 0x7FF`.

Since `l` is unrolled, the shifts are compile-time constants. The circuit only needs:
- `leaf_idx` — 11 bits from the message digest
- `tree_address & 0x7FF` — bottom 11 bits of `tree_address`
- `(tree_address >> 11) & 0x7FF` — next 11 bits of `tree_address`

These three values can be extracted together as part of OQ2's digest decomposition.

**Confirmed:** `layer_tree_address` plays no role in verification. The circuit omits it
entirely. Only `layer_leaf_index` is needed to determine left/right at each Merkle
level, and that is derived from `leaf_idx` and `tree_address` as described above.

---

## Dependency Graph

```
main_sphincs.py
  └── sphincs_aggregate.py
        ├── sphincs_fors.py
        │     ├── sphincs_utils.py  (do_1_merkle_level)
        │     └── sphincs_wots.py
        │           └── sphincs_utils.py  (iterate_hash, fold helpers)
        └── sphincs_hypertree.py
              ├── sphincs_utils.py  (do_1_merkle_level)
              └── sphincs_wots.py
                    └── sphincs_utils.py  (iterate_hash, fold helpers)
```

`sphincs_utils.py` is the single definition point for `do_1_merkle_level`,
`iterate_hash`, `fold_wots_pubkey`, and `fold_roots`. Both `sphincs_fors.py` and
`sphincs_hypertree.py` import from it to guarantee identical Merkle level behaviour.

Dependencies on existing infrastructure:
- `poseidon16_compress` — already available
- `match_range` — already available (for chain length dispatch)
- `slice_hash_with_iv_dynamic_unroll` — reuse for pubkeys_hash computation

---

## What Does NOT Need to Be Built

Since there is no recursive aggregation:
- No `bytecode_claim_output` in public input
- No `reduce_bytecode_claims` / sumcheck proof
- No `recursion()` call in main
- No `child_raw_proofs` or `merkle_paths` hint channel
- No `AggregationTopology` in Rust

The Rust side only needs: `AggregatedSPHINCS`, `sphincs_aggregate()` (builds witness
+ calls `prove_execution`), `sphincs_verify_aggregation()`, and `init_sphincs_bytecode()`.
