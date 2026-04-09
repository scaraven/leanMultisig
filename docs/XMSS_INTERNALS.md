# XMSS Implementation Internals

This document provides a comprehensive reference for the XMSS implementation in
`crates/xmss/`, covering module structure, per-function semantics, modifications
from standard XMSS, and the full proving pipeline. It is intended as the primary
reference for implementing SPHINCS+ in the same style.

---

## 1. Constants and Type Aliases (`src/lib.rs`)

All parameters are centralised here. The type aliases propagate through the crate.

```
type F       = KoalaBear           // Base field: 2^31 - 2^24 + 1 (31-bit prime)
type Digest  = [F; DIGEST_SIZE]    // 8 field elements ≈ 248 bits per node
```

| Constant | Value | Meaning |
|---|---|---|
| `DIGEST_SIZE` | 8 | Field elements per hash digest |
| `V` | 42 | WOTS+ chains per key |
| `W` | 3 | Winternitz parameter; chain length = 2^W = 8 |
| `CHAIN_LENGTH` | 8 | Maximum hashes per chain |
| `NUM_CHAIN_HASHES` | 110 | Chain steps exposed to the verifier |
| `TARGET_SUM` | 184 | Fixed sum encoding indices must equal (= V*(CHAIN_LENGTH-1) - NUM_CHAIN_HASHES = 42*7 - 110) |
| `V_GRINDING` | 2 | Extra chains pinned to max depth for proof-of-work |
| `LOG_LIFETIME` | 32 | XMSS tree depth; supports 2^32 signers |
| `RANDOMNESS_LEN_FE` | 7 | Field elements of per-signature randomness |
| `MESSAGE_LEN_FE` | 9 | Field elements per message |
| `TRUNCATED_MERKLE_ROOT_LEN_FE` | 6 | First 6 elements of Merkle root used for domain separation |
| `SIG_SIZE_FE` | 599 | Total signature in field elements (7 + (42+32)*8) |

**Why these values:**
- `DIGEST_SIZE=8`: Eight KoalaBear elements give ~248 bits of hash output; with the degree-5
  extension field used for proof security this achieves 123 provable security bits.
- `V=42, W=3`: 42 chains of length 8 covers 42×3 = 126 bits of encoded message space, well
  above the 72-bit message (9 FE × ~8 bits useful per element).
- `NUM_CHAIN_HASHES=110 / TARGET_SUM=184`: The verifier in the zkVM only performs 110 chain
  steps explicitly; the remaining 184 steps are the signer's work (encoded as the fixed sum).
  This reduces proof constraint count.
- `V_GRINDING=2`: Two extra chains forced to max depth (index 7) add ~2 bits of
  grinding cost to finding valid randomness without contributing to the message encoding.

---

## 2. Module: `src/wots.rs`

Implements WOTS+ (Winternitz One-Time Signature Plus). This is the lowest-level
building block: a single-use signature scheme over a fixed message space.

### 2.1 Data Structures

**`WotsSecretKey`**
```rust
pub struct WotsSecretKey {
    pub pre_images: [Digest; V],   // 42 random pre-images (chain starts)
    public_key: WotsPublicKey,     // Eagerly cached: iterate_hash(pre_image, 7) for each chain
}
```
Holds the 42 random chain starts and their corresponding chain tips (the public key).
The public key is computed eagerly at construction so `public_key()` is free.

**`WotsPublicKey`**
```rust
pub struct WotsPublicKey(pub [Digest; V]);
```
The 42 chain tips produced by hashing each pre-image CHAIN_LENGTH-1 = 7 times.
The public key is committed to inside the XMSS Merkle tree.

**`WotsSignature`**
```rust
pub struct WotsSignature {
    pub chain_tips: [Digest; V],           // Chain tip at the encoding-specified depth
    pub randomness: [F; RANDOMNESS_LEN_FE], // 7 FE used to reproduce the encoding
}
```
The signature exposes partial chain tips — each one is the pre-image hashed
`encoding[i]` times. A verifier hashes each tip a further `(7 - encoding[i])` times
to recover the full chain tip = the public key.

### 2.2 Functions

---

#### `WotsSecretKey::new(pre_images: [Digest; V]) -> Self`

Constructs a WOTS secret key from explicit pre-images.

```rust
Self {
    pre_images,
    public_key: WotsPublicKey(
        std::array::from_fn(|i| iterate_hash(&pre_images[i], CHAIN_LENGTH - 1))
    ),
}
```

Each chain is hashed `CHAIN_LENGTH - 1 = 7` times to produce its public chain tip.
All 42 tips are stored as the `WotsPublicKey`.

**Why it exists:** Eager public key caching avoids recomputing 42×7 = 294 hash calls every
time the public key is needed (e.g., when building the XMSS Merkle tree).

---

#### `WotsSecretKey::random(rng: &mut impl CryptoRng) -> Self`

Convenience constructor: generates 42 random pre-images from `rng` then calls `new`.

---

#### `WotsSecretKey::public_key(&self) -> &WotsPublicKey`

Returns a reference to the cached public key. `const fn`.

---

#### `WotsSecretKey::sign_with_randomness(...) -> WotsSignature`

```
Inputs:
  message:                &[F; 9]   — 9-element message
  slot:                   u32       — XMSS leaf index (unique per signer)
  truncated_merkle_root:  &[F; 6]   — first 6 elements of XMSS Merkle root
  randomness:             [F; 7]    — pre-chosen randomness (must yield valid encoding)

Output: WotsSignature
```

1. Calls `wots_encode(message, slot, truncated_merkle_root, &randomness)` — this must
   return `Some(encoding)` or the function panics (contract: caller must supply valid
   randomness, typically via `find_randomness_for_wots_encoding`).
2. Delegates to `sign_with_encoding(randomness, &encoding)`.

**Why it exists:** Separates randomness discovery (done by the signer before signing) from
the deterministic signing step. Allows pre-computed randomness (benchmarks/caching).

---

#### `WotsSecretKey::sign_with_encoding(randomness, encoding) -> WotsSignature` *(private)*

```rust
WotsSignature {
    chain_tips: std::array::from_fn(|i| iterate_hash(&self.pre_images[i], encoding[i] as usize)),
    randomness,
}
```

Hashes each pre-image exactly `encoding[i]` times. The signer reveals the partial
chain tip; the verifier completes the remaining `7 - encoding[i]` steps.

---

#### `WotsSignature::recover_public_key(...) -> Option<WotsPublicKey>`

```
Inputs: message, slot, truncated_merkle_root, signature (self)
Output: Option<WotsPublicKey>  — None if encoding fails (invalid randomness)
```

1. Recomputes the encoding from `(message, slot, truncated_merkle_root, signature.randomness)`.
2. For each chain `i`, completes the chain:
   ```rust
   iterate_hash(&self.chain_tips[i], CHAIN_LENGTH - 1 - encoding[i] as usize)
   ```
3. Returns the recovered public key.

**Why it exists:** This is the WOTS verification step. Given a valid signature the
recovered key must equal the signer's public key. An inconsistent signature yields
a different digest which then fails the Merkle path check.

---

#### `WotsPublicKey::hash(&self) -> Digest`

Collapses all 42 chain tips into a single digest by sequential Poseidon compression:

```rust
let init = poseidon16_compress_pair(&self.0[0], &self.0[1]);
self.0[2..].iter().fold(init, |acc, chunk| poseidon16_compress_pair(&acc, chunk))
```

Performs 41 compressions (pair init + 40 fold steps). The result is the XMSS leaf
value inserted into the Merkle tree.

**Why it exists:** The XMSS Merkle tree needs a single-digest commitment to each
WOTS key. Sequentially hashing 42 pairs into one digest achieves this.

---

#### `iterate_hash(a: &Digest, n: usize) -> Digest`

```rust
(0..n).fold(*a, |acc, _| poseidon16_compress_pair(&acc, &Default::default()))
```

Applies the Poseidon16 compression function `n` times, each time using the zero
digest as the right input. Returns `a` unchanged if `n = 0`.

**Why it exists:** This is the core chain primitive. Every WOTS chain step is one
call to `iterate_hash(..., 1)`. Using a fixed zero right-input keeps the chain
verifiable in the zkVM using the same precomputed Poseidon table.

---

#### `wots_encode(message, slot, truncated_merkle_root, randomness) -> Option<[u8; V]>`

The encoding function is the most important function in the crate. It converts the
tuple `(message, randomness, slot, truncated_root)` into 42 chain indices in [0,7]
that sum to `TARGET_SUM = 184`.

**Step-by-step:**

**Step 1 — Compute A = Poseidon(message ‖ randomness)**
```
Left  input: message[0..8]   (8 field elements)
Right input: [message[8], randomness[0..7]]  (8 field elements)
A = poseidon16_compress_pair(left, right)
```
The 9-element message is split across both halves of the 16-element Poseidon state,
with the 7 randomness elements filling the remaining slots.

**Step 2 — Compute B = Poseidon(A ‖ slot ‖ truncated_root)**
```
Left  input: A[0..8]
Right input: [slot_lo, slot_hi, truncated_root[0..6]]
B = poseidon16_compress_pair(left, right)
```
`slot_lo = slot & 0xFFFF`, `slot_hi = slot >> 16`. Slot is split into two 16-bit
field elements to avoid exceeding the field prime.

**Step 3 — Uniformity guard**
```rust
if B.iter().any(|&kb| kb == -F::ONE) { return None; }
```
Rejects the encoding if any output element equals the additive inverse of one
(-1 mod p). This is a non-standard modification (see Section 4) that ensures
the bit decomposition in step 4 is uniformly distributed.

**Step 4 — Bit decomposition into indices**
```
For each of the 8 output elements of B:
  extract 24 bits in little-endian order
8 elements × 24 bits = 192 bits total
Split into W=3-bit chunks → 64 indices
Take first V+V_GRINDING = 44 indices
```
Each 3-bit chunk becomes one index in [0, 7].

**Step 5 — Validity check (`is_valid_encoding`)**
```
1. All 44 indices < CHAIN_LENGTH (8)       [guaranteed by 3-bit chunks]
2. Sum of first 42 indices == TARGET_SUM (184)
3. Indices 42 and 43 both equal CHAIN_LENGTH-1 (7)  [grinding]
```
Returns `None` if any condition fails; otherwise returns the first 42 indices.

**Why it exists:** This function determines how the message is distributed across
the 42 chains. The fixed-sum constraint replaces the checksum chains used in
standard XMSS, reducing signature size. The grinding constraint adds proof-of-work
cost to finding valid randomness.

---

#### `is_valid_encoding(encoding: &[u8]) -> bool` *(private)*

Checks the three conditions listed in step 5 above. Returns false if length ≠ V+V_GRINDING.

---

#### `find_randomness_for_wots_encoding(...) -> ([F; 7], [u8; 42], usize)`

```
Inputs: message, slot, truncated_merkle_root, rng
Output: (randomness, encoding, iterations)
```

Samples random 7-element arrays until `wots_encode` returns `Some`. Returns the
first valid `(randomness, encoding)` pair and the number of iterations taken.

**Expected iterations:** ~4 on average (grinding adds ~2 bits of rejection probability
on top of the uniformity guard rejection rate of ~1/2^31 per element × 8 elements).

**Why it exists:** Signing cannot proceed until valid randomness is found. This
function encapsulates the retry loop. The `iterations` count is used in benchmarks
to measure grinding difficulty.

---

#### `slot_to_field_elements(slot: u32) -> [F; 2]`

```rust
[F::from_usize((slot & 0xFFFF) as usize),
 F::from_usize(((slot >> 16) & 0xFFFF) as usize)]
```

Splits a 32-bit slot index into two 16-bit field elements. Required because the
KoalaBear prime is 31 bits; directly passing a 32-bit value could overflow.

---

## 3. Module: `src/xmss.rs`

Implements the full XMSS tree: key generation, signing, and verification.

### 3.1 Data Structures

**`XmssSecretKey`**
```rust
pub struct XmssSecretKey {
    pub(crate) slot_start: u32,              // inclusive lower bound of managed slots
    pub(crate) slot_end: u32,                // inclusive upper bound
    pub(crate) seed: [u8; 20],              // master seed for all deterministic derivations
    pub(crate) merkle_tree: Vec<Vec<Digest>>, // level 0 = leaves, level 32 = root
}
```
The merkle_tree stores only the subtree covering [slot_start, slot_end]. All
out-of-range nodes are regenerated on demand from `seed` using `gen_random_node`.

**`XmssPublicKey`**
```rust
pub struct XmssPublicKey { pub merkle_root: Digest }
```
A single 8-element digest: the root of the 2^32-leaf Merkle tree. This is the
verifier's only persistent state.

**`XmssSignature`**
```rust
pub struct XmssSignature {
    pub wots_signature: WotsSignature,  // 42 chain tips + 7 randomness FE
    pub slot: u32,                      // which leaf was signed
    pub merkle_proof: Vec<Digest>,      // 32 sibling digests (one per tree level)
}
```
Total size: 7 + 42×8 + 32×8 = 599 field elements ≈ 2.28 KiB.

**Error types:**
- `XmssKeyGenError::InvalidRange` — `slot_start > slot_end`
- `XmssSignatureError::SlotOutOfRange` — requested slot not in [slot_start, slot_end]
- `XmssVerifyError::InvalidWots` — WOTS encoding failed during verification
- `XmssVerifyError::InvalidMerklePath` — recomputed root does not match claimed root,
  or Merkle proof has wrong length

### 3.2 Private Helper Functions

---

#### `gen_wots_secret_key(seed: &[u8; 20], slot: u32) -> WotsSecretKey`

Derives a WOTS key deterministically from the master seed and a slot index:

```
rng_seed = seed[0..20] ‖ 0x00 ‖ slot.to_le_bytes()
StdRng::from_seed(rng_seed) → WotsSecretKey::random(rng)
```

The `0x00` marker byte distinguishes WOTS keys from tree nodes (which use `0x01`).

**Why it exists:** Enables the "sparse tree" design — WOTS keys are never stored,
only regenerated when needed during signing. This reduces memory from O(2^32) to
O(slot_range_size × LOG_LIFETIME).

---

#### `gen_random_node(seed: &[u8; 20], level: usize, index: u32) -> Digest`

Derives a pseudo-random digest for a tree node outside [slot_start, slot_end]:

```
rng_seed = seed[0..20] ‖ 0x01 ‖ level as u8 ‖ index.to_le_bytes()
StdRng::from_seed(rng_seed) → rng.random::<Digest>()
```

The `0x01` marker distinguishes from WOTS keys. Level and index uniquely identify
the node.

**Why it exists:** The XMSS tree has 2^32 leaves. For a key covering a small slot
range, most sibling nodes on the Merkle path are "out of range." Rather than storing
them, they are regenerated deterministically from the seed. A verifier with only
the Merkle root cannot distinguish real from pseudo-random siblings — the Merkle
proof is still sound because the siblings are committed to by the root.

### 3.3 Public Functions

---

#### `xmss_key_gen(seed, slot_start, slot_end) -> Result<(XmssSecretKey, XmssPublicKey), XmssKeyGenError>`

Generates a full XMSS key pair for slots in [slot_start, slot_end].

**Algorithm:**

1. **Level 0 — Leaf generation (parallel):**
   For each `slot` in `[slot_start, slot_end]`:
   ```
   wots = gen_wots_secret_key(seed, slot)
   leaf = wots.public_key().hash()  // 41 Poseidon compressions
   ```
   Leaves are computed in parallel via `rayon::into_par_iter()`.

2. **Levels 1 to 32 — Tree construction (parallel per level):**
   For each level `l` from 1 to LOG_LIFETIME:
   - Active node range: `[slot_start >> l, slot_end >> l]`
   - For each node index `i` in range:
     - Left child index: `2*i`, right child index: `2*i + 1`
     - Fetch each child from the previous level if in range, otherwise call
       `gen_random_node(seed, l-1, child_index)`
     - Compress: `compress(&perm, [left, right])` using Poseidon2 in
       sponge/compression mode with the left child in the first 8 positions
       and right child in positions 8–15

3. **Public key:** `merkle_tree[LOG_LIFETIME][0]` — the single root node.

The `compress` function (from `backend/symetric/src/compression.rs`) places
`[left ‖ right]` into a zero-padded width-16 Poseidon state, permutes, and
returns the first 8 elements. This is distinct from `poseidon16_compress_pair`
(used in WOTS chains) which adds feed-forward; `compress` does not.

**Why it exists:** Key generation is a one-time operation. Parallelism at each
level makes it feasible for large slot ranges.

---

#### `XmssSecretKey::public_key(&self) -> XmssPublicKey`

Returns `XmssPublicKey { merkle_root: self.merkle_tree[LOG_LIFETIME][0] }`.
The root is always `merkle_tree.last()[0]`.

---

#### `xmss_sign(rng, secret_key, message, slot) -> Result<XmssSignature, XmssSignatureError>`

High-level signing function that finds randomness automatically.

1. Extract truncated Merkle root: `merkle_root[0..6]`.
2. Call `find_randomness_for_wots_encoding(message, slot, truncated_root, rng)` to
   find valid `randomness`.
3. Delegate to `xmss_sign_with_randomness(secret_key, message, slot, randomness)`.

**Why it exists:** Convenience wrapper for callers who don't pre-compute randomness.

---

#### `xmss_sign_with_randomness(secret_key, message, slot, randomness) -> Result<XmssSignature, XmssSignatureError>`

Core signing function. Assumes randomness is already known to be valid.

1. Bounds check: `slot_start <= slot <= slot_end`, else `SlotOutOfRange`.
2. Regenerate WOTS key: `gen_wots_secret_key(&secret_key.seed, slot)`.
3. Compute WOTS signature:
   ```
   wots_secret_key.sign_with_randomness(message, slot, &truncated_root, randomness)
   ```
4. Build Merkle proof (32 sibling digests):
   ```
   For level in 0..32:
     neighbour_index = (slot >> level) ^ 1  // flip the current bit to get sibling
     if neighbour_index in [slot_start >> level, slot_end >> level]:
       sibling = merkle_tree[level][neighbour_index - base]
     else:
       sibling = gen_random_node(&seed, level, neighbour_index)
   ```
5. Return `XmssSignature { wots_signature, slot, merkle_proof }`.

**Why it exists:** Separating randomness discovery from signing allows benchmarks and
tests to pre-compute randomness and sign deterministically.

---

#### `xmss_verify(pub_key, message, signature) -> Result<(), XmssVerifyError>`

Stateless verification. Takes only the public key, message, and signature.

1. Extract truncated root: `pub_key.merkle_root[0..6]`.
2. Recover WOTS public key:
   ```
   signature.wots_signature.recover_public_key(
       message, signature.slot, &truncated_root, &signature.wots_signature)
   ```
   Returns `None` → `Err(InvalidWots)`.
3. Hash recovered key: `current_hash = wots_public_key.hash()`.
4. Check proof length: must equal `LOG_LIFETIME = 32`.
5. Traverse Merkle path:
   ```
   For (level, neighbour) in merkle_proof:
     is_left = ((slot >> level) & 1) == 0
     if is_left:
       current_hash = poseidon16_compress_pair(&current_hash, neighbour)
     else:
       current_hash = poseidon16_compress_pair(neighbour, &current_hash)
   ```
   Note: `poseidon16_compress_pair` (with feed-forward) is used here; this is the
   same function as in chain hashing, not the bare `compress` used during key gen.
   **This asymmetry between key generation and verification is worth noting for
   SPHINCS+ implementation — verify which compression primitive is used at each step.**
6. Compare `current_hash == pub_key.merkle_root`. Match → `Ok(())`, mismatch →
   `Err(InvalidMerklePath)`.

---

## 4. Module: `src/signers_cache.rs`

Benchmark infrastructure. Not part of the core signature scheme.

**`SIGNERS_CACHE: OnceLock<Vec<[F; 7]>>`** — process-global cache, loaded once.

**`BENCHMARK_SLOT: u32 = 1111`** — fixed slot used by all benchmark signers.

**`message_for_benchmark() -> [F; 9]`** — returns `[F(0), F(1), ..., F(8)]`.

---

#### `find_randomness_for_benchmark(index: usize) -> [F; 7]`

For benchmark index `i`:
1. Seeds `StdRng` with `i as u64`.
2. Generates a key over a small random range around `BENCHMARK_SLOT`.
3. Calls `find_randomness_for_wots_encoding` with a fixed message.
4. Returns the found randomness.

This function is expensive (key generation + grinding). Its output is persisted.

---

#### `reconstruct_signer_for_benchmark(index, randomness) -> (XmssPublicKey, XmssSignature)`

Given pre-computed randomness for benchmark index `i`:
1. Re-derives the same key using the same `StdRng(i)` seed.
2. Signs the fixed message at `BENCHMARK_SLOT` with the provided randomness.
3. Returns `(public_key, signature)` ready to be passed to `xmss_aggregate`.

**Why it exists:** Benchmark aggregation (e.g., 1400 signers) would require finding
randomness for all 1400 signers on every run. Caching amortises the grinding cost
to a single offline precomputation step.

---

#### `write_benchmark_signers_cache / read_benchmark_signers_cache`

Write: serialises `&[[F; 7]]` as a flat JSON integer array.  
Read: parses the JSON, chunks by `RANDOMNESS_LEN_FE = 7`, converts to `[F; 7]`.

Cache file: `crates/xmss/test_data/benchmark_signers.json`.

---

## 5. Modifications from Standard XMSS

This implementation diverges from RFC 8391 in several deliberate ways to reduce
proving cost and improve compatibility with the KoalaBear field.

### 5.1 Fixed-Sum Encoding (no checksum chain)

**Standard XMSS:** Includes a separate checksum chain that encodes the sum of all
message encoding indices. This prevents an attacker from increasing any index (and
thus forging a partial chain).

**This implementation:** All 42 indices must sum to a fixed value `TARGET_SUM = 184`.
No checksum chain. An attacker cannot independently vary indices without changing
their sum.

**Why:** Eliminates one extra chain from the signature, reduces AIR constraint count,
and keeps the encoding self-contained in a single hash check.

### 5.2 Uniformity Guard (`kb == -F::ONE`)

**Standard XMSS:** No restriction on hash output.

**This implementation:** If any element of the 8-element encoding hash equals
`-1 mod p`, the encoding is rejected and the randomness must be retried.

**Why:** Bit decomposition in the zkVM uses 24 bits per field element. The element
`p-1 = 2^31 - 2^24` has its high 7 bits all set. If it appeared in the hash
output, the remaining-bits representation would overflow the 7-bit range checked
in the zkDSL (`remaining[i] < 2^7 - 1`). Rejecting it ensures uniform, well-formed
bit decompositions in every proof.

### 5.3 Grinding Indices (V_GRINDING = 2)

**Standard XMSS:** No grinding.

**This implementation:** The two indices beyond the 42 message-encoding indices must
both equal `CHAIN_LENGTH - 1 = 7`. This is checked in `is_valid_encoding`.

**Why:** Forces the encoding hash to have two specific 3-bit outputs simultaneously,
adding ~2 bits of difficulty to finding valid randomness. This is analogous to a
Hashcash-style proof-of-work — it increases the cost of grinding for an adversary
trying to malleate signatures.

### 5.4 Slot and Merkle Root in Domain Separation

**Standard XMSS:** The slot and root are not necessarily included in the per-message hash.

**This implementation:** Both `slot` (as two 16-bit field elements) and the first 6
elements of the Merkle root appear in the second Poseidon compression of `wots_encode`.

**Why:** Binds each WOTS signature to a specific XMSS key (via the root) and a
specific leaf position (via the slot). Without this, signatures from one key could
be re-used under a different key sharing the same leaf digest, breaking multi-user
security.

### 5.5 Deterministic Key Derivation

**Standard XMSS:** Usually requires storing all WOTS keys.

**This implementation:** Both WOTS keys and out-of-range tree nodes are derived from
`seed` on the fly. Only nodes in the active subtree are stored.

**Why:** Makes it practical to support 2^32 slots per key without 2^32 storage.

### 5.6 Two Distinct Compression Primitives

Two Poseidon16 variants are used for different purposes:

| Usage | Function | Feed-forward? |
|---|---|---|
| Chain hashing (WOTS) | `poseidon16_compress_pair` | Yes (Davies-Meyer) |
| Merkle tree (key gen) | `compress` from `symetric::compression` | No (plain permutation output) |
| Merkle path (verify) | `poseidon16_compress_pair` | Yes |

This means key generation and verification use different compression for tree nodes.
This is intentional: `poseidon16_compress_pair` (with feed-forward) is the primitive
exposed to the zkVM; the key generation uses the bare Poseidon permutation output
for efficiency. Both are correct because the Merkle root is committed to by the
public key, and verification uses the same function as key generation.

---

## 6. Cross-Crate Proving Pipeline

This section explains how XMSS verification is translated into a zero-knowledge proof.

### 6.1 Architecture Overview

```
crates/xmss/          Native Rust: key gen, sign, verify (no proving)
        |
        v
crates/rec_aggregation/xmss_aggregate.py    zkDSL: XMSS verification in the VM
        |
        v  (compiled by lean_compiler → bytecode)
crates/lean_vm/       Execute bytecode, record execution trace
        |
        v
crates/lean_prover/   prove_execution: trace → AIR constraints
        |
        v
crates/air/           SuperSpartan: AIR → polynomial identity
        |
        v
crates/whir/          WHIR PCS: polynomial commitments + openings
        |
        v
crates/rec_aggregation/src/lib.rs    Proof aggregation: combine N leaf proofs into 1
```

### 6.2 The zkDSL Verification Program (`xmss_aggregate.py`)

This Python-like DSL file defines what the zkVM executes to verify an XMSS signature.
It mirrors the native `xmss_verify` function but is expressed in a constraint-friendly form.

**Public inputs to the VM:**
- `merkle_root` — expected Merkle root (the public key)
- `message` — 9 field elements
- `slot_lo, slot_hi` — slot split into 16-bit halves
- `merkle_chunks` — 8 nibble values (4-bit each), one per chunk of 4 Merkle levels

**Private inputs (hints, not committed):**
- `signature` — encoded as `[randomness ‖ chain_tips ‖ merkle_path]`

**Program structure (inside `xmss_verify`):**

1. **Encoding re-derivation:** Two Poseidon16 compressions to reproduce `B`:
   ```python
   poseidon16_compress(message, a_input_right, b_input)
   poseidon16_compress(b_input, b_input + DIGEST_LEN, encoding_fe)
   ```

2. **Bit decomposition hint:** The VM's hint mechanism decomposes `encoding_fe`
   (8 field elements) into 2W=6-bit chunks. The `remaining` array holds the
   high bits discarded from each element.
   ```python
   hint_decompose_bits_xmss(encoding, remaining, encoding_fe, NUM_ENCODING_FE, 2 * W)
   ```
   The hint is verified in-circuit:
   ```python
   assert partial_sum == encoding_fe[i]    # re-assemble and check
   assert remaining[i] < 2**7 - 1          # uniformity guard in-circuit
   ```

3. **Grinding check:**
   ```python
   assert encoding[i] == CHAIN_LENGTH**2 - 1   # for i in V/2..(V+V_GRINDING)/2
   ```
   Indices are treated as pairs (two chains per encoded index) so `CHAIN_LENGTH^2 - 1 = 63`.

4. **Chain verification (`chain_hash`):** For each of V/2 = 21 chain pairs:
   - Unpack paired index `n` into `raw_left = n % 8`, `raw_right = n // 8`
   - Compute `n_left = 7 - raw_left`, `n_right = 7 - raw_right` (steps to complete chains)
   - Apply `n_left` (resp. `n_right`) Poseidon compressions to the chain start
   - Output `pair_chain_length_sum = raw_left + raw_right`
   - The `match_range` construct generates one circuit branch per possible value of `n`
     (0..64), so the number of Poseidon constraints is statically determined.

5. **Sum check:**
   ```python
   assert target_sum == TARGET_SUM
   ```

6. **WOTS public key hashing (`slice_hash`):** 41 sequential Poseidon compressions.

7. **Merkle path verification (`xmss_merkle_verify`):**
   - 32 levels divided into 8 chunks of 4 levels each.
   - Each chunk calls `do_4_merkle_levels(b, state_in, path_chunk, state_out)`.
   - `b` is a 4-bit nibble encoding whether each level is a left-child step (bit=1)
     or right-child step (bit=0). The 16 possible values are handled via `match_range`.
   - Within `do_4_merkle_levels`, each level calls `poseidon16_compress` with the
     path sibling on the appropriate side.

### 6.3 Encoding `merkle_chunks` (Rust side)

`compute_merkle_chunks_for_slot(slot)` in `rec_aggregation/src/lib.rs` pre-computes
the 8 nibble values passed to the zkVM:

```rust
for chunk_idx in 0..8 {
    let mut nibble_val = 0usize;
    for bit in 0..4 {
        let level = chunk_idx * 4 + bit;
        let is_left = (((slot as u64) >> level) & 1) == 0;
        if is_left { nibble_val |= 1 << bit; }
    }
    chunks.push(F::from_usize(nibble_val));
}
```

Note: a level is "left" here when the current node's slot index has a 0 bit at that
level — i.e., the current node is a left child, so its sibling (the proof element)
goes on the right. The zkDSL interpretation is inverted: `b0 == 0` means "place
sibling on left."

### 6.4 Public Input Layout (`build_non_reserved_public_input`)

The VM's public memory includes:
```
[n_sigs | slice_hash (8 FE) | message (9 FE) | slot_lo | slot_hi | merkle_chunks (8 FE) |
 bytecode_claim_output | padding | Poseidon(bytecode_hash ‖ SNARK_DOMAIN_SEP)]
```

`slice_hash = Poseidon(all_public_keys_flattened)` — a commitment to the full set of
verified public keys, included in the proof's public input.

### 6.5 Signature Encoding for the VM (`encode_xmss_signature`)

```rust
data = randomness (7 FE)
     ‖ chain_tips (42 × 8 FE = 336 FE)
     ‖ merkle_proof (32 × 8 FE = 256 FE)
// total: 599 FE = SIG_SIZE_FE
```

This flat array is passed as a `hint_xmss` to the VM, not included in public memory.

### 6.6 Aggregation (`xmss_aggregate`)

`xmss_aggregate` combines N raw XMSS signatures and M previously aggregated proofs
into a single proof over all N + (sum of M children's signers) signers.

Key steps:
1. Sort and deduplicate public keys.
2. Verify all child proofs (also extracts bytecode evaluation claims).
3. If there are child proofs, run a sumcheck reduction to consolidate bytecode claims.
4. Build the private memory layout with pointers to: global public keys, duplicate keys,
   raw XMSS blocks (index into global key list), child proof blocks, sumcheck transcript.
5. Call `prove_execution(bytecode, public_input, witness, whir_config)`.

The result is an `AggregatedXMSS` containing:
- `pub_keys`: sorted deduplicated list of all verified public keys
- `proof`: the WHIR-based zkSNARK
- `bytecode_point`: optional multilinear evaluation point (for further recursion)

---

## 7. Tests (`tests/xmss_tests.rs`)

| Test | What it checks |
|---|---|
| `test_xmss_serialize_deserialize` | Round-trip postcard serialization for signatures and public keys |
| `keygen_sign_verify` | Full cycle: key gen → sign 16 messages (different slots) → verify all |
| `encoding_grinding_bits` | Measures expected grinding bits (~2 expected) |

**Benchmark-related tests (in `signers_cache.rs`):**

| Test | Mode | What it checks |
|---|---|---|
| `generate_benchmark_signers_cache` | `#[ignore]` (run manually) | Pre-computes 10,000 randomnesses and writes to JSON |
| `test_benchmark_signers_cache` | Normal | Reads cache and verifies 5 sampled entries |

---

## 8. Key Relationships for SPHINCS+ Implementation

SPHINCS+ extends XMSS with:
1. **FORS** (Few-Times Signature): replaces the per-message WOTS key selection with a
   forest of binary trees. Adds a `fors.rs` module analogous to `wots.rs`.
2. **Hypertree**: multiple layers of XMSS trees where each non-leaf layer's WOTS key
   signs a child layer's Merkle root (rather than a user message). Extends `xmss.rs`.
3. **Parameter sets**: SPHINCS+ has multiple standardised parameter sets (SPHINCS+-128s,
   SPHINCS+-256f, etc.) requiring different `V`, `W`, tree heights, and layer counts.

The implementation pattern to follow:
- One Rust file per component (`fors.rs`, `hypertree.rs`, `sphincs.rs`)
- Constants in `lib.rs` as in this crate
- A matching `.py` zkDSL file in `crates/rec_aggregation/` for each verified operation
- A signers cache module for benchmarking

The hash function (`poseidon16_compress_pair`), field type (`KoalaBear`), digest size (8 FE),
and the Merkle tree compression function should be reused unchanged.
