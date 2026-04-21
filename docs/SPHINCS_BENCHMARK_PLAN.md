# SPHINCS+ Benchmark — Architecture & Implementation Plan

## Goal

Add a `cargo run --release -- sphincs --n-signatures N` CLI command that:
1. Generates (or loads from cache) SPHINCS+ key pairs and signatures.
2. Compiles `main_sphincs.py` into a `Bytecode`.
3. Calls a new `sphincs_aggregate()` function that builds the witness and runs `prove_execution`.
4. Verifies the proof with `sphincs_verify_aggregation()`.
5. Prints the same stats display as the XMSS benchmark (throughput, proof size KiB, cycles, memory, poseidons, extension ops).

Target: support up to **~3 000 signatures**, using a cache of **500 distinct key pairs** (each pair signs a fixed message, so multiple signatures per key are valid since SPHINCS+ is stateless).

---

## Key Constraints and Design Decisions

### C1 — SPHINCS+ is stateless: reusing public keys is safe

XMSS is stateful (each WOTS key is single-use), so it requires distinct key pairs per
signature. SPHINCS+ selects a one-time WOTS key deterministically from the message
digest, so the same key pair can sign the same message again and produce an identical
signature. This means:

- Cache 500 distinct `(SphincsSecretKey, SphincsSig, SphincsPublicKey)` triples.
- To benchmark N > 500 signatures, repeat signers cyclically: signer `i` uses entry
  `i % 500`. The circuit receives N copies of the same (pk, sig) pairs.
- The commitment hashes `(n_sigs, pubkeys_flat, messages_flat)` — with per-signer
  independent messages, repeated pubkeys but distinct messages keeps the commitment
  unique. **Decision: use per-signer distinct messages**: `message[i][j] = F::from_usize(i * MESSAGE_LEN_FE + j)`. This is consistent with how `main_sphincs.py` is already structured (per-signer messages).

### C2 — `main_sphincs.py` commitment scheme differs from XMSS

XMSS's public input hashes `(n_sigs, pubkeys_hash, message, slot, bytecode_claim)` into a
single 8-FE digest. SPHINCS+ hashes three segments independently then folds:
```
h0 = poseidon(ZERO_VEC, [n_sigs, 0, ..., 0])
h1 = slice_hash_with_iv_dynamic_unroll(pubkeys, n_sigs * DIGEST_LEN, ...)
h2 = slice_hash_with_iv_dynamic_unroll(messages, n_sigs * MESSAGE_LEN, ...)
commitment = poseidon(poseidon(h0, h1), h2)
```
`sphincs_public_input()` already implements this in `rec_aggregation/src/sphincs.rs`.

### C3 — No self-referential compilation loop needed

`main_sphincs.py` has no recursive proof children, so it never embeds its own bytecode
size. A single `compile_program_with_flags(...)` call suffices. A correctness assertion
(`assert_eq!(bytecode.log_size(), log_size_guess)`) is included as a regression guard.
If it fires, update the initial guess constant.

### C4 — Bytecode replacements: VM constants are shared, scheme constants differ

`build_replacements()` in `compilation.rs` has two distinct layers:
- **VM-level** (~300 lines): WHIR config tables, AIR table parameters, log sizes, grinding
  bits. These are independent of XMSS or SPHINCS+ and must be included unchanged.
- **Scheme-level** (~8 lines): V, W, TARGET_SUM, V_GRINDING, LOG_LIFETIME,
  MESSAGE_LEN, RANDOMNESS_LEN, MERKLE_LEVELS_PER_CHUNK.

The SPHINCS+ replacements replace the scheme-level keys with SPHINCS+ constants. The
VM-level keys are identical. The implementation approach is:

**Refactor `build_replacements` into two functions:**
- `build_vm_replacements(inner_program_log_size, bytecode_zero_eval, input_data_size_padded) -> BTreeMap<String, String>` — everything that is currently in `build_replacements` except the XMSS-specific block at the bottom.
- `build_xmss_replacements() -> BTreeMap<String, String>` — the 8 XMSS lines, merged on top.
- `build_sphincs_replacements() -> BTreeMap<String, String>` — the analogous SPHINCS+ lines.

`main_sphincs.py` uses different placeholder names than `main.py` for scheme-specific
constants (e.g. `SPX_D_PLACEHOLDER`, `SPX_TREE_HEIGHT_PLACEHOLDER`, etc.), so there is
no collision risk. The SPHINCS+ compile function builds `build_vm_replacements(...)` and
merges `build_sphincs_replacements()` into it.

SPHINCS+ parameters are **not** substituted via placeholders — they remain as Python
literals in the `.py` source files. `build_sphincs_scheme_replacements()` therefore
contributes no scheme-specific entries; only the VM-level replacements apply. A test
guards against drift (see Implementation Order step 4).

`input_data_size_padded` for SPHINCS+ is computed the same way as XMSS — passed into
`build_vm_replacements` as a parameter by the caller. For SPHINCS+ the value is
`DIGEST_LEN = 8` (the public input is one Poseidon digest; `8 % 8 == 0`). This mirrors
the XMSS calling convention exactly and leaves the door open for future recursion where
the public input grows and the formula changes.

### C5 — Public key visibility

`SphincsPublicKey::root` is currently a private field. The Rust witness builder
(`sphincs.rs`) accesses it via `HypertreeSecretKey::new(seed).public_key().0` to get
the `HypertreePublicKey(Digest)` tuple field directly. `sphincs_aggregate()` will
similarly derive pubkeys from secret keys. No change to `SphincsPublicKey` visibility
is needed unless a `pub fn root(&self) -> Digest` accessor is desired for cleanliness.
**Decision: add `pub fn root(&self) -> [F; DIGEST_LEN]` accessor to `SphincsPublicKey`
in `core.rs`**, avoiding the tuple-unwrap workaround.

### C6 — Cache design: `(SphincsSecretKey, SphincsSig, SphincsPublicKey)` vs `(SphincsPublicKey, SphincsSig)`

XMSS caches `(XmssPublicKey, XmssSignature)`. For SPHINCS+ benchmarking, the witness
builder needs `SphincsSecretKey` (not the sig) because it calls `sk.sign(message)`
internally to regenerate hints. However, `SphincsSecretKey::new(seed)` is expensive
(eager FORS keygen + FORS pubkey computation).

**Two options:**

**Option A (preferred): cache `(SphincsPublicKey, SphincsSig)`**
Modify `build_sphincs_witness` to accept pre-computed `(pk, sig)` pairs instead of
secret keys. Extract digest decomposition and hint data from the `SphincsSig` directly
(the necessary `extract_digest_parts`, `extract_fors_indices`, `fors_sig_to_flat`,
`hypertree_sig.flatten_hypertree_sig()` calls are all already in `sphincs.rs` and don't
require the secret key). The secret key is only needed to produce the signature, not to
build the hints. This is the better design — the benchmark function doesn't need to
reconstruct keys.

**Option B: cache `(SphincsSecretKey, SphincsSig)`**
Simpler but wastes space and requires `SphincsSecretKey: Serialize + Deserialize`
(currently only `serde` is derived for `SphincsPublicKey` and `SphincsSig`; `SphincsSecretKey`
needs `#[derive(Serialize, Deserialize)]` added).

**Decision: Option A** — cache `(SphincsPublicKey, SphincsSig)` and refactor
`build_sphincs_witness` accordingly.

### C7 — Message generation for the cache

The cached signatures are generated with a deterministic per-signer message:
```rust
fn message_for_sphincs_benchmark(signer_index: usize) -> [F; MESSAGE_LEN_FE] {
    std::array::from_fn(|j| F::from_usize(signer_index * MESSAGE_LEN_FE + j))
}
```
At benchmark time, signer `i` (for `i >= 500`) maps to cache entry `i % NUM_SPHINCS_SIGNERS`
but uses the message for index `i`, not `i % NUM_SPHINCS_SIGNERS`. This means the signature
is reused but the message differs — **this breaks verification** because the cached
signature is only valid for the original message.

**Revised decision for cache vs. benchmark:**

The cache stores a `(SphincsPublicKey, SphincsSig)` pair generated for message index `k`
where `k = 0..NUM_SPHINCS_SIGNERS`. At benchmark time, signer `i` uses:
- `pk = cache[i % NUM_SPHINCS_SIGNERS].pk`
- `sig = cache[i % NUM_SPHINCS_SIGNERS].sig`
- `message = message_for_sphincs_benchmark(i % NUM_SPHINCS_SIGNERS)`

All three come from the cached entry. Multiple "signers" at benchmark time present the
same (pk, sig, message) triple to the circuit. The circuit verifies N (possibly
non-distinct) triples, each of which is valid. This is semantically sound for a
throughput benchmark.

### C8 — Cache size and generation cost

SPHINCS+ signing involves:
- Full FORS tree construction (9 trees × 2^15 leaves = 294,912 leaf hashes per sign)
- 3-layer hypertree traversal

This is ~2–5 seconds per signature on a modern CPU. Generating 500 signatures takes
~15–40 minutes serially; with rayon parallelism across all cores it is ~1–3 minutes.
**Cache size: 500 signatures.** The file will be approximately:
- 500 × 2205 FEs × 4 bytes/FE (KoalaBear u32) ≈ 4.4 MiB raw
- Plus 500 × 8 × 4 bytes pubkeys ≈ 16 KiB
- LZ4-compressed: ~1–3 MiB (SPHINCS+ sigs have low entropy, compresses well)

---

## Architecture: New Components

### Component 1 — `crates/sphincs/src/signers_cache.rs`

New file, parallel in structure to `crates/xmss/src/signers_cache.rs`.

**Dependencies to add to `crates/sphincs/Cargo.toml`:**
```toml
rayon.workspace = true
lz4_flex.workspace = true
postcard.workspace = true
sha3.workspace = true
```

**API surface:**
```rust
pub const NUM_SPHINCS_SIGNERS: usize = 500;

// Returns message for cache entry i (deterministic)
pub fn message_for_sphincs_signer(index: usize) -> [F; MESSAGE_LEN_FE]

// Lazy global cache: (SphincsPublicKey, SphincsSig) x 500
pub fn get_sphincs_benchmark_signatures()
    -> &'static Vec<(SphincsPublicKey, SphincsSig)>
```

**Cache file:** `target/signers-cache/benchmark_sphincs_cache_{fingerprint}.bin`
Fingerprint inputs: `(NUM_SPHINCS_SIGNERS, first_pubkey_bytes, first_message_bytes)`.

**Generation:**
1. Generate signer 0 first (single-threaded) to derive the fingerprint.
2. Check for cached file; load if present.
3. Otherwise generate signers 1..500 in parallel via `rayon::par_iter`, printing progress.
4. Compress with lz4 and write to disk.

**Key change from XMSS:** No `BENCHMARK_SLOT` constant. The seed for signer `i` is derived
as `u64_to_seed(i as u64)` where `u64_to_seed` fills a `[u8; 20]` from the little-endian
bytes of the index (zero-padded).

### Component 2 — `crates/rec_aggregation/src/compilation.rs` (extended)

**Refactor:**
```rust
// Rename the bottom block of build_replacements → build_xmss_scheme_replacements()
// Rename the rest → build_vm_replacements(log_size, zero_eval, input_data_size_padded)
```

**New additions:**
```rust
static SPHINCS_BYTECODE: OnceLock<Bytecode> = OnceLock::new();

pub fn init_sphincs_bytecode() {
    SPHINCS_BYTECODE.get_or_init(compile_sphincs_program);
}

pub fn get_sphincs_bytecode() -> &'static Bytecode {
    SPHINCS_BYTECODE.get().unwrap_or_else(|| panic!("call init_sphincs_bytecode() first"))
}

fn compile_sphincs_program() -> Bytecode {
    // SPHINCS+ public input is 8 FEs (one Poseidon digest), input_data_size_padded = 8.
    let input_data_size_padded = DIGEST_LEN;    // 8
    let log_size_guess = 19;                    // starting guess; no loop needed
    let bytecode_zero_eval = F::ONE;
    let mut replacements = build_vm_replacements(log_size_guess, bytecode_zero_eval, input_data_size_padded);
    replacements.extend(build_sphincs_scheme_replacements());

    let filepath = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("main_sphincs.py")
        .to_str().unwrap().to_string();
    let bytecode = compile_program_with_flags(
        &ProgramSource::Filepath(filepath),
        CompilationFlags { replacements },
    );
    assert_eq!(bytecode_zero_eval, bytecode.instructions_multilinear[0]);
    bytecode
}

fn build_sphincs_scheme_replacements() -> BTreeMap<String, String> {
    // Insert all SPHINCS+-specific placeholder values from sphincs::lib constants
}
```

**Note on `log_size_guess`:** Because `main_sphincs.py` does not embed its own bytecode
size into the program logic (no recursive bytecode claim), the initial guess of 19 will
compile to the correct size on the first try. After compilation, `compile_sphincs_program`
asserts `bytecode.log_size() == log_size_guess` and panics with a clear message if it
doesn't match — the developer then updates the constant. This mirrors the XMSS pattern
structurally but without the loop, keeping the door open for adding recursion later
(at which point the loop would be reinstated).

### Component 3 — `crates/rec_aggregation/src/sphincs.rs` (extended)

#### 3a. New type: `AggregatedSPHINCS`

```rust
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AggregatedSPHINCS {
    pub proof: Proof<F>,
    #[serde(skip, default)]
    pub metadata: Option<ExecutionMetadata>,
}
```

No `bytecode_point` field (no recursion).

#### 3b. Refactor `SphincsSignerInput` and `build_sphincs_witness`

**Current:** `SphincsSignerInput { secret_key: SphincsSecretKey, message }` — requires the
secret key to be present at prove time.

**Proposed:** Change to accept pre-signed data:
```rust
pub struct SphincsSignerInput {
    pub pubkey: [F; DIGEST_LEN],
    pub sig: SphincsSig,
    pub message: [F; MESSAGE_LEN_FE],
}
```

`build_sphincs_witness` extracts all hint data from the `SphincsSig` fields directly
(the existing `extract_digest_parts`, `extract_fors_indices`, `fors_sig_to_flat`,
`hypertree_sig.flatten_hypertree_sig()` are already present in the function body,
just driven by `sk.sign(message)` today). The signing step moves to the caller
(i.e., the benchmark function), which constructs `SphincsSignerInput` from cached data.

#### 3c. New function: `sphincs_aggregate`

```rust
pub fn sphincs_aggregate(
    signers: &[SphincsSignerInput],
    log_inv_rate: usize,
) -> AggregatedSPHINCS
```

Internally:
1. Compute `public_input` via `sphincs_public_input(pubkeys, messages)`.
2. Call `build_sphincs_witness(signers)` → `ExecutionWitness`.
3. Call `prove_execution(get_sphincs_bytecode(), &public_input, &witness, &whir_config, false)`.
4. Return `AggregatedSPHINCS { proof, metadata: Some(execution_proof.metadata) }`.

Note: unlike `xmss_aggregate`, no pubkey sorting/deduplication is performed — the circuit
simply verifies all N (pk, message, sig) triples as given.

#### 3d. New function: `sphincs_verify_aggregation`

```rust
pub fn sphincs_verify_aggregation(
    pubkeys: &[[F; DIGEST_LEN]],
    messages: &[[F; MESSAGE_LEN_FE]],
    agg: &AggregatedSPHINCS,
) -> Result<ProofVerificationDetails, ProofError>
```

Internally:
1. Compute `public_input` via `sphincs_public_input(pubkeys, messages)`.
2. Call `verify_execution(get_sphincs_bytecode(), &public_input, agg.proof.clone())`.
3. Return the result (discarding the `raw_proof` second element).

### Component 4 — `crates/rec_aggregation/src/benchmark.rs` (extended)

```rust
pub fn run_sphincs_benchmark(n_sigs: usize, log_inv_rate: usize, tracing: bool) -> f64
```

Flow:
1. Optionally init tracing.
2. `precompute_dft_twiddles::<F>(1 << 24)`.
3. `init_sphincs_bytecode()` — compile `main_sphincs.py`.
4. Print bytecode instruction count.
5. Load cache: `get_sphincs_benchmark_signatures()`.
6. Assert `n_sigs <= 4096` (matching `MAX_N_SIGS` in `main_sphincs.py`) — **panic** with
   a descriptive message if exceeded, consistent with XMSS behaviour.
7. Build `Vec<SphincsSignerInput>` of length `n_sigs` by indexing `cache[i % NUM_SPHINCS_SIGNERS]` with `message_for_sphincs_signer(i % NUM_SPHINCS_SIGNERS)`.
8. Time `sphincs_aggregate(&signers, log_inv_rate)`.
9. Call `sphincs_verify_aggregation(pubkeys, messages, &agg)`.
10. Print a single-row stats display.

**Display:** Reuse `NodeStats` and `LiveTree` with a single-entry degenerate 1-node tree
(leaf, no children). This avoids duplicating the display logic entirely. The `n_xmss`
field in `NodeStats` is set to `Some(n_sigs)` to trigger the "sig/s" throughput display
column rather than raw seconds.

### Component 5 — `src/main.rs` (extended)

Add to the `Cli` enum:
```rust
#[command(about = "Aggregate SPHINCS+ signatures")]
Sphincs {
    #[arg(long)]
    n_signatures: usize,
    #[arg(long, help = "log(1/rate) in WHIR", default_value = "1", short = 'r')]
    log_inv_rate: usize,
    #[arg(long, help = "Enable tracing")]
    tracing: bool,
},
```

Add to the `match` arm:
```rust
Cli::Sphincs { n_signatures, log_inv_rate, tracing } => {
    rec_aggregation::benchmark::run_sphincs_benchmark(n_signatures, log_inv_rate, tracing);
}
```

`rec_aggregation::benchmark` is already `pub mod benchmark` in `lib.rs`, so no new
re-export is needed at that level.

### Component 6 — `src/lib.rs` (optional extension)

Mirror the XMSS public API:
```rust
pub use rec_aggregation::sphincs::{AggregatedSPHINCS, sphincs_aggregate, sphincs_verify_aggregation};
pub use sphincs::{SphincsPublicKey, SphincsSecretKey, SphincsSig};
```

This is a nice-to-have for consumers of the library crate but is not required for the
benchmark to work.

---

## Implementation Order

The steps are strictly ordered by dependency. Each step should compile and pass
`cargo check` before the next begins.

1. **`SphincsPublicKey::root()` accessor** — add `pub fn root(&self) -> [F; DIGEST_LEN]`
   to `core.rs`. Unblocks `sphincs_aggregate` from reading public key bytes.

2. **`crates/sphincs/src/signers_cache.rs`** — new file. Add `rayon`, `lz4_flex`,
   `postcard`, `sha3` to `crates/sphincs/Cargo.toml`. Enable `pub mod signers_cache` in
   `sphincs/src/lib.rs`.

3. **Refactor `build_replacements`** in `compilation.rs` — split into `build_vm_replacements`
   + `build_xmss_scheme_replacements`. No behaviour change; existing XMSS compilation
   path is untouched. Add `build_sphincs_scheme_replacements` and `compile_sphincs_program`
   + `init_sphincs_bytecode` / `get_sphincs_bytecode`.

4. **No placeholder substitution in `main_sphincs.py`** — SPHINCS+ parameters are kept
   as Python literals in the `.py` files (no `_PLACEHOLDER` names). The `build_sphincs_scheme_replacements()` function in Rust therefore has no scheme-specific entries, only the VM-level replacements apply. A `#[test]` in `compilation.rs` (or `sphincs.rs`) explicitly asserts that the Rust constants (`sphincs::SPX_WOTS_LEN`, `sphincs::TARGET_SUM`, etc.) match the hardcoded values expected by the Python source, acting as a compile-time safeguard. The test and its file must contain a clearly-marked `// TODO: if SPHINCS+ parameters change, update both the Python source files and this test` comment so future migration to full placeholder substitution is obvious.

5. **Refactor `SphincsSignerInput` and `build_sphincs_witness`** in `sphincs.rs` — change
   from secret-key-based to `(pubkey, sig, message)` triples. Update the existing test
   in `sphincs.rs` (if any) to adapt.

6. **Add `AggregatedSPHINCS`, `sphincs_aggregate`, `sphincs_verify_aggregation`** in
   `sphincs.rs`. Re-export from `rec_aggregation/src/lib.rs`.

7. **Add `run_sphincs_benchmark`** to `benchmark.rs`.

8. **Add `Cli::Sphincs`** to `src/main.rs`.

9. **Integration smoke-test:** `cargo run --release -- sphincs --n-signatures 1` —
   confirm end-to-end proof generation and verification succeeds before scaling up.

