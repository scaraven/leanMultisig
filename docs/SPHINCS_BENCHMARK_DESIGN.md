# SPHINCS+ Benchmark CLI — Architecture & Design Findings

## Purpose

This document captures the full findings from a codebase exploration of the XMSS benchmark
infrastructure. Its purpose is to brief a senior agent (Opus 4.7) that will draft the
implementation plan for adding a SPHINCS+ benchmark to `src/main.rs`.

---

## 1. The Existing XMSS Benchmark Flow (End-to-End)

### 1.1 CLI Entry Point (`src/main.rs`)

`Cli::Xmss { n_signatures, log_inv_rate, tracing }` constructs an `AggregationTopology`
and calls `run_aggregation_benchmark(&topology, overlap=0, tracing)`.

### 1.2 `run_aggregation_benchmark` (`crates/rec_aggregation/src/benchmark.rs`)

1. Optionally inits tracing.
2. `precompute_dft_twiddles::<F>(1 << 24)` — backend FFT warm-up (must be done once before proving).
3. `init_aggregation_bytecode()` — compiles `main.py` into `BYTECODE: OnceLock<Bytecode>`.
4. Reports `get_aggregation_bytecode().instructions.len()`.
5. `get_benchmark_signatures()` — loads or generates `NUM_BENCHMARK_SIGNERS=10_000` (pk, sig) pairs.
6. Builds a `LiveTree` display (ANSI, in-place update).
7. Calls `build_aggregation(topology, ...)` recursively (bottom-up).
8. At each node calls `xmss_aggregate(...)` and records metadata.
9. After the root proof is done, calls `xmss_verify_aggregation(...)` to confirm correctness.
10. Returns elapsed time.

### 1.3 `AggregationTopology`

```rust
pub struct AggregationTopology {
    pub raw_xmss: usize,
    pub children: Vec<AggregationTopology>,
    pub log_inv_rate: usize,
}
```

`SPHINCS+` does **not** have recursive aggregation — every run is a single flat leaf (no
`children`). A SPHINCS+ topology is therefore just `{ n_sigs, log_inv_rate }` with no nesting.

### 1.4 `xmss_aggregate` (`crates/rec_aggregation/src/lib.rs`)

Signature:
```rust
pub fn xmss_aggregate(
    children: &[(&[XmssPublicKey], AggregatedXMSS)],
    mut raw_xmss: Vec<(XmssPublicKey, XmssSignature)>,
    message: &[F; MESSAGE_LEN_FE],
    slot: u32,
    log_inv_rate: usize,
) -> (Vec<XmssPublicKey>, AggregatedXMSS)
```

Internally:
- Sorts & deduplicates pubkeys.
- Optionally verifies child proofs (for recursion; SPHINCS+ won't use this).
- Builds `ExecutionWitness { preamble_memory_len, hints: HashMap<String, Vec<Vec<F>>> }`.
- Calls `prove_execution(bytecode, &public_input, &witness, &whir_config, vm_profiler)`.
- Returns `(global_pub_keys, AggregatedXMSS { proof, bytecode_point, metadata })`.

SPHINCS+ will need its own `sphincs_aggregate()` with a different witness builder.

### 1.5 `AggregatedXMSS` and Metadata

```rust
pub struct AggregatedXMSS {
    pub proof: Proof<F>,
    pub bytecode_point: Option<MultilinearPoint<EF>>,  // None for leaf-only
    pub metadata: Option<ExecutionMetadata>,           // cycles, memory, n_poseidons, n_extension_ops
}
```

`ExecutionMetadata` fields used in the display: `cycles`, `memory`, `n_poseidons`,
`n_extension_ops`, plus `proof.proof_size_fe()` for the KiB column.

---

## 2. XMSS Signature Caching (`crates/xmss/src/signers_cache.rs`)

### Mechanism

1. `OnceLock<Vec<(XmssPublicKey, XmssSignature)>>` — lazy, in-process cache.
2. On first access, calls `gen_benchmark_signers_cache()`:
   - Derives the first signer: `StdRng::seed_from_u64(0)`, `xmss_key_gen(rng.random(), slot, slot+1)`.
   - Uses `first_pubkey` + `(NUM_SIGNERS, BENCHMARK_SLOT, message)` to derive a 128-bit cache fingerprint (SHA3-256).
   - Checks for a binary file at `target/signers-cache/benchmark_signers_cache_{fingerprint}.bin`.
   - If found, loads it (lz4 → postcard deserialize).
   - If not found, generates all `NUM_BENCHMARK_SIGNERS=10_000` signers in parallel via rayon, saves them.
3. The cache file is a `postcard`-serialized + `lz4`-compressed `SignersCacheFile { signatures }`.
4. `SIGNERS_CACHE_DIR` env var overrides the cache directory (used in CI).

### Key Exported Symbols

```rust
pub fn get_benchmark_signatures() -> &'static Vec<(XmssPublicKey, XmssSignature)>
pub fn message_for_benchmark() -> [F; MESSAGE_LEN_FE]   // [F::from_usize(0), ..., F::from_usize(8)]
pub const BENCHMARK_SLOT: u32 = 111;
pub const NUM_BENCHMARK_SIGNERS: usize = 10_000;
```

---

## 3. SPHINCS+ Crate State (`crates/sphincs/`)

### Public Key Derivation

```rust
let sk = SphincsSecretKey::new(seed: [u8; 20]);
let pk: SphincsPublicKey = sk.public_key();   // pk.root: [F; 8]  (= DIGEST_LEN)
```

`SphincsSecretKey::new` is **expensive** (builds the full FORS key + FORS pubkey eagerly).

### Signing

```rust
let sig: SphincsSig = sk.sign(&message).expect("signing failed");
```

`SphincsSig` has two parts:
```rust
pub struct SphincsSig {
    pub fors_sig: ForsSignature,
    pub hypertree_sig: HypertreeSignature,
}
```

### Cache Status

`crates/sphincs/src/lib.rs` line 5 has:
```rust
// pub mod signers_cache;  // TODO: not yet implemented
```

**No signature cache exists for SPHINCS+.** It needs to be created, modelled on
`xmss/src/signers_cache.rs`.

### Serialization

`SphincsSig` derives `Serialize, Deserialize` (confirmed from `core.rs` line 80+).
`SphincsPublicKey` is `[F; 8]`-equivalent, and `F: Serialize + Deserialize`.

---

## 4. Bytecode Compilation (`crates/rec_aggregation/src/compilation.rs`)

### XMSS Pattern

```rust
static BYTECODE: OnceLock<Bytecode> = OnceLock::new();
pub fn init_aggregation_bytecode() { BYTECODE.get_or_init(compile_main_program_self_referential); }
pub fn get_aggregation_bytecode() -> &'static Bytecode { BYTECODE.get().unwrap_or_else(|| panic!(...)) }
```

`compile_main_program_self_referential()` iteratively compiles until the bytecode's own
`log_size()` matches the guess used during compilation (it embeds its own size). It passes
a large `replacements: BTreeMap<String, String>` to substitute placeholder constants in the
Python source.

### SPHINCS+-Specific Replacements

The XMSS-specific replacements in `build_replacements(...)` are:
```rust
"V_PLACEHOLDER"          → V (= 40 for XMSS)
"V_GRINDING_PLACEHOLDER" → V_GRINDING
"W_PLACEHOLDER"          → W
"TARGET_SUM_PLACEHOLDER" → TARGET_SUM
"LOG_LIFETIME_PLACEHOLDER" → LOG_LIFETIME
"MESSAGE_LEN_PLACEHOLDER" → MESSAGE_LEN_FE
"RANDOMNESS_LEN_PLACEHOLDER" → RANDOMNESS_LEN_FE
"MERKLE_LEVELS_PER_CHUNK_PLACEHOLDER" → ...
```

SPHINCS+ parameters from `crates/sphincs/src/lib.rs`:
```
SPX_WOTS_LEN   = 32    (V in SPHINCS+ WOTS)
SPX_WOTS_W     = 16    (W = chain length)
SPX_WOTS_LOGW  = 4
TARGET_SUM     = 240
SPX_D          = 3     (hypertree layers)
SPX_TREE_HEIGHT = 11
SPX_FORS_HEIGHT = 15
SPX_FORS_TREES  = 9
RANDOMNESS_LEN  = 7
MESSAGE_LEN     = 9
V_GRINDING      = 0
```

The SPHINCS+ Python source `main_sphincs.py` **already exists** in
`crates/rec_aggregation/`. A separate `init_sphincs_bytecode()` / `get_sphincs_bytecode()`
pair using its own `OnceLock<Bytecode>` is needed, with a `build_sphincs_replacements()`
that substitutes SPHINCS+ constants rather than XMSS constants.

**Important design note:** The XMSS `compile_main_program_self_referential` is needed
because `main.py` encodes the bytecode sumcheck reduction (recursive children). For
SPHINCS+, `main_sphincs.py` has **no recursion** — it does not embed its own bytecode
size into the program. This means the SPHINCS+ compiler does **not** need a
self-referential loop; a single `compile_program_with_flags()` call suffices.

---

## 5. Public Input for SPHINCS+

The XMSS public input is built by `build_input_data(...)` which includes:
- `n_sigs`, `slice_hash`, `message`, `slot` bits, `bytecode_claim_output`, `bytecode_hash`

The SPHINCS+ public input (from `docs/SPHINCS_ZKDSL_PLAN.md` and `sphincs.rs`) is:
```
commitment = poseidon( poseidon( poseidon(ZERO_VEC, [n_sigs, 0,...]), seg_pubkeys ), seg_messages )
```

Already implemented as `sphincs_public_input(pubkeys, messages) -> [F; DIGEST_LEN]` in
`crates/rec_aggregation/src/sphincs.rs`.

No recursion → no `bytecode_claim_output`. Public input is just 8 FEs (one Poseidon digest).

---

## 6. `build_sphincs_witness` (`crates/rec_aggregation/src/sphincs.rs`)

Already implemented:

```rust
pub fn build_sphincs_witness(signers: &[SphincsSignerInput]) -> ExecutionWitness
```

Where:
```rust
pub struct SphincsSignerInput {
    pub secret_key: SphincsSecretKey,
    pub message: [F; MESSAGE_LEN_FE],
}
```

The witness builder calls `sk.sign(message)` internally for each signer, then populates
hint streams: `n_sigs`, `pubkeys`, `messages`, and per-signer: `digest_decomposition`,
`fors_sig`, `hypertree_sig`, `fe0_unused_bits`, `fe1_unused_bits`.

---

## 7. What's Missing for SPHINCS+ Benchmarking

### 7.1 `crates/sphincs/src/signers_cache.rs` (new file)

Parallel to XMSS `signers_cache.rs`. Must provide:
- `get_sphincs_benchmark_signatures() -> &'static Vec<(SphincsPublicKey, SphincsSig)>`
- `message_for_sphincs_benchmark() -> [F; MESSAGE_LEN_FE]`  
- `const NUM_SPHINCS_BENCHMARK_SIGNERS: usize` (e.g. 1_000 — SPHINCS+ is much slower to generate)

Key difference from XMSS: `SphincsSecretKey::new(seed)` is expensive (eager FORS keygen),
so parallel generation with rayon is even more important. The seed can be a `[u8; 20]`
derived from `index`.

**Serialization concern:** `SphincsSig` is large (~2205 FEs ≈ 8820 bytes each). 1_000 sigs ≈
8.4 MiB raw; compressed will be smaller. LZ4 is appropriate.

### 7.2 `crates/rec_aggregation/src/compilation.rs` (extend)

Add:
```rust
static SPHINCS_BYTECODE: OnceLock<Bytecode> = OnceLock::new();

pub fn init_sphincs_bytecode() { ... }
pub fn get_sphincs_bytecode() -> &'static Bytecode { ... }
```

With a `build_sphincs_replacements()` function that substitutes SPHINCS+ constants into
the program template. No self-referential loop needed (no recursive bytecode embedding).

The self-referential replacements (WHIR configs, AIR table parameters) are **VM-level
constants** and apply equally to SPHINCS+ — only the XMSS-specific constants differ.
The refactoring approach should split `build_replacements` into:
1. `build_vm_replacements(inner_program_log_size, ...)` — shared
2. `build_xmss_replacements()` — XMSS-specific additions
3. `build_sphincs_replacements()` — SPHINCS+-specific additions

### 7.3 `crates/rec_aggregation/src/sphincs.rs` (extend)

Add a top-level aggregate+prove function:
```rust
pub fn sphincs_aggregate(
    signers: &[SphincsSignerInput],
    log_inv_rate: usize,
) -> (Vec<SphincsPublicKey>, AggregatedSPHINCS)
```

And a verification function:
```rust
pub fn sphincs_verify_aggregation(
    pubkeys: &[[F; DIGEST_LEN]],
    agg: &AggregatedSPHINCS,
    messages: &[[F; MESSAGE_LEN_FE]],
) -> Result<ProofVerificationDetails, ProofError>
```

And a new proof struct:
```rust
pub struct AggregatedSPHINCS {
    pub proof: Proof<F>,
    pub metadata: Option<ExecutionMetadata>,
}
```

### 7.4 `crates/rec_aggregation/src/benchmark.rs` (extend)

Add `run_sphincs_benchmark(n_sigs: usize, log_inv_rate: usize, tracing: bool) -> f64`.

This is simpler than XMSS because:
- No recursive topology — just a flat single-node prove.
- No `LiveTree` tree display needed (or a degenerate 1-node tree).
- Can reuse the `LiveTree` / `NodeStats` structs for display.

### 7.5 `src/main.rs` (extend)

Add:
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

And the match arm:
```rust
Cli::Sphincs { n_signatures, log_inv_rate, tracing } => {
    run_sphincs_benchmark(n_signatures, log_inv_rate, tracing);
}
```

### 7.6 `src/lib.rs` (extend, optional)

Expose SPHINCS+ functions in the public API, mirroring the XMSS exports:
```rust
pub use rec_aggregation::{
    AggregatedSPHINCS,
    sphincs_aggregate,
    sphincs_verify_aggregation,
};
pub use sphincs::{SphincsPublicKey, SphincsSecretKey, SphincsSig};
```

---

## 8. Design Decisions & Open Questions

### D1: SPHINCS+ signature cache size

XMSS uses 10,000 cached signatures. SPHINCS+ signing is much slower (each signature
involves 9 FORS trees × 32768 leaf hashes + 3 hypertree layers). Recommended: start with
**500–1,000**. If a user requests more than the cache size, fail loudly or regenerate.

### D2: Message format for SPHINCS+

XMSS uses a single shared message (`message_for_benchmark()`). The current
`main_sphincs.py` supports **per-signer independent messages**. For benchmarking
simplicity, use a single fixed message for all signers (same as XMSS). The message can
be `[F::from_usize(i) for i in 0..9]` (same pattern).

### D3: No `slot` parameter for SPHINCS+

XMSS takes a `slot: u32` (Merkle tree leaf index for the OTS key). SPHINCS+ has no slot;
the leaf index is embedded in the message digest. The CLI and aggregate function should
not expose a slot.

### D4: Self-referential compilation

XMSS's `compile_main_program_self_referential` is needed because `main.py` embeds
`bytecode_claim_size` (derived from the bytecode's own size) into the program. This
causes a fixed-point iteration.

`main_sphincs.py` does **not** embed recursive bytecode structures. A single
`compile_program_with_flags(...)` call is sufficient. However, the same self-referential
check should still be done as a correctness guard (assert the bytecode's log_size matches
what was passed in).

### D5: Splitting `build_replacements`

`build_replacements` in `compilation.rs` is large (350+ lines) and mixes VM-level
constants (WHIR config, AIR tables) with XMSS-specific ones (V, W, TARGET_SUM, etc.).
The agent should refactor this into a shared VM replacements builder and per-scheme
additions, to avoid duplicating the WHIR/AIR logic for SPHINCS+.

### D6: `AggregatedSPHINCS` vs reusing `AggregatedXMSS`

`AggregatedXMSS` has `bytecode_point: Option<MultilinearPoint<EF>>` which is only
relevant for recursive proofs. SPHINCS+ does not have recursion. Options:
- **Reuse** `AggregatedXMSS` with `bytecode_point: None` always. Simple, avoids a new type.
- **Create** `AggregatedSPHINCS { proof, metadata }`. Cleaner API, no dead field.

Recommended: create a distinct `AggregatedSPHINCS` for clarity.

### D7: Exporting SPHINCS+ caching from `sphincs` crate vs `rec_aggregation`

XMSS caching lives in `crates/xmss/src/signers_cache.rs`. The analogous SPHINCS+ cache
could live in `crates/sphincs/src/signers_cache.rs` (noted as `// TODO: not yet
implemented` in `sphincs/src/lib.rs`). This keeps the sphincs crate self-contained.
However, `SphincsSignerInput` (which pairs a `SphincsSecretKey` with a message) is
defined in `rec_aggregation`. If only `(SphincsSecretKey, SphincsSig)` is cached (no
message), the cache can live in `crates/sphincs/`.

---

## 9. File Map (Summary)

| File | Action |
|------|--------|
| `crates/sphincs/src/signers_cache.rs` | **Create** — parallel to XMSS cache |
| `crates/sphincs/src/lib.rs` | **Extend** — `pub mod signers_cache;` |
| `crates/rec_aggregation/src/compilation.rs` | **Extend** — add `init_sphincs_bytecode`, `get_sphincs_bytecode`, `build_sphincs_replacements` |
| `crates/rec_aggregation/src/sphincs.rs` | **Extend** — add `sphincs_aggregate`, `sphincs_verify_aggregation`, `AggregatedSPHINCS` |
| `crates/rec_aggregation/src/benchmark.rs` | **Extend** — add `run_sphincs_benchmark` |
| `crates/rec_aggregation/src/lib.rs` | **Extend** — re-export new SPHINCS+ symbols |
| `src/main.rs` | **Extend** — add `Cli::Sphincs` variant |
| `src/lib.rs` | **Extend** (optional) — expose SPHINCS+ in public API |

---

## 10. Relevant Constants (Cross-Reference)

| Constant | XMSS | SPHINCS+ |
|---|---|---|
| WOTS chain count (V) | 40 | 32 |
| WOTS chain length (W) | 256 | 16 |
| TARGET_SUM | 800 | 240 |
| V_GRINDING | 2 | 0 |
| MESSAGE_LEN_FE | 9 | 9 |
| RANDOMNESS_LEN_FE | 7 | 7 |
| DIGEST_LEN | 8 | 8 |
| LOG_LIFETIME | 20 | 30 |
| Auth path levels | 20 | 11 (per layer) × 3 layers + 15 × 9 FORS |
| Sig size (FEs) | ~567 | ~2205 |

SPHINCS+ signature is ~4× larger than XMSS. Circuit cost per sig is ~1019 Poseidon calls
vs ~(V * avg_chains + auth_path) for XMSS. Expected throughput will be lower.
