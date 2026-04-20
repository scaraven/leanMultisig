# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

leanMultisig is a minimal hash-based zkVM targeting recursion and aggregation of XMSS (hash-based) signatures for a Post-Quantum Ethereum. It uses a multilinear proving system with WHIR, SuperSpartan (AIR-specific), and Logup.

The base field is KoalaBear (31-bit prime field) with a degree-5 extension for 123 bits of provable security.

## Build & Test Commands

```bash
# Build (release, with native CPU features via .cargo/config.toml)
cargo build --release

# Run all tests (alias defined in .cargo/config.toml)
cargo testall                    # equivalent to: cargo test --all --release

# Run a single test
cargo test --release -p <crate_name> <test_name>

# Check all SIMD targets (neon, AVX2, AVX512)
./src/check_all_targets.sh

# Run benchmarks
cargo run --release -- xmss --n-signatures 1400
cargo run --release -- recursion --n 2
cargo run --release -- poseidon --log-n-perms 16
cargo run --release -- fancy-aggregation

# Use conjectured security (smaller proofs) via feature flag
cargo run --release --features prox-gaps-conjecture -- xmss --n-signatures 1400
```

## Architecture

### Workspace Crates

- **`backend/`** — Cryptographic backend, re-exported as a single crate. Contains sub-crates:
  - `field/` — Generic field trait and arithmetic
  - `koala-bear/` — KoalaBear field implementation + Poseidon2 hash
  - `poly/` — Multilinear polynomial representations (dense, evaluations, eq-MLE)
  - `air/` — AIR (Algebraic Intermediate Representation) symbolic constraints
  - `sumcheck/` — Sumcheck protocol
  - `fiat-shamir/` — Transcript, challenger, Merkle proofs
  - `symetric/` — Symmetric crypto primitives (Merkle trees, hashing)
  - `utils/` — Shared utilities (Poseidon2 helpers, multilinear ops, display)
- **`whir/`** — WHIR polynomial commitment scheme (commit, open, verify)
- **`lean_compiler/`** — Compiles zkDSL (Python-like syntax) to VM bytecode. Pipeline: parse (pest grammar) → simplify → intermediate compile → final compile
- **`lean_vm/`** — Minimal VM: ISA definition, execution engine, trace tables
- **`lean_prover/`** — Generates execution traces and proves/verifies VM execution
- **`sub_protocols/`** — Logup, quotient GKR, stacked polynomial commitment
- **`air/`** — Top-level AIR prove/verify orchestration (SuperSpartan for AIR)
- **`xmss/`** — XMSS signature scheme (WOTS+, key gen, sign, verify)
- **`rec_aggregation/`** — Recursive proof aggregation with tree topologies

### Key Data Flow

1. **zkDSL source** (.py files) → `lean_compiler` → bytecode
2. **Bytecode** → `lean_vm` executes → execution trace
3. **Trace** → `lean_prover` → AIR constraints → `air` crate proves via SuperSpartan + sumcheck
4. **Polynomial commitments** via `whir` (WHIR PCS)
5. **Aggregation**: `rec_aggregation` composes proofs recursively in a tree (`AggregationTopology`)

### zkDSL

Programs are written in a Python-like DSL (see `crates/lean_compiler/zkDSL.md`). Key features: SSA memory model (write-once), `unroll`/`range`/`dynamic_unroll` loops, compile-time const evaluation, `DynArray`, precompiles for Poseidon16 and extension field ops. DSL files can also run as Python scripts via `snark_lib.py`.

### Library API (`src/lib.rs`)

The root crate exposes a public API for XMSS operations:
- `setup_prover()` / `setup_verifier()` — one-time initialization
- `xmss_key_gen`, `xmss_sign`, `xmss_verify` — signature operations
- `xmss_aggregate`, `xmss_verify_aggregation` — recursive proof aggregation

## Code Conventions

- Rust edition 2024, `max_width = 120` (rustfmt)
- Clippy: all + nursery + pedantic enabled (with some relaxations, see workspace `Cargo.toml`)
- All AIR columns use the base field only; extension field operations are done via AIR constraints
- Native CPU features enabled by default (`target-cpu=native` in `.cargo/config.toml`)
- `--release` is expected for all meaningful runs (proving is compute-intensive)
- zkDSL comments: use `"""..."""` multi-line strings for section separators and block explanations. Do NOT use `# ── ... ──` or similar `#`-based banner lines to section off code.

## Collaboration Style

There are two conversation modes. Read the user's request carefully to determine which applies.

### Fast Conversations

Used for small, well-defined changes: bug fixes, targeted features, tests, minor refactors.

- Implement directly without extensive scoping or back-and-forth
- Ask clarifying questions only if truly ambiguous and the wrong choice would waste significant effort
- Keep responses concise; skip lengthy preamble

### Slow Conversations

Used for larger features, architectural decisions, or anything with significant design surface.

**Phase 1 — Scoping (before any code is written):**
- Present a plan/outline when asked: list components, design choices, open questions, trade-offs
- Iterate on the plan through back-and-forth; revise based on feedback
- Do NOT write implementation code until the user explicitly approves the plan
- Approval phrases to watch for: "approved", "go ahead", "implement it", "looks good, proceed", or equivalent

**Phase 2 — Implementation (after approval):**
- Implement according to the approved plan
- Flag deviations from the plan before making them, not after

**Note:** The style of slow conversations will evolve as the user becomes more proficient with the codebase. Update this section periodically to reflect the current working style.

## SPHINCS+ Project Context

The `crates/sphincs/` crate is complete: keygen, sign, and verify are all implemented.
Parameters: KoalaBear field, 8-FE Poseidon2 digests, V=32 WOTS+ chains (w=16, TARGET_SUM=240),
9-tree FORS (height 15), 3-layer hypertree (height 11 per layer).

A provable zkDSL verifier lives in `rec_aggregation/`. Scope is **raw SPHINCS+
signature verification only — no recursive aggregation**. The architectural plan is at
`docs/SPHINCS_ZKDSL_PLAN.md`; all design decisions are resolved there.
Do not re-open those decisions without reading the plan first.

zkDSL implementation status:
- `sphincs_utils.py`, `sphincs_wots.py` — implemented and tested
- `sphincs_fors.py` — implemented; FORS Merkle test is compile-only pending a compiler fix (runtime `%` on `Mut` variables is not yet handled in the compiler)
- `sphincs_hypertree.py`, `sphincs_aggregate.py` — implemented, not yet tested
- `main_sphincs.py` — implemented (batch verifier, per-signer independent messages, public input = hash of [n_sigs | pubkeys | messages])

### rec_aggregation test infrastructure

All test programs follow this pattern:

**Python** — call `build_preamble_memory()` first, pull all test data via `hint_witness`, assert internally. Do not read raw test data from `pub_mem`.

**Rust** — pass `vec![F::from_usize(0); DIGEST_LEN]` as public input (8 zeros), put all test data in `hints: HashMap<String, Vec<Vec<F>>>`, use `ExecutionWitness { preamble_memory_len: PREAMBLE_MEMORY_LEN, hints }`.

Why the 8-zero public input matters: `hashing.py` hardcodes `ZERO_VEC_PTR = PUBLIC_INPUT_LEN = 8`. The VM places the preamble at `[public_memory_size..public_memory_size+PREAMBLE_MEMORY_LEN)`. Passing exactly 8 FEs aligns the preamble at `[8..53)`, matching all preamble pointer constants. Any other size misaligns the preamble and causes `MemoryAlreadySet` errors.

For full (non-test) programs, the 8-FE public input is the hash of all witness data; the Python reads and verifies it at address 0. See `tests/test_hashing.py` and `tests/test_hashing.rs` for the canonical example.
