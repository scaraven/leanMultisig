use backend::{PrimeCharacteristicRing, Proof, ProofError};
use lean_prover::default_whir_config;
use lean_prover::prove_execution::prove_execution;
use lean_prover::verify_execution::{ProofVerificationDetails, verify_execution};
use lean_vm::{DIGEST_LEN, ExecutionMetadata, ExecutionWitness, F};
use serde::{Deserialize, Serialize};
use sphincs::SPX_TREE_HEIGHT;
use sphincs::{
    MESSAGE_LEN_FE,
    core::{SphincsPublicKey, SphincsSig, extract_digest_parts},
    fors_sig_to_flat,
};
use std::collections::HashMap;
use utils::{poseidon_compress_slice, poseidon16_compress_pair};

use crate::PREAMBLE_MEMORY_LEN;

const HINT_DECOMPOSE_BITS_LOWER: usize = (31 - SPX_TREE_HEIGHT) / 2;
const HINT_DECOMPOSE_BITS_UPPER: usize = (31 - SPX_TREE_HEIGHT) - HINT_DECOMPOSE_BITS_LOWER;

/// Split a leaf upper value into (low HINT_DECOMPOSE_BITS_LOWER bits, remaining high bits).
pub fn split_leaf_upper(u: usize) -> (F, F) {
    (
        F::from_usize(u & ((1 << HINT_DECOMPOSE_BITS_LOWER) - 1)),
        F::from_usize(u >> HINT_DECOMPOSE_BITS_LOWER),
    )
}

/// One signer's pre-computed input to the SPHINCS+ batch verifier.
/// The secret key is not required here — all hint data is derivable from the signature.

#[derive(Debug)]
pub struct SphincsSignerInput {
    pub pubkey: SphincsPublicKey,
    pub sig: SphincsSig,
    pub message: [F; MESSAGE_LEN_FE],
}

/// Result of a SPHINCS+ batch aggregation: a proof and optional execution metadata.
/// No `bytecode_point` field — SPHINCS+ has no recursive proof children.
///
/// TODO: if recursion is ever added to main_sphincs.py, add `bytecode_point` here
/// analogous to `AggregatedXMSS` and reintroduce the self-referential compilation loop.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AggregatedSPHINCS {
    pub proof: Proof<F>,
    #[serde(skip, default)]
    pub metadata: Option<ExecutionMetadata>,
}

/// Compute the 8-FE public input commitment for a SPHINCS+ batch verification run.
///
/// Mirrors the Python commitment scheme in main_sphincs.py:
///   seg_nsigs    = poseidon(ZERO_VEC, [n_sigs, 0, ..., 0])
///   seg_pubkeys  = slice_hash_with_iv(pubkeys_flat)
///   seg_messages = slice_hash_with_iv(messages_flat)
///   commitment   = poseidon(poseidon(seg_nsigs, seg_pubkeys), seg_messages)
pub fn sphincs_public_input(pubkeys: &[[F; DIGEST_LEN]], messages: &[[F; MESSAGE_LEN_FE]]) -> [F; DIGEST_LEN] {
    let n = pubkeys.len();
    assert_eq!(messages.len(), n);

    let mut nsigs_chunk = [F::ZERO; DIGEST_LEN];
    nsigs_chunk[0] = F::from_usize(n);
    let seg_nsigs = poseidon16_compress_pair(&[F::ZERO; DIGEST_LEN], &nsigs_chunk);

    let pubkeys_flat: Vec<F> = pubkeys.iter().flatten().copied().collect();
    let seg_pubkeys = poseidon_compress_slice(&pubkeys_flat, true);

    let messages_flat: Vec<F> = messages.iter().flatten().copied().collect();
    let seg_messages = poseidon_compress_slice(&messages_flat, true);

    let h01 = poseidon16_compress_pair(&seg_nsigs, &seg_pubkeys);
    poseidon16_compress_pair(&h01, &seg_messages)
}

/// Append per-signer hints derived from a pre-computed signature.
/// The secret key is not needed: all hint data comes from the sig and message.
fn build_signer_hints(
    pubkey: &SphincsPublicKey,
    sig: &SphincsSig,
    message: &[F; MESSAGE_LEN_FE],
    hints: &mut HashMap<String, Vec<Vec<F>>>,
) {
    let mut right = [F::ZERO; DIGEST_LEN];
    right[0] = message[8];
    let message_digest = poseidon16_compress_pair(&message[0..8].try_into().unwrap(), &right);

    let (leaf_indices, fors_indices, leaf_uppers, fors_uppers) = extract_digest_parts(&message_digest);

    let digest_indices: Vec<F> = leaf_indices
        .iter()
        .chain(fors_indices.iter())
        .map(|&i| F::from_usize(i))
        .collect();
    let (digest_uppers_lower, digest_uppers_high) = leaf_uppers.iter().map(|&u| split_leaf_upper(u)).unzip();

    let digest_fors_uppers: Vec<F> = fors_uppers.iter().map(|&u| F::from_usize(u)).collect();

    hints
        .entry("digest_indices".to_string())
        .or_default()
        .push(digest_indices);
    hints
        .entry("digest_uppers_low".to_string())
        .or_default()
        .push(digest_uppers_lower);
    hints
        .entry("digest_uppers_high".to_string())
        .or_default()
        .push(digest_uppers_high);
    hints
        .entry("digest_uppers_fors".to_string())
        .or_default()
        .push(digest_fors_uppers);
    hints
        .entry("fors_sig".to_string())
        .or_default()
        .push(fors_sig_to_flat(&sig.fors_sig));
    hints
        .entry("hypertree_sig".to_string())
        .or_default()
        .push(sig.hypertree_sig.flatten_hypertree_sig());

    // Suppress unused variable warning — pubkey is passed for API clarity and future use
    // (e.g. if we need to cross-check pk against the sig's embedded public key).
    let _ = pubkey;
}

/// Prove a batch of SPHINCS+ signatures.
///
/// Returns an `AggregatedSPHINCS` containing the proof and execution metadata.
/// Unlike `xmss_aggregate` there are no recursive children and no pubkey deduplication —
/// the circuit verifies all N (pk, message, sig) triples independently as given.
pub fn sphincs_aggregate(signers: &[SphincsSignerInput], log_inv_rate: usize) -> AggregatedSPHINCS {
    let pubkeys: Vec<[F; DIGEST_LEN]> = signers.iter().map(|s| s.pubkey.root()).collect();
    let messages: Vec<[F; MESSAGE_LEN_FE]> = signers.iter().map(|s| s.message).collect();

    let public_input = sphincs_public_input(&pubkeys, &messages).to_vec();
    let witness = build_sphincs_witness(signers);
    let whir_config = default_whir_config(log_inv_rate);

    let execution_proof = prove_execution(
        crate::compilation::get_sphincs_bytecode(),
        &public_input,
        &witness,
        &whir_config,
        false,
    );

    AggregatedSPHINCS {
        proof: execution_proof.proof,
        metadata: Some(execution_proof.metadata),
    }
}

/// Verify a SPHINCS+ batch aggregation proof.
pub fn sphincs_verify_aggregation(
    pubkeys: &[[F; DIGEST_LEN]],
    messages: &[[F; MESSAGE_LEN_FE]],
    agg: &AggregatedSPHINCS,
) -> Result<ProofVerificationDetails, ProofError> {
    let public_input = sphincs_public_input(pubkeys, messages).to_vec();
    verify_execution(
        crate::compilation::get_sphincs_bytecode(),
        &public_input,
        agg.proof.clone(),
    )
    .map(|(details, _)| details)
}

/// Build the full `ExecutionWitness` for main_sphincs.py from pre-signed inputs.
pub fn build_sphincs_witness(signers: &[SphincsSignerInput]) -> ExecutionWitness {
    let n = signers.len();

    let pubkeys: Vec<[F; DIGEST_LEN]> = signers.iter().map(|s| s.pubkey.root()).collect();
    let pubkeys_flat: Vec<F> = pubkeys.iter().flatten().copied().collect();
    let messages_flat: Vec<F> = signers.iter().flat_map(|s| s.message.iter().copied()).collect();

    let mut hints: HashMap<String, Vec<Vec<F>>> = HashMap::new();
    hints.insert("n_sigs".to_string(), vec![vec![F::from_usize(n)]]);
    hints.insert("pubkeys".to_string(), vec![pubkeys_flat]);
    hints.insert("messages".to_string(), vec![messages_flat]);

    for signer in signers {
        build_signer_hints(&signer.pubkey, &signer.sig, &signer.message, &mut hints);
    }

    ExecutionWitness {
        preamble_memory_len: PREAMBLE_MEMORY_LEN,
        hints,
    }
}
