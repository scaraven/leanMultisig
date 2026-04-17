use backend::PrimeCharacteristicRing;
use lean_vm::{DIGEST_LEN, ExecutionWitness, F};
use sphincs::{
    MESSAGE_LEN_FE, SPX_FORS_TREES, core::SphincsSecretKey, core::extract_digest_parts, extract_fors_indices,
    fors_sig_to_flat,
};
use std::collections::HashMap;
use utils::{poseidon_compress_slice, poseidon16_compress_pair};

use crate::PREAMBLE_MEMORY_LEN;

#[derive(Debug)]
pub struct SphincsSignerInput {
    pub secret_key: SphincsSecretKey,
    pub message: [F; MESSAGE_LEN_FE],
}

/// Compute the 8-FE public input commitment for a sphincs batch verification run.
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

/// Build per-signer hints for sphincs_verify (the hints consumed inside sphincs_aggregate.py).
fn build_signer_hints(sk: &SphincsSecretKey, message: &[F; MESSAGE_LEN_FE], hints: &mut HashMap<String, Vec<Vec<F>>>) {
    let sig = sk.sign(message).expect("SPHINCS+ signing failed");

    let mut right = [F::ZERO; DIGEST_LEN];
    right[0] = message[8];
    let message_digest = poseidon16_compress_pair(&message[0..8].try_into().unwrap(), &right);

    let (leaf_idx, tree_address, mhash, fe5_upper, fe0_unused, fe1_unused) = extract_digest_parts(&message_digest);
    let fors_indices = extract_fors_indices(&mhash);

    let mut digest_decomposition = Vec::with_capacity(2 + SPX_FORS_TREES + 1);
    digest_decomposition.push(F::from_usize(leaf_idx));
    digest_decomposition.push(F::from_usize(tree_address));
    digest_decomposition.extend(fors_indices.iter().map(|&i| F::from_usize(i)));
    digest_decomposition.push(F::from_usize(fe5_upper));

    hints
        .entry("digest_decomposition".to_string())
        .or_default()
        .push(digest_decomposition);
    hints
        .entry("fors_sig".to_string())
        .or_default()
        .push(fors_sig_to_flat(&sig.fors_sig));
    hints
        .entry("hypertree_sig".to_string())
        .or_default()
        .push(sig.hypertree_sig.flatten_hypertree_sig());
    hints
        .entry("fe0_unused_bits".to_string())
        .or_default()
        .push(vec![F::from_usize(fe0_unused)]);
    hints
        .entry("fe1_unused_bits".to_string())
        .or_default()
        .push(vec![F::from_usize(fe1_unused)]);
}

/// Build the full ExecutionWitness for main_sphincs.py.
pub fn build_sphincs_witness(signers: &[SphincsSignerInput]) -> ExecutionWitness {
    let n = signers.len();

    let pubkeys: Vec<[F; DIGEST_LEN]> = signers
        .iter()
        .map(|s| sphincs::HypertreeSecretKey::new(s.secret_key.seed()).public_key().0)
        .collect();

    let pubkeys_flat: Vec<F> = pubkeys.iter().flatten().copied().collect();
    let messages_flat: Vec<F> = signers.iter().flat_map(|s| s.message.iter().copied()).collect();

    let mut hints: HashMap<String, Vec<Vec<F>>> = HashMap::new();
    hints.insert("n_sigs".to_string(), vec![vec![F::from_usize(n)]]);
    hints.insert("pubkeys".to_string(), vec![pubkeys_flat]);
    hints.insert("messages".to_string(), vec![messages_flat]);

    for signer in signers {
        build_signer_hints(&signer.secret_key, &signer.message, &mut hints);
    }

    ExecutionWitness {
        preamble_memory_len: PREAMBLE_MEMORY_LEN,
        hints,
    }
}
