use backend::PrimeCharacteristicRing;
use lean_compiler::*;
use lean_vm::*;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rec_aggregation::{PREAMBLE_MEMORY_LEN, compilation::build_replacements, sphincs::split_leaf_upper};
use sphincs::{
    HALF_DIGEST_SIZE, HalfDigest, MESSAGE_LEN_FE, MSG_RANDOMNESS_LEN_FE, RANDOMNESS_LEN_FE, SPX_D,
    SPX_TREE_BITS, SPX_TREE_HEIGHT, SPX_WOTS_LEN,
    address::Adrs,
    core::{SphincsSecretKey, extract_digest_parts, hmsg},
    fors_sig_to_flat, hypertree_sign,
    wots::{half_to_full, truncate_half},
    HypertreeSecretKey, HypertreeSignature,
};
use std::collections::HashMap;
use utils::poseidon16_compress_pair;

const TEST_STACK_SIZE: usize = 64 * 1024 * 1024;

fn run_on_large_stack<F: Send + 'static>(f: impl FnOnce() -> F + Send + 'static) -> F {
    std::thread::Builder::new()
        .stack_size(TEST_STACK_SIZE)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

/// Derive two HalfDigests from a [u8; 20] seed using a seeded RNG.
fn half_digests_from_seed(seed: [u8; 20]) -> (HalfDigest, HalfDigest) {
    // Pad to 32 bytes for StdRng
    let mut seed32 = [0u8; 32];
    seed32[..20].copy_from_slice(&seed);
    let mut rng = StdRng::from_seed(seed32);
    (rng.random(), rng.random())
}

fn make_hypertree_data(
    seed: [u8; 20],
    fors_pk: [F; DIGEST_LEN],
    leaf_idx: usize,
    tree_address: usize,
) -> (HalfDigest, HypertreeSignature) {
    let (sk_seed, pk_seed) = half_digests_from_seed(seed);
    let sk = HypertreeSecretKey::new(sk_seed, pk_seed);
    let pk = sk.public_key().0;
    let sig = hypertree_sign(&sk, &fors_pk, leaf_idx, tree_address);
    (pk, sig)
}

fn compute_layer_leaf_indices(leaf_idx: usize, tree_address: usize) -> [usize; SPX_D] {
    let mask = (1usize << SPX_TREE_HEIGHT) - 1;
    [leaf_idx, tree_address & mask, (tree_address >> SPX_TREE_HEIGHT) & mask]
}

/// Compute a Merkle root from a leaf node, auth path, leaf index, and addressing context.
/// Matches the tweaked poseidon layout in hypertree.rs::hash_xmss_node:
///   left  = [pk_seed | adrs0, adrs1, 0, 0]
///   right = [left_child | right_child]
fn compute_merkle_root(
    mut current: HalfDigest,
    leaf_index: usize,
    auth_path: &[HalfDigest],
    pk_seed: HalfDigest,
    layer: usize,
    layer_tree_address: usize,
) -> HalfDigest {
    for (level, sibling) in auth_path.iter().enumerate() {
        let is_left = ((leaf_index >> level) & 1) == 0;
        let node_idx = (leaf_index >> level) >> 1;
        let adrs = Adrs::tree(layer as u32, layer_tree_address as u32, (level + 1) as u32, node_idx as u32);
        let mut left = [F::ZERO; DIGEST_LEN];
        left[..HALF_DIGEST_SIZE].copy_from_slice(&pk_seed);
        left[HALF_DIGEST_SIZE] = adrs.adrs0;
        left[HALF_DIGEST_SIZE + 1] = adrs.adrs1;
        let mut right = [F::ZERO; DIGEST_LEN];
        if is_left {
            right[..HALF_DIGEST_SIZE].copy_from_slice(&current);
            right[HALF_DIGEST_SIZE..].copy_from_slice(sibling);
        } else {
            right[..HALF_DIGEST_SIZE].copy_from_slice(sibling);
            right[HALF_DIGEST_SIZE..].copy_from_slice(&current);
        }
        current = truncate_half(poseidon16_compress_pair(&left, &right));
    }
    current
}

fn build_sphincs_hints(seed: [u8; 20], message: [F; MESSAGE_LEN_FE]) -> HashMap<String, Vec<Vec<F>>> {
    let (sk_seed, sk_prf) = half_digests_from_seed(seed);
    let sk = SphincsSecretKey::new(sk_seed, sk_prf);
    let pk_root = sk.pk_root;
    let pk_seed = sk.pk_seed;
    let pk = pk_root; // HalfDigest (4 FEs)

    let sig = sk.sign(&message).expect("failed to sign message");

    // sig.r is the 4-FE HalfDigest message randomness R = PRFmsg(sk_prf, opt_rand, message)
    let message_digest = hmsg(sig.r, pk_seed, pk_root, &message);

    let (leaf_indices, fors_indices, leaf_uppers, fors_uppers) = extract_digest_parts(&message_digest);

    let digest_indices: Vec<F> = leaf_indices
        .iter()
        .chain(fors_indices.iter())
        .map(|&i| F::from_usize(i))
        .collect();

    let (digest_uppers_low, digest_uppers_high): (Vec<F>, Vec<F>) =
        leaf_uppers.iter().map(|&u| split_leaf_upper(u)).unzip();
    let digest_fors_uppers: Vec<F> = fors_uppers.iter().map(|&u| F::from_usize(u)).collect();

    let fors_sig_flat = fors_sig_to_flat(&sig.fors_sig);
    let hypertree_sig_flat = sig.hypertree_sig.flatten_hypertree_sig();

    // Per layer: randomness(RANDOMNESS_LEN_FE) + layer_idx(1) + chain_tips(SPX_WOTS_LEN*HALF_DIGEST_SIZE)
    //            + auth_path(SPX_TREE_HEIGHT*HALF_DIGEST_SIZE)
    let expected_hypertree_len =
        SPX_D * ((RANDOMNESS_LEN_FE + 1) + (SPX_WOTS_LEN + SPX_TREE_HEIGHT) * HALF_DIGEST_SIZE);
    assert_eq!(hypertree_sig_flat.len(), expected_hypertree_len);

    HashMap::from([
        ("pk".to_string(), vec![pk.to_vec()]),
        ("message".to_string(), vec![message.to_vec()]),
        (
            "randomness".to_string(),
            // sig.r = 4-FE HalfDigest; the Python circuit reads MSG_RANDOMNESS_LEN_FE (4) FEs
            vec![sig.r[..MSG_RANDOMNESS_LEN_FE].to_vec()],
        ),
        ("digest_indices".to_string(), vec![digest_indices]),
        ("digest_uppers_low".to_string(), vec![digest_uppers_low]),
        ("digest_uppers_high".to_string(), vec![digest_uppers_high]),
        ("digest_uppers_fors".to_string(), vec![digest_fors_uppers]),
        ("fors_sig".to_string(), vec![fors_sig_flat]),
        ("hypertree_sig".to_string(), vec![hypertree_sig_flat]),
    ])
}

fn make_bytecode(test_file: &str) -> lean_vm::Bytecode {
    let path = format!("{}/tests/{}", env!("CARGO_MANIFEST_DIR"), test_file);
    let replacements = build_replacements(18, F::ONE);
    compile_program_with_flags(&ProgramSource::Filepath(path), CompilationFlags { replacements })
}

#[test]
fn profile_sphincs_verify() {
    run_on_large_stack(|| {
        let bytecode = make_bytecode("test_sphincs_aggregate.py");

        let seed = [7u8; 20];
        let message = [F::from_usize(0); MESSAGE_LEN_FE];
        let hints = build_sphincs_hints(seed, message);
        let witness = ExecutionWitness {
            preamble_memory_len: PREAMBLE_MEMORY_LEN,
            hints,
        };

        let result = execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness, true);
        println!("{}", result.metadata.display());
    });
}

#[test]
fn test_sphincs_aggregate_verify() {
    run_on_large_stack(|| {
        let bytecode = make_bytecode("test_sphincs_aggregate.py");

        let seed = [7u8; 20];
        let message = [F::from_usize(0); MESSAGE_LEN_FE];

        let hints = build_sphincs_hints(seed, message);
        let witness = ExecutionWitness {
            preamble_memory_len: PREAMBLE_MEMORY_LEN,
            hints,
        };

        execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness, false);
    });
}

#[test]
fn test_hypertree_merkle_verify() {
    run_on_large_stack(|| {
        let bytecode = make_bytecode("test_hypertree_merkle_verify.py");

        let seed = [9u8; 20];
        let (sk_seed, pk_seed) = half_digests_from_seed(seed);
        // hypertree_sign takes a full Digest as the layer-0 message
        let fors_pk_half = HalfDigest::default();
        let fors_pk_digest = half_to_full(fors_pk_half);
        let leaf_idx = rand::random::<u32>() as usize & ((1 << SPX_TREE_HEIGHT) - 1);
        let tree_address = rand::random::<u32>() as usize & ((1 << SPX_TREE_BITS) - 1);

        let sk = HypertreeSecretKey::new(sk_seed, pk_seed);
        let sig = hypertree_sign(&sk, &fors_pk_digest, leaf_idx, tree_address);

        // Layer-0 message: poseidon(fors_pk_digest, zeros)
        let current_message = poseidon16_compress_pair(&fors_pk_digest, &[F::ZERO; DIGEST_LEN]);
        let layer0 = &sig.layers[0];
        let layer_tree_address = tree_address; // layer 0: no shift

        // Recover WOTS public key using layer-0 adrs
        let wots_adrs = Adrs::wots_hash(0, layer_tree_address as u32, leaf_idx as u32, 0, 0);
        let wots_pk = layer0
            .wots_sig
            .recover_public_key(&current_message, wots_adrs.adrs0, wots_adrs.adrs1)
            .expect("valid layer-0 WOTS signature");
        let pk_adrs = Adrs::wots_pk(0, layer_tree_address as u32, leaf_idx as u32);
        let leaf_node = wots_pk.hash(pk_seed, pk_adrs);

        let expected_root = compute_merkle_root(
            leaf_node,
            leaf_idx,
            &layer0.auth_path,
            pk_seed,
            0,
            layer_tree_address,
        );

        let hints = HashMap::from([
            ("layer_leaf_index".to_string(), vec![vec![F::from_usize(leaf_idx)]]),
            ("leaf_node".to_string(), vec![leaf_node.to_vec()]),
            (
                "auth_path".to_string(),
                vec![layer0.auth_path.iter().flatten().copied().collect()],
            ),
            ("expected_root".to_string(), vec![expected_root.to_vec()]),
        ]);

        let witness = ExecutionWitness {
            preamble_memory_len: PREAMBLE_MEMORY_LEN,
            hints,
        };

        execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness, false);
    });
}

#[test]
fn test_hypertree_verify() {
    run_on_large_stack(|| {
        let bytecode = make_bytecode("test_hypertree_verify.py");

        let seed = [11u8; 20];
        let (sk_seed, pk_seed) = half_digests_from_seed(seed);
        let fors_pk_half = HalfDigest::default();
        let fors_pk_digest = half_to_full(fors_pk_half);
        let leaf_idx = rand::random::<u32>() as usize & ((1 << SPX_TREE_HEIGHT) - 1);
        let tree_address = rand::random::<u32>() as usize & ((1 << SPX_TREE_BITS) - 1);

        let sk = HypertreeSecretKey::new(sk_seed, pk_seed);
        let pk = sk.public_key().0;
        let sig = hypertree_sign(&sk, &fors_pk_digest, leaf_idx, tree_address);

        let layer_leaf_indices = compute_layer_leaf_indices(leaf_idx, tree_address);

        // fors_pubkey hint: 4-FE HalfDigest (the circuit will hash it with zeros to get layer-0 message)
        let hints = HashMap::from([
            ("fors_pubkey".to_string(), vec![fors_pk_half.to_vec()]),
            (
                "layer_leaf_indices".to_string(),
                vec![layer_leaf_indices.iter().map(|&i| F::from_usize(i)).collect()],
            ),
            ("expected_pk".to_string(), vec![pk.to_vec()]),
            ("hypertree_sig".to_string(), vec![sig.flatten_hypertree_sig()]),
        ]);

        let witness = ExecutionWitness {
            preamble_memory_len: PREAMBLE_MEMORY_LEN,
            hints: hints.clone(),
        };
        execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness, false);

        let mut wrong_pk = pk;
        wrong_pk[0] += F::ONE;
        let wrong_hints = HashMap::from([
            ("fors_pubkey".to_string(), vec![fors_pk_half.to_vec()]),
            (
                "layer_leaf_indices".to_string(),
                vec![layer_leaf_indices.iter().map(|&i| F::from_usize(i)).collect()],
            ),
            ("expected_pk".to_string(), vec![wrong_pk.to_vec()]),
            ("hypertree_sig".to_string(), vec![sig.flatten_hypertree_sig()]),
        ]);
        let wrong_witness = ExecutionWitness {
            preamble_memory_len: PREAMBLE_MEMORY_LEN,
            hints: wrong_hints,
        };
        assert!(
            try_execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &wrong_witness, false).is_err(),
            "should fail: wrong expected hypertree root"
        );
    });
}
