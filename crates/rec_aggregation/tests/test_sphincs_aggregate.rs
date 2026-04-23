use backend::PrimeCharacteristicRing;
use lean_compiler::*;
use lean_vm::*;
use rec_aggregation::PREAMBLE_MEMORY_LEN;
use sphincs::{
    HypertreeSecretKey, HypertreeSignature, MESSAGE_LEN_FE, RANDOMNESS_LEN_FE, SPX_D, SPX_FORS_TREES, SPX_TREE_BITS,
    SPX_TREE_HEIGHT, SPX_WOTS_LEN, core::SphincsSecretKey, extract_fors_indices, fors_sig_to_flat, hypertree_sign,
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

fn make_hypertree_data(
    seed: [u8; 20],
    fors_pk: [F; DIGEST_LEN],
    leaf_idx: usize,
    tree_address: usize,
) -> ([F; DIGEST_LEN], HypertreeSignature) {
    let sk = HypertreeSecretKey::new(seed);
    let pk = sk.public_key().0;
    let sig = hypertree_sign(&sk, &fors_pk, leaf_idx, tree_address);
    (pk, sig)
}

fn compute_layer_leaf_indices(leaf_idx: usize, tree_address: usize) -> [usize; SPX_D] {
    let mask = (1usize << SPX_TREE_HEIGHT) - 1;
    [leaf_idx, tree_address & mask, (tree_address >> SPX_TREE_HEIGHT) & mask]
}

fn compute_merkle_root(
    mut current: [F; DIGEST_LEN],
    leaf_index: usize,
    auth_path: &[[F; DIGEST_LEN]],
) -> [F; DIGEST_LEN] {
    for (level, sibling) in auth_path.iter().enumerate() {
        let is_left = ((leaf_index >> level) & 1) == 0;
        current = if is_left {
            poseidon16_compress_pair(&current, sibling)
        } else {
            poseidon16_compress_pair(sibling, &current)
        };
    }
    current
}

fn build_sphincs_hints(seed: [u8; 20], message: [F; MESSAGE_LEN_FE]) -> HashMap<String, Vec<Vec<F>>> {
    let sk = SphincsSecretKey::new(seed);
    let pk = sphincs::HypertreeSecretKey::new(seed).public_key().0;
    let sig = sk.sign(&message).expect("failed to sign message");

    let mut right = [F::ZERO; DIGEST_LEN];
    right[0] = message[8];
    let message_digest = poseidon16_compress_pair(&message[0..8].try_into().unwrap(), &right);

    let (leaf_idx, tree_address, mhash, fe5_upper, fe0_unused, fe1_unused) =
        sphincs::core::extract_digest_parts(&message_digest);
    let fors_indices = extract_fors_indices(&mhash);

    let mut digest_decomposition = Vec::with_capacity(2 + SPX_FORS_TREES + 1);
    digest_decomposition.push(F::from_usize(leaf_idx));
    digest_decomposition.push(F::from_usize(tree_address));
    digest_decomposition.extend(fors_indices.iter().map(|&i| F::from_usize(i)));
    digest_decomposition.push(F::from_usize(fe5_upper));

    let fors_sig_flat = fors_sig_to_flat(&sig.fors_sig);
    let hypertree_sig_flat = sig.hypertree_sig.flatten_hypertree_sig();

    let expected_hypertree_len = SPX_D * (RANDOMNESS_LEN_FE + (SPX_WOTS_LEN + SPX_TREE_HEIGHT) * DIGEST_LEN);
    assert_eq!(hypertree_sig_flat.len(), expected_hypertree_len);

    HashMap::from([
        ("pk".to_string(), vec![pk.to_vec()]),
        ("message".to_string(), vec![message.to_vec()]),
        ("digest_decomposition".to_string(), vec![digest_decomposition]),
        ("fors_sig".to_string(), vec![fors_sig_flat]),
        ("hypertree_sig".to_string(), vec![hypertree_sig_flat]),
        ("fe0_unused_bits".to_string(), vec![vec![F::from_usize(fe0_unused)]]),
        ("fe1_unused_bits".to_string(), vec![vec![F::from_usize(fe1_unused)]]),
    ])
}

#[test]
fn profile_sphincs_verify() {
    run_on_large_stack(|| {
        let path = format!("{}/tests/test_sphincs_aggregate.py", env!("CARGO_MANIFEST_DIR"));
        let bytecode = compile_program(&ProgramSource::Filepath(path));

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
        let path = format!("{}/tests/test_sphincs_aggregate.py", env!("CARGO_MANIFEST_DIR"));
        let bytecode = compile_program(&ProgramSource::Filepath(path));

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
        let path = format!("{}/tests/test_hypertree_merkle_verify.py", env!("CARGO_MANIFEST_DIR"));
        let bytecode = compile_program(&ProgramSource::Filepath(path));

        let seed = [9u8; 20];
        let fors_pk = [F::ZERO; DIGEST_LEN];
        let leaf_idx = rand::random::<u32>() as usize & ((1 << SPX_TREE_HEIGHT) - 1);
        let tree_address = rand::random::<u32>() as usize & ((1 << SPX_TREE_BITS) - 1);
        let (_pk, sig) = make_hypertree_data(seed, fors_pk, leaf_idx, tree_address);

        // Layer-0 message in hypertree: poseidon(fors_pk, [0..0]).
        let current_message = poseidon16_compress_pair(&fors_pk, &[F::ZERO; DIGEST_LEN]);
        let layer0 = &sig.layers[0];
        let wots_pk = layer0
            .wots_sig
            .recover_public_key(&current_message, 0)
            .expect("valid layer-0 WOTS signature");
        let leaf_node = wots_pk.hash();

        let expected_root = compute_merkle_root(leaf_node, leaf_idx, &layer0.auth_path);

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
        let path = format!("{}/tests/test_hypertree_verify.py", env!("CARGO_MANIFEST_DIR"));
        let bytecode = compile_program(&ProgramSource::Filepath(path));

        let seed = [11u8; 20];
        let fors_pk = [F::ZERO; DIGEST_LEN];
        let leaf_idx = rand::random::<u32>() as usize & ((1 << SPX_TREE_HEIGHT) - 1);
        let tree_address = rand::random::<u32>() as usize & ((1 << SPX_TREE_BITS) - 1);
        let (pk, sig) = make_hypertree_data(seed, fors_pk, leaf_idx, tree_address);

        let layer_leaf_indices = compute_layer_leaf_indices(leaf_idx, tree_address);

        let hints = HashMap::from([
            ("fors_pubkey".to_string(), vec![fors_pk.to_vec()]),
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
            ("fors_pubkey".to_string(), vec![fors_pk.to_vec()]),
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
