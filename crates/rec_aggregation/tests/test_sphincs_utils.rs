use backend::PrimeCharacteristicRing;
use lean_compiler::*;
use lean_vm::*;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rec_aggregation::PREAMBLE_MEMORY_LEN;
use sphincs::{
    RANDOMNESS_LEN_FE, SPX_FORS_HEIGHT, SPX_FORS_TREES, SPX_TREE_HEIGHT, SPX_WOTS_LEN, SPX_WOTS_W,
    extract_fors_indices, fold_roots, fors_key_gen, fors_sig_to_flat, fors_sign, fors_sign_single_tree,
    wots::{WotsPublicKey, find_randomness_for_wots_encoding, iterate_hash, wots_encode},
};
use std::collections::HashMap;

#[test]
fn test_fold_roots_sphincs() {
    let path = format!("{}/tests/test_fold_roots.py", env!("CARGO_MANIFEST_DIR"));
    let bytecode = compile_program(&ProgramSource::Filepath(path));

    let mut rng = StdRng::seed_from_u64(0);
    let data: [[F; DIGEST_LEN]; SPX_FORS_TREES] = std::array::from_fn(|_| std::array::from_fn(|_| rng.random()));
    let hash = fold_roots(&data);
    let roots_flat: Vec<F> = data.iter().flatten().copied().collect();
    let hints = HashMap::from([
        ("roots".to_string(), vec![roots_flat]),
        ("expected".to_string(), vec![hash.to_vec()]),
    ]);
    let witness = ExecutionWitness {
        preamble_memory_len: PREAMBLE_MEMORY_LEN,
        hints,
    };
    execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness, false);
}

#[test]
fn test_chain_hash_sphincs() {
    let path = format!("{}/tests/test_chain_hash.py", env!("CARGO_MANIFEST_DIR"));
    let bytecode = compile_program(&ProgramSource::Filepath(path));

    for n in [0, 1, 2, 3, 4, 5, 8, 10, 12, 15] {
        let mut rng = StdRng::seed_from_u64(0);
        let data: Vec<F> = (0..DIGEST_LEN).map(|_| rng.random()).collect();
        let hash = iterate_hash(data.clone().try_into().unwrap(), n);
        let hints = HashMap::from([
            ("n".to_string(), vec![vec![F::from_usize(n)]]),
            ("input".to_string(), vec![data]),
            ("expected".to_string(), vec![hash.to_vec()]),
        ]);
        let witness = ExecutionWitness {
            preamble_memory_len: PREAMBLE_MEMORY_LEN,
            hints,
        };
        execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness, false);
    }
}

/// Build hints for test_sphincs_wots.py:
///   "message" (8) | "layer_index" (1) | "randomness" (7) | "chain_tips" (32*8) | "expected" (8)
fn build_wots_hints(
    message: &[F; DIGEST_LEN],
    layer_index: u32,
    randomness: &[F; RANDOMNESS_LEN_FE],
    chain_tips: &[[F; DIGEST_LEN]; SPX_WOTS_LEN],
    expected_pubkey: &[F; DIGEST_LEN],
) -> HashMap<String, Vec<Vec<F>>> {
    HashMap::from([
        ("message".to_string(), vec![message.to_vec()]),
        (
            "layer_index".to_string(),
            vec![vec![F::from_usize(layer_index as usize)]],
        ),
        ("randomness".to_string(), vec![randomness.to_vec()]),
        (
            "chain_tips".to_string(),
            vec![chain_tips.iter().flatten().copied().collect()],
        ),
        ("expected".to_string(), vec![expected_pubkey.to_vec()]),
    ])
}

#[test]
fn test_sphincs_wots_encode_complete() {
    let path = format!("{}/tests/test_sphincs_wots.py", env!("CARGO_MANIFEST_DIR"));
    let bytecode = compile_program(&ProgramSource::Filepath(path));

    let mut rng = StdRng::seed_from_u64(0);

    // ---- Case 1: Happy path ----
    // Valid message/randomness → correct chain tips → correct expected pubkey.
    {
        let message: [F; DIGEST_LEN] = rng.random();
        let layer_index = 0u32;
        let pre_images: [[F; DIGEST_LEN]; SPX_WOTS_LEN] = std::array::from_fn(|_| rng.random());

        let (randomness, encoding, _) = find_randomness_for_wots_encoding(&message, layer_index, &mut rng);

        // chain_tips[i] = iterate_hash(preimage[i], encoding[i])  (mid-chain position)
        let chain_tips: [[F; DIGEST_LEN]; SPX_WOTS_LEN] =
            std::array::from_fn(|i| iterate_hash(pre_images[i], encoding[i] as usize));

        // expected pubkey = fold of iterate_hash(chain_tips[i], SPX_WOTS_W - 1 - encoding[i])
        //                 = fold of iterate_hash(preimage[i], SPX_WOTS_W - 1)
        let expected_pubkey = WotsPublicKey(std::array::from_fn(|i| {
            iterate_hash(chain_tips[i], SPX_WOTS_W - 1 - encoding[i] as usize)
        }))
        .hash();

        let hints = build_wots_hints(&message, layer_index, &randomness, &chain_tips, &expected_pubkey);
        let witness = ExecutionWitness {
            preamble_memory_len: PREAMBLE_MEMORY_LEN,
            hints,
        };
        execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness, false);
    }

    // ---- Case 2: Wrong expected pubkey ----
    // All inputs are valid but the expected pubkey is random garbage.
    // Fails at `assert wots_pubkey == expected_wots_pubkey`.
    {
        let message: [F; DIGEST_LEN] = rng.random();
        let layer_index = 1u32;
        let pre_images: [[F; DIGEST_LEN]; SPX_WOTS_LEN] = std::array::from_fn(|_| rng.random());

        let (randomness, encoding, _) = find_randomness_for_wots_encoding(&message, layer_index, &mut rng);

        let chain_tips: [[F; DIGEST_LEN]; SPX_WOTS_LEN] =
            std::array::from_fn(|i| iterate_hash(pre_images[i], encoding[i] as usize));

        // Deliberately wrong: a random value instead of the real public key hash.
        let wrong_pubkey: [F; DIGEST_LEN] = rng.random();

        let hints = build_wots_hints(&message, layer_index, &randomness, &chain_tips, &wrong_pubkey);
        let witness = ExecutionWitness {
            preamble_memory_len: PREAMBLE_MEMORY_LEN,
            hints,
        };
        assert!(
            try_execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness, false).is_err(),
            "should fail: wrong expected pubkey"
        );
    }

    // ---- Case 3: Encoding sum != TARGET_SUM ----
    // Random (message, randomness) where wots_encode returns None means the Poseidon output
    // either contains -F::ONE (remaining check fails) or has sum != 240 (target sum check fails).
    // In both cases the circuit rejects the inputs.
    {
        let message: [F; DIGEST_LEN] = rng.random();
        let layer_index = 0u32;

        // Find randomness that produces an invalid encoding (most random choices do).
        let invalid_randomness: [F; RANDOMNESS_LEN_FE] = loop {
            let rand: [F; RANDOMNESS_LEN_FE] = rng.random();
            if wots_encode(&message, layer_index, &rand).is_none() {
                break rand;
            }
        };

        // chain_tips and expected_pubkey are irrelevant — circuit fails before reaching them.
        let chain_tips: [[F; DIGEST_LEN]; SPX_WOTS_LEN] = std::array::from_fn(|_| rng.random());
        let fake_pubkey: [F; DIGEST_LEN] = rng.random();

        let hints = build_wots_hints(&message, layer_index, &invalid_randomness, &chain_tips, &fake_pubkey);
        let witness = ExecutionWitness {
            preamble_memory_len: PREAMBLE_MEMORY_LEN,
            hints,
        };
        assert!(
            try_execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness, false).is_err(),
            "should fail: invalid encoding (sum != TARGET_SUM or -1 FE)"
        );
    }

    // ---- Case 4: Chain tips at the wrong position ----
    // chain_tips[i] = iterate_hash(preimage[i], encoding[i] + 1), i.e. one step past where the
    // signature should sit.  The circuit completes the remaining (SPX_WOTS_W - 1 - encoding[i])
    // steps and arrives at iterate_hash(preimage[i], SPX_WOTS_W), not the true public key
    // iterate_hash(preimage[i], SPX_WOTS_W - 1).
    // Fails at `assert wots_pubkey == expected_wots_pubkey`.
    {
        let message: [F; DIGEST_LEN] = rng.random();
        let layer_index = 2u32;
        let pre_images: [[F; DIGEST_LEN]; SPX_WOTS_LEN] = std::array::from_fn(|_| rng.random());

        let (randomness, encoding, _) = find_randomness_for_wots_encoding(&message, layer_index, &mut rng);

        // Shift each chain tip one step beyond its correct signing position.
        let chain_tips: [[F; DIGEST_LEN]; SPX_WOTS_LEN] =
            std::array::from_fn(|i| iterate_hash(pre_images[i], encoding[i] as usize + 1));

        // Correct expected pubkey (circuit should have produced this with proper chain tips).
        let correct_pubkey = WotsPublicKey(std::array::from_fn(|i| iterate_hash(pre_images[i], SPX_WOTS_W - 1))).hash();

        let hints = build_wots_hints(&message, layer_index, &randomness, &chain_tips, &correct_pubkey);
        let witness = ExecutionWitness {
            preamble_memory_len: PREAMBLE_MEMORY_LEN,
            hints,
        };
        assert!(
            try_execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness, false).is_err(),
            "should fail: chain tips shifted one position too far"
        );
    }
}

#[test]
fn test_sphincs_fors_merkle_verify() {
    let path = format!("{}/tests/test_fors_tree.py", env!("CARGO_MANIFEST_DIR"));
    // Just compile the program for now
    let bytecode = compile_program(&ProgramSource::Filepath(path));

    let mut rng = StdRng::seed_from_u64(0);
    let seed: [u8; 20] = rng.random();

    let (fors_sk, _) = fors_key_gen(seed);
    let leaf_index: usize = rng.random_range(..(1 << SPX_FORS_HEIGHT));
    let tree: usize = rng.random_range(..SPX_FORS_TREES);
    let root = fors_sk.tree_pubkey(tree);

    let sig = fors_sign_single_tree(&fors_sk, tree, leaf_index);

    let hints = HashMap::from([
        ("leaf_index".to_string(), vec![vec![F::from_usize(leaf_index)]]),
        ("leaf_node".to_string(), vec![sig.leaf_secret.to_vec()]),
        (
            "auth_path".to_string(),
            vec![sig.auth_path.iter().flatten().copied().collect()],
        ),
        ("expected_root".to_string(), vec![root.to_vec()]),
    ]);
    let witness = ExecutionWitness {
        preamble_memory_len: PREAMBLE_MEMORY_LEN,
        hints,
    };
    execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness, false);
}

#[test]
fn test_sphincs_fors_verify() {
    let path = format!("{}/tests/test_fors.py", env!("CARGO_MANIFEST_DIR"));
    // Just compile the program for now
    let bytecode = compile_program(&ProgramSource::Filepath(path));

    let mut rng = StdRng::seed_from_u64(0);
    let seed: [u8; 20] = rng.random();

    let (fors_sk, fors_pk) = fors_key_gen(seed);
    let leaf_indices: [usize; SPX_FORS_TREES] = std::array::from_fn(|_| rng.random_range(..(1 << SPX_FORS_HEIGHT)));
    let root = fors_pk.0;

    let sig = fors_sign(&fors_sk, &leaf_indices);
    let sig_flat = fors_sig_to_flat(&sig);

    let hints = HashMap::from([
        (
            "leaf_index".to_string(),
            vec![leaf_indices.iter().map(|&idx| F::from_usize(idx)).collect()],
        ),
        ("expected_root".to_string(), vec![root.to_vec()]),
        ("fors_sig".to_string(), vec![sig_flat.to_vec()]),
    ]);

    let witness = ExecutionWitness {
        preamble_memory_len: PREAMBLE_MEMORY_LEN,
        hints,
    };

    execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness, false);

    // Create new wrong root
    let root: [F; DIGEST_LEN] = rng.random();
    let hints_wrong = HashMap::from([
        (
            "leaf_index".to_string(),
            vec![leaf_indices.iter().map(|&idx| F::from_usize(idx)).collect()],
        ),
        ("expected_root".to_string(), vec![root.to_vec()]),
        ("fors_sig".to_string(), vec![sig_flat.to_vec()]),
    ]);

    let witness_wrong = ExecutionWitness {
        preamble_memory_len: PREAMBLE_MEMORY_LEN,
        hints: hints_wrong,
    };

    assert!(
        try_execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness_wrong, false).is_err(),
        "should fail: wrong expected root"
    );
}

#[test]
fn test_decompose_message_digest() {
    let path = format!("{}/tests/test_message_decompose.py", env!("CARGO_MANIFEST_DIR"));
    let bytecode = compile_program(&ProgramSource::Filepath(path));

    let mut rng = StdRng::seed_from_u64(42);
    let tree_mask = (1usize << SPX_TREE_HEIGHT) - 1;

    for _ in 0..10 {
        let message_digest: [F; DIGEST_LEN] = rng.random();

        let (leaf_idx, tree_address, mhash, fe5_upper) = sphincs::core::extract_digest_parts(&message_digest);
        let fors_indices = extract_fors_indices(&mhash);

        let mut digest_decomposition = Vec::with_capacity(2 + SPX_FORS_TREES + 1);
        digest_decomposition.push(F::from_usize(leaf_idx));
        digest_decomposition.push(F::from_usize(tree_address));
        digest_decomposition.extend(fors_indices.iter().map(|&i| F::from_usize(i)));
        digest_decomposition.push(F::from_usize(fe5_upper));

        let layer_leaf_indices = [
            leaf_idx,
            tree_address & tree_mask,
            (tree_address >> SPX_TREE_HEIGHT) & tree_mask,
        ];

        let hints = HashMap::from([
            ("message_digest".to_string(), vec![message_digest.to_vec()]),
            ("digest_decomposition".to_string(), vec![digest_decomposition]),
            (
                "expected_fors_indices".to_string(),
                vec![fors_indices.iter().map(|&i| F::from_usize(i)).collect()],
            ),
            (
                "expected_layer_leaf_indices".to_string(),
                vec![layer_leaf_indices.iter().map(|&i| F::from_usize(i)).collect::<Vec<_>>()],
            ),
        ]);

        let witness = ExecutionWitness {
            preamble_memory_len: PREAMBLE_MEMORY_LEN,
            hints,
        };

        execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness, false);
    }
}
