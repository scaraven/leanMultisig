use backend::PrimeCharacteristicRing;
use lean_compiler::*;
use lean_vm::*;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rec_aggregation::{PREAMBLE_MEMORY_LEN, compilation::build_replacements, sphincs::split_leaf_upper};
use sphincs::{
    HALF_DIGEST_SIZE, HalfDigest, SPX_FORS_HEIGHT, SPX_FORS_TREES, SPX_WOTS_LEN, SPX_WOTS_W,
    address::Adrs,
    fold_roots, fors_key_gen, fors_sig_to_flat, fors_sign, fors_sign_single_tree,
    wots::{WotsPublicKey, find_randomness_for_wots_encoding, iterate_hash_half_from_half, wots_encode},
};
use std::collections::HashMap;

const TEST_STACK_SIZE: usize = 64 * 1024 * 1024;

fn run_on_large_stack<F: Send + 'static>(f: impl FnOnce() -> F + Send + 'static) -> F {
    std::thread::Builder::new()
        .stack_size(TEST_STACK_SIZE)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

fn make_bytecode(test_file: &str) -> lean_vm::Bytecode {
    let path = format!("{}/tests/{}", env!("CARGO_MANIFEST_DIR"), test_file);
    let replacements = build_replacements(18, F::ONE);
    compile_program_with_flags(&ProgramSource::Filepath(path), CompilationFlags { replacements })
}

#[test]
fn test_fold_roots_sphincs() {
    run_on_large_stack(|| {
        let bytecode = make_bytecode("test_fold_roots.py");

        let mut rng = StdRng::seed_from_u64(0);
        // fold_roots takes a pk_seed tweak and a slice of HalfDigests (4 FEs each)
        let pk_seed: HalfDigest = rng.random();
        let data: [HalfDigest; SPX_FORS_TREES] = std::array::from_fn(|_| rng.random());
        let hash = fold_roots(pk_seed, &data);
        let roots_flat: Vec<F> = data.iter().flatten().copied().collect();
        let hints = HashMap::from([
            ("pk_seed".to_string(), vec![pk_seed.to_vec()]),
            ("roots".to_string(), vec![roots_flat]),
            ("expected".to_string(), vec![hash.to_vec()]),
        ]);
        let witness = ExecutionWitness {
            preamble_memory_len: PREAMBLE_MEMORY_LEN,
            hints,
        };
        execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness, false);
    });
}

/// Build hints for test_sphincs_wots.py.
/// randomness hint = [r0..r5, adrs0, adrs1] (8 FEs total).
fn build_wots_hints(
    pk_seed: &HalfDigest,
    message: &[F; DIGEST_LEN],
    adrs: Adrs,
    pk_adrs: Adrs,
    randomness: &[F; sphincs::RANDOMNESS_LEN_FE],
    chain_tips: &[HalfDigest; SPX_WOTS_LEN],
    expected_pubkey: &HalfDigest,
) -> HashMap<String, Vec<Vec<F>>> {
    let mut randomness_with_adrs = randomness.to_vec();
    randomness_with_adrs.push(adrs.adrs0);
    randomness_with_adrs.push(adrs.adrs1);
    HashMap::from([
        ("pk_seed".to_string(), vec![pk_seed.to_vec()]),
        ("message".to_string(), vec![message.to_vec()]),
        ("adrs0".to_string(), vec![vec![adrs.adrs0]]),
        ("adrs1".to_string(), vec![vec![adrs.adrs1]]),
        ("wots_pk_adrs0".to_string(), vec![vec![pk_adrs.adrs0]]),
        ("wots_pk_adrs1".to_string(), vec![vec![pk_adrs.adrs1]]),
        ("randomness".to_string(), vec![randomness_with_adrs]),
        (
            "chain_tips".to_string(),
            vec![chain_tips.iter().flatten().copied().collect()],
        ),
        ("expected".to_string(), vec![expected_pubkey.to_vec()]),
    ])
}

#[test]
fn test_sphincs_wots_encode_complete() {
    run_on_large_stack(|| {
        let bytecode = make_bytecode("test_sphincs_wots.py");

        let mut rng = StdRng::seed_from_u64(0);
        // Fixed pk_seed used for WotsPublicKey::hash; zero tree/kp addresses for unit tests.
        let pk_seed: HalfDigest = [F::ZERO; HALF_DIGEST_SIZE];

        // ---- Case 1: Happy path ----
        // Valid message/randomness → correct chain tips → correct expected pubkey.
        {
            let message: [F; DIGEST_LEN] = rng.random();
            let layer_index = 0u32;
            let pre_images: [HalfDigest; SPX_WOTS_LEN] = std::array::from_fn(|_| rng.random());

            // adrs0/adrs1 encode (layer=0, tree=0, kp=0) — matches the unit test's zero-address convention
            let adrs = Adrs::wots_hash(layer_index, 0, 0, 0, 0);
            let (randomness, encoding, _) =
                find_randomness_for_wots_encoding(&message, adrs.adrs0, adrs.adrs1, &mut rng);

            // chain_tips[i] = iterate_hash_half_from_half(preimage[i], encoding[i])
            let chain_tips: [HalfDigest; SPX_WOTS_LEN] = std::array::from_fn(|i| {
                iterate_hash_half_from_half(pre_images[i], encoding[i] as usize, pk_seed, adrs.with_chain(i as u32))
            });

            let pk_adrs = Adrs::wots_pk(layer_index, 0, 0);
            let expected_pubkey = WotsPublicKey(std::array::from_fn(|i| {
                iterate_hash_half_from_half(
                    chain_tips[i],
                    SPX_WOTS_W - 1 - encoding[i] as usize,
                    pk_seed,
                    adrs.with_chain(i as u32).with_hash_step(encoding[i] as u32),
                )
            }))
            .hash(pk_seed, pk_adrs);

            let hints = build_wots_hints(
                &pk_seed,
                &message,
                adrs,
                pk_adrs,
                &randomness,
                &chain_tips,
                &expected_pubkey,
            );
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
            let pre_images: [HalfDigest; SPX_WOTS_LEN] = std::array::from_fn(|_| rng.random());

            let adrs = Adrs::wots_hash(layer_index, 0, 0, 0, 0);
            let (randomness, encoding, _) =
                find_randomness_for_wots_encoding(&message, adrs.adrs0, adrs.adrs1, &mut rng);

            let chain_tips: [HalfDigest; SPX_WOTS_LEN] = std::array::from_fn(|i| {
                iterate_hash_half_from_half(pre_images[i], encoding[i] as usize, pk_seed, adrs.with_chain(i as u32))
            });

            let wrong_pubkey: HalfDigest = rng.random();

            let pk_adrs = Adrs::wots_pk(layer_index, 0, 0);
            let hints = build_wots_hints(
                &pk_seed,
                &message,
                adrs,
                pk_adrs,
                &randomness,
                &chain_tips,
                &wrong_pubkey,
            );
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
        // Random (message, randomness) where wots_encode returns None.
        {
            let message: [F; DIGEST_LEN] = rng.random();
            let layer_index = 0u32;
            let adrs = Adrs::wots_hash(layer_index, 0, 0, 0, 0);

            let invalid_randomness: [F; sphincs::RANDOMNESS_LEN_FE] = loop {
                let rand: [F; sphincs::RANDOMNESS_LEN_FE] = rng.random();
                if wots_encode(&message, adrs.adrs0, adrs.adrs1, &rand).is_none() {
                    break rand;
                }
            };

            let chain_tips: [HalfDigest; SPX_WOTS_LEN] = std::array::from_fn(|_| rng.random());
            let fake_pubkey: HalfDigest = rng.random();

            let pk_adrs = Adrs::wots_pk(layer_index, 0, 0);
            let hints = build_wots_hints(
                &pk_seed,
                &message,
                adrs,
                pk_adrs,
                &invalid_randomness,
                &chain_tips,
                &fake_pubkey,
            );
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
        // chain_tips[i] = iterate_hash_half_from_half(preimage[i], encoding[i] + 1), one step past.
        // The circuit completes the remaining (W-1-encoding[i]) steps and arrives at
        // iterate_hash(preimage[i], W), not the true public key iterate_hash(preimage[i], W-1).
        {
            let message: [F; DIGEST_LEN] = rng.random();
            let layer_index = 2u32;
            let pre_images: [HalfDigest; SPX_WOTS_LEN] = std::array::from_fn(|_| rng.random());

            let adrs = Adrs::wots_hash(layer_index, 0, 0, 0, 0);
            let (randomness, encoding, _) =
                find_randomness_for_wots_encoding(&message, adrs.adrs0, adrs.adrs1, &mut rng);

            // Shift each chain tip one step beyond its correct signing position.
            let chain_tips: [HalfDigest; SPX_WOTS_LEN] = std::array::from_fn(|i| {
                iterate_hash_half_from_half(
                    pre_images[i],
                    encoding[i] as usize + 1,
                    pk_seed,
                    adrs.with_chain(i as u32),
                )
            });

            let pk_adrs = Adrs::wots_pk(layer_index, 0, 0);
            let correct_pubkey = WotsPublicKey(std::array::from_fn(|i| {
                iterate_hash_half_from_half(
                    pre_images[i],
                    SPX_WOTS_W - 1,
                    pk_seed,
                    adrs.with_chain(i as u32).with_hash_step(0),
                )
            }))
            .hash(pk_seed, pk_adrs);

            let hints = build_wots_hints(
                &pk_seed,
                &message,
                adrs,
                pk_adrs,
                &randomness,
                &chain_tips,
                &correct_pubkey,
            );
            let witness = ExecutionWitness {
                preamble_memory_len: PREAMBLE_MEMORY_LEN,
                hints,
            };
            assert!(
                try_execute_bytecode(&bytecode, &vec![F::from_usize(0); DIGEST_LEN], &witness, false).is_err(),
                "should fail: chain tips shifted one position too far"
            );
        }
    });
}

#[test]
fn test_sphincs_fors_merkle_verify() {
    run_on_large_stack(|| {
        let bytecode = make_bytecode("test_fors_tree.py");

        let mut rng = StdRng::seed_from_u64(0);
        let sk_seed: HalfDigest = rng.random();
        let pk_seed: HalfDigest = rng.random();

        let (fors_sk, _) = fors_key_gen(sk_seed, pk_seed);
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
    });
}

#[test]
fn test_sphincs_fors_verify() {
    run_on_large_stack(|| {
        let bytecode = make_bytecode("test_fors.py");

        let mut rng = StdRng::seed_from_u64(0);
        let sk_seed: HalfDigest = rng.random();
        let pk_seed: HalfDigest = rng.random();

        let (fors_sk, fors_pk) = fors_key_gen(sk_seed, pk_seed);
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

        // Wrong root: random HalfDigest (4 FEs)
        let root_wrong: HalfDigest = rng.random();
        let hints_wrong = HashMap::from([
            (
                "leaf_index".to_string(),
                vec![leaf_indices.iter().map(|&idx| F::from_usize(idx)).collect()],
            ),
            ("expected_root".to_string(), vec![root_wrong.to_vec()]),
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
    });
}

#[test]
fn test_decompose_message_digest() {
    run_on_large_stack(|| {
        let bytecode = make_bytecode("test_message_decompose.py");

        let mut rng = StdRng::seed_from_u64(42);

        for _ in 0..10 {
            let message_digest: [F; DIGEST_LEN] = rng.random();

            let (leaf_indices, fors_indices, leaf_uppers, fors_uppers) =
                sphincs::core::extract_digest_parts(&message_digest);

            let digest_indices: Vec<F> = leaf_indices
                .iter()
                .chain(fors_indices.iter())
                .map(|&i| F::from_usize(i))
                .collect();
            let (digest_uppers_low, digest_uppers_high): (Vec<F>, Vec<F>) =
                leaf_uppers.iter().map(|&u| split_leaf_upper(u)).unzip();
            let digest_fors_uppers: Vec<F> = fors_uppers.iter().map(|&u| F::from_usize(u)).collect();

            let layer_leaf_indices = [leaf_indices[0], leaf_indices[1], leaf_indices[2]];

            let hints = HashMap::from([
                ("message_digest".to_string(), vec![message_digest.to_vec()]),
                ("digest_indices".to_string(), vec![digest_indices]),
                ("digest_uppers_low".to_string(), vec![digest_uppers_low]),
                ("digest_uppers_high".to_string(), vec![digest_uppers_high]),
                ("digest_uppers_fors".to_string(), vec![digest_fors_uppers]),
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
    });
}
