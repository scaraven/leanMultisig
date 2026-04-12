use backend::PrimeCharacteristicRing;
use lean_compiler::*;
use lean_vm::*;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use sphincs::{
    RANDOMNESS_LEN_FE, SPX_FORS_TREES, SPX_WOTS_LEN, SPX_WOTS_W,
    fold_roots,
    wots::{WotsPublicKey, find_randomness_for_wots_encoding, iterate_hash, wots_encode},
};

#[test]
fn test_fold_roots_sphincs() {
    let path = format!("{}/tests/test_fold_roots.py", env!("CARGO_MANIFEST_DIR"));
    let bytecode = compile_program(&ProgramSource::Filepath(path));

    let mut rng = StdRng::seed_from_u64(0);
    let data: [[F; DIGEST_LEN]; SPX_FORS_TREES] = std::array::from_fn(|_| std::array::from_fn(|_| rng.random()));
    let hash = fold_roots(&data);
    // Flatten [[F; DIGEST_LEN]; SPX_FORS_TREES] into Vec<F>, then append the hash
    let mut public_input: Vec<F> = data.iter().flatten().copied().collect();
    public_input.extend_from_slice(&hash);
    execute_bytecode(&bytecode, &public_input, &ExecutionWitness::empty(), false);
}

#[test]
fn test_chain_hash_sphincs() {
    let path = format!("{}/tests/test_chain_hash.py", env!("CARGO_MANIFEST_DIR"));
    let bytecode = compile_program(&ProgramSource::Filepath(path));

    for n in [0, 1, 2, 3, 4, 5, 8, 10, 12, 15] {
        let mut rng = StdRng::seed_from_u64(0);
        let data: Vec<F> = (0..DIGEST_LEN).map(|_| rng.random()).collect();
        let hash = iterate_hash(data.clone().try_into().unwrap(), n);
        let mut public_input = vec![F::from_usize(n)];
        public_input.extend(&data);
        public_input.extend(hash);
        execute_bytecode(&bytecode, &public_input, &ExecutionWitness::empty(), false);
    }
}

/// Build the flat public input expected by test_sphincs_wots.py:
///   message (8) | layer_index (1) | randomness (7) | chain_tips (32*8) | expected_pubkey (8)
fn build_wots_public_input(
    message: &[F; DIGEST_LEN],
    layer_index: u32,
    randomness: &[F; RANDOMNESS_LEN_FE],
    chain_tips: &[[F; DIGEST_LEN]; SPX_WOTS_LEN],
    expected_pubkey: &[F; DIGEST_LEN],
) -> Vec<F> {
    let mut pi = message.to_vec();
    pi.push(F::from_usize(layer_index as usize));
    pi.extend_from_slice(randomness);
    for tip in chain_tips {
        pi.extend_from_slice(tip);
    }
    pi.extend_from_slice(expected_pubkey);
    pi
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

        let (randomness, encoding, _) =
            find_randomness_for_wots_encoding(&message, layer_index, &mut rng);

        // chain_tips[i] = iterate_hash(preimage[i], encoding[i])  (mid-chain position)
        let chain_tips: [[F; DIGEST_LEN]; SPX_WOTS_LEN] =
            std::array::from_fn(|i| iterate_hash(pre_images[i], encoding[i] as usize));

        // expected pubkey = fold of iterate_hash(chain_tips[i], SPX_WOTS_W - 1 - encoding[i])
        //                 = fold of iterate_hash(preimage[i], SPX_WOTS_W - 1)
        let expected_pubkey = WotsPublicKey(std::array::from_fn(|i| {
            iterate_hash(chain_tips[i], SPX_WOTS_W - 1 - encoding[i] as usize)
        }))
        .hash();

        let pi = build_wots_public_input(&message, layer_index, &randomness, &chain_tips, &expected_pubkey);
        execute_bytecode(&bytecode, &pi, &ExecutionWitness::empty(), false);
    }

    // ---- Case 2: Wrong expected pubkey ----
    // All inputs are valid but the expected pubkey is random garbage.
    // Fails at `assert wots_pubkey == expected_wots_pubkey`.
    {
        let message: [F; DIGEST_LEN] = rng.random();
        let layer_index = 1u32;
        let pre_images: [[F; DIGEST_LEN]; SPX_WOTS_LEN] = std::array::from_fn(|_| rng.random());

        let (randomness, encoding, _) =
            find_randomness_for_wots_encoding(&message, layer_index, &mut rng);

        let chain_tips: [[F; DIGEST_LEN]; SPX_WOTS_LEN] =
            std::array::from_fn(|i| iterate_hash(pre_images[i], encoding[i] as usize));

        // Deliberately wrong: a random value instead of the real public key hash.
        let wrong_pubkey: [F; DIGEST_LEN] = rng.random();

        let pi = build_wots_public_input(&message, layer_index, &randomness, &chain_tips, &wrong_pubkey);
        assert!(
            try_execute_bytecode(&bytecode, &pi, &ExecutionWitness::empty(), false).is_err(),
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
        let chain_tips: [[F; DIGEST_LEN]; SPX_WOTS_LEN] =
            std::array::from_fn(|_| rng.random());
        let fake_pubkey: [F; DIGEST_LEN] = rng.random();

        let pi = build_wots_public_input(&message, layer_index, &invalid_randomness, &chain_tips, &fake_pubkey);
        assert!(
            try_execute_bytecode(&bytecode, &pi, &ExecutionWitness::empty(), false).is_err(),
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

        let (randomness, encoding, _) =
            find_randomness_for_wots_encoding(&message, layer_index, &mut rng);

        // Shift each chain tip one step beyond its correct signing position.
        let chain_tips: [[F; DIGEST_LEN]; SPX_WOTS_LEN] =
            std::array::from_fn(|i| iterate_hash(pre_images[i], encoding[i] as usize + 1));

        // Correct expected pubkey (circuit should have produced this with proper chain tips).
        let correct_pubkey = WotsPublicKey(std::array::from_fn(|i| {
            iterate_hash(pre_images[i], SPX_WOTS_W - 1)
        }))
        .hash();

        let pi = build_wots_public_input(&message, layer_index, &randomness, &chain_tips, &correct_pubkey);
        assert!(
            try_execute_bytecode(&bytecode, &pi, &ExecutionWitness::empty(), false).is_err(),
            "should fail: chain tips shifted one position too far"
        );
    }
}
