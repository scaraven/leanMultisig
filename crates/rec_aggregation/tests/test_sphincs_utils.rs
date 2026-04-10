use backend::PrimeCharacteristicRing;
use lean_compiler::*;
use lean_vm::*;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use sphincs::{SPX_FORS_TREES, fold_roots, wots::iterate_hash};

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
