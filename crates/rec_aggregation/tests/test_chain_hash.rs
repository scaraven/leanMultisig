use backend::PrimeCharacteristicRing;
use lean_compiler::*;
use lean_vm::*;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use sphincs::wots::iterate_hash;

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
