use sphincs::signers_cache::{NUM_SPHINCS_SIGNERS, get_sphincs_benchmark_signatures};

fn main() {
    println!("Generating SPHINCS+ benchmark cache ({NUM_SPHINCS_SIGNERS} signatures)...");
    let cache = get_sphincs_benchmark_signatures();
    println!("Done. {} (public key, signature) pairs ready.", cache.len());
}
