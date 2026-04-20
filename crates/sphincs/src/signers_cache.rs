use backend::{IntoParallelRefIterator, PrimeField32};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use sha3::{Digest as Sha3Digest, Sha3_256};
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use crate::{F, MESSAGE_LEN_FE, core::{SphincsPublicKey, SphincsSecretKey, SphincsSig}};

pub const NUM_SPHINCS_SIGNERS: usize = 500;

static SIGNERS_CACHE: OnceLock<Vec<(SphincsPublicKey, SphincsSig)>> = OnceLock::new();

/// Returns the deterministic benchmark message for cache entry `i`.
pub fn message_for_sphincs_signer(i: usize) -> [F; MESSAGE_LEN_FE] {
    let mut rng_seed = [0u8; 32];
    rng_seed[0..8].copy_from_slice(&(i as u64).to_le_bytes());
    let mut rng = StdRng::from_seed(rng_seed);
    rng.random()
}

/// Returns the global cache of 500 pre-generated (public key, signature) pairs.
/// On first call this either loads from disk or generates and saves to disk.
pub fn get_sphincs_benchmark_signatures() -> &'static Vec<(SphincsPublicKey, SphincsSig)> {
    SIGNERS_CACHE.get_or_init(gen_benchmark_signers_cache)
}

#[derive(Serialize, Deserialize)]
struct SignersCacheFile {
    signatures: Vec<(SphincsPublicKey, SphincsSig)>,
}

fn cache_footprint(first_pubkey: &SphincsPublicKey) -> u128 {
    let mut hasher = Sha3_256::new();
    hasher.update(NUM_SPHINCS_SIGNERS.to_le_bytes());
    for f in message_for_sphincs_signer(0) {
        hasher.update(f.as_canonical_u32().to_le_bytes());
    }
    for f in first_pubkey.root() {
        hasher.update(f.as_canonical_u32().to_le_bytes());
    }
    let hash = hasher.finalize();
    u128::from_le_bytes(hash[..16].try_into().unwrap())
}

fn cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SIGNERS_CACHE_DIR") {
        PathBuf::from(dir)
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/signers-cache")
    }
}

fn cache_path(first_pubkey: &SphincsPublicKey) -> PathBuf {
    let footprint = cache_footprint(first_pubkey);
    let file = format!("benchmark_sphincs_cache_{footprint:032x}.bin");
    cache_dir().join(file)
}

fn compute_signer(index: usize) -> (SphincsPublicKey, SphincsSig) {
    let mut seed = [0u8; 20];
    seed[0..8].copy_from_slice(&(index as u64).to_le_bytes());
    let sk = SphincsSecretKey::new(seed);
    let pk = sk.public_key();
    let message = message_for_sphincs_signer(index);
    let sig = sk.sign(&message).expect("SPHINCS+ signing failed");
    (pk, sig)
}

fn try_load_cache(path: &PathBuf) -> Option<Vec<(SphincsPublicKey, SphincsSig)>> {
    let data = fs::read(path).ok()?;
    let decompressed = lz4_flex::decompress_size_prepended(&data).ok()?;
    let cached: SignersCacheFile = postcard::from_bytes(&decompressed).ok()?;
    Some(cached.signatures)
}

fn gen_benchmark_signers_cache() -> Vec<(SphincsPublicKey, SphincsSig)> {
    let first_signer = compute_signer(0);
    let path = cache_path(&first_signer.0);

    if let Some(signers) = try_load_cache(&path) {
        return signers;
    }

    let completed = AtomicUsize::new(1);
    let time = Instant::now();
    let rest: Vec<_> = (1..NUM_SPHINCS_SIGNERS)
        .into_par_iter()
        .map(|index| {
            let signer = compute_signer(index);
            let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
            print!(
                "\rPrecomputing SPHINCS+ benchmark signatures (cached after first run): {:.0}%",
                100.0 * done as f64 / NUM_SPHINCS_SIGNERS as f64
            );
            signer
        })
        .collect();

    println!(
        "\rGenerating SPHINCS+ signatures for benchmark (one-time operation): 100% - done ({:.2}s)",
        time.elapsed().as_secs_f32()
    );

    let mut signers = Vec::with_capacity(NUM_SPHINCS_SIGNERS);
    signers.push(first_signer);
    signers.extend(rest);

    let cache_file = SignersCacheFile { signatures: signers.clone() };
    let encoded = postcard::to_allocvec(&cache_file).expect("postcard serialization failed");
    let compressed = lz4_flex::compress_prepend_size(&encoded);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&path, &compressed).expect("Failed to save SPHINCS+ benchmark cache");

    signers
}

#[test]
#[ignore]
fn test_sphincs_signature_cache() {
    use rayon::iter::IndexedParallelIterator;
    let signatures = get_sphincs_benchmark_signatures();
    assert_eq!(signatures.len(), NUM_SPHINCS_SIGNERS);
    signatures.par_iter().enumerate().for_each(|(i, (pk, sig))| {
        let message = message_for_sphincs_signer(i);
        assert!(pk.verify(&message, sig), "Signature {i} failed to verify");
    });
}
