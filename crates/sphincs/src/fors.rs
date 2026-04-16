use backend::{IntoParallelIterator, ParallelIterator, ParallelSlice};
use serde::{Deserialize, Serialize};
use utils::poseidon16_compress_pair;

use crate::*;

// FORS (Few-Times Signature Scheme)
//
// Signs a message by:
//   1. Splitting mhash into k=9 indices, each selecting a leaf in one of 9
//      binary trees of height 15 (32768 leaves each).
//   2. Revealing the selected leaf's secret value and its 15-node auth path.
//   3. Verifier recomputes each tree root from (leaf, auth path) and folds
//      the k roots into a single FORS public key via sequential hash.
//
// Secret values are derived from the master seed:
//   rng_seed = seed ‖ 0x02 ‖ fors_tree_index as u8 ‖ leaf_index.to_le_bytes()

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForsSecretKey {
    seed: [u8; 20],
    /// Materialised tree nodes: [tree][level][node]
    /// level 0 = leaf hashes, level SPX_FORS_HEIGHT = root
    nodes: Vec<Vec<Vec<Digest>>>,
    // Cached material
    root: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForsPublicKey(pub Digest);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForsSignature {
    /// For each of the k=9 trees: the revealed leaf secret and auth path.
    pub trees: [ForsTreeSig; SPX_FORS_TREES],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForsTreeSig {
    pub leaf_secret: Digest,
    /// Sibling digests from leaf level up to (but not including) the root.
    /// Length = SPX_FORS_HEIGHT = 15.
    pub auth_path: Vec<Digest>,
}

/// Derive the secret value for a single FORS leaf via a Poseidon hash.
///
/// Input digest layout (8 field elements = one Digest):
///   [0..5] : seed packed as 5 little-endian u32s (20 bytes)
///   [5]    : domain separator 0x02
///   [6]    : tree_index as u32
///   [7]    : leaf_index as u32
///
/// The input is hashed against an all-zero digest so the full 16-element
/// Poseidon state is used, matching the rest of the tree construction.
fn derive_leaf_secret(seed: &[u8; 20], tree_index: usize, leaf_index: usize) -> Digest {
    let mut input = Digest::default();
    for (i, chunk) in seed.chunks_exact(4).enumerate() {
        input[i] = F::new(u32::from_le_bytes(chunk.try_into().unwrap()));
    }
    input[5] = F::new(0x02);
    input[6] = F::new(tree_index as u32);
    input[7] = F::new(leaf_index as u32);
    poseidon16_compress_pair(&input, &Digest::default())
}

/// Hash a leaf secret to produce the level-0 tree node.
fn hash_leaf(secret: &Digest) -> Digest {
    poseidon16_compress_pair(secret, &Default::default())
}

/// Generate the full FORS keypair, materialising all leaf secrets and tree nodes.
pub fn fors_key_gen(seed: [u8; 20]) -> (ForsSecretKey, ForsPublicKey) {
    let num_leaves = 1usize << SPX_FORS_HEIGHT;

    let all_nodes: Vec<_> = (0..SPX_FORS_TREES).into_par_iter().map(|t| {
        // Level 0: hash of each secret value.
        let leaf_hashes: Vec<Digest> = (0..num_leaves).into_par_iter()
            .map(|l| derive_leaf_secret(&seed, t, l))
            .collect();

        // Build inner levels bottom-up.
        let mut levels = vec![leaf_hashes];
        for _ in 0..SPX_FORS_HEIGHT {
            let prev = levels.last().unwrap();
            let next: Vec<Digest> = prev
                .par_chunks_exact(2)
                .map(|pair| poseidon16_compress_pair(&pair[0], &pair[1]))
                .collect();
            levels.push(next);
        }
        levels
    }).collect();

    let pk = fors_public_key_from_nodes(&all_nodes);
    let sk = ForsSecretKey {
        seed,
        nodes: all_nodes,
        root: pk.0,
    };
    (sk, pk)
}

fn fors_public_key_from_nodes(nodes: &[Vec<Vec<Digest>>]) -> ForsPublicKey {
    let roots: Vec<Digest> = nodes.iter().map(|levels| levels[SPX_FORS_HEIGHT][0]).collect();
    ForsPublicKey(fold_roots(&roots))
}

/// Sequential left-fold of k roots into a single digest.
/// fold([r0, r1, r2, ...]) = hash(hash(r0, r1), r2) ...
pub fn fold_roots(roots: &[Digest]) -> Digest {
    assert!(roots.len() >= 2, "fold_roots requires at least 2 roots");
    let init = poseidon16_compress_pair(&roots[0], &roots[1]);
    roots[2..].iter().fold(init, |acc, r| poseidon16_compress_pair(&acc, r))
}

/// Sign a single tree in the FORS forest, revealing the leaf secret and auth path for the selected leaf.
pub fn fors_sign_single_tree(sk: &ForsSecretKey, tree_index: usize, leaf_index: usize) -> ForsTreeSig {
    assert!(tree_index < SPX_FORS_TREES, "Tree index out of bounds");
    assert!(leaf_index < (1 << SPX_FORS_HEIGHT), "Leaf index out of bounds");

    let leaf_secret = sk.nodes[tree_index][0][leaf_index];

    let auth_path = (0..SPX_FORS_HEIGHT)
        .map(|level| {
            let sibling_idx = (leaf_index >> level) ^ 1;
            sk.nodes[tree_index][level][sibling_idx]
        })
        .collect();

    ForsTreeSig { leaf_secret, auth_path }
}

pub fn fors_sign(sk: &ForsSecretKey, indices: &[usize; SPX_FORS_TREES]) -> ForsSignature {
    let trees = std::array::from_fn(|t| fors_sign_single_tree(sk, t, indices[t]));

    ForsSignature { trees }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ForsVerifyError {
    WrongAuthPathLength,
    OutofBoundsLeafIndex,
}

/// Verify a FORS signature and recover the FORS public key.
pub fn fors_verify(sig: &ForsSignature, indices: &[usize; SPX_FORS_TREES]) -> Result<ForsPublicKey, ForsVerifyError> {
    let mut roots = [Digest::default(); SPX_FORS_TREES];
    for (t, (tree_sig, &leaf_idx)) in sig.trees.iter().zip(indices.iter()).enumerate() {
        if tree_sig.auth_path.len() != SPX_FORS_HEIGHT {
            return Err(ForsVerifyError::WrongAuthPathLength);
        }

        if leaf_idx >= (1 << SPX_FORS_HEIGHT) {
            return Err(ForsVerifyError::OutofBoundsLeafIndex);
        }

        // Create a mutable copy
        let mut current = tree_sig.leaf_secret;

        // Walk up the tree using the auth path.
        for (level, sibling) in tree_sig.auth_path.iter().enumerate() {
            let is_left = ((leaf_idx >> level) & 1) == 0;
            current = if is_left {
                poseidon16_compress_pair(&current, sibling)
            } else {
                poseidon16_compress_pair(sibling, &current)
            };
        }

        roots[t] = current;
    }

    Ok(ForsPublicKey(fold_roots(&roots)))
}

impl ForsSecretKey {
    pub fn public_key(&self) -> ForsPublicKey {
        ForsPublicKey(self.root)
    }

    pub fn tree_pubkey(&self, tree_index: usize) -> Digest {
        self.nodes[tree_index][SPX_FORS_HEIGHT][0]
    }
}

/// Size of a flat FORS signature in field elements.
/// Layout: for each of SPX_FORS_TREES trees: [leaf_secret (DIGEST_SIZE FEs) | auth_path (SPX_FORS_HEIGHT * DIGEST_SIZE FEs)]
pub const FORS_SIG_SIZE_FE: usize = SPX_FORS_TREES * (1 + SPX_FORS_HEIGHT) * DIGEST_SIZE;

/// Flatten a `ForsSignature` into a `Vec<F>` matching the zkDSL hint layout.
///
/// Layout (per tree t):
///   offset t*(1+SPX_FORS_HEIGHT)*DIGEST_SIZE       : leaf_secret  (DIGEST_SIZE FEs)
///   offset t*(1+SPX_FORS_HEIGHT)*DIGEST_SIZE + DIGEST_SIZE : auth_path[0..SPX_FORS_HEIGHT] (each DIGEST_SIZE FEs)
pub fn fors_sig_to_flat(sig: &ForsSignature) -> Vec<F> {
    let mut out = Vec::with_capacity(FORS_SIG_SIZE_FE);
    for tree in &sig.trees {
        out.extend_from_slice(&tree.leaf_secret);
        for node in &tree.auth_path {
            out.extend_from_slice(node);
        }
    }
    debug_assert_eq!(out.len(), FORS_SIG_SIZE_FE);
    out
}

/// Reconstruct a `ForsSignature` from a flat `Vec<F>` produced by `fors_sig_to_flat`.
///
/// Returns `None` if `flat` does not have exactly `FORS_SIG_SIZE_FE` elements.
pub fn fors_sig_from_flat(flat: &[F]) -> Option<ForsSignature> {
    if flat.len() != FORS_SIG_SIZE_FE {
        return None;
    }
    let stride = (1 + SPX_FORS_HEIGHT) * DIGEST_SIZE;
    let trees = std::array::from_fn(|t| {
        let base = t * stride;
        let leaf_secret: Digest = flat[base..base + DIGEST_SIZE].try_into().unwrap();
        let auth_path = (0..SPX_FORS_HEIGHT)
            .map(|i| {
                let off = base + DIGEST_SIZE + i * DIGEST_SIZE;
                flat[off..off + DIGEST_SIZE].try_into().unwrap()
            })
            .collect();
        ForsTreeSig { leaf_secret, auth_path }
    });
    Some(ForsSignature { trees })
}

/// Extract the k=9 FORS leaf indices from the mhash bytes.
/// mhash is 17 bytes = 136 bits; split into 9 consecutive 15-bit chunks.
pub fn extract_fors_indices(mhash: &[u8; SPX_FORS_MSG_BYTES]) -> [usize; SPX_FORS_TREES] {
    let mask = (1usize << SPX_FORS_HEIGHT) - 1;

    std::array::from_fn(|t| {
        let bit_offset = t * SPX_FORS_HEIGHT;
        let byte_offset = bit_offset / 8;
        let bit_in_byte = bit_offset % 8;

        // 15 bits can span at most 3 bytes.
        let mut window: u32 = 0;
        for i in 0..3 {
            if let Some(&b) = mhash.get(byte_offset + i) {
                window |= (b as u32) << (8 * i);
            }
        }

        ((window >> bit_in_byte) as usize) & mask
    })
}

#[cfg(test)]
mod tests {
    use backend::PrimeCharacteristicRing;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    use super::*;

    #[test]
    fn test_extract_fors_indices_basic_properties() {
        // mhash is 17 bytes = 136 bits; this should deterministically map to 9 15-bit indices.
        let mhash = [0xA5u8; SPX_FORS_MSG_BYTES];
        let indices = extract_fors_indices(&mhash);

        // All indices must be < 2^SPX_FORS_HEIGHT.
        for &idx in indices.iter() {
            assert!(idx < (1 << SPX_FORS_HEIGHT));
        }

        // Determinism: repeated calls match.
        assert_eq!(indices, extract_fors_indices(&mhash));
    }

    #[test]
    fn test_fors_sign_verify_roundtrip_ignored() {
        // NOTE: This roundtrip is correct but extremely expensive in this implementation.
        // Run explicitly with: cargo test -p sphincs -- --ignored
        let seed = [7u8; 20];
        let (sk, pk) = fors_key_gen(seed);

        let mhash = [0x11u8; SPX_FORS_MSG_BYTES];
        let indices = extract_fors_indices(&mhash);
        let sig = fors_sign(&sk, &indices);
        let recovered_pk = fors_verify(&sig, &indices).expect("valid signature");

        assert_eq!(pk, recovered_pk);
    }

    #[test]
    fn test_flat_layout_total_length() {
        let mut rng = StdRng::seed_from_u64(42);
        let sig = ForsSignature {
            trees: std::array::from_fn(|_| ForsTreeSig {
                leaf_secret: rng.random(),
                auth_path: (0..SPX_FORS_HEIGHT).map(|_| rng.random()).collect(),
            }),
        };
        let flat = fors_sig_to_flat(&sig);
        assert_eq!(flat.len(), FORS_SIG_SIZE_FE);
        assert_eq!(FORS_SIG_SIZE_FE, 1152);
    }

    #[test]
    fn test_flat_layout_positions() {
        // Build a signature where each tree uses recognisable values so we can
        // assert exact offsets in the flat vector.
        let stride = (1 + SPX_FORS_HEIGHT) * DIGEST_SIZE;
        let trees_data: Vec<(Digest, Vec<Digest>)> = (0..SPX_FORS_TREES)
            .map(|t| {
                let leaf: Digest = std::array::from_fn(|i| F::from_usize(t * 100 + i));
                let auth: Vec<Digest> = (0..SPX_FORS_HEIGHT)
                    .map(|level| std::array::from_fn(|i| F::from_usize(t * 1000 + level * 10 + i)))
                    .collect();
                (leaf, auth)
            })
            .collect();

        let sig = ForsSignature {
            trees: std::array::from_fn(|t| ForsTreeSig {
                leaf_secret: trees_data[t].0,
                auth_path: trees_data[t].1.clone(),
            }),
        };

        let flat = fors_sig_to_flat(&sig);

        for t in 0..SPX_FORS_TREES {
            let base = t * stride;
            // leaf_secret occupies [base, base + DIGEST_SIZE)
            assert_eq!(
                &flat[base..base + DIGEST_SIZE],
                &trees_data[t].0,
                "tree {t} leaf_secret mismatch"
            );
            // each auth_path node at base + DIGEST_SIZE + level * DIGEST_SIZE
            for level in 0..SPX_FORS_HEIGHT {
                let off = base + DIGEST_SIZE + level * DIGEST_SIZE;
                assert_eq!(
                    &flat[off..off + DIGEST_SIZE],
                    &trees_data[t].1[level],
                    "tree {t} auth_path[{level}] mismatch"
                );
            }
        }
    }

    #[test]
    fn test_flat_round_trip() {
        let mut rng = StdRng::seed_from_u64(99);
        let sig = ForsSignature {
            trees: std::array::from_fn(|_| ForsTreeSig {
                leaf_secret: rng.random(),
                auth_path: (0..SPX_FORS_HEIGHT).map(|_| rng.random()).collect(),
            }),
        };
        let flat = fors_sig_to_flat(&sig);
        let recovered = fors_sig_from_flat(&flat).expect("round-trip should succeed");
        assert_eq!(sig, recovered);
    }
}
