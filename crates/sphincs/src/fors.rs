use backend::{
    IndexedParallelIterator, IntoParallelIterator, ParallelIterator, ParallelSlice, PrimeCharacteristicRing,
};
use serde::{Deserialize, Serialize};
use utils::poseidon16_compress_pair;

use crate::{
    address::Adrs,
    core::prf,
    wots::{half_to_full, truncate_half},
    *,
};

// FORS (Few-Times Signature Scheme)
//
// Signs a message by:
//   1. Splitting mhash into k=9 indices, each selecting a leaf in one of 9
//      binary trees of height 15 (32768 leaves each).
//   2. Revealing the selected leaf's secret value and its 15-node auth path.
//   3. Verifier recomputes each tree root from (leaf, auth path) and folds
//      the k roots into a single FORS public key via sequential hash.
//
// Secret values are derived via PRF: prf(pk_seed, sk_seed, Adrs::fors_prf(tree, 0, leaf)).
// Leaf hashing and Merkle nodes use Adrs::fors_tree with the uniform tweak layout.
// Root folding uses Adrs::fors_roots.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForsSecretKey {
    sk_seed: HalfDigest,
    pk_seed: HalfDigest,
    /// Materialised tree nodes: [tree][level][node]
    /// level 0 = leaf hashes, level SPX_FORS_HEIGHT = root
    nodes: Vec<Vec<Vec<HalfDigest>>>,
    root: HalfDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForsPublicKey(pub HalfDigest);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForsSignature {
    /// For each of the k=9 trees: the revealed leaf secret and auth path.
    pub trees: [ForsTreeSig; SPX_FORS_TREES],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForsTreeSig {
    pub leaf_secret: HalfDigest,
    /// Sibling digests from leaf level up to (but not including) the root.
    /// Length = SPX_FORS_HEIGHT = 15.
    pub auth_path: Vec<HalfDigest>,
}

/// Derive the FORS leaf secret for (tree_index, leaf_index) from key material.
fn derive_leaf_secret(sk_seed: HalfDigest, pk_seed: HalfDigest, tree_index: usize, leaf_index: usize) -> HalfDigest {
    let adrs = Adrs::fors_prf(tree_index as u32, 0, leaf_index as u32);
    prf(pk_seed, sk_seed, adrs)
}

/// Hash a leaf secret into the level-0 tree node, tweaked with Adrs::fors_tree(height=0).
pub fn hash_leaf(secret: HalfDigest, pk_seed: HalfDigest, tree_index: usize, leaf_index: usize) -> HalfDigest {
    let adrs = Adrs::fors_tree(tree_index as u32, 0, leaf_index as u32);
    let mut left = [F::ZERO; DIGEST_SIZE];
    left[..4].copy_from_slice(&pk_seed);
    left[4] = adrs.adrs0;
    left[5] = adrs.adrs1;
    truncate_half(poseidon16_compress_pair(&left, &half_to_full(secret)))
}

/// Hash two sibling nodes at (tree_index, height, node_index) into their parent.
///
/// Tweak layout:
///   left  = [pk_seed[0..4] | adrs0, adrs1, 0, 0]
///   right = [left_child[0..4] | right_child[0..4]]
fn hash_merkle_node(
    left_child: HalfDigest,
    right_child: HalfDigest,
    pk_seed: HalfDigest,
    tree_index: usize,
    height: usize,
    node_index: usize,
) -> HalfDigest {
    let adrs = Adrs::fors_tree(tree_index as u32, height as u32, node_index as u32);
    let mut left = [F::ZERO; DIGEST_SIZE];
    left[..4].copy_from_slice(&pk_seed);
    left[4] = adrs.adrs0;
    left[5] = adrs.adrs1;
    let mut right = [F::ZERO; DIGEST_SIZE];
    right[..4].copy_from_slice(&left_child);
    right[4..8].copy_from_slice(&right_child);
    truncate_half(poseidon16_compress_pair(&left, &right))
}

/// Generate the full FORS keypair, materialising all leaf secrets and tree nodes.
pub fn fors_key_gen(sk_seed: HalfDigest, pk_seed: HalfDigest) -> (ForsSecretKey, ForsPublicKey) {
    let num_leaves = 1usize << SPX_FORS_HEIGHT;

    let all_nodes: Vec<_> = (0..SPX_FORS_TREES)
        .into_par_iter()
        .map(|t| {
            // Level 0: derive secret, then hash into leaf node.
            let leaf_hashes: Vec<HalfDigest> = (0..num_leaves)
                .into_par_iter()
                .map(|l| {
                    let secret = derive_leaf_secret(sk_seed, pk_seed, t, l);
                    hash_leaf(secret, pk_seed, t, l)
                })
                .collect();

            // Build inner levels bottom-up.
            let mut levels = vec![leaf_hashes];
            for h in 0..SPX_FORS_HEIGHT {
                let prev = levels.last().unwrap();
                let next: Vec<HalfDigest> = prev
                    .par_chunks_exact(2)
                    .enumerate()
                    .map(|(node_idx, pair)| hash_merkle_node(pair[0], pair[1], pk_seed, t, h + 1, node_idx))
                    .collect();
                levels.push(next);
            }
            levels
        })
        .collect();

    let pk = fors_public_key_from_nodes(&all_nodes, pk_seed);
    let sk = ForsSecretKey {
        sk_seed,
        pk_seed,
        nodes: all_nodes,
        root: pk.0,
    };
    (sk, pk)
}

fn fors_public_key_from_nodes(nodes: &[Vec<Vec<HalfDigest>>], pk_seed: HalfDigest) -> ForsPublicKey {
    let roots: Vec<HalfDigest> = nodes.iter().map(|levels| levels[SPX_FORS_HEIGHT][0]).collect();
    ForsPublicKey(fold_roots(pk_seed, &roots))
}

/// Fold k roots into a single half-digest using a T-Sponge with replacement.
///
/// Poseidon-16 in compression mode is used as a sponge (capacity 8 / rate 8): each compression
/// absorbs a full 8-FE block of *two* roots by overwriting the rate, while the running
/// accumulator lives in the capacity. The fixed sponge tweak is `Adrs::fors_roots(0, 0)`, fed
/// directly as the first compression's left input (no priming call, and no per-step adrs1):
///   IV    = [pk_seed[0..4] | adrs0, adrs1, 0, 0]
///   block = [root_{2i}[0..4] | root_{2i+1}[0..4]]
///   state = P16(state, block)
/// The 8-FE Poseidon output is carried in full between calls; only the final squeeze truncates
/// to a HalfDigest. When the root count is odd the final block's high half is zero-padded.
pub fn fold_roots(pk_seed: HalfDigest, roots: &[HalfDigest]) -> HalfDigest {
    assert!(roots.len() >= 2, "fold_roots requires at least 2 roots");

    let adrs = Adrs::fors_roots(0, 0);
    let mut iv = [F::ZERO; DIGEST_SIZE];
    iv[..4].copy_from_slice(&pk_seed);
    iv[4] = adrs.adrs0;
    iv[5] = adrs.adrs1;

    let mut block = [F::ZERO; DIGEST_SIZE];
    block[..4].copy_from_slice(&roots[0]);
    block[4..8].copy_from_slice(&roots[1]);
    let mut state = poseidon16_compress_pair(&iv, &block);

    let mut chunks = roots[2..].chunks_exact(2);
    for pair in chunks.by_ref() {
        block[..4].copy_from_slice(&pair[0]);
        block[4..8].copy_from_slice(&pair[1]);
        state = poseidon16_compress_pair(&state, &block);
    }
    // Odd root count: absorb the final lone root with a zero-padded high half.
    let rem = chunks.remainder();
    if let [root] = rem {
        block = [F::ZERO; DIGEST_SIZE];
        block[..4].copy_from_slice(root);
        state = poseidon16_compress_pair(&state, &block);
    }

    truncate_half(state)
}

/// Sign a single tree in the FORS forest, revealing the leaf secret and auth path.
pub fn fors_sign_single_tree(sk: &ForsSecretKey, tree_index: usize, leaf_index: usize) -> ForsTreeSig {
    assert!(tree_index < SPX_FORS_TREES, "Tree index out of bounds");
    assert!(leaf_index < (1 << SPX_FORS_HEIGHT), "Leaf index out of bounds");

    // Reveal the raw leaf secret (not the hashed node).
    let leaf_secret = derive_leaf_secret(sk.sk_seed, sk.pk_seed, tree_index, leaf_index);

    let auth_path: Vec<HalfDigest> = (0..SPX_FORS_HEIGHT)
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
pub fn fors_verify(
    sig: &ForsSignature,
    indices: &[usize; SPX_FORS_TREES],
    pk_seed: HalfDigest,
) -> Result<ForsPublicKey, ForsVerifyError> {
    let mut roots = [HalfDigest::default(); SPX_FORS_TREES];
    for (t, (tree_sig, &leaf_idx)) in sig.trees.iter().zip(indices.iter()).enumerate() {
        if tree_sig.auth_path.len() != SPX_FORS_HEIGHT {
            return Err(ForsVerifyError::WrongAuthPathLength);
        }

        if leaf_idx >= (1 << SPX_FORS_HEIGHT) {
            return Err(ForsVerifyError::OutofBoundsLeafIndex);
        }

        // Recompute level-0 node from the revealed secret.
        let mut current = hash_leaf(tree_sig.leaf_secret, pk_seed, t, leaf_idx);

        // Walk up the tree using the auth path.
        for (level, sibling) in tree_sig.auth_path.iter().enumerate() {
            let is_left = ((leaf_idx >> level) & 1) == 0;
            let node_idx = (leaf_idx >> level) >> 1; // parent node index at level+1
            current = if is_left {
                hash_merkle_node(current, *sibling, pk_seed, t, level + 1, node_idx)
            } else {
                hash_merkle_node(*sibling, current, pk_seed, t, level + 1, node_idx)
            };
        }

        roots[t] = current;
    }

    Ok(ForsPublicKey(fold_roots(pk_seed, &roots)))
}

impl ForsSecretKey {
    pub fn public_key(&self) -> ForsPublicKey {
        ForsPublicKey(self.root)
    }

    pub fn tree_pubkey(&self, tree_index: usize) -> HalfDigest {
        self.nodes[tree_index][SPX_FORS_HEIGHT][0]
    }
}

/// Size of a flat FORS signature in field elements.
/// Layout: for each of SPX_FORS_TREES trees: [leaf_secret (HALF_DIGEST_SIZE FEs) | auth_path (SPX_FORS_HEIGHT * HALF_DIGEST_SIZE FEs)]
pub const FORS_SIG_SIZE_FE: usize = SPX_FORS_TREES * (1 + SPX_FORS_HEIGHT) * HALF_DIGEST_SIZE;

/// Flatten a `ForsSignature` into a `Vec<F>` matching the zkDSL hint layout.
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

/// Flatten only the FORS leaf secrets (one HalfDigest per tree), for the "fors_sig" hint queue.
/// Layout: `[leaf_secret_0 | leaf_secret_1 | ... | leaf_secret_{k-1}]`.
pub fn fors_leaf_secrets_to_flat(sig: &ForsSignature) -> Vec<F> {
    let mut out = Vec::with_capacity(SPX_FORS_TREES * HALF_DIGEST_SIZE);
    for tree in &sig.trees {
        out.extend_from_slice(&tree.leaf_secret);
    }
    out
}

/// The FORS auth-path siblings as one buffer per sibling, for the "fors_auth" hint queue.
/// The zkDSL issues one `hint_witness("fors_auth", ...)` call per Merkle level (each writing
/// one HALF_DIGEST_SIZE sibling), so each sibling must be a separate queue entry. Order: per
/// tree, the SPX_FORS_HEIGHT siblings bottom-up — the same order the levels consume them.
pub fn fors_auth_buffers(sig: &ForsSignature) -> Vec<Vec<F>> {
    let mut out = Vec::with_capacity(SPX_FORS_TREES * SPX_FORS_HEIGHT);
    for tree in &sig.trees {
        for node in &tree.auth_path {
            out.push(node.to_vec());
        }
    }
    out
}

/// Reconstruct a `ForsSignature` from a flat `Vec<F>` produced by `fors_sig_to_flat`.
pub fn fors_sig_from_flat(flat: &[F]) -> Option<ForsSignature> {
    if flat.len() != FORS_SIG_SIZE_FE {
        return None;
    }
    let stride = (1 + SPX_FORS_HEIGHT) * HALF_DIGEST_SIZE;
    let trees = std::array::from_fn(|t| {
        let base = t * stride;
        let leaf_secret: HalfDigest = flat[base..base + HALF_DIGEST_SIZE].try_into().unwrap();
        let auth_path = (0..SPX_FORS_HEIGHT)
            .map(|i| {
                let off = base + HALF_DIGEST_SIZE + i * HALF_DIGEST_SIZE;
                flat[off..off + HALF_DIGEST_SIZE].try_into().unwrap()
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
        let mhash = [0xA5u8; SPX_FORS_MSG_BYTES];
        let indices = extract_fors_indices(&mhash);

        for &idx in indices.iter() {
            assert!(idx < (1 << SPX_FORS_HEIGHT));
        }

        assert_eq!(indices, extract_fors_indices(&mhash));
    }

    #[test]
    #[ignore]
    fn test_fors_sign_verify_roundtrip_ignored() {
        let sk_seed = [F::new(7); 4];
        let pk_seed = [F::new(11); 4];
        let (sk, pk) = fors_key_gen(sk_seed, pk_seed);

        let mhash = [0x11u8; SPX_FORS_MSG_BYTES];
        let indices = extract_fors_indices(&mhash);
        let sig = fors_sign(&sk, &indices);
        let recovered_pk = fors_verify(&sig, &indices, pk_seed).expect("valid signature");

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
        assert_eq!(FORS_SIG_SIZE_FE, 576);
    }

    #[test]
    fn test_flat_layout_positions() {
        let stride = (1 + SPX_FORS_HEIGHT) * HALF_DIGEST_SIZE;
        let trees_data: Vec<(HalfDigest, Vec<HalfDigest>)> = (0..SPX_FORS_TREES)
            .map(|t| {
                let leaf: HalfDigest = std::array::from_fn(|i| F::from_usize(t * 100 + i));
                let auth: Vec<HalfDigest> = (0..SPX_FORS_HEIGHT)
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
            assert_eq!(
                &flat[base..base + HALF_DIGEST_SIZE],
                &trees_data[t].0,
                "tree {t} leaf_secret mismatch"
            );
            for level in 0..SPX_FORS_HEIGHT {
                let off = base + HALF_DIGEST_SIZE + level * HALF_DIGEST_SIZE;
                assert_eq!(
                    &flat[off..off + HALF_DIGEST_SIZE],
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
