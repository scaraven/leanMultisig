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

// SPHINCS+ Hypertree
//
// A d=3 layer XMSS hypertree. Each layer is an XMSS tree of height SPX_TREE_HEIGHT=11
// (2048 leaves). Layer 0 signs a Digest derived from the FORS public key. Each subsequent
// layer signs the previous layer's Merkle root (as a full Digest via half_to_full).
//
// Tree addressing:
//   tree_address is a 22-bit value (SPX_TREE_BITS). At layer l, the relevant subtree is:
//     layer_tree_address = tree_address >> (l * SPX_TREE_HEIGHT)
//   The leaf within that tree at layer l is:
//     layer 0: leaf_index (bottom 11 bits)
//     layer l>0: lower SPX_TREE_HEIGHT bits of the layer below's tree_address component
//       i.e. (tree_address >> ((l-1) * SPX_TREE_HEIGHT)) & TREE_MASK

const TREE_MASK: usize = (1 << SPX_TREE_HEIGHT) - 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HypertreeSecretKey {
    sk_seed: HalfDigest,
    pk_seed: HalfDigest,
}

impl HypertreeSecretKey {
    pub fn new(sk_seed: HalfDigest, pk_seed: HalfDigest) -> Self {
        Self { sk_seed, pk_seed }
    }

    pub fn public_key(&self) -> HypertreePublicKey {
        let (root, _) = build_layer_tree(self.sk_seed, self.pk_seed, SPX_D - 1, 0);
        HypertreePublicKey(root)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HypertreePublicKey(pub HalfDigest);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HypertreeSignature {
    /// One entry per layer, bottom (layer 0) to top (layer SPX_D-1).
    pub layers: [HypertreeLayerSig; SPX_D],
}

impl HypertreeSignature {
    pub fn flatten_hypertree_sig(&self) -> Vec<F> {
        let mut out = Vec::new();
        for layer in self.layers.iter() {
            out.extend_from_slice(&layer.randomness_with_adrs);
            out.extend(layer.wots_sig.chain_tips.iter().flatten().copied());
            out.extend(layer.auth_path.iter().flatten().copied());
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HypertreeLayerSig {
    pub wots_sig: WotsSignature,
    /// [r0..r5, adrs0, adrs1] — 8-FE block consumed by wots_encode_and_complete in the zkDSL.
    pub randomness_with_adrs: [F; 8],
    /// Sibling digests from the leaf level up to (but not including) the root.
    /// Length = SPX_TREE_HEIGHT = 11.
    pub auth_path: Vec<HalfDigest>,
}

// ---------------------------------------------------------------------------
// WOTS+ pre-image derivation via PRF
// ---------------------------------------------------------------------------

fn derive_wots_preimages(
    sk_seed: HalfDigest,
    pk_seed: HalfDigest,
    layer: usize,
    layer_tree_address: usize,
    local_leaf: usize,
) -> [HalfDigest; SPX_WOTS_LEN] {
    std::array::from_fn(|chain| {
        let adrs = Adrs::wots_prf(layer as u32, layer_tree_address as u32, local_leaf as u32, chain as u32);
        prf(pk_seed, sk_seed, adrs)
    })
}

// ---------------------------------------------------------------------------
// Merkle tree construction
// ---------------------------------------------------------------------------

/// Hash two sibling XMSS nodes at (layer, tree_address, height, node_index) into their parent.
///
/// Tweak layout (uniform):
///   left  = [pk_seed[0..4] | adrs0, adrs1, 0, 0]
///   right = [left_child[0..4] | right_child[0..4]]
fn hash_xmss_node(
    left_child: HalfDigest,
    right_child: HalfDigest,
    pk_seed: HalfDigest,
    layer: usize,
    tree_address: usize,
    height: usize,
    node_index: usize,
) -> HalfDigest {
    let adrs = Adrs::tree(layer as u32, tree_address as u32, height as u32, node_index as u32);
    let mut left = [F::ZERO; DIGEST_SIZE];
    left[..4].copy_from_slice(&pk_seed);
    left[4] = adrs.adrs0;
    left[5] = adrs.adrs1;
    let mut right = [F::ZERO; DIGEST_SIZE];
    right[..4].copy_from_slice(&left_child);
    right[4..8].copy_from_slice(&right_child);
    truncate_half(poseidon16_compress_pair(&left, &right))
}

/// Materialise one full XMSS layer tree (2^SPX_TREE_HEIGHT = 2048 leaves).
pub fn build_layer_tree(
    sk_seed: HalfDigest,
    pk_seed: HalfDigest,
    layer: usize,
    tree_address: usize,
) -> (HalfDigest, Vec<Vec<HalfDigest>>) {
    let num_leaves = 1usize << SPX_TREE_HEIGHT;

    let leaf_nodes: Vec<HalfDigest> = (0..num_leaves)
        .into_par_iter()
        .map(|local| {
            let preimages = derive_wots_preimages(sk_seed, pk_seed, layer, tree_address, local);
            let base_adrs = Adrs::wots_hash(layer as u32, tree_address as u32, local as u32, 0, 0);
            let wots_pk = WotsSecretKey::new(preimages, pk_seed, base_adrs).public_key().clone();
            let pk_adrs = Adrs::wots_pk(layer as u32, tree_address as u32, local as u32);
            wots_pk.hash(pk_seed, pk_adrs)
        })
        .collect();

    let mut levels = vec![leaf_nodes];
    for h in 0..SPX_TREE_HEIGHT {
        let prev = levels.last().unwrap();
        let next: Vec<HalfDigest> = prev
            .par_chunks_exact(2)
            .enumerate()
            .map(|(node_idx, pair)| hash_xmss_node(pair[0], pair[1], pk_seed, layer, tree_address, h + 1, node_idx))
            .collect();
        levels.push(next);
    }

    let root = levels[SPX_TREE_HEIGHT][0];
    (root, levels)
}

/// Extract the auth path for `leaf_index` from a materialised tree.
pub fn extract_auth_path(levels: &[Vec<HalfDigest>], leaf_index: usize) -> Vec<HalfDigest> {
    (0..SPX_TREE_HEIGHT)
        .map(|level| {
            let sibling_idx = (leaf_index >> level) ^ 1;
            levels[level][sibling_idx]
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

fn calculate_address_info(leaf_index: usize, tree_address: usize, layer: usize) -> (usize, usize, usize) {
    let layer_tree_address = tree_address >> (layer * SPX_TREE_HEIGHT);
    let layer_leaf_index = if layer == 0 {
        leaf_index
    } else {
        (tree_address >> ((layer - 1) * SPX_TREE_HEIGHT)) & TREE_MASK
    };
    let global_leaf = layer_tree_address * (1 << SPX_TREE_HEIGHT) + layer_leaf_index;
    (layer_tree_address, layer_leaf_index, global_leaf)
}

/// Sign `message` (a Digest) with the hypertree.
pub fn hypertree_sign(
    sk: &HypertreeSecretKey,
    message: &Digest,
    leaf_index: usize,
    tree_address: usize,
) -> HypertreeSignature {
    let mut current_message = *message;
    let mut rng = rand::rng();

    let layers: [HypertreeLayerSig; SPX_D] = std::array::from_fn(|layer| {
        let (layer_tree_address, layer_leaf_index, _) = calculate_address_info(leaf_index, tree_address, layer);

        let (root, levels) = build_layer_tree(sk.sk_seed, sk.pk_seed, layer, layer_tree_address);

        let preimages = derive_wots_preimages(sk.sk_seed, sk.pk_seed, layer, layer_tree_address, layer_leaf_index);
        let adrs = Adrs::wots_hash(layer as u32, layer_tree_address as u32, layer_leaf_index as u32, 0, 0);
        let wots_sk = WotsSecretKey::new(preimages, sk.pk_seed, adrs);
        let (randomness, _, _) = find_randomness_for_wots_encoding(&current_message, adrs.adrs0, adrs.adrs1, &mut rng);
        let wots_sig =
            wots_sk.sign_with_randomness(&current_message, adrs.adrs0, adrs.adrs1, randomness, sk.pk_seed, adrs);

        let auth_path = extract_auth_path(&levels, layer_leaf_index);

        if layer < SPX_D - 1 {
            current_message = half_to_full(root);
        }

        let mut randomness_with_adrs = [F::ZERO; 8];
        randomness_with_adrs[..6].copy_from_slice(&wots_sig.randomness);
        randomness_with_adrs[6] = adrs.adrs0;
        randomness_with_adrs[7] = adrs.adrs1;
        HypertreeLayerSig {
            wots_sig,
            randomness_with_adrs,
            auth_path,
        }
    });

    HypertreeSignature { layers }
}

/// Verify a hypertree signature, recovering the expected public key.
pub fn hypertree_verify(
    sig: &HypertreeSignature,
    message: &Digest,
    leaf_index: usize,
    tree_address: usize,
    expected_pk: &HalfDigest,
    pk_seed: HalfDigest,
) -> bool {
    let mut current_message = *message;

    for (layer, layer_sig) in sig.layers.iter().enumerate() {
        let (layer_tree_address, layer_leaf_index, _) = calculate_address_info(leaf_index, tree_address, layer);

        let adrs = Adrs::wots_hash(layer as u32, layer_tree_address as u32, layer_leaf_index as u32, 0, 0);

        let wots_pk =
            match layer_sig
                .wots_sig
                .recover_public_key(&current_message, adrs.adrs0, adrs.adrs1, pk_seed, adrs)
            {
                Some(pk) => pk,
                None => return false,
            };

        let pk_adrs = Adrs::wots_pk(layer as u32, layer_tree_address as u32, layer_leaf_index as u32);
        let mut current: HalfDigest = wots_pk.hash(pk_seed, pk_adrs);

        if layer_sig.auth_path.len() != SPX_TREE_HEIGHT {
            return false;
        }

        for (level, sibling) in layer_sig.auth_path.iter().enumerate() {
            let is_left = ((layer_leaf_index >> level) & 1) == 0;
            let node_idx = (layer_leaf_index >> level) >> 1;
            current = if is_left {
                hash_xmss_node(
                    current,
                    *sibling,
                    pk_seed,
                    layer,
                    layer_tree_address,
                    level + 1,
                    node_idx,
                )
            } else {
                hash_xmss_node(
                    *sibling,
                    current,
                    pk_seed,
                    layer,
                    layer_tree_address,
                    level + 1,
                    node_idx,
                )
            };
        }

        let layer_root = current;

        if layer < SPX_D - 1 {
            current_message = half_to_full(layer_root);
        } else {
            return layer_root == *expected_pk;
        }
    }

    unreachable!("SPX_D layers iterated without returning")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hypertree_sign_verify() {
        let sk_seed = [F::new(42); 4];
        let pk_seed = [F::new(99); 4];
        let sk = HypertreeSecretKey::new(sk_seed, pk_seed);
        let pk = sk.public_key();

        let message = poseidon16_compress_pair(&Digest::default(), &Digest::default());

        let leaf_index = 0;
        let tree_address = 0;

        let sig = hypertree_sign(&sk, &message, leaf_index, tree_address);
        assert!(hypertree_verify(
            &sig,
            &message,
            leaf_index,
            tree_address,
            &pk.0,
            pk_seed
        ));
    }
}
