use serde::{Deserialize, Serialize};
use utils::poseidon16_compress_pair;

use crate::*;

// SPHINCS+ Hypertree
//
// A d=3 layer XMSS hypertree. Each layer is an XMSS tree of height SPX_TREE_HEIGHT=11
// (2048 leaves). Layer 0 signs a Digest derived from the FORS public key. Each subsequent
// layer signs the Merkle root of the layer below, hashed with a randomness counter to
// ensure the encoding sums to TARGET_SUM.
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
    /// Master seed — trees are materialised on demand, never cached.
    seed: [u8; 20],
}

impl HypertreeSecretKey {
    pub fn new(seed: [u8; 20]) -> Self {
        Self { seed }
    }

    pub fn public_key(&self) -> HypertreePublicKey {
        let (root, _) = build_layer_tree(&self.seed, SPX_D - 1, 0);
        HypertreePublicKey(root)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HypertreePublicKey(pub Digest);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HypertreeSignature {
    /// One entry per layer, bottom (layer 0) to top (layer SPX_D-1).
    pub layers: [HypertreeLayerSig; SPX_D],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HypertreeLayerSig {
    pub wots_sig: WotsSignature,
    /// Sibling digests from the leaf level up to (but not including) the root.
    /// Length = SPX_TREE_HEIGHT = 11.
    pub auth_path: Vec<Digest>,
}

// ---------------------------------------------------------------------------
// Seed derivation
// ---------------------------------------------------------------------------

/// Derive the WOTS+ pre-images for a given (layer, leaf_index) from the master seed.
///
/// Input layout (Poseidon 16-state via two Digests):
///   left[0..5] : seed packed as 5 little-endian u32s (20 bytes)
///   left[5]    : domain marker 0x00 (WOTS pre-images)
///   left[6]    : layer as u32
///   left[7]    : 0
///   right[0]   : leaf_index low 32 bits
///   right[1]   : leaf_index high 32 bits
///   right[2]   : chain index (0..SPX_WOTS_LEN-1)
fn derive_wots_preimages(seed: &[u8; 20], layer: usize, leaf_index: usize) -> [Digest; SPX_WOTS_LEN] {
    // Each chain gets its own PRF output so chain secrets are independent.
    std::array::from_fn(|chain| {
        let mut left = Digest::default();
        for (i, chunk) in seed.chunks_exact(4).enumerate() {
            left[i] = F::new(u32::from_le_bytes(chunk.try_into().unwrap()));
        }
        left[5] = F::new(0x00);
        left[6] = F::new(layer as u32);

        let leaf_u64 = leaf_index as u64;
        let leaf_lo = (leaf_u64 & 0xFFFF_FFFF) as u32;
        let leaf_hi = (leaf_u64 >> 32) as u32;

        let mut right = Digest::default();
        right[0] = F::new(leaf_lo);
        right[1] = F::new(leaf_hi);
        right[2] = F::new(chain as u32);

        poseidon16_compress_pair(&left, &right)
    })
}

// ---------------------------------------------------------------------------
// Merkle tree construction
// ---------------------------------------------------------------------------

/// Materialise one full XMSS layer tree (2^SPX_TREE_HEIGHT = 2048 leaves).
///
/// For each leaf: derive pre-images → WotsSecretKey → public key → pk.hash() → leaf node.
/// Levels are built bottom-up; levels[0] = leaf hashes, levels[SPX_TREE_HEIGHT] = [root].
///
/// `tree_address` is the index of this subtree within the layer (used only for pre-image
/// derivation — the leaf index passed to derive_wots_preimages is
/// tree_address * num_leaves + local_leaf_index so keys are globally unique).
fn build_layer_tree(seed: &[u8; 20], layer: usize, tree_address: usize) -> (Digest, Vec<Vec<Digest>>) {
    let num_leaves = 1usize << SPX_TREE_HEIGHT;
    let global_base = tree_address * num_leaves;

    let leaf_nodes: Vec<Digest> = (0..num_leaves)
        .map(|local| {
            let preimages = derive_wots_preimages(seed, layer, global_base + local);
            WotsSecretKey::new(preimages).public_key().hash()
        })
        .collect();

    let mut levels = vec![leaf_nodes];
    for _ in 0..SPX_TREE_HEIGHT {
        let prev = levels.last().unwrap();
        let next: Vec<Digest> = prev
            .chunks_exact(2)
            .map(|pair| poseidon16_compress_pair(&pair[0], &pair[1]))
            .collect();
        levels.push(next);
    }

    let root = levels[SPX_TREE_HEIGHT][0];
    (root, levels)
}

/// Extract the auth path for `leaf_index` from a materialised tree.
/// Returns SPX_TREE_HEIGHT sibling digests, from leaf level up to (not including) root.
fn extract_auth_path(levels: &[Vec<Digest>], leaf_index: usize) -> Vec<Digest> {
    (0..SPX_TREE_HEIGHT)
        .map(|level| {
            let sibling_idx = (leaf_index >> level) ^ 1;
            levels[level][sibling_idx]
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Inter-layer message hashing
// ---------------------------------------------------------------------------

/// Hash a child Merkle root into a message Digest for the next WOTS layer.
///
/// Input layout:
///   left[0..8]  = child_merkle_root   (full Digest, 8 FEs)
///   right[0]    = layer_index as F    (the layer being signed INTO, i.e. child layer + 1)
///   right[2..8] = F::default()
fn hash_inter_layer_message(child_root: &Digest, layer: usize) -> Digest {
    let mut right = Digest::default();
    right[0] = F::new(layer as u32);
    poseidon16_compress_pair(child_root, &right)
}
// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

fn calculate_address_info(leaf_index: usize, tree_address: usize, layer: usize) -> (usize, usize, usize) {
    // Subtree address for this layer.
    let layer_tree_address = tree_address >> (layer * SPX_TREE_HEIGHT);
    // Leaf within this layer's tree.
    let layer_leaf_index = if layer == 0 {
        leaf_index
    } else {
        (tree_address >> ((layer - 1) * SPX_TREE_HEIGHT)) & TREE_MASK
    };
    let global_leaf = layer_tree_address * (1 << SPX_TREE_HEIGHT) + layer_leaf_index;
    (layer_tree_address, layer_leaf_index, global_leaf)
}

/// Sign `message` (a Digest) with the hypertree.
///
/// `leaf_index`: selects the WOTS key within the layer-0 tree (0..2047).
/// `tree_address`: 22-bit value; at layer l the subtree index is
///   `tree_address >> (l * SPX_TREE_HEIGHT)` and the local leaf is
///   `(tree_address >> ((l-1) * SPX_TREE_HEIGHT)) & TREE_MASK` for l > 0.
///
/// Signing flow (layer 0 → SPX_D-1):
///   1. Determine layer_tree_address and layer_leaf_index.
///   2. build_layer_tree → (root, levels).
///   3. derive_wots_preimages + WotsSecretKey::new.
///   4. find_randomness_for_wots_encoding; sign_with_randomness(message, layer, root[..6], randomness).
///   5. extract_auth_path.
///   6. For layers 0..SPX_D-2: hash_inter_layer_message(root) → message for next layer.
pub fn hypertree_sign(
    sk: &HypertreeSecretKey,
    message: &Digest,
    leaf_index: usize,
    tree_address: usize,
) -> HypertreeSignature {
    let mut current_message = hash_inter_layer_message(message, 0);

    let mut rng = rand::rng();

    let layers: [HypertreeLayerSig; SPX_D] = std::array::from_fn(|layer| {
        let (layer_tree_address, layer_leaf_index, global_leaf) =
            calculate_address_info(leaf_index, tree_address, layer);

        let (root, levels) = build_layer_tree(&sk.seed, layer, layer_tree_address);

        let preimages = derive_wots_preimages(&sk.seed, layer, global_leaf);
        let wots_sk = WotsSecretKey::new(preimages);

        let (randomness, _, _) = find_randomness_for_wots_encoding(&current_message, layer as u32, &mut rng);
        let wots_sig = wots_sk.sign_with_randomness(&current_message, layer as u32, randomness);

        let auth_path = extract_auth_path(&levels, layer_leaf_index);

        // Prepare message for the next layer (not needed after the top layer).
        if layer < SPX_D - 1 {
            let next_msg = hash_inter_layer_message(&root, layer + 1);
            current_message = next_msg;
        }

        HypertreeLayerSig { wots_sig, auth_path }
    });

    HypertreeSignature { layers }
}

/// Verify a hypertree signature, recovering the expected public key.
///
/// Verification walks bottom to top (layer 0 → SPX_D-1):
///   1. Recover the layer's Merkle root by:
///      a. recover_public_key(wots_sig, message, layer) → WotsPublicKey
///      b. leaf_node = wots_pk.hash()
///      c. Walk auth_path up using (layer_leaf_index >> level) & 1 for left/right → root
///   2. The recovered root is the next layer's input to hash_inter_layer_message.
///   3. Repeat until top; return the top-layer root as HypertreePublicKey.
pub fn hypertree_verify(
    sig: &HypertreeSignature,
    message: &Digest,
    leaf_index: usize,
    tree_address: usize,
    expected_pk: &Digest,
) -> bool {
    let mut current_message = hash_inter_layer_message(message, 0);

    for (layer, layer_sig) in sig.layers.iter().enumerate() {
        let (_, layer_leaf_index, _) = calculate_address_info(leaf_index, tree_address, layer);

        let wots_pk = match layer_sig.wots_sig.recover_public_key(&current_message, layer as u32) {
            Some(pk) => pk,
            None => return false, // Invalid WOTS signature
        };

        // Hash the recovered public key to get the leaf node.
        let mut current = wots_pk.hash();

        // Fail if auth_path is not the correct length
        if layer_sig.auth_path.len() != SPX_TREE_HEIGHT {
            return false;
        }

        // Walk the auth path up to recover the layer's Merkle root.
        for (level, sibling) in layer_sig.auth_path.iter().enumerate() {
            let is_left = ((layer_leaf_index >> level) & 1) == 0;
            current = if is_left {
                poseidon16_compress_pair(&current, sibling)
            } else {
                poseidon16_compress_pair(sibling, &current)
            };
        }

        // `current` is now the recovered Merkle root of this layer.
        let layer_root = current;

        // Derive the next layer's message from this root.
        if layer < SPX_D - 1 {
            let next_msg = hash_inter_layer_message(&layer_root, layer + 1);
            current_message = next_msg;
        } else {
            // Top layer: the recovered root is the public key.
            return layer_root == *expected_pk;
        }
    }

    unreachable!("SPX_D layers iterated without returning")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Perform a full sign-then-verify flow test for the hypertree. This is a basic correctness test
    #[test]
    fn test_hypertree_sign_verify() {
        let seed = [42u8; 20];
        let sk = HypertreeSecretKey::new(seed);
        let pk = sk.public_key();

        // Deterministic message digest.
        let message = poseidon16_compress_pair(&Digest::default(), &Digest::default());

        let leaf_index = 0;
        let tree_address = 0;

        let sig = hypertree_sign(&sk, &message, leaf_index, tree_address);
        assert!(hypertree_verify(&sig, &message, leaf_index, tree_address, &pk.0));
    }
}
