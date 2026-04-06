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
//     layer_tree_address = tree_address >> (l * SPX_TREE_HEIGHT)  (truncated to 11 bits)
//   The leaf within that tree at layer l is:
//     layer 0: leaf_index (bottom 11 bits)
//     layer l>0: lower SPX_TREE_HEIGHT bits of the layer below's tree_address component
//       i.e. (tree_address >> ((l-1) * SPX_TREE_HEIGHT)) & TREE_MASK

const TREE_MASK: usize = (1 << SPX_TREE_HEIGHT) - 1;

pub struct HypertreeSecretKey {
    /// Master seed — trees are materialised on demand, never cached.
    seed: [u8; 20],
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
/// Input Digest layout:
///   [0..5] : seed packed as 5 little-endian u32s (20 bytes)
///   [5]    : domain marker 0x00 (WOTS pre-images)
///   [6]    : layer as u32
///   [7]    : leaf_index as u32
fn derive_wots_preimages(seed: &[u8; 20], layer: usize, leaf_index: usize) -> [Digest; SPX_WOTS_LEN] {
    // Each chain gets its own PRF output so chain secrets are independent.
    std::array::from_fn(|chain| {
        let mut input = Digest::default();
        for (i, chunk) in seed.chunks_exact(4).enumerate() {
            input[i] = F::new(u32::from_le_bytes(chunk.try_into().unwrap()));
        }
        input[5] = F::new(0x00);
        input[6] = F::new(layer as u32);
        // Encode (leaf_index, chain) together so each chain secret is unique.
        // Leaf index is at most 11 bits, SPX_WOTS_LEN is 32 (8 bits) so at most 19 bits are needed, which fits in a u32
        input[7] = F::new((leaf_index * SPX_WOTS_LEN + chain) as u32);
        poseidon16_compress_pair(&input, &Digest::default())
    })
}

/// Derive the WOTS+ randomness for a given (layer, leaf_index) deterministically.
///
/// Input Digest layout:
///   [0..5] : seed packed as 5 little-endian u32s (20 bytes)
///   [5]    : domain marker 0x01 (WOTS randomness)
///   [6]    : layer as u32
///   [7]    : leaf_index as u32
fn derive_wots_randomness(seed: &[u8; 20], layer: usize, leaf_index: usize) -> [F; RANDOMNESS_LEN_FE] {
    let mut input = Digest::default();
    for (i, chunk) in seed.chunks_exact(4).enumerate() {
        input[i] = F::new(u32::from_le_bytes(chunk.try_into().unwrap()));
    }
    input[5] = F::new(0x01);
    input[6] = F::new(layer as u32);
    input[7] = F::new(leaf_index as u32);
    let hash = poseidon16_compress_pair(&input, &Digest::default());
    // Take the first RANDOMNESS_LEN_FE = 7 elements of the hash output.
    hash[..RANDOMNESS_LEN_FE].try_into().unwrap()
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
///   right[1]    = randomness_counter  (retry counter for TARGET_SUM constraint)
///   right[2..8] = F::default()
fn hash_inter_layer_message(child_root: &Digest, layer: usize, randomness_counter: u32) -> Digest {
    let mut right = Digest::default();
    right[0] = F::new(layer as u32);
    right[1] = F::new(randomness_counter);
    poseidon16_compress_pair(child_root, &right)
}

/// Find the smallest randomness_counter such that the inter-layer message hash produces
/// a Digest that `wots_encode` accepts (indices sum to TARGET_SUM).
///
/// Deterministic — no RNG. Returns (counter, message_digest).
fn find_inter_layer_message(
    child_root: &Digest,
    layer: usize,
    randomness: &[F; RANDOMNESS_LEN_FE],
) -> (u32, Digest) {
    for counter in 0u32.. {
        let msg = hash_inter_layer_message(child_root, layer, counter);
        if wots_encode(&msg, layer as u32, randomness).is_some() {
            return (counter, msg);
        }
    }
    unreachable!("find_inter_layer_message did not converge")
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a SPHINCS+ hypertree key pair.
///
/// Only materialises the top-level tree (layer = SPX_D-1, tree_address = 0).
/// The public key is the root of that tree.
pub fn hypertree_key_gen(seed: [u8; 20]) -> (HypertreeSecretKey, HypertreePublicKey) {
    let (root, _levels) = build_layer_tree(&seed, SPX_D - 1, 0);
    (HypertreeSecretKey { seed }, HypertreePublicKey(root))
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
///   4. derive_wots_randomness; sign_with_randomness(message, layer, root[..6], randomness).
///   5. extract_auth_path.
///   6. For layers 0..SPX_D-2: find_inter_layer_message(root) → message for next layer.
pub fn hypertree_sign(
    sk: &HypertreeSecretKey,
    message: &Digest,
    leaf_index: usize,
    tree_address: usize,
) -> HypertreeSignature {
    let mut current_message = *message;
    let layers = std::array::from_fn(|layer| {
        // Subtree address for this layer.
        let layer_tree_address = tree_address >> (layer * SPX_TREE_HEIGHT);
        // Leaf within this layer's tree.
        let layer_leaf_index = if layer == 0 {
            leaf_index
        } else {
            (tree_address >> ((layer - 1) * SPX_TREE_HEIGHT)) & TREE_MASK
        };

        let (root, levels) = build_layer_tree(&sk.seed, layer, layer_tree_address);
        let global_leaf = layer_tree_address * (1 << SPX_TREE_HEIGHT) + layer_leaf_index;

        let preimages = derive_wots_preimages(&sk.seed, layer, global_leaf);
        let wots_sk = WotsSecretKey::new(preimages);

        let randomness = derive_wots_randomness(&sk.seed, layer, global_leaf);
        let wots_sig = wots_sk.sign_with_randomness(&current_message, layer as u32, randomness);

        let auth_path = extract_auth_path(&levels, layer_leaf_index);

        // Prepare message for the next layer (not needed after the top layer).
        if layer < SPX_D - 1 {
            let next_randomness = derive_wots_randomness(&sk.seed, layer + 1, global_leaf);
            let (_counter, next_msg) =
                find_inter_layer_message(&root, layer + 1, &next_randomness);
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
) -> HypertreePublicKey {
    let mut current_message = *message;

    for (layer, layer_sig) in sig.layers.iter().enumerate() {
        let layer_tree_address = tree_address >> (layer * SPX_TREE_HEIGHT);
        let layer_leaf_index = if layer == 0 {
            leaf_index
        } else {
            (tree_address >> ((layer - 1) * SPX_TREE_HEIGHT)) & TREE_MASK
        };

        let wots_pk = layer_sig
            .wots_sig
            .recover_public_key(&current_message, layer as u32)
            .expect("wots encoding invalid during hypertree_verify");

        // Hash the recovered public key to get the leaf node.
        let mut current = wots_pk.hash();

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
            // Randomness for the inter-layer message is stored in the next layer's WotsSignature.
            let next_randomness = sig.layers[layer + 1].wots_sig.randomness;
            let (_counter, next_msg) =
                find_inter_layer_message(&layer_root, layer + 1, &next_randomness);
            current_message = next_msg;
        } else {
            // Top layer: the recovered root is the public key.
            return HypertreePublicKey(layer_root);
        }

        let _ = layer_tree_address;
    }

    unreachable!("SPX_D layers iterated without returning")
}
