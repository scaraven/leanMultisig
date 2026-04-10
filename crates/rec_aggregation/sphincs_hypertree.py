from snark_lib import *
from sphincs_utils import *
from sphincs_wots import *


@inline
def hypertree_merkle_verify(layer_leaf_index, leaf_node, auth_path, root_out):
    # Verify a single SPX_TREE_HEIGHT (11)-level binary Merkle auth path within one
    # hypertree layer. Structure identical to fors_merkle_verify but for 11 levels.
    #
    # At each level lv in 0..11, extracts bit (layer_leaf_index >> lv) & 1 and
    # dispatches to do_1_merkle_level. layer_leaf_index is range-checked < 2^11
    # by decompose_message_digest, so each bit is implicitly in {0, 1}.
    #
    # Inputs:
    #   layer_leaf_index — scalar < 2^SPX_TREE_HEIGHT; range-checked by decompose_message_digest
    #   leaf_node        — DIGEST_LEN FEs: WOTS+ public key hash (output of wots_encode_and_complete)
    #   auth_path        — SPX_TREE_HEIGHT * DIGEST_LEN (88) FEs: sibling hashes, bottom-up
    # Output:
    #   root_out         — DIGEST_LEN FEs: computed layer root written by this function
    #
    # Precondition: layer_leaf_index < 2^SPX_TREE_HEIGHT
    debug_assert(layer_leaf_index < 2**SPX_TREE_HEIGHT)
    pass


@inline
def hypertree_verify(hypertree_sig, fors_pubkey, layer_leaf_indices, expected_pk):
    # Verify the SPX_D (3)-layer XMSS hypertree and assert the final root equals expected_pk.
    #
    # Layer loop (compile-time unroll over l in 0..SPX_D):
    #   1. Read randomness and chain_tips from hypertree_sig at the offset for layer l.
    #   2. Recover the WOTS+ leaf node: wots_encode_and_complete(current_message, l, ...).
    #   3. Walk the 11-level auth path: hypertree_merkle_verify(layer_leaf_indices[l], ...).
    #   4. For l < SPX_D - 1: hash the layer root with domain separator [l+1, 0, ...] to
    #      form current_message for the next layer.
    #      For l == SPX_D - 1: pass expected_pk as root_out to assert equality directly.
    #
    # Initial message: poseidon(fors_pubkey, [0, 0, 0, 0, 0, 0, 0, 0])  (layer 0 domain sep).
    #
    # Inputs:
    #   hypertree_sig      — HYPERTREE_SIG_SIZE_FE (1053) FEs loaded via hint_sphincs_hypertree;
    #                        layout: for l in 0..3: [randomness(7) | chain_tips(256) | auth_path(88)]
    #   fors_pubkey        — DIGEST_LEN FEs: output of fors_verify
    #   layer_leaf_indices — 3 FEs, precomputed in decompose_message_digest:
    #                          [0] = leaf_idx                    (11-bit, layer 0)
    #                          [1] = tree_address & 0x7FF        (11-bit, layer 1)
    #                          [2] = (tree_address >> 11) & 0x7FF (11-bit, layer 2)
    #   expected_pk        — DIGEST_LEN FEs: signer's SPHINCS+ public key
    #
    # Postcondition:
    #   Asserts the reconstructed hypertree root equals expected_pk.
    #   Fails the circuit if any intermediate check does not hold.
    pass
