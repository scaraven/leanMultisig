from snark_lib import *
from sphincs_utils import *
from sphincs_wots import *


HYPERTREE_STEP = 5

@inline
def hypertree_merkle_verify(layer_leaf_index, leaf_node, auth_path, root_out):
    # Verify a single SPX_TREE_HEIGHT (11)-level binary Merkle auth path within one
    # hypertree layer. 11 = 1 + 5 + 5, so we decompose as:
    #   bit0        — low bit, constrained to {0,1} via bit-squaring
    #   sub_indices — two 5-bit chunks of the upper 10 bits, range-checked inside do_5_merkle_level
    #
    # The reconstruction assertion layer_leaf_index == bit0 + sub_indices[0]*2 + sub_indices[1]*2^6
    # binds the hints to layer_leaf_index.
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

    # Hint the low bit, constrain it to {0,1}, then derive the upper 10 bits.
    bit0 = Array(1)
    hint_decompose_bits(layer_leaf_index, bit0, 1, LITTLE_ENDIAN)
    assert bit0[0] * (1 - bit0[0]) == 0

    # upper_10 = (layer_leaf_index - bit0) / 2; decompose into two MERKLE_LEVEL_STEP-bit chunks.
    upper_10 = (layer_leaf_index - bit0[0]) / 2
    sub_indices = Array(2)
    hint_decompose_bits_fors(sub_indices, upper_10, HYPERTREE_STEP, 2)

    # Reconstruction: bind both hints to layer_leaf_index.
    assert layer_leaf_index == bit0[0] + sub_indices[0] * 2 + sub_indices[1] * 2**6

    # Walk the auth path: 1 level, then two 5-level strides.
    after_bit0 = Array(DIGEST_LEN)
    do_1_merkle_level(bit0[0], leaf_node, auth_path, after_bit0)

    after_chunk0 = Array(DIGEST_LEN)
    do_5_merkle_level(sub_indices[0], after_bit0, auth_path + DIGEST_LEN, after_chunk0)

    do_5_merkle_level(sub_indices[1], after_chunk0, auth_path + (1 + HYPERTREE_STEP) * DIGEST_LEN, root_out)
    return

@inline
def hypertree_verify(fors_pubkey, layer_leaf_indices, expected_pk):
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

    hypertree_sig = Array(HYPERTREE_SIG_SIZE_FE)
    hint_witness("hypertree_sig", hypertree_sig)

    # Shared zero buffer: read-only, use preamble ZERO_VEC_PTR directly.
    local_zero_buf = ZERO_VEC_PTR

    # messages[l * DIGEST_LEN] holds the input message for hypertree layer l.
    # Layer 0 message: poseidon(fors_pubkey, [0,...,0]).
    messages = Array((SPX_D + 1) * DIGEST_LEN)
    poseidon16_compress(fors_pubkey, local_zero_buf, messages)

    for l in unroll(0, SPX_D):
        # Per-layer layout in hypertree_sig:
        #   randomness:  RANDOMNESS_LEN (8) FEs  [r0..r6, layer_index]
        #   chain_tips:  SPX_WOTS_LEN * DIGEST_LEN (256) FEs
        #   auth_path:   SPX_TREE_HEIGHT * DIGEST_LEN (88) FEs
        layer_offset = l * (RANDOMNESS_LEN + (SPX_WOTS_LEN + SPX_TREE_HEIGHT) * DIGEST_LEN)
        randomness_ptr = hypertree_sig + layer_offset
        chain_tips_ptr = randomness_ptr + RANDOMNESS_LEN
        auth_path_ptr  = chain_tips_ptr + SPX_WOTS_LEN * DIGEST_LEN

        # Recover WOTS+ leaf node from the current message, layer randomness, and chain tips.
        wots_leaf = Array(DIGEST_LEN)
        wots_encode_and_complete(messages + l * DIGEST_LEN, l, randomness_ptr, chain_tips_ptr, local_zero_buf, wots_leaf)

        if l < SPX_D - 1:
            # Intermediate layer: walk the auth path to get the layer root, then hash it
            # with domain separator [l+1, 0, ..., 0] to produce the next layer's message.
            layer_root = Array(DIGEST_LEN)
            hypertree_merkle_verify(layer_leaf_indices[l], wots_leaf, auth_path_ptr, layer_root)

            domain_sep = Array(DIGEST_LEN)
            domain_sep[0] = l + 1
            set_to_7_zeros(domain_sep + 1)
            poseidon16_compress(layer_root, domain_sep, messages + (l + 1) * DIGEST_LEN)
        else:
            # Final layer: walk the auth path and assert the computed root equals expected_pk.
            hypertree_merkle_verify(layer_leaf_indices[l], wots_leaf, auth_path_ptr, expected_pk)
    return
