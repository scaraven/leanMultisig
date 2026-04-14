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

    bits = Array(SPX_TREE_HEIGHT)
    decompose_bits(layer_leaf_index, bits, SPX_TREE_HEIGHT, LITTLE_ENDIAN)

    # Ensure bits are constrained
    for i in unroll(0, SPX_TREE_HEIGHT):
        assert bits[i] * (1 - bits[i]) == 0
        
    reconstructed: Mut = bits[0]
    for i in unroll(1, SPX_TREE_HEIGHT):
        reconstructed += bits[i] * 2**i
    assert layer_leaf_index == reconstructed

    intermediate_states = Array((SPX_TREE_HEIGHT + 1) * DIGEST_LEN)
    copy_8(leaf_node, intermediate_states)
    for i in unroll(0, SPX_TREE_HEIGHT):
        do_1_merkel_level(bits[i], intermediate_states + i * DIGEST_LEN, auth_path + i * DIGEST_LEN, intermediate_states + (i + 1) * DIGEST_LEN)
    
    copy_8(intermediate_states + SPX_TREE_HEIGHT * DIGEST_LEN, root_out)
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

    # Shared zero buffer: read-only, used for initial message hash and iterate_hash calls.
    local_zero_buf = Array(DIGEST_LEN)
    set_to_8_zeros(local_zero_buf)

    # messages[l * DIGEST_LEN] holds the input message for hypertree layer l.
    # Layer 0 message: poseidon(fors_pubkey, [0,...,0]).
    messages = Array((SPX_D + 1) * DIGEST_LEN)
    poseidon16_compress(fors_pubkey, local_zero_buf, messages)

    for l in unroll(0, SPX_D):
        # Per-layer layout in hypertree_sig:
        #   randomness:  RANDOMNESS_LEN (7) FEs
        #   chain_tips:  SPX_WOTS_LEN * DIGEST_LEN (256) FEs
        #   auth_path:   SPX_TREE_HEIGHT * DIGEST_LEN (88) FEs
        layer_offset = l * (RANDOMNESS_LEN + (SPX_WOTS_LEN + SPX_TREE_HEIGHT) * DIGEST_LEN)
        randomness_ptr = hypertree_sig + layer_offset
        chain_tips_ptr = randomness_ptr + RANDOMNESS_LEN
        auth_path_ptr  = chain_tips_ptr + SPX_WOTS_LEN * DIGEST_LEN

        # Recover WOTS+ leaf node from the current message, layer randomness, and chain tips.
        wots_leaf = Array(DIGEST_LEN)
        wots_encode_and_complete(messages + l * DIGEST_LEN, l, randomness_ptr, chain_tips_ptr, wots_leaf, local_zero_buf)

        if l < SPX_D - 1:
            # Intermediate layer: walk the auth path to get the layer root, then hash it
            # with domain separator [l+1, 0, ..., 0] to produce the next layer's message.
            layer_root = Array(DIGEST_LEN)
            hypertree_merkle_verify(layer_leaf_indices[l], wots_leaf, auth_path_ptr, layer_root)

            domain_sep = Array(DIGEST_LEN)
            domain_sep[0] = l + 1
            for j in unroll(1, DIGEST_LEN):
                domain_sep[j] = 0
            poseidon16_compress(layer_root, domain_sep, messages + (l + 1) * DIGEST_LEN)
        else:
            # Final layer: walk the auth path and assert the computed root equals expected_pk.
            final_root = Array(DIGEST_LEN)
            hypertree_merkle_verify(layer_leaf_indices[l], wots_leaf, auth_path_ptr, final_root)
            for j in unroll(0, DIGEST_LEN):
                assert final_root[j] == expected_pk[j]
    return
