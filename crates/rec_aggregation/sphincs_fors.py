from snark_lib import *
from sphincs_utils import *


@inline
def fors_merkle_verify(leaf_index, leaf_node, auth_path, out):
    # Verify a single SPX_FORS_HEIGHT (15)-level binary Merkle auth path.
    #
    # At each level lv in 0..15, extracts bit (leaf_index >> lv) & 1 and dispatches
    # to do_1_merkle_level. Because leaf_index is range-checked < 2^SPX_FORS_HEIGHT
    # by decompose_message_digest, each bit is implicitly in {0, 1}.
    #
    # Inputs:
    #   leaf_index — scalar < 2^SPX_FORS_HEIGHT; range-checked by the caller
    #   leaf_node  — DIGEST_LEN FEs: poseidon(leaf_secret, zero_buf)
    #   auth_path  — SPX_FORS_HEIGHT * DIGEST_LEN (120) FEs: sibling hashes, bottom-up
    # Output:
    #   root_out   — DIGEST_LEN FEs: computed Merkle root written by this function;
    #                the caller compares it against the expected root
    #
    # Precondition: leaf_index < 2^SPX_FORS_HEIGHT
    debug_assert(leaf_index < 2**SPX_FORS_HEIGHT)

    leaf_node_arr = Array(DIGEST_LEN * (1 + SPX_FORS_HEIGHT / MERKLE_LEVEL_STEP))
    copy_8(leaf_node, leaf_node_arr)

    bits = Array(SPX_FORS_HEIGHT)
    # As of now this is not constrained!
    hint_decompose_bits(leaf_index, bits, SPX_FORS_HEIGHT, LITTLE_ENDIAN)

    for i in unroll(0, SPX_FORS_HEIGHT / MERKLE_LEVEL_STEP):
        do_3_merkle_level(bits + i * MERKLE_LEVEL_STEP, leaf_node_arr + i * DIGEST_LEN, 
                          auth_path + MERKLE_LEVEL_STEP * i * DIGEST_LEN, leaf_node_arr + (i + 1) * DIGEST_LEN)        
    copy_8(leaf_node_arr + SPX_FORS_HEIGHT / MERKLE_LEVEL_STEP * DIGEST_LEN, out)
    return


# @inline
# def fors_verify(fors_sig, fors_indices, fors_pubkey):
#     # Verify all SPX_FORS_TREES (9) FORS trees and fold their roots into the FORS public key.
#     #
#     # For each tree t in unroll(0, SPX_FORS_TREES):
#     #   - Read leaf_secret at fors_sig + t * (1 + SPX_FORS_HEIGHT) * DIGEST_LEN.
#     #   - Hash leaf_secret to level-0 node: leaf_node = poseidon(leaf_secret, zero_buf).
#     #   - Run fors_merkle_verify(fors_indices[t], leaf_node, auth_path, roots[t]).
#     # Then fold the 9 roots into fors_pubkey via fold_roots.
#     # Costs 9 (leaf hashes) + 9*15 (auth path) + 8 (fold) = 152 Poseidon calls.
#     #
#     # Inputs:
#     #   fors_sig     — FORS_SIG_SIZE_FE (1152) FEs loaded via hint_sphincs_fors;
#     #                  layout: for t in 0..9: [leaf_secret(8) | auth_path(120)]
#     #   fors_indices — SPX_FORS_TREES FEs, each < 2^SPX_FORS_HEIGHT;
#     #                  produced by decompose_message_digest
#     # Output:
#     #   fors_pubkey  — DIGEST_LEN FEs: FORS public key (folded root hash)
#     pass
