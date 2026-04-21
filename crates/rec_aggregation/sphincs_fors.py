from snark_lib import *
from sphincs_utils import *
from utils import *

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
    #   leaf_node  — DIGEST_LEN FEs: level-0 node digest from the signature
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
    hint_decompose_bits(leaf_index, bits, SPX_FORS_HEIGHT, LITTLE_ENDIAN)
    # Constrain each bit to {0, 1} and verify reconstruction matches leaf_index.
    for i in unroll(0, SPX_FORS_HEIGHT):
        assert bits[i] * (1 - bits[i]) == 0
        
    reconstructed: Mut = bits[0]
    for i in unroll(1, SPX_FORS_HEIGHT):
        reconstructed += bits[i] * 2**i
    assert leaf_index == reconstructed

    for i in unroll(0, SPX_FORS_HEIGHT / MERKLE_LEVEL_STEP):
        do_5_merkle_level(bits + i * MERKLE_LEVEL_STEP, leaf_node_arr + i * DIGEST_LEN, 
                          auth_path + MERKLE_LEVEL_STEP * i * DIGEST_LEN, leaf_node_arr + (i + 1) * DIGEST_LEN)        
    copy_8(leaf_node_arr + SPX_FORS_HEIGHT / MERKLE_LEVEL_STEP * DIGEST_LEN, out)
    return

@inline
def fors_verify(fors_indices, fors_pk):
    # Verify all SPX_FORS_TREES (9) FORS trees and fold their roots into the FORS public key.
    #
    # For each tree t in unroll(0, SPX_FORS_TREES):
    #   - Read leaf_secret at fors_sig + t * (1 + SPX_FORS_HEIGHT) * DIGEST_LEN.
    #   - Run fors_merkle_verify(fors_indices[t], leaf_node, auth_path, roots[t]).
    # Then fold the 9 roots into fors_pubkey via fold_roots.
    # Costs 9*15 (auth path) + 8 (fold) = 143 Poseidon calls.
    #
    # Inputs:
    #   fors_indices — SPX_FORS_TREES FEs, each < 2^SPX_FORS_HEIGHT;
    #                  produced by decompose_message_digest
    # Hints:
    #   fors_sig     — FORS_SIG_SIZE_FE FEs: introduced via hint_witness
    # Output:
    #   fors_pubkey  — DIGEST_LEN FEs: FORS public key (folded root hash)
    fors_sig = Array(FORS_SIG_SIZE_FE)
    hint_witness("fors_sig", fors_sig)

    roots = Array(SPX_FORS_TREES * DIGEST_LEN)
    for t in unroll(0, SPX_FORS_TREES):
        tree_base = fors_sig + t * (1 + SPX_FORS_HEIGHT) * DIGEST_LEN
        fors_merkle_verify(fors_indices[t], tree_base, tree_base + DIGEST_LEN, roots + t * DIGEST_LEN)

    # Fold the 9 roots into the FORS public key.
    fold_roots(roots, fors_pk)
    return
