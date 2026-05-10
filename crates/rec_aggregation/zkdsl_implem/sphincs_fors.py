from snark_lib import *
from sphincs_utils import *
from utils import *

@inline
def fors_merkle_verify(leaf_index, leaf_node, auth_path, out):
    # Verify a single SPX_FORS_HEIGHT (15)-level binary Merkle auth path.
    #
    # leaf_index is decomposed into N_GROUPS = SPX_FORS_HEIGHT / MERKLE_LEVEL_STEP
    # sub-indices of MERKLE_LEVEL_STEP bits each via hint_decompose_bits_xmss.
    # Each sub-index is range-constrained to [0, 2^MERKLE_LEVEL_STEP) by match_range,
    # and the reconstruction assert ensures the decomposition is faithful.
    #
    # Inputs:
    #   leaf_index — scalar < 2^SPX_FORS_HEIGHT; range-checked by the caller
    #   leaf_node  — DIGEST_LEN FEs: level-0 node digest from the signature
    #   auth_path  — SPX_FORS_HEIGHT * DIGEST_LEN FEs: sibling hashes, bottom-up
    # Output:
    #   out        — DIGEST_LEN FEs: computed Merkle root written by this function;
    #                the caller compares it against the expected root
    #
    # Precondition: leaf_index < 2^SPX_FORS_HEIGHT
    debug_assert(leaf_index < 2**SPX_FORS_HEIGHT)

    N_GROUPS = SPX_FORS_HEIGHT / MERKLE_LEVEL_STEP

    sub_indices = Array(N_GROUPS)
    hint_decompose_bits_fors(sub_indices, leaf_index, MERKLE_LEVEL_STEP, N_GROUPS)

    # Verify the decomposition reconstructs leaf_index.
    reconstructed: Mut = sub_indices[0]
    assert sub_indices[0] < 2**MERKLE_LEVEL_STEP
    
    for i in unroll(1, N_GROUPS):
        reconstructed += sub_indices[i] * 2**(i * MERKLE_LEVEL_STEP)
        assert sub_indices[i] < 2**MERKLE_LEVEL_STEP
    assert leaf_index == reconstructed

    leaf_node_arr = Array(DIGEST_LEN * (N_GROUPS - 1))

    do_5_merkle_level(sub_indices[0], leaf_node, auth_path, leaf_node_arr)
    for i in unroll(1, N_GROUPS - 1):
        do_5_merkle_level(sub_indices[i], leaf_node_arr + (i - 1) * DIGEST_LEN,
                           auth_path + MERKLE_LEVEL_STEP * i * DIGEST_LEN,
                           leaf_node_arr + i * DIGEST_LEN)
    do_5_merkle_level(sub_indices[N_GROUPS - 1], leaf_node_arr + (N_GROUPS - 2) * DIGEST_LEN,
                                            auth_path + MERKLE_LEVEL_STEP * (N_GROUPS - 1) * DIGEST_LEN,
                                            out)
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
