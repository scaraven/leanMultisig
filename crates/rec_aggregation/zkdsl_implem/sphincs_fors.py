from snark_lib import *
from sphincs_utils import *
from utils import *

@inline
def _fors_merkle_verify_const(tree_index, pk_seed_offset, leaf_index, leaf_secret, auth_path, out):
    # Inner implementation of fors_merkle_verify with compile-time tree_index.
    # Called via match_range in fors_merkle_verify.
    #
    # For each group of MERKLE_LEVEL_STEP Merkle levels, we hint MERKLE_LEVEL_STEP adrs1 values
    # and MERKLE_LEVEL_STEP remainders, range-checked to prove they correctly encode
    # node_index = leaf_index >> H at each absolute height H.
    debug_assert(leaf_index < 2**SPX_FORS_HEIGHT)

    FORS_LEAF_ADRS0 = ADRS_FORS_TREE * (2 ** ADRS0_TYPE_SHIFT) + tree_index * (2 ** ADRS0_TREE_SHIFT)
    leaf_right = Array(DIGEST_LEN)
    copy_4(leaf_secret, leaf_right)
    leaf_right[4] = 0
    leaf_right[5] = 0
    leaf_right[6] = 0
    leaf_right[7] = 0
    leaf_node = Array(HALF_DIGEST_LEN)
    adrs_compress_hcl(pk_seed_offset, FORS_LEAF_ADRS0, leaf_index, leaf_right, leaf_node)

    N_GROUPS = SPX_FORS_HEIGHT / MERKLE_LEVEL_STEP

    sub_indices = Array(N_GROUPS)
    hint_decompose_bits_fors(sub_indices, leaf_index, MERKLE_LEVEL_STEP, N_GROUPS)

    reconstructed: Mut = sub_indices[0]
    assert sub_indices[0] < 2**MERKLE_LEVEL_STEP

    for i in unroll(1, N_GROUPS):
        reconstructed += sub_indices[i] * 2**(i * MERKLE_LEVEL_STEP)
        assert sub_indices[i] < 2**MERKLE_LEVEL_STEP
    assert leaf_index == reconstructed

    # For each group, hint the adrs1 and remainder values for that group's 5 levels.
    # hint_fors_node_adrs(adrs1_ptr, rem_ptr, leaf_index, tree_ht_start) fills
    # MERKLE_LEVEL_STEP slots at each pointer; values are range-checked in do_5_fors_merkle_level_const.
    adrs1_buf = Array(N_GROUPS * MERKLE_LEVEL_STEP)
    rem_buf   = Array(N_GROUPS * MERKLE_LEVEL_STEP)
    for i in unroll(0, N_GROUPS):
        hint_fors_node_adrs(adrs1_buf + i * MERKLE_LEVEL_STEP,
                            rem_buf   + i * MERKLE_LEVEL_STEP,
                            leaf_index, i * MERKLE_LEVEL_STEP)

    intermediate_nodes = Array(HALF_DIGEST_LEN * (N_GROUPS - 1))

    do_5_fors_merkle_level(sub_indices[0], pk_seed_offset, tree_index, 0,
                            adrs1_buf, rem_buf, leaf_index,
                            leaf_node, auth_path, intermediate_nodes)
    for i in unroll(1, N_GROUPS - 1):
        do_5_fors_merkle_level(sub_indices[i], pk_seed_offset, tree_index, i * MERKLE_LEVEL_STEP,
                                adrs1_buf + i * MERKLE_LEVEL_STEP,
                                rem_buf   + i * MERKLE_LEVEL_STEP, leaf_index,
                                intermediate_nodes + (i - 1) * HALF_DIGEST_LEN,
                                auth_path + MERKLE_LEVEL_STEP * i * HALF_DIGEST_LEN,
                                intermediate_nodes + i * HALF_DIGEST_LEN)
    do_5_fors_merkle_level(sub_indices[N_GROUPS - 1], pk_seed_offset, tree_index,
                            (N_GROUPS - 1) * MERKLE_LEVEL_STEP,
                            adrs1_buf + (N_GROUPS - 1) * MERKLE_LEVEL_STEP,
                            rem_buf   + (N_GROUPS - 1) * MERKLE_LEVEL_STEP, leaf_index,
                            intermediate_nodes + (N_GROUPS - 2) * HALF_DIGEST_LEN,
                            auth_path + MERKLE_LEVEL_STEP * (N_GROUPS - 1) * HALF_DIGEST_LEN,
                            out)
    return


@inline
def fors_merkle_verify(pk_seed_offset, tree_index, leaf_index, leaf_secret, auth_path, out):
    # Verify a single SPX_FORS_HEIGHT (15)-level binary Merkle auth path.
    # Dispatches on tree_index via match_range so that the compile-time tree_index reaches
    # _fors_merkle_verify_const (needed for compile-time ADRS constants).
    #
    # Inputs:
    #   pk_seed_offset — compile-time constant: address of this signer's pk_seed in the pk_seed table
    #   tree_index  — runtime or compile-time scalar: which FORS tree (0..SPX_FORS_TREES-1)
    #   leaf_index  — scalar < 2^SPX_FORS_HEIGHT
    #   leaf_secret — HALF_DIGEST_LEN FEs: raw FORS leaf secret (pre-image)
    #   auth_path   — SPX_FORS_HEIGHT * HALF_DIGEST_LEN FEs: sibling hashes, bottom-up
    # Output:
    #   out         — HALF_DIGEST_LEN FEs: computed Merkle root
    match_range(tree_index, range(0, SPX_FORS_TREES), lambda t: _fors_merkle_verify_const(t, pk_seed_offset, leaf_index, leaf_secret, auth_path, out))
    return

@inline
def fors_verify(pk_seed_offset, fors_indices, fors_pk):
    # Verify all SPX_FORS_TREES (9) FORS trees and fold their roots into the FORS public key.
    #
    # For each tree t in unroll(0, SPX_FORS_TREES):
    #   - Read leaf_secret at fors_sig + t * (1 + SPX_FORS_HEIGHT) * HALF_DIGEST_LEN.
    #   - Run fors_merkle_verify(pk_seed_offset, t, fors_indices[t], leaf_secret, auth_path, roots[t]).
    # Then fold the 9 roots into fors_pubkey via fold_roots.
    # Costs 9*(1 + 15) (leaf hash + auth path) + 8 (fold) = 152 adrs_compress_hcl calls.
    #
    # Inputs:
    #   pk_seed_offset — compile-time constant: address of this signer's pk_seed in the pk_seed table
    #   fors_indices — SPX_FORS_TREES FEs, each < 2^SPX_FORS_HEIGHT
    # Hints:
    #   fors_sig     — FORS_SIG_SIZE_FE FEs: introduced via hint_witness
    # Output:
    #   fors_pk      — HALF_DIGEST_LEN (4) FEs: FORS public key (folded root hash)
    fors_sig = Array(FORS_SIG_SIZE_FE)
    hint_witness("fors_sig", fors_sig)

    roots = Array(SPX_FORS_TREES * HALF_DIGEST_LEN)
    for t in unroll(0, SPX_FORS_TREES):
        tree_base = fors_sig + t * (1 + SPX_FORS_HEIGHT) * HALF_DIGEST_LEN
        fors_merkle_verify(pk_seed_offset, t, fors_indices[t], tree_base, tree_base + HALF_DIGEST_LEN, roots + t * HALF_DIGEST_LEN)

    fold_roots(pk_seed_offset, roots, fors_pk)
    return
