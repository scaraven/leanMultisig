from snark_lib import *
from sphincs_utils import *
from utils import *

@inline
def _fors_merkle_verify_const(tree_index, pk_seed, leaf_index, leaf_secret, out):
    # Inner implementation of fors_merkle_verify with compile-time tree_index.
    # Called via match_range in fors_merkle_verify.
    #
    # For each group of MERKLE_LEVEL_STEP Merkle levels, we hint MERKLE_LEVEL_STEP adrs1 values
    # and MERKLE_LEVEL_STEP remainders, range-checked to prove they correctly encode
    # node_index = leaf_index >> H at each absolute height H.
    #
    # Auth-path siblings are not passed in: each Merkle level streams its sibling from the
    # "fors_auth" hint queue directly into its Poseidon right-input block (see
    # do_5_merkle_block_fors_const). The leaf hash uses ZERO_VEC as its right half, so the
    # leaf level consumes no sibling — the queue holds exactly the 15 auth-path nodes per tree.
    debug_assert(leaf_index < 2**SPX_FORS_HEIGHT)

    # adrs0 (FORS_ADRS0) is constant across the leaf hash AND all 15 Merkle levels of this tree,
    # so the 5-FE tweak prefix [pk_seed | adrs0] is built once here and threaded into every
    # compression below (the leaf hash and the three do_5 groups).
    FORS_ADRS0 = ADRS_FORS_TREE * (2 ** ADRS0_TYPE_SHIFT) + tree_index * (2 ** ADRS0_TREE_SHIFT)
    tweak5 = make_tweak5(pk_seed, FORS_ADRS0)

    leaf_node = Array(HALF_DIGEST_LEN)
    adrs_compress_pair_t5(tweak5, leaf_index, leaf_secret, ZERO_VEC_PTR, leaf_node)

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
    # MERKLE_LEVEL_STEP slots at each pointer; values are range-checked in do_5_merkle_block_fors_const.
    adrs1_buf = Array(N_GROUPS * MERKLE_LEVEL_STEP)
    rem_buf   = Array(N_GROUPS * MERKLE_LEVEL_STEP)
    for i in unroll(0, N_GROUPS):
        hint_fors_node_adrs(adrs1_buf + i * MERKLE_LEVEL_STEP,
                            rem_buf   + i * MERKLE_LEVEL_STEP,
                            leaf_index, i * MERKLE_LEVEL_STEP)

    intermediate_nodes = Array(HALF_DIGEST_LEN * (N_GROUPS - 1))

    do_5_fors_merkle_level(sub_indices[0], tweak5, 0,
                            adrs1_buf, rem_buf, leaf_index,
                            leaf_node, intermediate_nodes)
    for i in unroll(1, N_GROUPS - 1):
        do_5_fors_merkle_level(sub_indices[i], tweak5, i * MERKLE_LEVEL_STEP,
                                adrs1_buf + i * MERKLE_LEVEL_STEP,
                                rem_buf   + i * MERKLE_LEVEL_STEP, leaf_index,
                                intermediate_nodes + (i - 1) * HALF_DIGEST_LEN,
                                intermediate_nodes + i * HALF_DIGEST_LEN)
    do_5_fors_merkle_level(sub_indices[N_GROUPS - 1], tweak5,
                            (N_GROUPS - 1) * MERKLE_LEVEL_STEP,
                            adrs1_buf + (N_GROUPS - 1) * MERKLE_LEVEL_STEP,
                            rem_buf   + (N_GROUPS - 1) * MERKLE_LEVEL_STEP, leaf_index,
                            intermediate_nodes + (N_GROUPS - 2) * HALF_DIGEST_LEN,
                            out)
    return


@inline
def fors_merkle_verify(pk_seed, tree_index, leaf_index, leaf_secret, out):
    # Verify a single SPX_FORS_HEIGHT (15)-level binary Merkle auth path.
    # Dispatches on tree_index via match_range so that the compile-time tree_index reaches
    # _fors_merkle_verify_const (needed for compile-time ADRS constants).
    #
    # Inputs:
    #   pk_seed     — pointer to HALF_DIGEST_LEN (4) FEs: per-signer public seed
    #   tree_index  — runtime or compile-time scalar: which FORS tree (0..SPX_FORS_TREES-1)
    #   leaf_index  — scalar < 2^SPX_FORS_HEIGHT
    #   leaf_secret — HALF_DIGEST_LEN FEs: raw FORS leaf secret (pre-image)
    # Siblings:
    #   consumed level-by-level from the "fors_auth" hint queue (15 nodes per tree, bottom-up)
    # Output:
    #   out         — HALF_DIGEST_LEN FEs: computed Merkle root
    match_range(tree_index, range(0, SPX_FORS_TREES), lambda t: _fors_merkle_verify_const(t, pk_seed, leaf_index, leaf_secret, out))
    return

@inline
def fors_verify(pk_seed, fors_indices, fors_pk):
    # Verify all SPX_FORS_TREES (9) FORS trees and fold their roots into the FORS public key.
    #
    # For each tree t in unroll(0, SPX_FORS_TREES):
    #   - Read leaf_secret at fors_sig + t * (1 + SPX_FORS_HEIGHT) * HALF_DIGEST_LEN.
    #   - Run fors_merkle_verify(pk_seed, t, fors_indices[t], leaf_secret, auth_path, roots[t]).
    # Then fold the 9 roots into fors_pubkey via fold_roots.
    # Costs 9*(1 + 15) (leaf hash + auth path) + 8 (fold) = 152 adrs_compress calls.
    #
    # Inputs:
    #   pk_seed      — pointer to HALF_DIGEST_LEN (4) FEs: per-signer public seed
    #   fors_indices — SPX_FORS_TREES FEs, each < 2^SPX_FORS_HEIGHT
    # Hints:
    #   fors_sig     — SPX_FORS_TREES * HALF_DIGEST_LEN FEs: the 9 leaf secrets, via hint_witness
    #   fors_auth    — auth-path siblings, consumed level-by-level inside fors_merkle_verify
    #                  (15 nodes per tree, bottom-up; same order as the legacy auth-path layout)
    # Output:
    #   fors_pk      — HALF_DIGEST_LEN (4) FEs: FORS public key (folded root hash)
    leaf_secrets = Array(SPX_FORS_TREES * HALF_DIGEST_LEN)
    hint_witness("fors_sig", leaf_secrets)

    # Each FORS tree root is written DIRECTLY into its contiguous fold-buffer tip-slot
    # (root t @ fold_buf + t * HALF_DIGEST_LEN), so the fold_roots T-Sponge reads each absorb
    # block as a contiguous 8-FE pair with no copy. SPX_FORS_TREES (9) is odd: the buffer holds
    # one extra (10th) tip, zeroed here, that pads the final absorb block to [root8 | 0,0,0,0].
    fold_buf = Array(fold_tips_len(SPX_FORS_TREES + 1))
    for t in unroll(0, SPX_FORS_TREES):
        leaf_secret = leaf_secrets + t * HALF_DIGEST_LEN
        fors_merkle_verify(pk_seed, t, fors_indices[t], leaf_secret, fold_buf + t * HALF_DIGEST_LEN)
    for i in unroll(0, HALF_DIGEST_LEN):
        fold_buf[SPX_FORS_TREES * HALF_DIGEST_LEN + i] = 0

    fold_roots(pk_seed, fold_buf, fors_pk)
    return
