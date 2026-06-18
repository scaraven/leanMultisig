from snark_lib import *
from sphincs_fors import *
from sphincs_hypertree import *


@inline
def decompose_message_digest(message_digest):
    """
    Field-native decomposition of the 8-FE message digest using two Poseidon expand calls.

    Call A: poseidon([DS,   0, ..], message_digest) → expanded_a[8]
      expanded_a[0..2] lower 11 bits → leaf_idx, lli1, lli2
      expanded_a[3..7] lower 15 bits → fors_indices[0..4]

    Call B: poseidon([DS+1, 0, ..], message_digest) → expanded_b[8]
      expanded_b[0..3] lower 15 bits → fors_indices[5..8]

    Constraints per slot: index < 2^N, upper < 2^(31-N),
      expanded[slot] == index + upper * 2^N

    Hints:
      digest_indices — 12 values: [leaf_idx, lli1, lli2, fi[0]..fi[8]]
      digest_uppers  — 12 values: [upper0, upper1, upper2, ufi[0]..ufi[8]]
    """

    LEAF_BITS  = SPX_TREE_HEIGHT   # 11
    UPPER_LEAF_LOWER = (31 - LEAF_BITS) / 2  # 10
    UPPER_LEAF_HIGHER = 31 - LEAF_BITS - UPPER_LEAF_LOWER  # 10
    FORS_BITS  = SPX_FORS_HEIGHT   # 15
    UPPER_FORS = 31 - FORS_BITS    # 16
    FORS_A     = DIGEST_LEN - SPX_D
    FORS_B     = SPX_D + SPX_FORS_TREES - DIGEST_LEN
    N_SLOTS    = SPX_D + SPX_FORS_TREES  # 12

    domain_sep_a = Array(DIGEST_LEN)
    domain_sep_a[0] = 1298655175
    set_to_7_zeros(domain_sep_a + 1)

    domain_sep_b = Array(DIGEST_LEN)
    domain_sep_b[0] = 1298655176
    set_to_7_zeros(domain_sep_b + 1)

    expanded_a = Array(DIGEST_LEN)
    poseidon16_compress(domain_sep_a, message_digest, expanded_a)

    expanded_b = Array(DIGEST_LEN)
    poseidon16_compress(domain_sep_b, message_digest, expanded_b)

    indices = Array(N_SLOTS)
    hint_witness("digest_indices", indices)

    uppers_lower = Array(SPX_D)
    hint_witness("digest_uppers_low", uppers_lower)

    uppers_higher = Array(SPX_D)
    hint_witness("digest_uppers_high", uppers_higher)

    fors_uppers = Array(SPX_FORS_TREES)
    hint_witness("digest_uppers_fors", fors_uppers)

    for i in unroll(0, SPX_D):
        assert indices[i] < 2**LEAF_BITS
        assert uppers_lower[i] < 2**UPPER_LEAF_LOWER
        assert uppers_higher[i] < 2**UPPER_LEAF_HIGHER
        assert expanded_a[i] == indices[i] + (uppers_lower[i] * 2**LEAF_BITS) + (uppers_higher[i] * 2**(LEAF_BITS + UPPER_LEAF_LOWER))

    for t in unroll(0, FORS_A):
        assert indices[SPX_D + t] < 2**FORS_BITS
        assert fors_uppers[t] < 2**UPPER_FORS
        assert expanded_a[SPX_D + t] == indices[SPX_D + t] + (fors_uppers[t] * 2**FORS_BITS)

    for t in unroll(0, FORS_B):
        assert indices[SPX_D + FORS_A + t] < 2**FORS_BITS
        assert fors_uppers[FORS_A + t] < 2**UPPER_FORS
        assert expanded_b[t] == indices[SPX_D + FORS_A + t] + fors_uppers[FORS_A + t] * 2**FORS_BITS

    return indices


@inline
def sphincs_verify(pk, message):
    # Top-level SPHINCS+ signature verifier.
    #
    # Steps:
    #   1. Compute message digest via hmsg(r, pk_seed, pk_root, message) — two Poseidon calls:
    #        call1: left=[r[0..4] | pk_seed[0..4]], right=[pk_root[0..4] | message[0..4]]
    #        call2: left=[call1_out[0..4] | 0,0,0,0], right=[message[4..8] | 0,0,0,0]
    #   2. Decompose the digest via decompose_message_digest to obtain
    #      layer_leaf_indices[3] and fors_indices[9].
    #   3. Verify FORS: fors_pk = fors_verify(pk_seed, fors_indices).
    #   4. Verify hypertree: hypertree_verify(pk_seed, fors_pk, layer_leaf_indices, pk_root).
    #
    # Inputs:
    #   pk      — DIGEST_LEN (8) FEs: [pk_seed(4) | pk_root(4)]
    #   message — MESSAGE_LEN (8) FEs
    randomness_arr = Array(MSG_RANDOMNESS_LEN_FE)
    hint_witness("randomness", randomness_arr)

    pk_seed = pk
    pk_root = pk + HALF_DIGEST_LEN

    left1 = Array(DIGEST_LEN)
    copy_4(randomness_arr, left1)
    copy_4(pk_seed, left1 + HALF_DIGEST_LEN)

    right1 = Array(DIGEST_LEN)
    copy_4(pk_root, right1)
    for k in unroll(0, HALF_DIGEST_LEN):
        right1[HALF_DIGEST_LEN + k] = message[k]

    mid = Array(DIGEST_LEN)
    poseidon16_compress(left1, right1, mid)

    left2 = Array(DIGEST_LEN)
    copy_4(mid, left2)
    set_to_4_zeros(left2 + HALF_DIGEST_LEN)

    right2 = Array(DIGEST_LEN)
    for k in unroll(0, HALF_DIGEST_LEN):
        right2[k] = message[HALF_DIGEST_LEN + k]
    set_to_4_zeros(right2 + HALF_DIGEST_LEN)

    message_digest = Array(DIGEST_LEN)
    poseidon16_compress(left2, right2, message_digest)

    indices = decompose_message_digest(message_digest)

    # Hypertree leaf position binding the FORS keypair (matches extract_digest_hash in core.rs):
    #   idx_leaf = leaf_idx = indices[0]
    #   idx_tree = lli1 | (lli2 << SPX_TREE_HEIGHT) = indices[1] + indices[2] * 2^SPX_TREE_HEIGHT
    idx_leaf = indices[0]
    idx_tree = indices[1] + indices[2] * (2 ** SPX_TREE_HEIGHT)

    fors_pk = Array(HALF_DIGEST_LEN)
    fors_verify(pk_seed, idx_tree, idx_leaf, indices + SPX_D, fors_pk)

    hypertree_verify(pk_seed, fors_pk, indices, pk_root)
    return
