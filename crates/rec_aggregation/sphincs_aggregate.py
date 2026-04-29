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
    UPPER_LEAF = 31 - LEAF_BITS    # 20
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

    uppers = Array(N_SLOTS)
    hint_witness("digest_uppers", uppers)

    for i in unroll(0, SPX_D):
        assert indices[i] < 2**LEAF_BITS
        assert uppers[i] < 2**UPPER_LEAF
        assert expanded_a[i] == indices[i] + uppers[i] * 2**LEAF_BITS

    for t in unroll(0, FORS_A):
        assert indices[SPX_D + t] < 2**FORS_BITS
        assert uppers[SPX_D + t] < 2**UPPER_FORS
        assert expanded_a[SPX_D + t] == indices[SPX_D + t] + uppers[SPX_D + t] * 2**FORS_BITS

    for t in unroll(0, FORS_B):
        assert indices[SPX_D + FORS_A + t] < 2**FORS_BITS
        assert uppers[SPX_D + FORS_A + t] < 2**UPPER_FORS
        assert expanded_b[t] == indices[SPX_D + FORS_A + t] + uppers[SPX_D + FORS_A + t] * 2**FORS_BITS

    return indices


@inline
def sphincs_verify(pk, message):
    # Top-level SPHINCS+ signature verifier.
    #
    # Steps:
    #   1. Hash the MESSAGE_LEN (9)-FE message to an 8-FE message digest:
    #        right[0] = message[8]
    #        message_digest = poseidon(message[0..8], right)   (1 Poseidon call)
    #   2. Decompose the digest once via decompose_message_digest to obtain
    #      fors_indices[9] and layer_leaf_indices[3].
    #   3. Verify FORS: fors_pubkey = fors_verify(fors_indices).
    #   4. Verify hypertree: hypertree_verify(fors_pubkey,
    #                                         layer_leaf_indices, pk).
    #
    # Inputs:
    #   pk            — DIGEST_LEN FEs: signer's SPHINCS+ public key
    #   message       — MESSAGE_LEN (9) FEs: shared message
    #
    # Postcondition:
    #   Asserts the signature is valid for (pk, message).
    #   Fails the circuit if any sub-verification does not hold.
    right = Array(DIGEST_LEN)
    right[0] = message[8]
    set_to_7_zeros(right + 1)

    message_digest = Array(DIGEST_LEN)
    poseidon16_compress(message, right, message_digest)

    indices = decompose_message_digest(message_digest)
    
    fors_pk = Array(DIGEST_LEN)
    fors_verify(indices + SPX_D, fors_pk)
    hypertree_verify(fors_pk, indices, pk)
    return
