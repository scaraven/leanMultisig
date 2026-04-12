from snark_lib import *
from sphincs_utils import *


@inline
def wots_encode_and_complete(message, layer_index, randomness, chain_tips, wots_pubkey, local_zero_buf):
    # Recover the WOTS+ public key from a message, the layer index, the per-layer
    # randomness, and the signature chain tips.
    #
    # Steps:
    #   1. Compute encoding:
    #        a_right = [randomness[0..7], 0]  (8 FEs)
    #        A = poseidon(message, a_right)
    #        b_right = [layer_index, 0, 0, 0, 0, 0, 0, 0]
    #        B = poseidon(A, b_right)
    #   2. Decompose B into SPX_WOTS_LEN (32) 4-bit encoding indices via hint:
    #        extract 6 chunks of 4 bits each from bits 0–23 of each of B's 8 FEs (LE),
    #        take the first 32 chunks as encoding[0..32].
    #        Assert each encoding[i] < SPX_WOTS_W.
    #        Assert sum(encoding) == TARGET_SUM.
    #   3. For each chain i in 0..32:
    #        complete (SPX_WOTS_W - 1 - encoding[i]) hashes via iterate_hash,
    #        writing the result into chain_ends[i].
    #   4. Fold the 32 chain-end digests into a single public key hash via fold_wots_pubkey.
    #
    # Inputs:
    #   message      — DIGEST_LEN FEs: the value to encode (FORS pubkey hash or layer root)
    #   layer_index  — scalar in 0..SPX_D; compile-time constant at all call sites
    #   randomness   — RANDOMNESS_LEN (7) FEs: per-layer randomness from the signature
    #   chain_tips   — SPX_WOTS_LEN * DIGEST_LEN (256) FEs: mid-chain values from the signature
    # Output:
    #   wots_pubkey  — DIGEST_LEN FEs: recovered WOTS+ public key hash
    #
    # Preconditions:
    #   - chain_tips are provided via hint_sphincs_hypertree; their validity is implied
    #     by the final Merkle root check against expected_pk
    debug_assert(layer_index < SPX_D)

    # Step 1: compute encoding field elements
    #   A = poseidon(message, [randomness[0..7], 0])
    #   B = poseidon(A, [layer_index, 0, ..., 0])
    a_right = Array(DIGEST_LEN)
    for i in unroll(0, RANDOMNESS_LEN):
        a_right[i] = randomness[i]
    a_right[RANDOMNESS_LEN] = 0  # zero-pad the 8th element

    b_input = Array(DIGEST_LEN * 2)
    poseidon16_compress(message, a_right, b_input)

    b_input[8] = layer_index
    set_to_7_zeros(b_input + 9) # zero-pad the last 7 elements
    encoding_fe = Array(DIGEST_LEN)
    poseidon16_compress(b_input, b_input + 8, encoding_fe)

    # Step 2: decompose first 6 FEs of encoding_fe into 4-bit chunks via hint
    # 24 usable bits / 4 bits per chunk = 6 chunks per FE
    # 6 FEs × 6 chunks = 36 total; first 32 are the WOTS encoding indices
    encoding = Array(36)
    remaining = Array(6)
    hint_decompose_bits_xmss(encoding, remaining, encoding_fe, 6, 4)

    # Verify decomposition: each chunk in [0, 16), remainder < 127,
    # and reconstructed value matches original FE
    for i in unroll(0, 6):
        for j in unroll(0, 6):
            assert encoding[i * 6 + j] < SPX_WOTS_W

        partial_sum: Mut = remaining[i] * 2**24
        for j in unroll(0, 6):
            partial_sum += encoding[i * 6 + j] * SPX_WOTS_W**j
        assert partial_sum == encoding_fe[i]

    # Verify TARGET_SUM over the 32 encoding indices
    target_sum: Mut = 0
    for i in unroll(0, SPX_WOTS_LEN):
        target_sum += encoding[i]
    assert target_sum == TARGET_SUM

    # Step 3: complete each chain — hash (CHAIN_LENGTH - 1 - encoding[i]) more times
    chain_ends = Array(SPX_WOTS_LEN * DIGEST_LEN)
    for i in unroll(0, SPX_WOTS_LEN):
        n_remaining = (SPX_WOTS_W - 1) - encoding[i]
        iterate_hash(chain_tips + i * DIGEST_LEN, n_remaining, chain_ends + i * DIGEST_LEN, local_zero_buf)

    # Step 4: fold 32 chain-end digests into wots_pubkey
    fold_wots_pubkey(chain_ends, wots_pubkey)

    return
