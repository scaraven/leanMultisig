from snark_lib import *
from sphincs_utils import *


@inline
def wots_encode_and_complete(message, layer_index, randomness, chain_tips, local_zero_buf, wots_pubkey):
    # Recover the WOTS+ public key from a message, the layer index, the per-layer
    # randomness, and the signature chain tips.
    #
    # Steps:
    #   1. Compute encoding:
    #        Assert randomness[7] == layer_index.
    #        encoding_fe = poseidon(message, randomness)  # randomness = [r0..r6, layer_index]
    #   2. Decompose B into SPX_WOTS_LEN (32) 4-bit encoding indices via hint:
    #        extract 6 chunks of 4 bits each from bits 0–23 of each of B's 8 FEs (LE),
    #        take the first 32 chunks as encoding[0..32].
    #        Assert each encoding[i] < SPX_WOTS_W.
    #        Assert sum(encoding) == TARGET_SUM.
    #   3. For each pair i in 0..16:
    #        joint_n = encoding[2i] + encoding[2i+1] * SPX_WOTS_W
    #        complete both chains via iterate_hash_pair, accumulate pair sums.
    #        Assert accumulated pair_sum == TARGET_SUM.
    #   4. Fold the 32 chain-end digests into a single public key hash via fold_wots_pubkey.
    #
    # Inputs:
    #   message      — DIGEST_LEN FEs: the value to encode (FORS pubkey hash or layer root)
    #   layer_index  — scalar in 0..SPX_D; compile-time constant at all call sites
    #   randomness   — RANDOMNESS_LEN (8) FEs: [7 random FEs | layer_index] from the signature
    #   chain_tips   — SPX_WOTS_LEN * DIGEST_LEN (256) FEs: mid-chain values from the signature
    # Output:
    #   wots_pubkey  — DIGEST_LEN FEs: recovered WOTS+ public key hash
    #
    # Preconditions:
    #   - chain_tips are provided via hint_sphincs_hypertree; their validity is implied
    #     by the final Merkle root check against expected_pk
    debug_assert(layer_index < SPX_D)

    # Step 1: compute encoding field elements
    #   encoding_fe = poseidon(message, randomness)
    #   where randomness = [r0..r6, layer_index] — slot 7 holds layer_index (asserted below)
    assert randomness[RANDOMNESS_LEN - 1] == layer_index

    encoding_fe = Array(DIGEST_LEN)
    poseidon16_compress(message, randomness, encoding_fe)

    # Step 2: decompose each of the 8 FEs into 2 chunks of 8 bits (each chunk packs two 4-bit indices)
    # 2 chunks × 8 FEs = 16 paired values; remaining holds bits 16–30 of each FE
    encoding = Array(SPX_WOTS_LEN / 2)
    remaining = Array(DIGEST_LEN)
    hint_decompose_wots(encoding, remaining, encoding_fe, 2, SPX_WOTS_LOGW * 2)

    # We do not need to range check remaining here, because if remaining is too large, the encoding_fe decomposition will not pass
    for i in unroll(0, DIGEST_LEN):
        assert encoding[2 * i] < SPX_WOTS_W ** 2
        assert encoding[2 * i + 1] < SPX_WOTS_W ** 2
        assert encoding_fe[i] == encoding[2 * i] + encoding[2 * i + 1] * SPX_WOTS_W ** 2 + remaining[i] * 2 ** (SPX_WOTS_LOGW * 4)

    # Step 3: complete each chain pair — dispatch two adjacent chains per match_range call,
    # accumulating raw_left + raw_right per pair; the total equals sum(encoding[0..32]).
    chain_ends = Array(SPX_WOTS_LEN * DIGEST_LEN)
    pair_sum: Mut = 0
    for i in unroll(0, SPX_WOTS_LEN / 2):
        pair_sum_ptr = Array(1)
        iterate_hash_pair(chain_tips + 2 * i * DIGEST_LEN, encoding[i], chain_ends + 2 * i * DIGEST_LEN, pair_sum_ptr, local_zero_buf)
        pair_sum += pair_sum_ptr[0]

    # Verify TARGET_SUM: sum(raw_left[i] + raw_right[i]) == sum(encoding[0..32])
    assert pair_sum == TARGET_SUM

    # Step 4: fold 32 chain-end digests into wots_pubkey
    fold_wots_pubkey(chain_ends, wots_pubkey)
    return
