from snark_lib import *
from sphincs_utils import *


@inline
def _iterate_hash_const_tweaked(input, k, pk_seed, adrs0, adrs1_start, output):
    # Hash a HalfDigest input for k steps with WOTS_HASH tweak, starting at hash_address = adrs1_start.
    # adrs0, adrs1_start, and k are all compile-time constants at every call site.
    #
    # Each step j: right = [input[0..4] | 0,0,0,0], then adrs_compress with adrs1 advancing by 2**ADRS1_HASH_SHIFT.
    #
    # input  — pointer to HALF_DIGEST_LEN (4) FEs
    # output — pointer to HALF_DIGEST_LEN (4) FEs
    if k == 0:
        copy_4(input, output)
    elif k == 1:
        right = Array(DIGEST_LEN)
        copy_4(input, right)
        right[4] = 0
        right[5] = 0
        right[6] = 0
        right[7] = 0
        adrs_compress(pk_seed, adrs0, adrs1_start, right, output)
    else:
        states = Array((k - 1) * HALF_DIGEST_LEN)
        right0 = Array(DIGEST_LEN)
        copy_4(input, right0)
        right0[4] = 0
        right0[5] = 0
        right0[6] = 0
        right0[7] = 0
        adrs_compress(pk_seed, adrs0, adrs1_start, right0, states)
        for j in unroll(1, k - 1):
            right_j = Array(DIGEST_LEN)
            copy_4(states + (j - 1) * HALF_DIGEST_LEN, right_j)
            right_j[4] = 0
            right_j[5] = 0
            right_j[6] = 0
            right_j[7] = 0
            adrs_compress(pk_seed, adrs0, adrs1_start + j * (2 ** ADRS1_HASH_SHIFT), right_j, states + j * HALF_DIGEST_LEN)
        right_last = Array(DIGEST_LEN)
        copy_4(states + (k - 2) * HALF_DIGEST_LEN, right_last)
        right_last[4] = 0
        right_last[5] = 0
        right_last[6] = 0
        right_last[7] = 0
        adrs_compress(pk_seed, adrs0, adrs1_start + (k - 1) * (2 ** ADRS1_HASH_SHIFT), right_last, output)
    return


@inline
def _chain_hash_pair_const(input_left, n, pk_seed, adrs0, kp_adrs1, chain_left, output_left, pair_sum_ptr):
    # Complete two adjacent WOTS+ chains (chain_left and chain_left+1) given compile-time n.
    # n = raw_left + raw_right * SPX_WOTS_W; chain_left and n are both compile-time here.
    #
    # adrs1 for chain c starting at step s: kp_adrs1 + c*(2**ADRS1_CHAIN_SHIFT) + s*(2**ADRS1_HASH_SHIFT)
    # kp_adrs1 = kp_addr (chain=0, hash=0 in adrs1 encoding — lower ADRS1_CHAIN_SHIFT bits only)
    debug_assert(n < SPX_WOTS_W**2)

    raw_left = n % SPX_WOTS_W
    raw_right = (n - raw_left) / SPX_WOTS_W
    chain_right = chain_left + 1

    n_left = (SPX_WOTS_W - 1) - raw_left
    adrs1_left = kp_adrs1 + chain_left * (2 ** ADRS1_CHAIN_SHIFT) + raw_left * (2 ** ADRS1_HASH_SHIFT)
    _iterate_hash_const_tweaked(input_left, n_left, pk_seed, adrs0, adrs1_left, output_left)

    n_right = (SPX_WOTS_W - 1) - raw_right
    input_right = input_left + HALF_DIGEST_LEN
    output_right = output_left + HALF_DIGEST_LEN
    adrs1_right = kp_adrs1 + chain_right * (2 ** ADRS1_CHAIN_SHIFT) + raw_right * (2 ** ADRS1_HASH_SHIFT)
    _iterate_hash_const_tweaked(input_right, n_right, pk_seed, adrs0, adrs1_right, output_right)

    pair_sum_ptr[0] = raw_left + raw_right
    return


@inline
def iterate_hash_pair(input_left, n, pk_seed, adrs0, kp_adrs1, pair_i, output_left, pair_sum_ptr):
    # Dispatch two adjacent WOTS+ chains (2*pair_i and 2*pair_i+1) via match_range over [0, SPX_WOTS_W²).
    # pair_i is a compile-time constant (from the unrolled loop in wots_encode_and_complete).
    # The lambda captures pair_i, so chain_left = 2*pair_i is compile-time inside _chain_hash_pair_const.
    debug_assert(n < SPX_WOTS_W**2)
    match_range(n, range(0, SPX_WOTS_W**2), lambda k: _chain_hash_pair_const(input_left, k, pk_seed, adrs0, kp_adrs1, 2 * pair_i, output_left, pair_sum_ptr))
    return


@inline
def wots_encode_and_complete(message, adrs0, adrs1, randomness, chain_tips, pk_seed, wots_pk_adrs0, wots_pk_adrs1, wots_pubkey):
    # Recover the WOTS+ public key from a message, ADRS values, randomness, and chain tips.
    #
    # Steps:
    #   1. Assert randomness[RANDOMNESS_LEN] == adrs0 and randomness[RANDOMNESS_LEN+1] == adrs1.
    #      encoding_fe = poseidon(message, randomness)  # right = [r0..r5, adrs0, adrs1]
    #   2. Decompose encoding_fe into 32 4-bit indices; assert sum == TARGET_SUM.
    #   3. For each pair i in 0..SPX_WOTS_LEN/2:
    #      complete both chains via iterate_hash_pair (WOTS_HASH tweak), accumulate pair sums.
    #   4. Fold 32 chain-end HalfDigests into wots_pubkey via fold_wots_pubkey (WOTS_PK tweak).
    #
    # Inputs:
    #   message       — DIGEST_LEN (8) FEs
    #   adrs0         — scalar: WOTS_HASH adrs0 (layer/type/tree) — compile-time at all call sites
    #   adrs1         — scalar: kp_addr (chain=0, hash=0)         — compile-time at all call sites
    #   randomness    — RANDOMNESS_LEN+2 (8) FEs: [r0..r5, adrs0, adrs1]
    #   chain_tips    — SPX_WOTS_LEN * HALF_DIGEST_LEN (128) FEs
    #   pk_seed       — pointer to HALF_DIGEST_LEN (4) FEs
    #   wots_pk_adrs0 — scalar: WOTS_PK adrs0 — compile-time
    #   wots_pk_adrs1 — scalar: kp_addr (chain=0, hash=0) — compile-time
    # Output:
    #   wots_pubkey   — HALF_DIGEST_LEN (4) FEs

    # Step 1: assert ADRS slots embedded in randomness, then compute encoding FEs.
    assert randomness[RANDOMNESS_LEN] == adrs0
    assert randomness[RANDOMNESS_LEN + 1] == adrs1

    encoding_fe = Array(DIGEST_LEN)
    poseidon16_compress(message, randomness, encoding_fe)

    # Step 2: decompose encoding_fe into 16 paired values (each packs two 4-bit indices).
    encoding = Array(SPX_WOTS_LEN / 2)
    remaining = Array(DIGEST_LEN)
    hint_decompose_wots(encoding, remaining, encoding_fe, 2, SPX_WOTS_LOGW * 2)

    for i in unroll(0, DIGEST_LEN):
        assert encoding[2 * i] < SPX_WOTS_W ** 2
        assert encoding[2 * i + 1] < SPX_WOTS_W ** 2
        assert encoding_fe[i] == encoding[2 * i] + encoding[2 * i + 1] * SPX_WOTS_W ** 2 + remaining[i] * 2 ** (SPX_WOTS_LOGW * 4)

    # Step 3: complete each chain pair with WOTS_HASH tweak.
    # adrs1 passed as kp_adrs1 — contains only kp_addr (chain=0, hash=0).
    chain_ends = Array(SPX_WOTS_LEN * HALF_DIGEST_LEN)
    pair_sum: Mut = 0
    for i in unroll(0, SPX_WOTS_LEN / 2):
        pair_sum_ptr = Array(1)
        iterate_hash_pair(chain_tips + 2 * i * HALF_DIGEST_LEN, encoding[i], pk_seed, adrs0, adrs1, i, chain_ends + 2 * i * HALF_DIGEST_LEN, pair_sum_ptr)
        pair_sum += pair_sum_ptr[0]

    assert pair_sum == TARGET_SUM

    # Step 4: fold 32 chain-end HalfDigests into wots_pubkey with WOTS_PK tweak.
    fold_wots_pubkey(pk_seed, wots_pk_adrs0, wots_pk_adrs1, chain_ends, wots_pubkey)
    return
