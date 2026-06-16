from snark_lib import *
from sphincs_utils import *


@inline
def _iterate_hash_const_tweaked(input, k, pk_seed, adrs0, adrs1_start, output):
    # Run k WOTS_HASH chain steps starting at hash_address = adrs1_start.
    # adrs0, adrs1_start, and k are all compile-time constants at every call site.
    #
    # The chain carries FULL 8-FE state between steps (the 8-FE Poseidon output of one step is
    # fed directly as the next step's right input — no truncation, no zero-write, no copy). This
    # matches the Rust reference iterate_hash_full_from_full: the revealed mid-chain tip is
    # 8-FE, and only the chain-final value (the WOTS-pubkey component) is truncated to 4 FE.
    #
    # input  — pointer to DIGEST_LEN (8) FEs: the revealed 8-FE chain tip
    # output — pointer to HALF_DIGEST_LEN (4) FEs: chain end, truncated (fed to fold_wots_pubkey)
    if k == 0:
        # Zero remaining steps: the chain end is the tip itself, truncated to its low 4 FE.
        copy_4(input, output)
    elif k == 1:
        # Single step: full 8-FE input → 4-FE output (out4 truncating compress).
        tweak5 = make_tweak5(pk_seed, adrs0)
        adrs_compress_pair_t5_block(tweak5, adrs1_start, input, output)
    else:
        # adrs0 is constant across the chain steps: build the tweak prefix once.
        # First k-1 steps keep full 8-FE state (out8); the last step truncates to 4-FE.
        tweak5 = make_tweak5(pk_seed, adrs0)
        states = Array((k - 1) * DIGEST_LEN)
        adrs_compress_pair_t5_block_out8(tweak5, adrs1_start, input, states)
        for j in unroll(1, k - 1):
            adrs_compress_pair_t5_block_out8(tweak5, adrs1_start + j * (2 ** ADRS1_HASH_SHIFT), states + (j - 1) * DIGEST_LEN, states + j * DIGEST_LEN)
        adrs_compress_pair_t5_block(tweak5, adrs1_start + (k - 1) * (2 ** ADRS1_HASH_SHIFT), states + (k - 2) * DIGEST_LEN, output)
    return


@inline
def iterate_hash_single(input, n, pk_seed, adrs0, kp_adrs1, chain_i, output):
    # Complete one WOTS+ chain: apply (SPX_WOTS_W - 1 - n) further hash steps.
    # n = encoding[chain_i] (the raw signing index, already hashed that many times).
    # chain_i is compile-time (from unroll), so adrs1_start inside the lambda is compile-time.
    debug_assert(n < SPX_WOTS_W)
    match_range(n, range(0, SPX_WOTS_W),
        lambda k: _iterate_hash_const_tweaked(
            input, (SPX_WOTS_W - 1) - k, pk_seed, adrs0,
            kp_adrs1 + chain_i * (2 ** ADRS1_CHAIN_SHIFT) + k * (2 ** ADRS1_HASH_SHIFT),
            output))
    return


@inline
def wots_encode_and_complete(message, adrs0, adrs1, randomness, chain_tips, pk_seed, wots_pk_adrs0, wots_pk_adrs1, wots_pubkey):
    # Recover the WOTS+ public key from a message, ADRS values, randomness, and chain tips.
    #
    # Steps:
    #   1. Assert randomness[RANDOMNESS_LEN] == adrs0 and randomness[RANDOMNESS_LEN+1] == adrs1.
    #      encoding_fe = poseidon(message, randomness)  # right = [r0..r5, adrs0, adrs1]
    #   2. Decompose encoding_fe into 32 individual 4-bit indices; assert sum == TARGET_SUM.
    #   3. For each chain i in 0..SPX_WOTS_LEN:
    #      complete chain via iterate_hash_single (WOTS_HASH tweak).
    #   4. Fold 32 chain-end HalfDigests into wots_pubkey via fold_wots_pubkey (WOTS_PK tweak).
    #
    # Inputs:
    #   message       — DIGEST_LEN (8) FEs
    #   adrs0         — scalar: WOTS_HASH adrs0 (layer/type/tree) — compile-time at all call sites
    #   adrs1         — scalar: kp_addr (chain=0, hash=0)         — compile-time at all call sites
    #   randomness    — RANDOMNESS_LEN+2 (8) FEs: [r0..r5, adrs0, adrs1]
    #   chain_tips    — SPX_WOTS_LEN * DIGEST_LEN (256) FEs: revealed 8-FE chain tips
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

    # Step 2: decompose encoding_fe into 32 individual 4-bit indices (4 chunks per FE).
    encoding = Array(SPX_WOTS_LEN)
    remaining = Array(DIGEST_LEN)
    hint_decompose_wots(encoding, remaining, encoding_fe, 4, SPX_WOTS_LOGW)

    for i in unroll(0, DIGEST_LEN):
        for j in unroll(0, 4):
            assert encoding[i * 4 + j] < SPX_WOTS_W
        assert remaining[i] < 2 ** (31 - 4 * SPX_WOTS_LOGW)
        partial_sum: Mut = remaining[i] * 2 ** (4 * SPX_WOTS_LOGW)
        for j in unroll(0, 4):
            partial_sum += encoding[i * 4 + j] * SPX_WOTS_W ** j
        assert partial_sum == encoding_fe[i]

    # Step 3: complete each chain individually with WOTS_HASH tweak.
    # adrs1 passed as kp_adrs1 — contains only kp_addr (chain=0, hash=0).
    # chain_tips are revealed at full 8-FE width (DIGEST_LEN stride); each chain end is the
    # truncated 4-FE value fed to the WOTS pubkey fold.
    chain_ends = Array(SPX_WOTS_LEN * HALF_DIGEST_LEN)
    for i in unroll(0, SPX_WOTS_LEN):
        iterate_hash_single(chain_tips + i * DIGEST_LEN, encoding[i],
                            pk_seed, adrs0, adrs1, i, chain_ends + i * HALF_DIGEST_LEN)

    target_sum: Mut = encoding[0]
    for i in unroll(1, SPX_WOTS_LEN):
        target_sum += encoding[i]
    assert target_sum == TARGET_SUM

    # Step 4: fold 32 chain-end HalfDigests into wots_pubkey with WOTS_PK tweak.
    fold_wots_pubkey(pk_seed, wots_pk_adrs0, wots_pk_adrs1, chain_ends, wots_pubkey)
    return
