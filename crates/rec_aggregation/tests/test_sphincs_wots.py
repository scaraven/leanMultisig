from snark_lib import *
from ..zkdsl_implem.sphincs_wots import *
from ..zkdsl_implem.utils import *


def main():
    build_preamble_memory()

    pk_seed = Array(HALF_DIGEST_LEN)
    hint_witness("pk_seed", pk_seed)

    message = Array(DIGEST_LEN)
    hint_witness("message", message)

    # adrs0 and adrs1 are compile-time constants supplied by the Rust test harness
    # via the randomness hint (slots RANDOMNESS_LEN and RANDOMNESS_LEN+1).
    # The circuit asserts these slots equal the expected compile-time values,
    # so we read them back from the randomness buffer rather than as separate hints.
    adrs0_buf = Array(1)
    hint_witness("adrs0", adrs0_buf)
    adrs0 = adrs0_buf[0]

    adrs1_buf = Array(1)
    hint_witness("adrs1", adrs1_buf)
    adrs1 = adrs1_buf[0]

    wots_pk_adrs0_buf = Array(1)
    hint_witness("wots_pk_adrs0", wots_pk_adrs0_buf)
    wots_pk_adrs0 = wots_pk_adrs0_buf[0]

    wots_pk_adrs1_buf = Array(1)
    hint_witness("wots_pk_adrs1", wots_pk_adrs1_buf)
    wots_pk_adrs1 = wots_pk_adrs1_buf[0]

    # randomness = [r0..r5, adrs0, adrs1] — 8 FEs total
    randomness = Array(RANDOMNESS_LEN + 2)
    hint_witness("randomness", randomness)

    # Revealed chain tips are full 8-FE digests (DIGEST_LEN stride) under the 8-FE-internal
    # WOTS chain scheme.
    chain_tips = Array(SPX_WOTS_LEN * DIGEST_LEN)
    hint_witness("chain_tips", chain_tips)

    expected_wots_pubkey = Array(HALF_DIGEST_LEN)
    hint_witness("expected", expected_wots_pubkey)

    wots_pubkey = Array(HALF_DIGEST_LEN)
    wots_encode_and_complete(message, adrs0, adrs1, randomness, chain_tips, pk_seed, wots_pk_adrs0, wots_pk_adrs1, wots_pubkey)
    for i in unroll(0, HALF_DIGEST_LEN):
        assert wots_pubkey[i] == expected_wots_pubkey[i]
    return
