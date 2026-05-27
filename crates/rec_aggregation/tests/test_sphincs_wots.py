from snark_lib import *
from ..zkdsl_implem.sphincs_wots import *
from ..zkdsl_implem.utils import *


def main():
    build_preamble_memory()

    pk_seed_slot: Mut = PK_SEED_TABLE_ADDR
    hint_witness("pk_seed", pk_seed_slot)

    message = Array(DIGEST_LEN)
    hint_witness("message", message)

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

    chain_tips = Array(SPX_WOTS_LEN * HALF_DIGEST_LEN)
    hint_witness("chain_tips", chain_tips)

    expected_wots_pubkey = Array(HALF_DIGEST_LEN)
    hint_witness("expected", expected_wots_pubkey)

    wots_pubkey = Array(HALF_DIGEST_LEN)
    wots_encode_and_complete(message, adrs0, adrs1, randomness, chain_tips, PK_SEED_TABLE_ADDR, wots_pk_adrs0, wots_pk_adrs1, wots_pubkey)
    for i in unroll(0, HALF_DIGEST_LEN):
        assert wots_pubkey[i] == expected_wots_pubkey[i]
    return
