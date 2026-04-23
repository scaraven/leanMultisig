from snark_lib import *
from ..sphincs_wots import *
from ..utils import *


def main():
    build_preamble_memory()
    message = Array(DIGEST_LEN)
    hint_witness("message", message)

    layer_index_buf = Array(1)
    hint_witness("layer_index", layer_index_buf)
    layer_index = layer_index_buf[0]

    randomness = Array(RANDOMNESS_LEN)
    hint_witness("randomness", randomness)

    chain_tips = Array(SPX_WOTS_LEN * DIGEST_LEN)
    hint_witness("chain_tips", chain_tips)

    expected_wots_pubkey = Array(DIGEST_LEN)
    hint_witness("expected", expected_wots_pubkey)

    local_zero_buf = Array(DIGEST_LEN)
    set_to_8_zeros(local_zero_buf)

    wots_pubkey = Array(DIGEST_LEN)
    wots_encode_and_complete(message, layer_index, randomness, chain_tips, local_zero_buf, wots_pubkey)
    for i in unroll(0, DIGEST_LEN):
        assert wots_pubkey[i] == expected_wots_pubkey[i]
    return
