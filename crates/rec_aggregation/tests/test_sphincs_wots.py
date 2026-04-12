from snark_lib import *
from ..sphincs_wots import *
from ..utils import *


def main():
    pub_mem = NONRESERVED_PROGRAM_INPUT_START
    # roots are placed at the start of pub_mem by the Rust test harness
    message = Array(DIGEST_LEN)
    copy_8(pub_mem, message)

    layer_index = pub_mem[DIGEST_LEN]
    randomness = Array(RANDOMNESS_LEN)
    copy_7(pub_mem + DIGEST_LEN + 1, randomness)

    chain_tips = Array(SPX_WOTS_LEN * DIGEST_LEN)
    for i in unroll(0, SPX_WOTS_LEN):
        copy_8(pub_mem + DIGEST_LEN + 1 + RANDOMNESS_LEN + i * DIGEST_LEN, chain_tips + i * DIGEST_LEN)

    expected_wots_pubkey = Array(DIGEST_LEN)
    copy_8(pub_mem + DIGEST_LEN + 1 + RANDOMNESS_LEN + SPX_WOTS_LEN * DIGEST_LEN, expected_wots_pubkey)

    local_zero_buf = Array(DIGEST_LEN)
    set_to_8_zeros(local_zero_buf)

    wots_pubkey = Array(DIGEST_LEN)
    wots_encode_and_complete(message, layer_index, randomness, chain_tips, wots_pubkey, local_zero_buf)
    for i in unroll(0, DIGEST_LEN):
        assert wots_pubkey[i] == expected_wots_pubkey[i]
    return
