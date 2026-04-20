from snark_lib import *
from ..sphincs_utils import *
from ..utils import *


def main():
    build_preamble_memory()
    n_buf = Array(1)
    hint_witness("n", n_buf)
    n = n_buf[0]
    input = Array(DIGEST_LEN)
    hint_witness("input", input)
    expected_output = Array(DIGEST_LEN)
    hint_witness("expected", expected_output)

    output = Array(DIGEST_LEN)
    local_zero_buff = Array(DIGEST_LEN)
    set_to_8_zeros(local_zero_buff)
    iterate_hash(input, n, output, local_zero_buff)
    for i in unroll(0, DIGEST_LEN):
        assert expected_output[i] == output[i]
    return
