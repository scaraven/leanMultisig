from snark_lib import *
from ..sphincs_utils import *
from ..utils import *


def main():
    pub_mem = NONRESERVED_PROGRAM_INPUT_START
    n = pub_mem[0]
    input = Array(DIGEST_LEN)
    copy_8(pub_mem + 1, input)
    expected_output = Array(DIGEST_LEN)
    copy_8(pub_mem + 1 + DIGEST_LEN, expected_output)

    output = Array(DIGEST_LEN)
    local_zero_buff = Array(DIGEST_LEN)
    set_to_8_zeros(local_zero_buff)

    iterate_hash(input, n, output, local_zero_buff)
    for i in unroll(0, DIGEST_LEN):
        assert expected_output[i] == output[i]
    return
