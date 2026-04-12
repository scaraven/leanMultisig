from snark_lib import *
from ..sphincs_utils import *
from ..utils import *


def main():
    pub_mem = NONRESERVED_PROGRAM_INPUT_START
    # roots are placed at the start of pub_mem by the Rust test harness
    roots = pub_mem
    expected_output = Array(DIGEST_LEN)
    copy_8(pub_mem + SPX_FORS_TREES * DIGEST_LEN, expected_output)

    output = Array(DIGEST_LEN)

    fold_roots(roots, output)
    for i in unroll(0, DIGEST_LEN):
        assert expected_output[i] == output[i]
    return
