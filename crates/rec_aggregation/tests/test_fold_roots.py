from snark_lib import *
from ..sphincs_utils import *
from ..utils import *


def main():
    build_preamble_memory()
    roots = Array(SPX_FORS_TREES * DIGEST_LEN)
    hint_witness("roots", roots)
    expected_output = Array(DIGEST_LEN)
    hint_witness("expected", expected_output)

    output = Array(DIGEST_LEN)
    fold_roots(roots, output)
    for i in unroll(0, DIGEST_LEN):
        assert expected_output[i] == output[i]
    return
