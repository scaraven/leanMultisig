from snark_lib import *
from ..zkdsl_implem.sphincs_utils import *
from ..zkdsl_implem.utils import *


def main():
    build_preamble_memory()
    pk_seed = Array(HALF_DIGEST_LEN)
    hint_witness("pk_seed", pk_seed)
    roots = Array(SPX_FORS_TREES * HALF_DIGEST_LEN)
    hint_witness("roots", roots)
    expected_output = Array(HALF_DIGEST_LEN)
    hint_witness("expected", expected_output)

    # fold_roots reads a contiguous tip buffer: place each of the 9 hinted roots at
    # fold_buf + t * HALF_DIGEST_LEN, then zero the trailing pad-tip (9 is odd), then fold.
    fold_buf = Array(fold_tips_len(SPX_FORS_TREES + 1))
    for t in unroll(0, SPX_FORS_TREES):
        copy_4(roots + t * HALF_DIGEST_LEN, fold_buf + t * HALF_DIGEST_LEN)
    for i in unroll(0, HALF_DIGEST_LEN):
        fold_buf[SPX_FORS_TREES * HALF_DIGEST_LEN + i] = 0

    output = Array(HALF_DIGEST_LEN)
    fold_roots(pk_seed, fold_buf, output)
    for i in unroll(0, HALF_DIGEST_LEN):
        assert expected_output[i] == output[i]
    return
