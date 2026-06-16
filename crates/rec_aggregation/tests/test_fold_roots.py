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

    # fold_roots now reads an interleaved buffer (see fold_buf_len / tip_slot): place each of
    # the 9 hinted roots into its tip-slot, then fold.
    fold_buf = Array(fold_buf_len(SPX_FORS_TREES))
    for t in unroll(0, SPX_FORS_TREES):
        copy_4(roots + t * HALF_DIGEST_LEN, tip_slot(fold_buf, t))

    output = Array(HALF_DIGEST_LEN)
    fold_roots(pk_seed, fold_buf, output)
    for i in unroll(0, HALF_DIGEST_LEN):
        assert expected_output[i] == output[i]
    return
