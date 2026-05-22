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

    output = Array(HALF_DIGEST_LEN)
    fold_roots(pk_seed, roots, output)
    for i in unroll(0, HALF_DIGEST_LEN):
        assert expected_output[i] == output[i]
    return
