from snark_lib import *
from ..zkdsl_implem.sphincs_fors import *
from ..zkdsl_implem.utils import *


def main():
    build_preamble_memory()

    pk_seed = Array(HALF_DIGEST_LEN)
    hint_witness("pk_seed", pk_seed)

    leaf_index_arr = Array(SPX_FORS_TREES)
    hint_witness("leaf_index", leaf_index_arr)

    expected_root = Array(HALF_DIGEST_LEN)
    hint_witness("expected_root", expected_root)

    out = Array(HALF_DIGEST_LEN)
    fors_verify(pk_seed, leaf_index_arr, out)

    for i in unroll(0, HALF_DIGEST_LEN):
        assert expected_root[i] == out[i]
    return
