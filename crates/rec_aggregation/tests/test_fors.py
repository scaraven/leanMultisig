from snark_lib import *
from ..sphincs_fors import *
from ..utils import *


def main():
    build_preamble_memory()   
    leaf_index_arr = Array(SPX_FORS_TREES)
    hint_witness("leaf_index", leaf_index_arr)

    expected_root = Array(DIGEST_LEN)
    hint_witness("expected_root", expected_root)

    out = Array(DIGEST_LEN)
    fors_verify(leaf_index_arr, out)
    
    for i in unroll(0, DIGEST_LEN):
        assert expected_root[i] == out[i]
    return
