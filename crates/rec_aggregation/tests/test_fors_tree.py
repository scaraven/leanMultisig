from snark_lib import *
from ..sphincs_fors import *
from ..utils import *


def main():
    build_preamble_memory()   
    # roots are placed at the start of pub_mem by the Rust test harness
    leaf_index_arr = Array(1)
    hint_witness("leaf_index", leaf_index_arr)
    leaf_index = leaf_index_arr[0]

    leaf_node = Array(DIGEST_LEN)
    hint_witness("leaf_node", leaf_node)

    auth_path = Array(SPX_FORS_HEIGHT * DIGEST_LEN)
    hint_witness("auth_path", auth_path)

    expected_root = Array(DIGEST_LEN)
    hint_witness("expected_root", expected_root)

    out = Array(DIGEST_LEN)
    fors_merkle_verify(leaf_index, leaf_node, auth_path, out)
    
    for i in unroll(0, DIGEST_LEN):
        assert expected_root[i] == out[i]
    return
