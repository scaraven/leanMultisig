from snark_lib import *
from ..sphincs_fors import *
from ..utils import *


def main():
    build_preamble_memory()   
    # roots are placed at the start of pub_mem by the Rust test harness
    pub_mem = Array(1 + DIGEST_LEN + SPX_FORS_HEIGHT * DIGEST_LEN + DIGEST_LEN)
    hint_witness("pub_mem", pub_mem)
    leaf_index = pub_mem[0]
    leaf_node = Array(DIGEST_LEN)
    copy_8(pub_mem + 1, leaf_node)

    auth_path = Array(SPX_FORS_HEIGHT * DIGEST_LEN)
    for i in unroll(0, SPX_FORS_HEIGHT):
        copy_8(pub_mem + 1 + DIGEST_LEN + i * DIGEST_LEN, auth_path + i * DIGEST_LEN)

    expected_root = Array(DIGEST_LEN)
    copy_8(pub_mem + 1 + (SPX_FORS_HEIGHT + 1) * DIGEST_LEN, expected_root)

    out = Array(DIGEST_LEN)
    fors_merkle_verify(leaf_index, leaf_node, auth_path, out)
    
    for i in unroll(0, DIGEST_LEN):
        assert expected_root[i] == out[i]
    return
