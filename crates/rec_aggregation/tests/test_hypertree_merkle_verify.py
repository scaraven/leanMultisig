from snark_lib import *
from ..sphincs_hypertree import *
from ..utils import *


def main():
    build_preamble_memory()

    layer_leaf_index_buf = Array(1)
    hint_witness("layer_leaf_index", layer_leaf_index_buf)
    layer_leaf_index = layer_leaf_index_buf[0]

    leaf_node = Array(DIGEST_LEN)
    hint_witness("leaf_node", leaf_node)

    auth_path = Array(SPX_TREE_HEIGHT * DIGEST_LEN)
    hint_witness("auth_path", auth_path)

    expected_root = Array(DIGEST_LEN)
    hint_witness("expected_root", expected_root)

    out = hypertree_merkle_verify(layer_leaf_index, leaf_node, auth_path)
    for i in unroll(0, DIGEST_LEN):
        assert out[i] == expected_root[i]
    return
