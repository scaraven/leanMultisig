from snark_lib import *
from ..zkdsl_implem.sphincs_fors import *
from ..zkdsl_implem.utils import *


def main():
    build_preamble_memory()

    pk_seed = Array(HALF_DIGEST_LEN)
    hint_witness("pk_seed", pk_seed)

    idx_tree_buf = Array(1)
    hint_witness("idx_tree", idx_tree_buf)
    idx_tree = idx_tree_buf[0]

    idx_leaf_buf = Array(1)
    hint_witness("idx_leaf", idx_leaf_buf)
    idx_leaf = idx_leaf_buf[0]

    tree_index_buf = Array(1)
    hint_witness("tree_index", tree_index_buf)
    tree_index = tree_index_buf[0]

    leaf_index_arr = Array(1)
    hint_witness("leaf_index", leaf_index_arr)
    leaf_index = leaf_index_arr[0]

    leaf_secret = Array(HALF_DIGEST_LEN)
    hint_witness("leaf_secret", leaf_secret)

    expected_root = Array(HALF_DIGEST_LEN)
    hint_witness("expected_root", expected_root)

    # Auth-path siblings are streamed level-by-level from the "fors_auth" queue inside
    # fors_merkle_verify (15 siblings, bottom-up).
    out = Array(HALF_DIGEST_LEN)
    fors_merkle_verify(pk_seed, idx_tree, idx_leaf, tree_index, leaf_index, leaf_secret, out)

    for i in unroll(0, HALF_DIGEST_LEN):
        assert expected_root[i] == out[i]
    return
