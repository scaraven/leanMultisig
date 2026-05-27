from snark_lib import *
from ..zkdsl_implem.sphincs_fors import *
from ..zkdsl_implem.utils import *


def main():
    build_preamble_memory()

    pk_seed_slot: Mut = PK_SEED_TABLE_ADDR
    hint_witness("pk_seed", pk_seed_slot)

    tree_index_buf = Array(1)
    hint_witness("tree_index", tree_index_buf)
    tree_index = tree_index_buf[0]

    leaf_index_arr = Array(1)
    hint_witness("leaf_index", leaf_index_arr)
    leaf_index = leaf_index_arr[0]

    leaf_secret = Array(HALF_DIGEST_LEN)
    hint_witness("leaf_secret", leaf_secret)

    auth_path = Array(SPX_FORS_HEIGHT * HALF_DIGEST_LEN)
    hint_witness("auth_path", auth_path)

    expected_root = Array(HALF_DIGEST_LEN)
    hint_witness("expected_root", expected_root)

    out = Array(HALF_DIGEST_LEN)
    fors_merkle_verify(PK_SEED_TABLE_ADDR, tree_index, leaf_index, leaf_secret, auth_path, out)

    for i in unroll(0, HALF_DIGEST_LEN):
        assert expected_root[i] == out[i]
    return
