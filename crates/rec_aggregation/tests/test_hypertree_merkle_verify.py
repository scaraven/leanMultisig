from snark_lib import *
from ..zkdsl_implem.sphincs_hypertree import *
from ..zkdsl_implem.utils import *


def main():
    build_preamble_memory()

    pk_seed_slot: Mut = PK_SEED_TABLE_ADDR
    hint_witness("pk_seed", pk_seed_slot)

    tree_adrs0_buf = Array(1)
    hint_witness("tree_adrs0", tree_adrs0_buf)
    tree_adrs0 = tree_adrs0_buf[0]

    layer_leaf_index_buf = Array(1)
    hint_witness("layer_leaf_index", layer_leaf_index_buf)
    layer_leaf_index = layer_leaf_index_buf[0]

    leaf_node = Array(HALF_DIGEST_LEN)
    hint_witness("leaf_node", leaf_node)

    auth_path = Array(SPX_TREE_HEIGHT * HALF_DIGEST_LEN)
    hint_witness("auth_path", auth_path)

    expected_root = Array(HALF_DIGEST_LEN)
    hint_witness("expected_root", expected_root)

    out = Array(HALF_DIGEST_LEN)
    hypertree_merkle_verify(PK_SEED_TABLE_ADDR, tree_adrs0, layer_leaf_index, leaf_node, auth_path, out)
    copy_4(out, expected_root)
    return
