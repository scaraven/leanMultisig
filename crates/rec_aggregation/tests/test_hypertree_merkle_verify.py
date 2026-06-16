from snark_lib import *
from ..zkdsl_implem.sphincs_hypertree import *
from ..zkdsl_implem.utils import *


def main():
    build_preamble_memory()

    pk_seed = Array(HALF_DIGEST_LEN)
    hint_witness("pk_seed", pk_seed)

    tree_adrs0_buf = Array(1)
    hint_witness("tree_adrs0", tree_adrs0_buf)
    tree_adrs0 = tree_adrs0_buf[0]

    layer_leaf_index_buf = Array(1)
    hint_witness("layer_leaf_index", layer_leaf_index_buf)
    layer_leaf_index = layer_leaf_index_buf[0]

    leaf_node = Array(HALF_DIGEST_LEN)
    hint_witness("leaf_node", leaf_node)

    expected_root = Array(HALF_DIGEST_LEN)
    hint_witness("expected_root", expected_root)

    # Auth-path siblings are streamed level-by-level from the "ht_auth" queue inside
    # hypertree_merkle_verify (11 siblings, bottom-up).
    out = Array(HALF_DIGEST_LEN)
    hypertree_merkle_verify(pk_seed, tree_adrs0, layer_leaf_index, leaf_node, out)
    copy_4(out, expected_root)
    return
