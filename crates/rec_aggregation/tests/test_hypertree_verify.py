from snark_lib import *
from ..sphincs_hypertree import *
from ..utils import *


def main():
    build_preamble_memory()

    fors_pubkey = Array(DIGEST_LEN)
    hint_witness("fors_pubkey", fors_pubkey)

    layer_leaf_indices = Array(SPX_D)
    hint_witness("layer_leaf_indices", layer_leaf_indices)

    expected_pk = Array(DIGEST_LEN)
    hint_witness("expected_pk", expected_pk)

    hypertree_verify(fors_pubkey, layer_leaf_indices, expected_pk)
    return
