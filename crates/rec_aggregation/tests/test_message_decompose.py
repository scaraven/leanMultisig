from snark_lib import *
from ..sphincs_aggregate import *
from ..utils import *

def main():
    build_preamble_memory()

    message_digest = Array(DIGEST_LEN)
    hint_witness("message_digest", message_digest)

    indices = decompose_message_digest(message_digest)

    expected_fors_indices = Array(SPX_FORS_TREES)
    hint_witness("expected_fors_indices", expected_fors_indices)

    expected_layer_leaf_indices = Array(SPX_D)
    hint_witness("expected_layer_leaf_indices", expected_layer_leaf_indices)

    for i in unroll(0, SPX_FORS_TREES):
        assert indices[i + SPX_D] == expected_fors_indices[i]

    for i in unroll(0, SPX_D):
        assert indices[i] == expected_layer_leaf_indices[i]

    return
