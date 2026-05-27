from snark_lib import *
from ..zkdsl_implem.sphincs_hypertree import *
from ..zkdsl_implem.utils import *


def main():
    build_preamble_memory()

    pk_seed_slot: Mut = PK_SEED_TABLE_ADDR
    hint_witness("pk_seed", pk_seed_slot)

    fors_pubkey = Array(HALF_DIGEST_LEN)
    hint_witness("fors_pubkey", fors_pubkey)

    layer_leaf_indices = Array(SPX_D)
    hint_witness("layer_leaf_indices", layer_leaf_indices)

    expected_pk = Array(HALF_DIGEST_LEN)
    hint_witness("expected_pk", expected_pk)

    hypertree_verify(PK_SEED_TABLE_ADDR, fors_pubkey, layer_leaf_indices, expected_pk)
    return
