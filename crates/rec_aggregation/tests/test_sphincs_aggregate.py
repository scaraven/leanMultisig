from snark_lib import *
from ..zkdsl_implem.sphincs_aggregate import *
from ..zkdsl_implem.utils import *


def main():
    build_preamble_memory()

    # Place pk_seed into the preamble pk_seed table slot 0 so that pk_seed_offset is compile-time.
    pk_seed_slot: Mut = PK_SEED_TABLE_ADDR
    hint_witness("pk", pk_seed_slot)

    pk_root = Array(HALF_DIGEST_LEN)
    hint_witness("pk_root", pk_root)

    message = Array(MESSAGE_LEN)
    hint_witness("message", message)

    sphincs_verify(PK_SEED_TABLE_ADDR, pk_root, message)
    return
