from snark_lib import *
from ..zkdsl_implem.sphincs_aggregate import *
from ..zkdsl_implem.utils import *


def main():
    build_preamble_memory()

    pk = Array(DIGEST_LEN)
    hint_witness("pk", pk)

    message = Array(MESSAGE_LEN)
    hint_witness("message", message)

    sphincs_verify(pk, message)
    return
