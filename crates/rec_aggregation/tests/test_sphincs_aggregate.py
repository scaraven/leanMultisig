from snark_lib import *
from ..sphincs_aggregate import *
from ..utils import *


def main():
    build_preamble_memory()

    pk = Array(DIGEST_LEN)
    hint_witness("pk", pk)

    message = Array(MESSAGE_LEN)
    hint_witness("message", message)

    sphincs_verify(pk, message)
    return
