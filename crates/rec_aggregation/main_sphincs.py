from snark_lib import *
from hashing import *
from sphincs_aggregate import *

MAX_N_SIGS = 2**12
MAX_LOG_N_SIGS = 12


def main():
    """
    Entry point for SPHINCS+ signature batch verification.
    No recursion, no slot, no bytecode claim reduction.

    Public input (8 FEs at address 0):
        hash of [ n_sigs(1) | pubkeys(n_sigs x DIGEST_LEN) | messages(n_sigs x MESSAGE_LEN) ]
        The commitment is built by chaining Poseidon absorptions without copying:
            h0 = poseidon(ZERO_VEC, [n_sigs, 0, 0, ..., 0])
            h1 = slice_hash_with_iv_dynamic_unroll(pubkeys, ...) continued from h0
            h2 = continued absorption of messages

        Because no DSL primitive takes an incoming state for dynamic hashing, we
        hash each segment independently and then chain the three digests:
            segment_nsigs    = poseidon(ZERO_VEC, [n_sigs, 0, ..., 0])
            segment_pubkeys  = slice_hash_with_iv_dynamic_unroll(pubkeys, n_sigs * DIGEST_LEN, ...)
            segment_messages = slice_hash_with_iv_dynamic_unroll(messages, n_sigs * MESSAGE_LEN, ...)
            commitment       = poseidon(poseidon(segment_nsigs, segment_pubkeys), segment_messages)

    Private witness hints (consumed in order):
        "n_sigs"   — [n_sigs]
        "pubkeys"  — flat array of n_sigs x DIGEST_LEN FEs
        "messages" — flat array of n_sigs x MESSAGE_LEN FEs
        Per sphincs_verify call (consumed inside sphincs_aggregate.py):
            "digest_decomposition", "fors_sig", "hypertree_sig",
            "fe0_unused_bits", "fe1_unused_bits"
    """
    pub_mem = 0
    build_preamble_memory()

    n_sigs_arr = Array(1)
    hint_witness("n_sigs", n_sigs_arr)
    n_sigs = n_sigs_arr[0]
    assert n_sigs != 0
    assert n_sigs - 1 < MAX_N_SIGS

    pubkeys = Array(n_sigs * DIGEST_LEN)
    hint_witness("pubkeys", pubkeys)

    messages = Array(n_sigs * MESSAGE_LEN)
    hint_witness("messages", messages)

    """
    Commit to (n_sigs, pubkeys, messages) without copying by hashing each segment
    independently then folding the three digests into one.
    """
    n_sigs_chunk = Array(DIGEST_LEN)
    n_sigs_chunk[0] = n_sigs
    for k in unroll(1, DIGEST_LEN):
        n_sigs_chunk[k] = 0
    seg_nsigs = Array(DIGEST_LEN)
    poseidon16_compress(ZERO_VEC_PTR, n_sigs_chunk, seg_nsigs)

    seg_pubkeys = slice_hash_with_iv_dynamic_unroll(pubkeys, n_sigs * DIGEST_LEN, MAX_LOG_N_SIGS + 4)

    seg_messages = slice_hash_with_iv_dynamic_unroll(messages, n_sigs * MESSAGE_LEN, MAX_LOG_N_SIGS + 4)

    h01 = Array(DIGEST_LEN)
    poseidon16_compress(seg_nsigs, seg_pubkeys, h01)
    commitment = Array(DIGEST_LEN)
    poseidon16_compress(h01, seg_messages, commitment)

    for k in unroll(0, DIGEST_LEN):
        assert commitment[k] == pub_mem[k]

    """
    Verify each signature independently. sphincs_verify consumes per-signer hints
    internally in order, one set per call.
    """
    for i in parallel_range(0, n_sigs):
        pk = pubkeys + i * DIGEST_LEN
        message = messages + i * MESSAGE_LEN
        sphincs_verify(pk, message)

    return
