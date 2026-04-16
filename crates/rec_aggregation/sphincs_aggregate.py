from snark_lib import *
from sphincs_fors import *
from sphincs_hypertree import *


@inline
def decompose_message_digest(message_digest, fors_indices, layer_leaf_indices):
    # Single-pass decomposition of the 8-FE message digest into the routing and
    # index values needed by fors_verify and hypertree_verify.
    #
    # The message digest (8 KoalaBear FEs) is serialised as 8 × LE u32 (32 bytes).
    # Bit layout within that 32-byte buffer:
    #   bits  0–10  : leaf_idx      (11-bit, SPX_TREE_HEIGHT)
    #   bits 11–15  : unused
    #   bits 16–37  : tree_address  (22-bit, SPX_FULL_HEIGHT - SPX_TREE_HEIGHT)
    #   bits 38–39  : unused
    #   bits 40–174 : mhash         (135 bits = 9 × 15-bit fors_indices, LE-packed)
    #   bit  175    : unused (136th mhash bit per fors.rs:187)
    #
    # Hints consumed: a flat array of 12 elements:
    #   [0]    = leaf_idx      (< 2^11)
    #   [1]    = tree_address  (< 2^22)
    #   [2..10]= fors_indices[0..8]  (each < 2^15)
    #   [11]   = fe5_upper     (< 2^16): FE[5] bits 15–30, outside the mhash window
    #
    # Soundness: bit-decomposes each hinted value and reconstructs FE[0..5] from
    # the resulting bits, asserting equality with message_digest[0..5].
    # Four structural-zero constraints (KoalaBear bit-31 = 0 for FE[1..4]) are
    # enforced explicitly: fi_bits[23,55,87,119] == 0.

    LEAF_BITS = SPX_TREE_HEIGHT      # 11
    TREE_BITS = 22
    FORS_BITS = SPX_FORS_HEIGHT      # 15
    HINT_LEN  = 2 + SPX_FORS_TREES + 1  # 12

    hints = Array(HINT_LEN)
    hint_witness("digest_decomposition", hints)

    leaf_idx     = hints[0]
    tree_address = hints[1]
    fe5_upper    = hints[HINT_LEN - 1]

    # Write fors_indices output before any assertions so the output is always set.
    for t in unroll(0, SPX_FORS_TREES):
        fors_indices[t] = hints[2 + t]

    # ── Bit-decompose and range-check leaf_idx (11 bits, LE) ──────────────────
    assert leaf_idx < 2**LEAF_BITS

    # ── Bit-decompose and range-check tree_address (22 bits, LE) ──────────────
    ta_bits = Array(TREE_BITS)
    hint_decompose_bits(tree_address, ta_bits, TREE_BITS, LITTLE_ENDIAN)
    ta_reconstructed: Mut = ta_bits[0]
    for i in unroll(0, TREE_BITS):
        assert ta_bits[i] * (1 - ta_bits[i]) == 0
    for i in unroll(1, TREE_BITS):
        ta_reconstructed += ta_bits[i] * 2**i
    assert tree_address == ta_reconstructed

    # ── Bit-decompose and range-check each fors_index (15 bits, LE) ───────────
    # fi_bits is a flat 135-element array where fi_bits[t*15 + i] = bit i of
    # fors_indices[t].  Because the 9 indices are packed consecutively in the
    # mhash bitstream, fi_bits[j] == mhash bit j  for j in 0..134.
    fi_bits = Array(SPX_FORS_TREES * FORS_BITS)
    for t in unroll(0, SPX_FORS_TREES):
        hint_decompose_bits(fors_indices[t], fi_bits + t * FORS_BITS, FORS_BITS, LITTLE_ENDIAN)
        fi_reconstructed: Mut = fi_bits[t * FORS_BITS]
        for i in unroll(0, FORS_BITS):
            assert fi_bits[t * FORS_BITS + i] * (1 - fi_bits[t * FORS_BITS + i]) == 0
        for i in unroll(1, FORS_BITS):
            fi_reconstructed += fi_bits[t * FORS_BITS + i] * 2**i
        assert fors_indices[t] == fi_reconstructed

    # ── Structural-zero assertions ─────────────────────────────────────────────
    # KoalaBear FEs have bit 31 = 0.  The four mhash bits that fall at bit-31
    # positions of FE[1..4] must therefore be 0.
    # Indices into fi_bits correspond directly to mhash bit positions.
    assert fi_bits[23] == 0   # mhash bit 23 = FE[1] bit 31 = fors_indices[1] bit 8
    assert fi_bits[55] == 0   # mhash bit 55 = FE[2] bit 31 = fors_indices[3] bit 10
    assert fi_bits[87] == 0   # mhash bit 87 = FE[3] bit 31 = fors_indices[5] bit 12
    assert fi_bits[119] == 0  # mhash bit 119 = FE[4] bit 31 = fors_indices[7] bit 14

    # ── Range-check fe5_upper (< 2^16) ────────────────────────────────────────
    assert fe5_upper < 2**16

    # ── Compute layer_leaf_indices from tree_address bits ─────────────────────
    layer_leaf_indices[0] = leaf_idx
    ll1: Mut = ta_bits[0]
    for i in unroll(1, LEAF_BITS):
        ll1 += ta_bits[i] * 2**i
    layer_leaf_indices[1] = ll1   # tree_address bits 0–10
    ll2: Mut = ta_bits[LEAF_BITS]
    for i in unroll(1, LEAF_BITS):
        ll2 += ta_bits[LEAF_BITS + i] * 2**i
    layer_leaf_indices[2] = ll2   # tree_address bits 11–21

    # ── Reconstruct FE[0..5] and assert against message_digest ────────────────
    # FE[0]: leaf_idx at bits 0–10; bits 11–15 unused; ta_bits[0:15] at bits 16–30.
    fe0: Mut = leaf_idx
    for i in unroll(0, 15):
        fe0 += ta_bits[i] * 2**(16 + i)
    assert message_digest[0] == fe0

    # FE[1]: ta_bits[15:22] at bits 0–6; bit 7 unused; fi_bits[0:23] at bits 8–30.
    fe1: Mut = 0
    for i in unroll(0, 7):
        fe1 += ta_bits[15 + i] * 2**i
    for j in unroll(0, 23):
        fe1 += fi_bits[j] * 2**(8 + j)
    assert message_digest[1] == fe1

    # FE[2]: fi_bits[24:55] at bits 0–30 (mhash bits 24–54; gap at bit 23 = 0).
    fe2: Mut = 0
    for j in unroll(0, 31):
        fe2 += fi_bits[24 + j] * 2**j
    assert message_digest[2] == fe2

    # FE[3]: fi_bits[56:87] at bits 0–30 (mhash bits 56–86; gap at bit 55 = 0).
    fe3: Mut = 0
    for j in unroll(0, 31):
        fe3 += fi_bits[56 + j] * 2**j
    assert message_digest[3] == fe3

    # FE[4]: fi_bits[88:119] at bits 0–30 (mhash bits 88–118; gap at bit 87 = 0).
    fe4: Mut = 0
    for j in unroll(0, 31):
        fe4 += fi_bits[88 + j] * 2**j
    assert message_digest[4] == fe4

    # FE[5]: fi_bits[120:135] at bits 0–14 (mhash bits 120–134; gap at bit 119 = 0);
    #        fe5_upper at bits 15–30 (outside the mhash window, hinted separately).
    fe5: Mut = fe5_upper * 2**15
    for j in unroll(0, 15):
        fe5 += fi_bits[120 + j] * 2**j
    assert message_digest[5] == fe5

    return


@inline
def sphincs_verify(pk, message):
    # Top-level SPHINCS+ signature verifier.
    #
    # Steps:
    #   1. Hash the MESSAGE_LEN (9)-FE message to an 8-FE message digest:
    #        right[0] = message[8]
    #        message_digest = poseidon(message[0..8], right)   (1 Poseidon call)
    #   2. Decompose the digest once via decompose_message_digest to obtain
    #      fors_indices[9] and layer_leaf_indices[3].
    #   3. Verify FORS: fors_pubkey = fors_verify(fors_indices).
    #   4. Verify hypertree: hypertree_verify(fors_pubkey,
    #                                         layer_leaf_indices, pk).
    #
    # Inputs:
    #   pk            — DIGEST_LEN FEs: signer's SPHINCS+ public key
    #   message       — MESSAGE_LEN (9) FEs: shared message
    #
    # Postcondition:
    #   Asserts the signature is valid for (pk, message).
    #   Fails the circuit if any sub-verification does not hold.
    right = Array(DIGEST_LEN)
    right[0] = message[8]
    set_to_7_zeros(right + 1)

    message_digest = Array(DIGEST_LEN)
    poseidon16_compress(message, right, message_digest)

    fors_indices = Array(SPX_FORS_TREES)
    layer_leaf_indices = Array(SPX_D)
    decompose_message_digest(message_digest, fors_indices, layer_leaf_indices)
    
    fors_pk = Array(DIGEST_LEN)
    fors_verify(fors_indices, fors_pk)

    hypertree_verify(fors_pk, layer_leaf_indices, pk)
    return
