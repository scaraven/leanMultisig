from snark_lib import *
from hashing import *

# SPHINCS+ Parameters
SPX_WOTS_LEN    = 32   # V  — chains per WOTS instance
SPX_WOTS_W      = 16   # CHAIN_LENGTH
SPX_WOTS_LOGW   = 4    # log2(SPX_WOTS_W)
TARGET_SUM      = 304  # sum of all 32 encoding indices
SPX_D           = 3    # hypertree layers
SPX_TREE_HEIGHT = 11   # leaves per hypertree layer = 2^11
SPX_FORS_HEIGHT = 15   # leaves per FORS tree = 2^15
SPX_FORS_TREES  = 9    # k — number of FORS trees
HALF_DIGEST_LEN       = 4    # FEs per half-digest (pk_seed, sk_seed, etc.)
RANDOMNESS_LEN        = 6    # FEs per WOTS randomness value (6 random FEs; adrs0/adrs1 are compile-time constants)
MESSAGE_LEN           = 8    # FEs per message
MSG_RANDOMNESS_LEN_FE = 4    # FEs of per-signature message randomness (prepended to zero-padded right half)

FORS_SIG_SIZE_FE      = SPX_FORS_TREES * (1 + SPX_FORS_HEIGHT) * HALF_DIGEST_LEN   # 576 (half-digests)
HYPERTREE_SIG_SIZE_FE = SPX_D * (RANDOMNESS_LEN + SPX_WOTS_LEN * HALF_DIGEST_LEN + SPX_TREE_HEIGHT * HALF_DIGEST_LEN)  # 456

# ADRS type codes — must match address.rs constants
ADRS_WOTS_HASH  = 0
ADRS_WOTS_PK    = 1
ADRS_TREE       = 2
ADRS_FORS_TREE  = 3
ADRS_FORS_ROOTS = 4
ADRS_WOTS_PRF   = 5
ADRS_FORS_PRF   = 6

# Bit offsets within adrs0: layer(2) | type(3) | tree_address(22)
ADRS0_TYPE_SHIFT = 2
ADRS0_TREE_SHIFT = 5  # 2 + 3

# Bit offsets within adrs1 (WOTS / FORS_ROOTS layout)
SPX_KP_ADDR_BITS    = 22
SPX_CHAIN_ADDR_BITS = 5
SPX_HASH_ADDR_BITS  = 4
ADRS1_CHAIN_SHIFT = SPX_KP_ADDR_BITS        # 22
ADRS1_HASH_SHIFT  = SPX_KP_ADDR_BITS + SPX_CHAIN_ADDR_BITS  # 27

# Bit offsets within adrs1 (TREE / FORS_TREE layout)
ADRS1_TREE_HT_SHIFT = SPX_FORS_HEIGHT  # 15

MERKLE_LEVEL_STEP = 5 # number of Merkle levels processed by do_3_merkle_level; must divide SPX_FORS_HEIGHT

@inline
def adrs_compress(pk_seed, adrs0, adrs1, data_right, out):
    # Tweaked Poseidon16 compression: left = [pk_seed[0..4] | adrs0, adrs1, 0, 0].
    # Uses poseidon16_compress_half so only the first 4 output FEs (the HalfDigest) are constrained.
    #
    # pk_seed    — pointer to HALF_DIGEST_LEN (4) FEs: per-signer public seed
    # adrs0      — scalar: packed layer/type/tree_address field element
    # adrs1      — scalar: packed positional fields (kp_addr / chain / hash or tree_height / tree_index)
    # data_right — pointer to DIGEST_LEN (8) FEs: right half of the Poseidon input
    # out        — pointer to HALF_DIGEST_LEN (4) FEs: first 4 FEs of Poseidon output (HalfDigest)
    left = Array(DIGEST_LEN)
    copy_4(pk_seed, left)
    left[4] = adrs0
    left[5] = adrs1
    left[6] = 0
    left[7] = 0
    poseidon16_compress_half(left, data_right, out)
    return

@inline
def do_1_merkle_level(bit, state_in, sibling, out):
    match_range(bit, range(0, 2), lambda b: do_1_merkel_level_const(b, state_in, sibling, out))
    return

@inline
def do_1_merkel_level_const(bit, state_in, sibling, out):
    if bit == 0:
        poseidon16_compress(state_in, sibling, out)
    else:
        poseidon16_compress(sibling, state_in, out)
    return

@inline
def do_5_merkle_level(k, state_in, sibling, out):
    match_range(k, range(0, 2**MERKLE_LEVEL_STEP), lambda k_prime: do_5_merkle_level_const(k_prime, state_in, sibling, out))
    return

@inline
def do_5_merkle_level_const(k, state_in, sibling, state_out):
    # Advance MERKLE_LEVEL_STEP levels of the Merkle tree given a compile-time index k.
    #
    # Inputs:
    #   k         — compile-time integer in [0, 2^MERKLE_LEVEL_STEP); bits extracted via (k // 2^i) % 2
    #   state_in  — DIGEST_LEN FEs: hash of the current node
    #   sibling   — MERKLE_LEVEL_STEP * DIGEST_LEN FEs: sibling hashes for each level
    # Output:
    #   state_out — DIGEST_LEN FEs: computed node after MERKLE_LEVEL_STEP Poseidon compressions
    b0 = k % 2
    b0r = (k - b0) / 2
    b1 = b0r % 2
    b1r = (b0r - b1) / 2
    b2 = b1r % 2
    b2r = (b1r - b2) / 2
    b3 = b2r % 2
    b3r = (b2r - b3) / 2
    b4 = b3r % 2

    intermediate_states = Array((MERKLE_LEVEL_STEP - 1) * DIGEST_LEN)
    if b0 == 0:
        poseidon16_compress(state_in, sibling, intermediate_states)
    else:
        poseidon16_compress(sibling, state_in, intermediate_states)

    if b1 == 0:
        poseidon16_compress(intermediate_states, sibling + DIGEST_LEN, intermediate_states + DIGEST_LEN)
    else:
        poseidon16_compress(sibling + DIGEST_LEN, intermediate_states, intermediate_states + DIGEST_LEN)

    if b2 == 0:
        poseidon16_compress(intermediate_states + DIGEST_LEN, sibling + 2 * DIGEST_LEN, intermediate_states + 2 * DIGEST_LEN)
    else:
        poseidon16_compress(sibling + 2 * DIGEST_LEN, intermediate_states + DIGEST_LEN, intermediate_states + 2 * DIGEST_LEN)

    if b3 == 0:
        poseidon16_compress(intermediate_states + 2 * DIGEST_LEN, sibling + 3 * DIGEST_LEN, intermediate_states + 3 * DIGEST_LEN)
    else:
        poseidon16_compress(sibling + 3 * DIGEST_LEN, intermediate_states + 2 * DIGEST_LEN, intermediate_states + 3 * DIGEST_LEN)

    if b4 == 0:
        poseidon16_compress(intermediate_states + 3 * DIGEST_LEN, sibling + 4 * DIGEST_LEN, state_out)
    else:
        poseidon16_compress(sibling + 4 * DIGEST_LEN, intermediate_states + 3 * DIGEST_LEN, state_out)

    return

@inline
def fold_wots_pubkey(pk_seed, adrs0, adrs1, chain_pub_keys, out):
    # Fold SPX_WOTS_LEN (32) completed chain tips into a single WOTS+ public key digest.
    # Matches WotsPublicKey::hash() in wots.rs — tweaked left-fold:
    #   left  = [pk_seed[0..4] | adrs0, adrs1, 0, 0]   (constant across all steps)
    #   right = [acc[0..4] | next_tip[0..4]]
    # adrs0/adrs1 encode Adrs::wots_pk(layer, tree_addr, kp_addr) — compile-time constants at all call sites.
    # Costs 31 adrs_compress calls.
    #
    # Inputs:
    #   pk_seed        — pointer to HALF_DIGEST_LEN (4) FEs: per-signer public seed
    #   adrs0          — scalar: packed layer/type/tree_address (WOTS_PK type)
    #   adrs1          — scalar: kp_addr (chain=0, hash=0)
    #   chain_pub_keys — SPX_WOTS_LEN * HALF_DIGEST_LEN FEs: completed chain-end HalfDigests
    # Output:
    #   out — HALF_DIGEST_LEN (4) FEs: folded WOTS+ public key hash
    states = Array((SPX_WOTS_LEN - 2) * HALF_DIGEST_LEN)

    right0 = Array(DIGEST_LEN)
    copy_4(chain_pub_keys, right0)
    copy_4(chain_pub_keys + HALF_DIGEST_LEN, right0 + HALF_DIGEST_LEN)
    adrs_compress(pk_seed, adrs0, adrs1, right0, states)

    for i in unroll(1, SPX_WOTS_LEN - 2):
        right_i = Array(DIGEST_LEN)
        copy_4(states + (i - 1) * HALF_DIGEST_LEN, right_i)
        copy_4(chain_pub_keys + (i + 1) * HALF_DIGEST_LEN, right_i + HALF_DIGEST_LEN)
        adrs_compress(pk_seed, adrs0, adrs1, right_i, states + i * HALF_DIGEST_LEN)

    right_last = Array(DIGEST_LEN)
    copy_4(states + (SPX_WOTS_LEN - 3) * HALF_DIGEST_LEN, right_last)
    copy_4(chain_pub_keys + (SPX_WOTS_LEN - 1) * HALF_DIGEST_LEN, right_last + HALF_DIGEST_LEN)
    adrs_compress(pk_seed, adrs0, adrs1, right_last, out)
    return

@inline
def fold_roots(pk_seed, roots, out):
    # Fold SPX_FORS_TREES (9) FORS tree roots into the FORS public key digest.
    # Tweaked left-fold matching fors.rs::fold_roots:
    #   adrs0 = pack(layer=0, type=FORS_ROOTS, tree_addr=0)  — constant across all steps
    #   adrs1 = i                                              — step index (kp_addr field)
    #   right = [acc[0..4] | next_root[0..4]]
    # Costs 8 adrs_compress calls.
    #
    # Inputs:
    #   pk_seed — pointer to HALF_DIGEST_LEN (4) FEs: per-signer public seed
    #   roots   — SPX_FORS_TREES * HALF_DIGEST_LEN FEs: one HalfDigest root per FORS tree
    # Output:
    #   out     — HALF_DIGEST_LEN (4) FEs: FORS public key hash
    FORS_ROOTS_ADRS0 = ADRS_FORS_ROOTS * (2 ** ADRS0_TYPE_SHIFT)  # layer=0, type=4, tree_addr=0 → 16

    states = Array((SPX_FORS_TREES - 2) * HALF_DIGEST_LEN)

    right0 = Array(DIGEST_LEN)
    copy_4(roots, right0)
    copy_4(roots + HALF_DIGEST_LEN, right0 + HALF_DIGEST_LEN)
    adrs_compress(pk_seed, FORS_ROOTS_ADRS0, 0, right0, states)

    for i in unroll(1, SPX_FORS_TREES - 2):
        right_i = Array(DIGEST_LEN)
        copy_4(states + (i - 1) * HALF_DIGEST_LEN, right_i)
        copy_4(roots + (i + 1) * HALF_DIGEST_LEN, right_i + HALF_DIGEST_LEN)
        adrs_compress(pk_seed, FORS_ROOTS_ADRS0, i, right_i, states + i * HALF_DIGEST_LEN)

    right_last = Array(DIGEST_LEN)
    copy_4(states + (SPX_FORS_TREES - 3) * HALF_DIGEST_LEN, right_last)
    copy_4(roots + (SPX_FORS_TREES - 1) * HALF_DIGEST_LEN, right_last + HALF_DIGEST_LEN)
    adrs_compress(pk_seed, FORS_ROOTS_ADRS0, SPX_FORS_TREES - 2, right_last, out)
    return
