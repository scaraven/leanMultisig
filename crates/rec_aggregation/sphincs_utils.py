from snark_lib import *
from hashing import *

# SPHINCS+ Parameters
SPX_WOTS_LEN    = 32   # V  — chains per WOTS instance
SPX_WOTS_W      = 16   # CHAIN_LENGTH
TARGET_SUM      = 304  # sum of all 32 encoding indices
SPX_D           = 3    # hypertree layers
SPX_TREE_HEIGHT = 11   # leaves per hypertree layer = 2^11
SPX_FORS_HEIGHT = 15   # leaves per FORS tree = 2^15
SPX_FORS_TREES  = 9    # k — number of FORS trees
RANDOMNESS_LEN  = 8    # FEs per WOTS randomness value (7 random FEs + layer_index in slot 7)
MESSAGE_LEN     = 9    # FEs per message

FORS_SIG_SIZE_FE      = SPX_FORS_TREES * (1 + SPX_FORS_HEIGHT) * DIGEST_LEN        # 1152
HYPERTREE_SIG_SIZE_FE = SPX_D * (RANDOMNESS_LEN + SPX_WOTS_LEN * DIGEST_LEN + SPX_TREE_HEIGHT * DIGEST_LEN)  # 1056

MERKLE_LEVEL_STEP = 5 # number of Merkle levels processed by do_3_merkle_level; must divide SPX_FORS_HEIGHT

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
def _iterate_hash_const(input, k, output, local_zero_buf):
    if k == 0:
        copy_8(input, output)
    elif k == 1:
        poseidon16_compress(input, local_zero_buf, output)
    else:
        states = Array((k - 1) * DIGEST_LEN)
        poseidon16_compress(input, local_zero_buf, states)
        for i in unroll(1, k - 1):
            poseidon16_compress(states + (i - 1) * DIGEST_LEN, local_zero_buf, states + i * DIGEST_LEN)
        poseidon16_compress(states + (k - 2) * DIGEST_LEN, local_zero_buf, output)
    return


@inline
def iterate_hash(input, n, output, local_zero_buf):
    # Apply poseidon16_compress(state, zero_buf) exactly n times.
    #
    # Precondition: n < SPX_WOTS_W (enforced by encoding checks in wots_encode_and_complete)
    debug_assert(n < SPX_WOTS_W)
    match_range(n, range(0, SPX_WOTS_W), lambda k: _iterate_hash_const(input, k, output, local_zero_buf))
    return

@inline
def fold_wots_pubkey(chain_pub_keys, out):
    # Fold SPX_WOTS_LEN (32) completed chain tips into a single WOTS+ public key digest.
    # Matches WotsPublicKey::hash() in wots.rs:77-82.
    # Sequential left-fold:
    #   init = poseidon(chain_pub_keys[0], chain_pub_keys[1])
    #   for i in 2..32: acc = poseidon(acc, chain_pub_keys[i])
    # Costs 31 Poseidon calls.
    #
    # Input:
    #   chain_pub_keys — SPX_WOTS_LEN * DIGEST_LEN FEs: completed chain-end hashes
    # Output:
    #   out — DIGEST_LEN FEs: folded public key hash
    states = Array((SPX_WOTS_LEN - 2) * DIGEST_LEN)
    poseidon16_compress(chain_pub_keys, chain_pub_keys + DIGEST_LEN, states)
    for i in unroll(1, SPX_WOTS_LEN - 2):
        poseidon16_compress(states + (i - 1) * DIGEST_LEN, chain_pub_keys + (i + 1) * DIGEST_LEN, states + i * DIGEST_LEN)
    poseidon16_compress(states + (SPX_WOTS_LEN - 3) * DIGEST_LEN, chain_pub_keys + (SPX_WOTS_LEN - 1) * DIGEST_LEN, out)
    return

@inline
def fold_roots(roots, out):
    # Fold SPX_FORS_TREES (9) FORS tree roots into the FORS public key digest.
    # Sequential left-fold:
    #   acc = poseidon(roots[0], roots[1])
    #   for i in 2..9: acc = poseidon(acc, roots[i])
    # Costs 8 Poseidon calls.
    #
    # Input:
    #   roots — SPX_FORS_TREES * DIGEST_LEN FEs: one root per FORS tree
    # Output:
    #   out — DIGEST_LEN FEs: FORS public key hash
    states = Array((SPX_FORS_TREES - 2) * DIGEST_LEN)
    poseidon16_compress(roots, roots + DIGEST_LEN, states)
    for i in unroll(1, SPX_FORS_TREES - 2):
        poseidon16_compress(states + (i - 1) * DIGEST_LEN, roots + (i + 1) * DIGEST_LEN, states + i * DIGEST_LEN)
    poseidon16_compress(states + (SPX_FORS_TREES - 3) * DIGEST_LEN, roots + (SPX_FORS_TREES - 1) * DIGEST_LEN, out)
    return
