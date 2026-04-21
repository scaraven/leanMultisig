from snark_lib import *
from hashing import *

# SPHINCS+ Parameters
SPX_WOTS_LEN    = 32   # V  — chains per WOTS instance
SPX_WOTS_W      = 16   # CHAIN_LENGTH
TARGET_SUM      = 240  # sum of all 32 encoding indices
SPX_D           = 3    # hypertree layers
SPX_TREE_HEIGHT = 11   # leaves per hypertree layer = 2^11
SPX_FORS_HEIGHT = 15   # leaves per FORS tree = 2^15
SPX_FORS_TREES  = 9    # k — number of FORS trees
RANDOMNESS_LEN  = 7    # FEs per WOTS randomness value
MESSAGE_LEN     = 9    # FEs per message

FORS_SIG_SIZE_FE      = SPX_FORS_TREES * (1 + SPX_FORS_HEIGHT) * DIGEST_LEN        # 1152
HYPERTREE_SIG_SIZE_FE = SPX_D * (RANDOMNESS_LEN + SPX_WOTS_LEN * DIGEST_LEN + SPX_TREE_HEIGHT * DIGEST_LEN)  # 1053

MERKLE_LEVEL_STEP = 3 # number of Merkle levels processed by do_3_merkle_level; must divide SPX_FORS_HEIGHT

@inline
def do_1_merkel_level(bit, state_in, sibling, out):
    if bit == 0:
        poseidon16_compress(state_in, sibling, out)
    else:
        poseidon16_compress(sibling, state_in, out)
    return

def do_3_merkle_level(bits, state_in, sibling):
    # Advance 3 levels of the Merkle tree.
    #
    # Inputs:
    #   bit       — position bit for this level, in {0, 1};
    #               already binary-constrained by the caller's hint reconstruction
    #   state_in  — DIGEST_LEN FEs: hash of the current node
    #   sibling   — DIGEST_LEN FEs: sibling node hash from the auth path
    # Output:
    #   state_out — DIGEST_LEN FEs: poseidon(left, right) where
    #               bit == 0 → left = state_in, right = sibling  (current is left child)
    #               bit == 1 → left = sibling,  right = state_in (current is right child)
    # Use bit multiplication for now
    b0 = bits[0]
    b1 = bits[1]
    b2 = bits[2]

    state_out = Array(DIGEST_LEN)
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
        poseidon16_compress(intermediate_states + DIGEST_LEN, sibling + 2 * DIGEST_LEN, state_out)
    else:
        poseidon16_compress(sibling + 2 * DIGEST_LEN, intermediate_states + DIGEST_LEN, state_out)
        
    return state_out

def _iterate_hash_const(input, k: Const, output, local_zero_buf):
    # Fixed-footprint specialization: every k uses the same buffer size and
    # unroll bounds so frame size is uniform across match_range arms.
    states = Array(SPX_WOTS_W * DIGEST_LEN)
    copy_8(input, states)

    for i in unroll(0, SPX_WOTS_W - 1):
        curr = states + i * DIGEST_LEN
        nxt = states + (i + 1) * DIGEST_LEN
        if i < k:
            poseidon16_compress(curr, local_zero_buf, nxt)
        else:
            copy_8(curr, nxt)

    copy_8(states + k * DIGEST_LEN, output)
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
    copy_8(fold_keys(chain_pub_keys, SPX_WOTS_LEN), out)
    return


def fold_keys(keys, n: Const):
    states = Array((n - 1) * DIGEST_LEN)
    poseidon16_compress(keys, keys + DIGEST_LEN, states)
    for i in unroll(1, n - 1):
        poseidon16_compress(states + (i - 1) * DIGEST_LEN, keys + (i + 1) * DIGEST_LEN, states + i * DIGEST_LEN)
    
    return states + (n - 2) * DIGEST_LEN


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
    copy_8(fold_keys(roots, SPX_FORS_TREES), out)
    return
