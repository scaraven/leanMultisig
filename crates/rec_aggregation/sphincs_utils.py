from snark_lib import *
from hashing import *

# ── SPHINCS+ parameters ─────────────────────────────────────────────────────
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


# ── Shared Merkle helper ─────────────────────────────────────────────────────

# @inline
# def do_1_merkle_level(bit, state_in, sibling, state_out):
#     # Advance one binary Merkle level.
#     #
#     # Inputs:
#     #   bit       — position bit for this level, in {0, 1};
#     #               already binary-constrained by the caller's hint reconstruction
#     #   state_in  — DIGEST_LEN FEs: hash of the current node
#     #   sibling   — DIGEST_LEN FEs: sibling node hash from the auth path
#     # Output:
#     #   state_out — DIGEST_LEN FEs: poseidon(left, right) where
#     #               bit == 0 → left = state_in, right = sibling  (current is left child)
#     #               bit == 1 → left = sibling,  right = state_in (current is right child)
#     pass


# ── Chain helper ─────────────────────────────────────────────────────────────

def _iterate_hash_const(input, k: Const, output, local_zero_buf):
    # Inner compile-time-constant implementation of iterate_hash.
    # k is a Const so Array(k * ...) and unroll(..., k) are both legal here.
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
    # n is a runtime value so dispatch to the compile-time helper via match_range.
    # Only the taken branch executes — the VM's conditional jump skips the rest.
    #
    # Precondition: n < SPX_WOTS_W  (enforced by the encoding range check in wots_encode_and_complete)
    debug_assert(n < SPX_WOTS_W)
    match_range(n, range(0, SPX_WOTS_W), lambda k: _iterate_hash_const(input, k, output, local_zero_buf))
    return


# ── Fold helpers ─────────────────────────────────────────────────────────────

# @inline
# def fold_wots_pubkey(chain_pub_keys, out):
#     # Fold SPX_WOTS_LEN (32) completed chain tips into a single WOTS+ public key digest.
#     # Sequential left-fold:
#     #   acc = poseidon(chain_pub_keys[0], chain_pub_keys[1])
#     #   for i in 2..32: acc = poseidon(acc, chain_pub_keys[i])
#     # Costs 31 Poseidon calls.
#     #
#     # Input:
#     #   chain_pub_keys — SPX_WOTS_LEN * DIGEST_LEN FEs: completed chain-end hashes
#     # Output:
#     #   out — DIGEST_LEN FEs: folded public key hash
#     pass


# @inline
# def fold_roots(roots, out):
#     # Fold SPX_FORS_TREES (9) FORS tree roots into the FORS public key digest.
#     # Sequential left-fold:
#     #   acc = poseidon(roots[0], roots[1])
#     #   for i in 2..9: acc = poseidon(acc, roots[i])
#     # Costs 8 Poseidon calls.
#     #
#     # Input:
#     #   roots — SPX_FORS_TREES * DIGEST_LEN FEs: one root per FORS tree
#     # Output:
#     #   out — DIGEST_LEN FEs: FORS public key hash
#     pass
