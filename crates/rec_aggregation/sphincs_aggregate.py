from snark_lib import *
from sphincs_fors import *
from sphincs_hypertree import *


@inline
def decompose_message_digest(message_digest, fors_indices, layer_leaf_indices):
    # Single-pass decomposition of the 8-FE message digest into the routing and
    # index values needed by fors_verify and hypertree_verify.
    # This is called once per signature at the top of sphincs_verify.
    #
    # All values are provided via hints and verified by reconstructing the original
    # field elements from the hinted values, then asserting equality with message_digest.
    #
    # Hints consumed (in order):
    #   leaf_idx:       11-bit value occupying FE[0] bits 0–10
    #   tree_address:   22-bit value occupying FE[0] bits 16–31 + FE[1] bits 0–5
    #   fors_indices[9]: each 15-bit; 135 bits packed LE into FE[1] bits 8–31 and FE[2..5]
    #                    (the 136th mhash bit is left unconstrained per fors.rs:187)
    #
    # Range checks enforced:
    #   leaf_idx        < 2^11
    #   tree_address    < 2^22
    #   fors_indices[i] < 2^15  for i in 0..9
    #
    # Verification:
    #   FE[0] reconstructed as leaf_idx + (tree_address_lo << 16) and asserted == message_digest[0]
    #   FE[1..5] reconstructed from tree_address_hi + packed fors_indices and
    #   asserted == message_digest[1..5]  (one field-arithmetic expression per FE)
    #
    # Input:
    #   message_digest    — DIGEST_LEN FEs: output of the message hash
    # Outputs:
    #   fors_indices      — SPX_FORS_TREES FEs (written in-place):
    #                         each < 2^SPX_FORS_HEIGHT; FORS leaf index for tree t
    #   layer_leaf_indices — 3 FEs (written in-place):
    #                         [0] = leaf_idx                     (layer 0 routing)
    #                         [1] = tree_address & 0x7FF         (layer 1 routing)
    #                         [2] = (tree_address >> 11) & 0x7FF (layer 2 routing)
    pass


@inline
def sphincs_verify(pk, message, fors_sig, hypertree_sig):
    # Top-level SPHINCS+ signature verifier.
    #
    # Steps:
    #   1. Hash the MESSAGE_LEN (9)-FE message to an 8-FE message digest:
    #        right[0] = message[8]
    #        message_digest = poseidon(message[0..8], right)   (1 Poseidon call)
    #   2. Decompose the digest once via decompose_message_digest to obtain
    #      fors_indices[9] and layer_leaf_indices[3].
    #   3. Verify FORS: fors_pubkey = fors_verify(fors_sig, fors_indices).
    #   4. Verify hypertree: hypertree_verify(hypertree_sig, fors_pubkey,
    #                                         layer_leaf_indices, pk).
    #
    # Inputs:
    #   pk            — DIGEST_LEN FEs: signer's SPHINCS+ public key
    #   message       — MESSAGE_LEN (9) FEs: shared message
    #   fors_sig      — FORS_SIG_SIZE_FE (1152) FEs loaded via hint_sphincs_fors
    #   hypertree_sig — HYPERTREE_SIG_SIZE_FE (1053) FEs loaded via hint_sphincs_hypertree
    #
    # Postcondition:
    #   Asserts the signature is valid for (pk, message).
    #   Fails the circuit if any sub-verification does not hold.
    pass
