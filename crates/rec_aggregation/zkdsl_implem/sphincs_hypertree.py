from snark_lib import *
from sphincs_utils import *
from sphincs_wots import *


@inline
def hypertree_merkle_verify(pk_seed, tree_adrs0, layer_leaf_index, leaf_node, root_out):
    # Verify a single SPX_TREE_HEIGHT (11)-level binary Merkle auth path within one
    # hypertree layer. 11 = 1 + 5 + 5, so we decompose as:
    #   bit0        — low bit, constrained to {0,1} via bit-squaring
    #   sub_indices — two 5-bit chunks of the upper 10 bits, range-checked inside do_5_hypertree_merkle_level
    #
    # The reconstruction assertion layer_leaf_index == bit0 + sub_indices[0]*2 + sub_indices[1]*2^6
    # binds the hints to layer_leaf_index.
    #
    # Inputs:
    #   pk_seed          — pointer to HALF_DIGEST_LEN (4) FEs: per-signer public seed
    #   tree_adrs0       — scalar: packed TREE adrs0 = layer + (ADRS_TREE<<2) + (layer_tree_address<<5)
    #   layer_leaf_index — scalar < 2^SPX_TREE_HEIGHT; range-checked by decompose_message_digest
    #   leaf_node        — HALF_DIGEST_LEN (4) FEs: WOTS+ public key hash
    # Siblings:
    #   consumed level-by-level from the "ht_auth" hint queue (11 nodes per layer, bottom-up):
    #   the bit0 level consumes one sibling, then each of the two do_5 groups consumes five.
    # Output:
    #   root_out         — HALF_DIGEST_LEN (4) FEs: computed layer root
    #
    # Precondition: layer_leaf_index < 2^SPX_TREE_HEIGHT
    debug_assert(layer_leaf_index < 2**SPX_TREE_HEIGHT)

    # Hint the low bit, constrain it to {0,1}, then derive the upper 10 bits.
    bit0 = Array(1)
    hint_decompose_bits_little(layer_leaf_index, bit0, 1)
    assert bit0[0] * (1 - bit0[0]) == 0

    # upper_10 = (layer_leaf_index - bit0) / 2; decompose into two MERKLE_LEVEL_STEP-bit chunks.
    upper_10 = (layer_leaf_index - bit0[0]) / 2
    sub_indices = Array(2)
    hint_decompose_bits_fors(sub_indices, upper_10, MERKLE_LEVEL_STEP, 2)

    # Reconstruction: bind both hints to layer_leaf_index.
    assert layer_leaf_index == bit0[0] + sub_indices[0] * 2 + sub_indices[1] * 2**6

    # Level 0 (single level): tweaked hash with TREE adrs.
    # adrs1 for level 0: hinted via hint_fors_node_adrs with tree_ht_start=0.
    # The hint always fills MERKLE_LEVEL_STEP slots; only index 0 (H=1) is used here.
    adrs1_buf0 = Array(MERKLE_LEVEL_STEP)
    rem_buf0   = Array(MERKLE_LEVEL_STEP)
    hint_fors_node_adrs(adrs1_buf0, rem_buf0, layer_leaf_index, 0)
    assert rem_buf0[0] < 2
    assert layer_leaf_index == (adrs1_buf0[0] - 1 * (2 ** ADRS1_TREE_HT_SHIFT)) * 2 + rem_buf0[0]

    # The bit0 direction is runtime (not a compile-time match arm), so this single level keeps
    # the staged-sibling form: witness the sibling into a 4-FE buffer and pass it to
    # adrs_compress_pair. The siblings for the two do_5 groups are streamed inside those calls.
    sib0 = Array(HALF_DIGEST_LEN)
    hint_witness("ht_auth", sib0)
    after_bit0 = Array(HALF_DIGEST_LEN)
    if bit0[0] == 0:
        adrs_compress_pair(pk_seed, tree_adrs0, adrs1_buf0[0], leaf_node, sib0, after_bit0)
    else:
        adrs_compress_pair(pk_seed, tree_adrs0, adrs1_buf0[0], sib0, leaf_node, after_bit0)

    # Levels 1–5 (tree_ht_start=1): five tweaked levels via do_5_hypertree_merkle_level.
    adrs1_chunk0 = Array(MERKLE_LEVEL_STEP)
    rem_chunk0   = Array(MERKLE_LEVEL_STEP)
    hint_fors_node_adrs(adrs1_chunk0, rem_chunk0, layer_leaf_index, 1)
    after_chunk0 = Array(HALF_DIGEST_LEN)
    do_5_hypertree_merkle_level(sub_indices[0], pk_seed, tree_adrs0, 1,
                                 adrs1_chunk0, rem_chunk0, layer_leaf_index,
                                 after_bit0, after_chunk0)

    # Levels 6–10 (tree_ht_start=6): five tweaked levels via do_5_hypertree_merkle_level.
    adrs1_chunk1 = Array(MERKLE_LEVEL_STEP)
    rem_chunk1   = Array(MERKLE_LEVEL_STEP)
    hint_fors_node_adrs(adrs1_chunk1, rem_chunk1, layer_leaf_index, 6)
    do_5_hypertree_merkle_level(sub_indices[1], pk_seed, tree_adrs0, 6,
                                 adrs1_chunk1, rem_chunk1, layer_leaf_index,
                                 after_chunk0, root_out)
    return

@inline
def hypertree_verify(pk_seed, fors_pubkey, layer_leaf_indices, expected_pk):
    # Verify the SPX_D (3)-layer XMSS hypertree and assert the final root equals expected_pk.
    #
    # Layer loop (compile-time unroll over l in 0..SPX_D):
    #   1. Read randomness, chain_tips, auth_path from hypertree_sig at the layer offset.
    #   2. Recover the WOTS+ leaf node: wots_encode_and_complete(current_msg, ...).
    #   3. Walk the 11-level auth path: hypertree_merkle_verify(pk_seed, layer, layer_tree_address, ...).
    #   4. For l < SPX_D - 1: next message = half_to_full(layer_root) = [root | 0,0,0,0].
    #      For l == SPX_D - 1: write directly to expected_pk (asserting equality).
    #
    # Layer 0 initial message: half_to_full(fors_pubkey).
    # layer_tree_address for l=0,1 is hinted (runtime); for l=2 it is always 0 (compile-time).
    #
    # Inputs:
    #   hypertree_sig       — HYPERTREE_SIG_SIZE_FE FEs; layout per layer l:
    #                         [randomness(6) | adrs0(1) | adrs1(1) | chain_tips(128)]
    #                         (auth paths are no longer in this blob — see ht_auth below)
    #   ht_auth             — auth-path siblings, consumed level-by-level inside
    #                         hypertree_merkle_verify (11 nodes per layer, bottom-up; same order
    #                         as the legacy per-layer auth-path layout)
    #   pk_seed             — pointer to HALF_DIGEST_LEN (4) FEs
    #   fors_pubkey         — HALF_DIGEST_LEN (4) FEs: output of fors_verify
    #   layer_leaf_indices  — SPX_D (3) FEs, precomputed by decompose_message_digest
    #   layer_tree_addresses — 2 FEs: tree addresses for layers 0 and 1 (layer 2 is always 0)
    #   expected_pk         — HALF_DIGEST_LEN (4) FEs: signer's SPHINCS+ public key root
    #
    # Postcondition: asserts reconstructed hypertree root equals expected_pk.

    hypertree_sig = Array(HYPERTREE_SIG_SIZE_FE)
    hint_witness("hypertree_sig", hypertree_sig)

    layer_tree_addresses = Array(SPX_D)
    hint_witness("layer_tree_addresses", layer_tree_addresses)

    # Layer 0 message: half_to_full(fors_pubkey) = [fors_pubkey | 0,0,0,0].
    msg_0 = Array(DIGEST_LEN)
    copy_4(fors_pubkey, msg_0)
    set_to_4_zeros(msg_0 + 4)

    # Per-layer layout: randomness(6) | adrs0(1) | adrs1(1) | chain_tips(128) = 136 FEs.
    # (Auth-path siblings are streamed via the ht_auth hint queue, not stored here.)
    layer_stride = RANDOMNESS_LEN + 2 + SPX_WOTS_LEN * HALF_DIGEST_LEN

    # --- Layer 0 ---
    randomness_ptr_0 = hypertree_sig
    chain_tips_ptr_0 = randomness_ptr_0 + RANDOMNESS_LEN + 2

    layer_tree_address_0 = layer_tree_addresses[0]
    kp_adrs1_0        = layer_leaf_indices[0]
    wots_hash_adrs0_0 = 0 + (ADRS_WOTS_HASH * (2 ** ADRS0_TYPE_SHIFT)) + (layer_tree_address_0 * (2 ** ADRS0_TREE_SHIFT))
    wots_pk_adrs0_0   = 0 + (ADRS_WOTS_PK   * (2 ** ADRS0_TYPE_SHIFT)) + (layer_tree_address_0 * (2 ** ADRS0_TREE_SHIFT))

    wots_leaf_0 = Array(HALF_DIGEST_LEN)
    wots_encode_and_complete(msg_0, wots_hash_adrs0_0, kp_adrs1_0, randomness_ptr_0, chain_tips_ptr_0,
                              pk_seed, wots_pk_adrs0_0, kp_adrs1_0, wots_leaf_0)

    tree_adrs0_0 = 0 + (ADRS_TREE * (2 ** ADRS0_TYPE_SHIFT)) + (layer_tree_address_0 * (2 ** ADRS0_TREE_SHIFT))
    layer_root_0 = Array(HALF_DIGEST_LEN)
    hypertree_merkle_verify(pk_seed, tree_adrs0_0, layer_leaf_indices[0],
                             wots_leaf_0, layer_root_0)

    msg_1 = Array(DIGEST_LEN)
    copy_4(layer_root_0, msg_1)
    set_to_4_zeros(msg_1 + 4)

    # --- Layer 1 ---
    randomness_ptr_1 = hypertree_sig + layer_stride
    chain_tips_ptr_1 = randomness_ptr_1 + RANDOMNESS_LEN + 2

    layer_tree_address_1 = layer_tree_addresses[1]
    kp_adrs1_1        = layer_leaf_indices[1]
    wots_hash_adrs0_1 = 1 + (ADRS_WOTS_HASH * (2 ** ADRS0_TYPE_SHIFT)) + (layer_tree_address_1 * (2 ** ADRS0_TREE_SHIFT))
    wots_pk_adrs0_1   = 1 + (ADRS_WOTS_PK   * (2 ** ADRS0_TYPE_SHIFT)) + (layer_tree_address_1 * (2 ** ADRS0_TREE_SHIFT))

    wots_leaf_1 = Array(HALF_DIGEST_LEN)
    wots_encode_and_complete(msg_1, wots_hash_adrs0_1, kp_adrs1_1, randomness_ptr_1, chain_tips_ptr_1,
                              pk_seed, wots_pk_adrs0_1, kp_adrs1_1, wots_leaf_1)

    tree_adrs0_1 = 1 + (ADRS_TREE * (2 ** ADRS0_TYPE_SHIFT)) + (layer_tree_address_1 * (2 ** ADRS0_TREE_SHIFT))
    layer_root_1 = Array(HALF_DIGEST_LEN)
    hypertree_merkle_verify(pk_seed, tree_adrs0_1, layer_leaf_indices[1],
                             wots_leaf_1, layer_root_1)

    msg_2 = Array(DIGEST_LEN)
    copy_4(layer_root_1, msg_2)
    set_to_4_zeros(msg_2 + 4)

    # --- Layer 2 (final): tree_address is always 0 ---
    randomness_ptr_2 = hypertree_sig + 2 * layer_stride
    chain_tips_ptr_2 = randomness_ptr_2 + RANDOMNESS_LEN + 2

    kp_adrs1_2        = layer_leaf_indices[2]
    wots_hash_adrs0_2 = 2 + (ADRS_WOTS_HASH * (2 ** ADRS0_TYPE_SHIFT))
    wots_pk_adrs0_2   = 2 + (ADRS_WOTS_PK   * (2 ** ADRS0_TYPE_SHIFT))

    wots_leaf_2 = Array(HALF_DIGEST_LEN)
    wots_encode_and_complete(msg_2, wots_hash_adrs0_2, kp_adrs1_2, randomness_ptr_2, chain_tips_ptr_2,
                              pk_seed, wots_pk_adrs0_2, kp_adrs1_2, wots_leaf_2)

    tree_adrs0_2 = 2 + (ADRS_TREE * (2 ** ADRS0_TYPE_SHIFT))
    hypertree_merkle_verify(pk_seed, tree_adrs0_2, layer_leaf_indices[2],
                             wots_leaf_2, expected_pk)
    return
