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
HYPERTREE_SIG_SIZE_FE = SPX_D * (RANDOMNESS_LEN + 2 + SPX_WOTS_LEN * HALF_DIGEST_LEN + SPX_TREE_HEIGHT * HALF_DIGEST_LEN)  # 540

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
def adrs_compress_hcl(pk_seed_offset, adrs0, adrs1, data_right, out):
    # Tweaked Poseidon16 compression using poseidon16_compress_half_hardcoded_left.
    # The first 4 FEs of the left input (pk_seed) are read directly from memory[pk_seed_offset..pk_seed_offset+4]
    # at the AIR level — no copy needed.
    #
    # pk_seed_offset — compile-time constant: address of this signer's pk_seed in the pk_seed table
    # adrs0          — scalar: packed layer/type/tree_address field element
    # adrs1          — scalar: packed positional fields (kp_addr / chain / hash or tree_height / tree_index)
    # data_right     — pointer to DIGEST_LEN (8) FEs: right half of the Poseidon input
    # out            — pointer to HALF_DIGEST_LEN (4) FEs: first 4 FEs of Poseidon output (HalfDigest)
    left_adrs = Array(HALF_DIGEST_LEN)
    left_adrs[0] = adrs0
    left_adrs[1] = adrs1
    left_adrs[2] = 0
    left_adrs[3] = 0
    poseidon16_compress_half_hardcoded_left(left_adrs, data_right, out, pk_seed_offset)
    return

@inline
def do_5_fors_merkle_level_const(k, pk_seed_offset, tree_index, tree_ht_start, adrs1_ptr, rem_ptr, leaf_index, state_in, sibling, state_out):
    # Advance MERKLE_LEVEL_STEP (5) levels of a FORS Merkle tree with tweaked Poseidon.
    # k, tree_index, tree_ht_start are compile-time; adrs1_ptr, rem_ptr, leaf_index are runtime.
    #
    # k selects the left/right direction at each level (bit i of k).
    #
    # adrs1 for each level is provided by hint_fors_node_adrs and range-checked here:
    #   adrs1_ptr[h] = (leaf_index >> H) | (H << ADRS1_TREE_HT_SHIFT)
    #   rem_ptr[h]   = leaf_index % (1 << H)
    # Constraint: leaf_index == (adrs1_ptr[h] - H * 2^ADRS1_TREE_HT_SHIFT) * 2^H + rem_ptr[h]
    #             rem_ptr[h] < 2^H
    #
    # state_in  — HALF_DIGEST_LEN (4) FEs: current node
    # sibling   — MERKLE_LEVEL_STEP * HALF_DIGEST_LEN FEs: siblings per level
    # state_out — HALF_DIGEST_LEN (4) FEs: output node after MERKLE_LEVEL_STEP compressions
    FORS_ADRS0 = ADRS_FORS_TREE * (2 ** ADRS0_TYPE_SHIFT) + tree_index * (2 ** ADRS0_TREE_SHIFT)

    b0 = k % 2
    b0r = (k - b0) / 2
    b1 = b0r % 2
    b1r = (b0r - b1) / 2
    b2 = b1r % 2
    b2r = (b1r - b2) / 2
    b3 = b2r % 2
    b3r = (b2r - b3) / 2
    b4 = b3r % 2

    intermediate_states = Array((MERKLE_LEVEL_STEP - 1) * HALF_DIGEST_LEN)

    # Level 0: absolute height H0 = tree_ht_start + 1
    H0 = tree_ht_start + 1
    adrs1_0 = adrs1_ptr[0]
    rem_0   = rem_ptr[0]
    assert rem_0 < 2 ** H0
    assert leaf_index == (adrs1_0 - H0 * (2 ** ADRS1_TREE_HT_SHIFT)) * (2 ** H0) + rem_0

    right0 = Array(DIGEST_LEN)
    if b0 == 0:
        copy_4(state_in, right0)
        copy_4(sibling, right0 + HALF_DIGEST_LEN)
    else:
        copy_4(sibling, right0)
        copy_4(state_in, right0 + HALF_DIGEST_LEN)
    adrs_compress_hcl(pk_seed_offset, FORS_ADRS0, adrs1_0, right0, intermediate_states)

    # Level 1: absolute height H1 = tree_ht_start + 2
    H1 = tree_ht_start + 2
    adrs1_1 = adrs1_ptr[1]
    rem_1   = rem_ptr[1]
    assert rem_1 < 2 ** H1
    assert leaf_index == (adrs1_1 - H1 * (2 ** ADRS1_TREE_HT_SHIFT)) * (2 ** H1) + rem_1

    right1 = Array(DIGEST_LEN)
    if b1 == 0:
        copy_4(intermediate_states, right1)
        copy_4(sibling + HALF_DIGEST_LEN, right1 + HALF_DIGEST_LEN)
    else:
        copy_4(sibling + HALF_DIGEST_LEN, right1)
        copy_4(intermediate_states, right1 + HALF_DIGEST_LEN)
    adrs_compress_hcl(pk_seed_offset, FORS_ADRS0, adrs1_1, right1, intermediate_states + HALF_DIGEST_LEN)

    # Level 2: absolute height H2 = tree_ht_start + 3
    H2 = tree_ht_start + 3
    adrs1_2 = adrs1_ptr[2]
    rem_2   = rem_ptr[2]
    assert rem_2 < 2 ** H2
    assert leaf_index == (adrs1_2 - H2 * (2 ** ADRS1_TREE_HT_SHIFT)) * (2 ** H2) + rem_2

    right2 = Array(DIGEST_LEN)
    if b2 == 0:
        copy_4(intermediate_states + HALF_DIGEST_LEN, right2)
        copy_4(sibling + 2 * HALF_DIGEST_LEN, right2 + HALF_DIGEST_LEN)
    else:
        copy_4(sibling + 2 * HALF_DIGEST_LEN, right2)
        copy_4(intermediate_states + HALF_DIGEST_LEN, right2 + HALF_DIGEST_LEN)
    adrs_compress_hcl(pk_seed_offset, FORS_ADRS0, adrs1_2, right2, intermediate_states + 2 * HALF_DIGEST_LEN)

    # Level 3: absolute height H3 = tree_ht_start + 4
    H3 = tree_ht_start + 4
    adrs1_3 = adrs1_ptr[3]
    rem_3   = rem_ptr[3]
    assert rem_3 < 2 ** H3
    assert leaf_index == (adrs1_3 - H3 * (2 ** ADRS1_TREE_HT_SHIFT)) * (2 ** H3) + rem_3

    right3 = Array(DIGEST_LEN)
    if b3 == 0:
        copy_4(intermediate_states + 2 * HALF_DIGEST_LEN, right3)
        copy_4(sibling + 3 * HALF_DIGEST_LEN, right3 + HALF_DIGEST_LEN)
    else:
        copy_4(sibling + 3 * HALF_DIGEST_LEN, right3)
        copy_4(intermediate_states + 2 * HALF_DIGEST_LEN, right3 + HALF_DIGEST_LEN)
    adrs_compress_hcl(pk_seed_offset, FORS_ADRS0, adrs1_3, right3, intermediate_states + 3 * HALF_DIGEST_LEN)

    # Level 4: absolute height H4 = tree_ht_start + 5
    H4 = tree_ht_start + 5
    adrs1_4 = adrs1_ptr[4]
    rem_4   = rem_ptr[4]
    assert rem_4 < 2 ** H4
    assert leaf_index == (adrs1_4 - H4 * (2 ** ADRS1_TREE_HT_SHIFT)) * (2 ** H4) + rem_4

    right4 = Array(DIGEST_LEN)
    if b4 == 0:
        copy_4(intermediate_states + 3 * HALF_DIGEST_LEN, right4)
        copy_4(sibling + 4 * HALF_DIGEST_LEN, right4 + HALF_DIGEST_LEN)
    else:
        copy_4(sibling + 4 * HALF_DIGEST_LEN, right4)
        copy_4(intermediate_states + 3 * HALF_DIGEST_LEN, right4 + HALF_DIGEST_LEN)
    adrs_compress_hcl(pk_seed_offset, FORS_ADRS0, adrs1_4, right4, state_out)
    return


@inline
def do_5_fors_merkle_level(k, pk_seed_offset, tree_index, tree_ht_start, adrs1_ptr, rem_ptr, leaf_index, state_in, sibling, state_out):
    match_range(k, range(0, 2**MERKLE_LEVEL_STEP), lambda k_prime: do_5_fors_merkle_level_const(k_prime, pk_seed_offset, tree_index, tree_ht_start, adrs1_ptr, rem_ptr, leaf_index, state_in, sibling, state_out))
    return


@inline
def do_5_hypertree_merkle_level_const(k, pk_seed_offset, tree_adrs0, tree_ht_start,
                                       adrs1_ptr, rem_ptr, leaf_index,
                                       state_in, sibling, state_out):
    # Advance MERKLE_LEVEL_STEP (5) levels of an XMSS hypertree Merkle tree with tweaked Poseidon.
    # Identical structure to do_5_fors_merkle_level_const but uses TREE tweak in adrs0.
    # k, tree_ht_start are compile-time; tree_adrs0, leaf_index are runtime.
    #
    # tree_adrs0 = layer + (ADRS_TREE << ADRS0_TYPE_SHIFT) + (layer_tree_address << ADRS0_TREE_SHIFT)
    # adrs1 per level: filled by hint_fors_node_adrs (reused — TREE and FORS_TREE share adrs1 layout).

    b0 = k % 2
    b0r = (k - b0) / 2
    b1 = b0r % 2
    b1r = (b0r - b1) / 2
    b2 = b1r % 2
    b2r = (b1r - b2) / 2
    b3 = b2r % 2
    b3r = (b2r - b3) / 2
    b4 = b3r % 2

    intermediate_states = Array((MERKLE_LEVEL_STEP - 1) * HALF_DIGEST_LEN)

    # Level 0: absolute height H0 = tree_ht_start + 1
    H0 = tree_ht_start + 1
    adrs1_0 = adrs1_ptr[0]
    rem_0   = rem_ptr[0]
    assert rem_0 < 2 ** H0
    assert leaf_index == (adrs1_0 - H0 * (2 ** ADRS1_TREE_HT_SHIFT)) * (2 ** H0) + rem_0

    right0 = Array(DIGEST_LEN)
    if b0 == 0:
        copy_4(state_in, right0)
        copy_4(sibling, right0 + HALF_DIGEST_LEN)
    else:
        copy_4(sibling, right0)
        copy_4(state_in, right0 + HALF_DIGEST_LEN)
    adrs_compress_hcl(pk_seed_offset, tree_adrs0, adrs1_0, right0, intermediate_states)

    # Level 1: absolute height H1 = tree_ht_start + 2
    H1 = tree_ht_start + 2
    adrs1_1 = adrs1_ptr[1]
    rem_1   = rem_ptr[1]
    assert rem_1 < 2 ** H1
    assert leaf_index == (adrs1_1 - H1 * (2 ** ADRS1_TREE_HT_SHIFT)) * (2 ** H1) + rem_1

    right1 = Array(DIGEST_LEN)
    if b1 == 0:
        copy_4(intermediate_states, right1)
        copy_4(sibling + HALF_DIGEST_LEN, right1 + HALF_DIGEST_LEN)
    else:
        copy_4(sibling + HALF_DIGEST_LEN, right1)
        copy_4(intermediate_states, right1 + HALF_DIGEST_LEN)
    adrs_compress_hcl(pk_seed_offset, tree_adrs0, adrs1_1, right1, intermediate_states + HALF_DIGEST_LEN)

    # Level 2: absolute height H2 = tree_ht_start + 3
    H2 = tree_ht_start + 3
    adrs1_2 = adrs1_ptr[2]
    rem_2   = rem_ptr[2]
    assert rem_2 < 2 ** H2
    assert leaf_index == (adrs1_2 - H2 * (2 ** ADRS1_TREE_HT_SHIFT)) * (2 ** H2) + rem_2

    right2 = Array(DIGEST_LEN)
    if b2 == 0:
        copy_4(intermediate_states + HALF_DIGEST_LEN, right2)
        copy_4(sibling + 2 * HALF_DIGEST_LEN, right2 + HALF_DIGEST_LEN)
    else:
        copy_4(sibling + 2 * HALF_DIGEST_LEN, right2)
        copy_4(intermediate_states + HALF_DIGEST_LEN, right2 + HALF_DIGEST_LEN)
    adrs_compress_hcl(pk_seed_offset, tree_adrs0, adrs1_2, right2, intermediate_states + 2 * HALF_DIGEST_LEN)

    # Level 3: absolute height H3 = tree_ht_start + 4
    H3 = tree_ht_start + 4
    adrs1_3 = adrs1_ptr[3]
    rem_3   = rem_ptr[3]
    assert rem_3 < 2 ** H3
    assert leaf_index == (adrs1_3 - H3 * (2 ** ADRS1_TREE_HT_SHIFT)) * (2 ** H3) + rem_3

    right3 = Array(DIGEST_LEN)
    if b3 == 0:
        copy_4(intermediate_states + 2 * HALF_DIGEST_LEN, right3)
        copy_4(sibling + 3 * HALF_DIGEST_LEN, right3 + HALF_DIGEST_LEN)
    else:
        copy_4(sibling + 3 * HALF_DIGEST_LEN, right3)
        copy_4(intermediate_states + 2 * HALF_DIGEST_LEN, right3 + HALF_DIGEST_LEN)
    adrs_compress_hcl(pk_seed_offset, tree_adrs0, adrs1_3, right3, intermediate_states + 3 * HALF_DIGEST_LEN)

    # Level 4: absolute height H4 = tree_ht_start + 5
    H4 = tree_ht_start + 5
    adrs1_4 = adrs1_ptr[4]
    rem_4   = rem_ptr[4]
    assert rem_4 < 2 ** H4
    assert leaf_index == (adrs1_4 - H4 * (2 ** ADRS1_TREE_HT_SHIFT)) * (2 ** H4) + rem_4

    right4 = Array(DIGEST_LEN)
    if b4 == 0:
        copy_4(intermediate_states + 3 * HALF_DIGEST_LEN, right4)
        copy_4(sibling + 4 * HALF_DIGEST_LEN, right4 + HALF_DIGEST_LEN)
    else:
        copy_4(sibling + 4 * HALF_DIGEST_LEN, right4)
        copy_4(intermediate_states + 3 * HALF_DIGEST_LEN, right4 + HALF_DIGEST_LEN)
    adrs_compress_hcl(pk_seed_offset, tree_adrs0, adrs1_4, right4, state_out)
    return


@inline
def do_5_hypertree_merkle_level(k, pk_seed_offset, tree_adrs0, tree_ht_start,
                                 adrs1_ptr, rem_ptr, leaf_index,
                                 state_in, sibling, state_out):
    match_range(k, range(0, 2**MERKLE_LEVEL_STEP),
        lambda k_prime: do_5_hypertree_merkle_level_const(k_prime, pk_seed_offset, tree_adrs0,
                                                           tree_ht_start, adrs1_ptr, rem_ptr, leaf_index,
                                                           state_in, sibling, state_out))
    return


@inline
def fold_wots_pubkey(pk_seed_offset, adrs0, adrs1, chain_pub_keys, out):
    # Fold SPX_WOTS_LEN (32) completed chain tips into a single WOTS+ public key digest.
    # Matches WotsPublicKey::hash() in wots.rs — tweaked left-fold:
    #   left  = [pk_seed[0..4] | adrs0, adrs1, 0, 0]   (constant across all steps)
    #   right = [acc[0..4] | next_tip[0..4]]
    # adrs0/adrs1 encode Adrs::wots_pk(layer, tree_addr, kp_addr) — compile-time constants at all call sites.
    # Costs 31 adrs_compress_hcl calls.
    #
    # Inputs:
    #   pk_seed_offset — compile-time constant: address of this signer's pk_seed in the pk_seed table
    #   adrs0          — scalar: packed layer/type/tree_address (WOTS_PK type)
    #   adrs1          — scalar: kp_addr (chain=0, hash=0)
    #   chain_pub_keys — SPX_WOTS_LEN * HALF_DIGEST_LEN FEs: completed chain-end HalfDigests
    # Output:
    #   out — HALF_DIGEST_LEN (4) FEs: folded WOTS+ public key hash
    states = Array((SPX_WOTS_LEN - 2) * HALF_DIGEST_LEN)

    right0 = Array(DIGEST_LEN)
    copy_4(chain_pub_keys, right0)
    copy_4(chain_pub_keys + HALF_DIGEST_LEN, right0 + HALF_DIGEST_LEN)
    adrs_compress_hcl(pk_seed_offset, adrs0, adrs1, right0, states)

    for i in unroll(1, SPX_WOTS_LEN - 2):
        right_i = Array(DIGEST_LEN)
        copy_4(states + (i - 1) * HALF_DIGEST_LEN, right_i)
        copy_4(chain_pub_keys + (i + 1) * HALF_DIGEST_LEN, right_i + HALF_DIGEST_LEN)
        adrs_compress_hcl(pk_seed_offset, adrs0, adrs1, right_i, states + i * HALF_DIGEST_LEN)

    right_last = Array(DIGEST_LEN)
    copy_4(states + (SPX_WOTS_LEN - 3) * HALF_DIGEST_LEN, right_last)
    copy_4(chain_pub_keys + (SPX_WOTS_LEN - 1) * HALF_DIGEST_LEN, right_last + HALF_DIGEST_LEN)
    adrs_compress_hcl(pk_seed_offset, adrs0, adrs1, right_last, out)
    return

@inline
def fold_roots(pk_seed_offset, roots, out):
    # Fold SPX_FORS_TREES (9) FORS tree roots into the FORS public key digest.
    # Tweaked left-fold matching fors.rs::fold_roots:
    #   adrs0 = pack(layer=0, type=FORS_ROOTS, tree_addr=0)  — constant across all steps
    #   adrs1 = i                                              — step index (kp_addr field)
    #   right = [acc[0..4] | next_root[0..4]]
    # Costs 8 adrs_compress_hcl calls.
    #
    # Inputs:
    #   pk_seed_offset — compile-time constant: address of this signer's pk_seed in the pk_seed table
    #   roots          — SPX_FORS_TREES * HALF_DIGEST_LEN FEs: one HalfDigest root per FORS tree
    # Output:
    #   out            — HALF_DIGEST_LEN (4) FEs: FORS public key hash
    FORS_ROOTS_ADRS0 = ADRS_FORS_ROOTS * (2 ** ADRS0_TYPE_SHIFT)  # layer=0, type=4, tree_addr=0 → 16

    states = Array((SPX_FORS_TREES - 2) * HALF_DIGEST_LEN)

    right0 = Array(DIGEST_LEN)
    copy_4(roots, right0)
    copy_4(roots + HALF_DIGEST_LEN, right0 + HALF_DIGEST_LEN)
    adrs_compress_hcl(pk_seed_offset, FORS_ROOTS_ADRS0, 0, right0, states)

    for i in unroll(1, SPX_FORS_TREES - 2):
        right_i = Array(DIGEST_LEN)
        copy_4(states + (i - 1) * HALF_DIGEST_LEN, right_i)
        copy_4(roots + (i + 1) * HALF_DIGEST_LEN, right_i + HALF_DIGEST_LEN)
        adrs_compress_hcl(pk_seed_offset, FORS_ROOTS_ADRS0, i, right_i, states + i * HALF_DIGEST_LEN)

    right_last = Array(DIGEST_LEN)
    copy_4(states + (SPX_FORS_TREES - 3) * HALF_DIGEST_LEN, right_last)
    copy_4(roots + (SPX_FORS_TREES - 1) * HALF_DIGEST_LEN, right_last + HALF_DIGEST_LEN)
    adrs_compress_hcl(pk_seed_offset, FORS_ROOTS_ADRS0, SPX_FORS_TREES - 2, right_last, out)
    return
