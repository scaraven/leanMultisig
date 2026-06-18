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

# Auth-path siblings are no longer carried in the committed fors_sig / hypertree_sig blobs;
# they are streamed via the "fors_auth" / "ht_auth" hint queues and placed directly into each
# Merkle level's Poseidon right-input block. The committed blobs hold only the non-sibling data.
FORS_SIG_SIZE_FE      = SPX_FORS_TREES * HALF_DIGEST_LEN   # 36: the 9 leaf secrets only
FORS_AUTH_SIZE_FE     = SPX_FORS_TREES * SPX_FORS_HEIGHT * HALF_DIGEST_LEN   # 540: 15 siblings per tree
HYPERTREE_SIG_SIZE_FE = SPX_D * (RANDOMNESS_LEN + 2 + SPX_WOTS_LEN * DIGEST_LEN)  # 792: no auth paths, 8-FE chain tips
HYPERTREE_AUTH_SIZE_FE = SPX_D * SPX_TREE_HEIGHT * HALF_DIGEST_LEN   # 132: 11 siblings per layer

# ADRS type codes — must match address.rs constants
ADRS_WOTS_HASH  = 0
ADRS_WOTS_PK    = 1
ADRS_TREE       = 2
ADRS_FORS_TREE  = 3
ADRS_FORS_ROOTS = 4
ADRS_WOTS_PRF   = 5
ADRS_FORS_PRF   = 6

# Bit offsets within adrs0: layer(2) | type(3) | tree_address(22) | fors_tree(4)
SPX_TREE_BITS = 22
ADRS0_TYPE_SHIFT = 2
ADRS0_TREE_SHIFT = 5  # 2 + 3
# FORS-internal tree number (0..SPX_FORS_TREES-1) packed above tree_address (FORS types only).
ADRS0_FORS_TREE_SHIFT = 5 + SPX_TREE_BITS  # 27

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
def adrs_compress_pair_t5(tweak5, adrs1, adrs2, right_lo, right_hi, out):
    # Compress with a pre-built 5-FE tweak prefix [pk_seed | adrs0] (built once per constant-adrs0
    # scope) plus the two per-call tweak FEs adrs1, adrs2. The 8-FE right half is assembled from
    # two separate HALF_DIGEST_LEN halves. Callers with only two tweaks pass adrs2 = 0.
    #
    # left = [tweak5[0..5] | adrs1, adrs2, 0]
    #
    # tweak5   — pointer to 5 FEs: [pk_seed | adrs0]
    # adrs1    — scalar (e.g. idx_leaf / key_pair_address)
    # adrs2    — scalar (e.g. FORS (tree_height, tree_index) Merkle coordinate; 0 if unused)
    # right_lo — pointer to HALF_DIGEST_LEN (4) FEs: first half of the Poseidon right input
    # right_hi — pointer to HALF_DIGEST_LEN (4) FEs: second half of the Poseidon right input
    # out      — pointer to HALF_DIGEST_LEN (4) FEs
    left = Array(DIGEST_LEN)
    copy_5(tweak5, left)
    left[5] = adrs1
    left[6] = adrs2
    left[7] = 0
    right = Array(DIGEST_LEN)
    copy_4(right_lo, right)
    copy_4(right_hi, right + HALF_DIGEST_LEN)
    poseidon16_compress_half(left, right, out)
    return


@inline
def make_tweak5(pk_seed, adrs0):
    # Build the 5-FE tweak prefix [pk_seed[0..4] | adrs0] used by adrs_compress_pair_t5.
    # Construct once per constant-adrs0 scope (a do_5_* group, a fold loop, a WOTS chain)
    # and reuse across every level/step in that scope, so the pk_seed copy is paid once
    # rather than once per Poseidon compression.
    tweak5 = Array(5)
    copy_4(pk_seed, tweak5)
    tweak5[4] = adrs0
    return tweak5


@inline
def adrs_compress_pair_t5_block(tweak5, adrs1, adrs2, right_block, out):
    # Same as adrs_compress_pair_t5 but the 8-FE right half is supplied pre-assembled as a
    # single contiguous pointer, so no right-half copy is performed. Used by the Merkle level
    # helpers, where the running state is written directly into one half of right_block by the
    # previous compression and the sibling is hint-placed into the other half. Callers with only
    # two tweaks pass adrs2 = 0.
    #
    # left = [tweak5[0..5] | adrs1, adrs2, 0]
    #
    # tweak5      — pointer to 5 FEs: [pk_seed | adrs0]
    # adrs1       — scalar
    # adrs2       — scalar (FORS (tree_height, tree_index) Merkle coordinate; 0 if unused)
    # right_block — pointer to DIGEST_LEN (8) contiguous FEs (the full Poseidon right input)
    # out         — pointer to HALF_DIGEST_LEN (4) FEs
    left = Array(DIGEST_LEN)
    copy_5(tweak5, left)
    left[5] = adrs1
    left[6] = adrs2
    left[7] = 0
    poseidon16_compress_half(left, right_block, out)
    return


@inline
def adrs_compress_pair_t5_block_out8(tweak5, adrs1, right_block, out8):
    # Like adrs_compress_pair_t5_block but writes the FULL 8-FE Poseidon output (constrained),
    # used by the WOTS hash chain so each step's full output can be fed directly as the next
    # step's 8-FE right input — no truncation, no zero-write, no copy between steps.
    #
    # left = [tweak5[0..5] | adrs1, 0, 0]
    #
    # tweak5      — pointer to 5 FEs: [pk_seed | adrs0]
    # adrs1       — scalar
    # right_block — pointer to DIGEST_LEN (8) contiguous FEs (the full Poseidon right input)
    # out8        — pointer to DIGEST_LEN (8) FEs (full constrained Poseidon output)
    left = Array(DIGEST_LEN)
    copy_5(tweak5, left)
    left[5] = adrs1
    left[6] = 0
    left[7] = 0
    poseidon16_compress(left, right_block, out8)
    return


@inline
def _merkle_level_assert(adrs1_h, rem_h, H, leaf_index):
    # Range-check + reconstruction binding for one Merkle level (shared by FORS and hypertree).
    assert rem_h < 2 ** H
    assert leaf_index == (adrs1_h - H * (2 ** ADRS1_TREE_HT_SHIFT)) * (2 ** H) + rem_h
    return


@inline
def state_half_offset(b):
    # Compile-time: the offset of the running-state half within an 8-FE block, given the
    # direction bit b in {0,1}. b == 0 → state on the left (low half, offset 0); b == 1 → right
    # half (offset HALF_DIGEST_LEN).
    return b * HALF_DIGEST_LEN


@inline
def sibling_half_offset(b):
    # Compile-time: the offset of the sibling half within an 8-FE block (the half not used by
    # the running state), for b in {0,1}.
    return HALF_DIGEST_LEN - b * HALF_DIGEST_LEN


@inline
def do_5_merkle_block_fors_const(k, tweak5, idx_leaf, tree_ht_start, adrs2_ptr, rem_ptr, leaf_index, state_in, state_out):
    # Advance MERKLE_LEVEL_STEP (5) levels of a FORS Merkle tree with copy-free right-half
    # assembly, hinting each sibling from the "fors_auth" queue. k, tree_ht_start are
    # compile-time; idx_leaf, adrs2_ptr, rem_ptr, leaf_index are runtime. k selects the
    # direction at each level (bit i of k).
    #
    # tweak5 — pointer to 5 FEs [pk_seed | FORS_ADRS0], built once per FORS tree by the caller
    # (constant across all levels of the tree, so it is hoisted out of this helper).
    # idx_leaf — hypertree key_pair_address, constant per FORS verification, passed as adrs1.
    #
    # adrs2 for each level is the (tree_height, tree_index) Merkle coordinate, provided by
    # hint_fors_node_adrs and range-checked here:
    #   adrs2_ptr[h] = (leaf_index >> H) | (H << ADRS1_TREE_HT_SHIFT); rem_ptr[h] = leaf_index % 2^H
    # Constraint: leaf_index == (adrs2_ptr[h] - H * 2^ADRS1_TREE_HT_SHIFT) * 2^H + rem_ptr[h].
    #
    # Per level i, the 8-FE Poseidon right input lives in blocks[i*DIGEST_LEN ..]. The running
    # state occupies the low half if bit b_i == 0 (state on the left) or the high half if b_i == 1
    # (state on the right); the sibling is hint-placed into the other half. The previous level's
    # output is written straight into the next level's state half, so only level 0's state needs
    # a single copy_4 of the incoming state_in.
    #
    # The levels are written out explicitly (rather than looped) because the hint_witness label
    # must be a string literal and the direction bits are distinct compile-time values.
    b0 = k % 2
    b0r = (k - b0) / 2
    b1 = b0r % 2
    b1r = (b0r - b1) / 2
    b2 = b1r % 2
    b2r = (b1r - b2) / 2
    b3 = b2r % 2
    b3r = (b2r - b3) / 2
    b4 = b3r % 2

    blocks = Array(MERKLE_LEVEL_STEP * DIGEST_LEN)
    block0 = blocks + 0 * DIGEST_LEN
    block1 = blocks + 1 * DIGEST_LEN
    block2 = blocks + 2 * DIGEST_LEN
    block3 = blocks + 3 * DIGEST_LEN
    block4 = blocks + 4 * DIGEST_LEN

    # Level 0: state placed from state_in; output into level 1's state half.
    copy_4(state_in, block0 + state_half_offset(b0))
    hint_witness("fors_auth", block0 + sibling_half_offset(b0))
    _merkle_level_assert(adrs2_ptr[0], rem_ptr[0], tree_ht_start + 1, leaf_index)
    adrs_compress_pair_t5_block(tweak5, idx_leaf, adrs2_ptr[0], block0, block1 + state_half_offset(b1))

    # Level 1
    hint_witness("fors_auth", block1 + sibling_half_offset(b1))
    _merkle_level_assert(adrs2_ptr[1], rem_ptr[1], tree_ht_start + 2, leaf_index)
    adrs_compress_pair_t5_block(tweak5, idx_leaf, adrs2_ptr[1], block1, block2 + state_half_offset(b2))

    # Level 2
    hint_witness("fors_auth", block2 + sibling_half_offset(b2))
    _merkle_level_assert(adrs2_ptr[2], rem_ptr[2], tree_ht_start + 3, leaf_index)
    adrs_compress_pair_t5_block(tweak5, idx_leaf, adrs2_ptr[2], block2, block3 + state_half_offset(b3))

    # Level 3
    hint_witness("fors_auth", block3 + sibling_half_offset(b3))
    _merkle_level_assert(adrs2_ptr[3], rem_ptr[3], tree_ht_start + 4, leaf_index)
    adrs_compress_pair_t5_block(tweak5, idx_leaf, adrs2_ptr[3], block3, block4 + state_half_offset(b4))

    # Level 4: output into state_out.
    hint_witness("fors_auth", block4 + sibling_half_offset(b4))
    _merkle_level_assert(adrs2_ptr[4], rem_ptr[4], tree_ht_start + 5, leaf_index)
    adrs_compress_pair_t5_block(tweak5, idx_leaf, adrs2_ptr[4], block4, state_out)
    return


@inline
def do_5_fors_merkle_level(k, tweak5, idx_leaf, tree_ht_start, adrs2_ptr, rem_ptr, leaf_index, state_in, state_out):
    match_range(k, range(0, 2**MERKLE_LEVEL_STEP), lambda k_prime: do_5_merkle_block_fors_const(k_prime, tweak5, idx_leaf, tree_ht_start, adrs2_ptr, rem_ptr, leaf_index, state_in, state_out))
    return


@inline
def do_5_merkle_block_ht_const(k, tweak5, tree_ht_start, adrs1_ptr, rem_ptr, leaf_index, state_in, state_out):
    # Advance MERKLE_LEVEL_STEP (5) levels of an XMSS hypertree Merkle tree with copy-free
    # right-half assembly, hinting each sibling from the "ht_auth" queue. k, tree_ht_start are
    # compile-time; leaf_index is runtime.
    #
    # tweak5 — pointer to 5 FEs [pk_seed | tree_adrs0], built once per hypertree layer by the
    # caller (tree_adrs0 is constant across all 11 levels of the layer, so it is hoisted out).
    # adrs1 per level: filled by hint_fors_node_adrs (reused — TREE and FORS_TREE share adrs1 layout).
    #
    # state_in  — HALF_DIGEST_LEN (4) FEs: current node
    # state_out — HALF_DIGEST_LEN (4) FEs: output node after MERKLE_LEVEL_STEP compressions
    #
    # NOTE: structurally identical to do_5_merkle_block_fors_const except the "ht_auth" hint label;
    # kept separate because hint_witness needs a string literal.
    b0 = k % 2
    b0r = (k - b0) / 2
    b1 = b0r % 2
    b1r = (b0r - b1) / 2
    b2 = b1r % 2
    b2r = (b1r - b2) / 2
    b3 = b2r % 2
    b3r = (b2r - b3) / 2
    b4 = b3r % 2

    blocks = Array(MERKLE_LEVEL_STEP * DIGEST_LEN)
    block0 = blocks + 0 * DIGEST_LEN
    block1 = blocks + 1 * DIGEST_LEN
    block2 = blocks + 2 * DIGEST_LEN
    block3 = blocks + 3 * DIGEST_LEN
    block4 = blocks + 4 * DIGEST_LEN

    # Level 0
    copy_4(state_in, block0 + state_half_offset(b0))
    hint_witness("ht_auth", block0 + sibling_half_offset(b0))
    _merkle_level_assert(adrs1_ptr[0], rem_ptr[0], tree_ht_start + 1, leaf_index)
    adrs_compress_pair_t5_block(tweak5, adrs1_ptr[0], 0, block0, block1 + state_half_offset(b1))

    # Level 1
    hint_witness("ht_auth", block1 + sibling_half_offset(b1))
    _merkle_level_assert(adrs1_ptr[1], rem_ptr[1], tree_ht_start + 2, leaf_index)
    adrs_compress_pair_t5_block(tweak5, adrs1_ptr[1], 0, block1, block2 + state_half_offset(b2))

    # Level 2
    hint_witness("ht_auth", block2 + sibling_half_offset(b2))
    _merkle_level_assert(adrs1_ptr[2], rem_ptr[2], tree_ht_start + 3, leaf_index)
    adrs_compress_pair_t5_block(tweak5, adrs1_ptr[2], 0, block2, block3 + state_half_offset(b3))

    # Level 3
    hint_witness("ht_auth", block3 + sibling_half_offset(b3))
    _merkle_level_assert(adrs1_ptr[3], rem_ptr[3], tree_ht_start + 4, leaf_index)
    adrs_compress_pair_t5_block(tweak5, adrs1_ptr[3], 0, block3, block4 + state_half_offset(b4))

    # Level 4
    hint_witness("ht_auth", block4 + sibling_half_offset(b4))
    _merkle_level_assert(adrs1_ptr[4], rem_ptr[4], tree_ht_start + 5, leaf_index)
    adrs_compress_pair_t5_block(tweak5, adrs1_ptr[4], 0, block4, state_out)
    return


@inline
def do_5_hypertree_merkle_level(k, tweak5, tree_ht_start,
                                 adrs1_ptr, rem_ptr, leaf_index,
                                 state_in, state_out):
    match_range(k, range(0, 2**MERKLE_LEVEL_STEP),
        lambda k_prime: do_5_merkle_block_ht_const(k_prime, tweak5,
                                                    tree_ht_start, adrs1_ptr, rem_ptr, leaf_index,
                                                    state_in, state_out))
    return


# The folds use a T-Sponge with replacement (Poseidon-16 compression mode, capacity 8 / rate 8):
# each compression absorbs a full 8-FE block of TWO 4-FE tips by overwriting the rate, while the
# running accumulator lives in the capacity. This roughly halves the compression count versus a
# per-tip left-fold. The structured IV [tweak5 | adrs1, 0, 0] is fed directly as the first
# compression's left input (no priming call); subsequent compressions take the previous full 8-FE
# state as their left input. Only the final squeeze truncates to a 4-FE HalfDigest.
#
# Tips are laid out CONTIGUOUSLY in `buf` (tip m @ buf + m * HALF_DIGEST_LEN), so absorb block i
# is the 8-FE slice buf[2i*HALF_DIGEST_LEN ..][..DIGEST_LEN] with no copy. The producer writes each
# tip directly into buf + m * HALF_DIGEST_LEN as it is computed.


@inline
def fold_tips_len(n):
    # Size of the contiguous tip buffer for n tips: n * HALF_DIGEST_LEN.
    return n * HALF_DIGEST_LEN


@inline
def _fold_tips_sponge(tweak5, adrs1, buf, n_pairs, out):
    # Shared T-Sponge core. Absorbs n_pairs 8-FE blocks (2 tips each) from the contiguous buffer
    # `buf` and squeezes the low 4 FE into `out`. n_pairs is compile-time and must be >= 1; the
    # buffer must hold at least 2 * n_pairs tips, zero-padded if the true tip count is odd.
    #
    #   tweak5 — pointer to 5 FEs [pk_seed | adrs0]: the fixed sponge tweak prefix
    #   adrs1  — scalar: occupies IV slot 5 (the only per-fold domain separator)
    #   buf    — contiguous tip buffer, 2 * n_pairs tips of HALF_DIGEST_LEN FE each
    #   out    — HALF_DIGEST_LEN (4) FEs: the squeezed digest
    states = Array(n_pairs * DIGEST_LEN)

    # Block 0: structured IV (left) absorbs the first pair (right) -> full 8-FE state.
    adrs_compress_pair_t5_block_out8(tweak5, adrs1, buf, states)

    # Blocks 1..n_pairs-2: previous full state absorbs the next pair.
    for j in unroll(1, n_pairs - 1):
        poseidon16_compress(states + (j - 1) * DIGEST_LEN, buf + j * DIGEST_LEN, states + j * DIGEST_LEN)

    # Final block: squeeze the low half into the 4-FE `out`.
    poseidon16_compress_half(states + (n_pairs - 2) * DIGEST_LEN, buf + (n_pairs - 1) * DIGEST_LEN, out)
    return


@inline
def fold_wots_pubkey(pk_seed, adrs0, adrs1, buf, out):
    # Fold SPX_WOTS_LEN (32) completed chain tips into a single WOTS+ public key digest.
    # Matches WotsPublicKey::hash() in wots.rs — T-Sponge with replacement (see notes above).
    # adrs0/adrs1 encode Adrs::wots_pk(layer, tree_addr, kp_addr) — compile-time constants at all
    # call sites. V=32 is even, so all 16 absorb blocks are full pairs. Costs 16 poseidon calls.
    #
    # Inputs:
    #   pk_seed — pointer to HALF_DIGEST_LEN (4) FEs: per-signer public seed
    #   adrs0   — scalar: packed layer/type/tree_address (WOTS_PK type)
    #   adrs1   — scalar: kp_addr (chain=0, hash=0)
    #   buf     — contiguous tip buffer of fold_tips_len(SPX_WOTS_LEN) FE, with the 32 chain-end
    #             HalfDigests pre-placed in tip order by the producer (no packed copy)
    # Output:
    #   out — HALF_DIGEST_LEN (4) FEs: folded WOTS+ public key hash
    tweak5 = make_tweak5(pk_seed, adrs0)
    _fold_tips_sponge(tweak5, adrs1, buf, SPX_WOTS_LEN / 2, out)
    return


@inline
def fold_roots(pk_seed, idx_tree, idx_leaf, buf, out):
    # Fold SPX_FORS_TREES (9) FORS tree roots into the FORS public key digest.
    # Matches fors.rs::fold_roots — T-Sponge with replacement (see notes above):
    #   adrs0 = pack(layer=0, type=FORS_ROOTS, tree_addr=idx_tree)  — fixed IV tweak
    #   adrs1 = idx_leaf (hypertree key_pair_address)               — binds the fold to the leaf
    # SPX_FORS_TREES (9) is odd, so the buffer holds 10 tips with the 10th zero-padded; the final
    # absorb block is [root8 | 0,0,0,0]. Costs ceil(9/2) = 5 poseidon calls.
    #
    # Inputs:
    #   pk_seed  — pointer to HALF_DIGEST_LEN (4) FEs: per-signer public seed
    #   idx_tree — hypertree subtree address (FORS_ROOTS adrs0 tree_address)
    #   idx_leaf — hypertree leaf address (FORS_ROOTS adrs1 key_pair_address)
    #   buf      — contiguous tip buffer of fold_tips_len(SPX_FORS_TREES + 1) FE, with the 9 roots
    #              pre-placed in tip order and the trailing pad-tip zeroed by the producer
    # Output:
    #   out     — HALF_DIGEST_LEN (4) FEs: FORS public key hash
    FORS_ROOTS_ADRS0 = ADRS_FORS_ROOTS * (2 ** ADRS0_TYPE_SHIFT) + idx_tree * (2 ** ADRS0_TREE_SHIFT)

    tweak5 = make_tweak5(pk_seed, FORS_ROOTS_ADRS0)
    _fold_tips_sponge(tweak5, idx_leaf, buf, (SPX_FORS_TREES + 1) / 2, out)
    return
