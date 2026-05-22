#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod address;
pub mod core;
pub mod fors;
pub mod hypertree;
pub mod signers_cache;
pub mod wots;

pub use address::*;
pub use fors::*;
pub use hypertree::*;
pub use wots::*;

use backend::KoalaBear;

// --- Field / digest types ---
pub(crate) const DIGEST_SIZE: usize = 8;
pub const HALF_DIGEST_SIZE: usize = 4;

pub(crate) type F = KoalaBear;
pub(crate) type Digest = [F; DIGEST_SIZE];
pub type HalfDigest = [KoalaBear; HALF_DIGEST_SIZE];

// --- SPHINCS+ structural parameters ---
pub const SPX_N: usize = 16;
pub const SPX_FULL_HEIGHT: usize = 33;
pub const SPX_D: usize = 3;
pub const SPX_TREE_HEIGHT: usize = 11; // SPX_FULL_HEIGHT / SPX_D
pub const SPX_FORS_HEIGHT: usize = 15;
pub const SPX_FORS_TREES: usize = 9;

// --- WOTS+ parameters ---
pub const SPX_WOTS_W: usize = 16;
pub const SPX_WOTS_LOGW: usize = 4; // log2(SPX_WOTS_W)
pub const SPX_WOTS_LEN: usize = 32; // 8 * N / LOGW = 8 * 16 / 4
pub const TARGET_SUM: usize = 304; // fixed sum of all 32 encoding indices
pub const NUM_CHAIN_HASHES: usize = 176; // V*(w-1) - TARGET_SUM = 32*15 - 304
pub const V_GRINDING: usize = 0;

// --- Lifetime / key material ---
pub const LOG_LIFETIME: usize = 30; // 2^30 total signatures

// --- ADRS field bit widths (used by address.rs) ---
// SPX_TREE_BITS (22) doubles as the key-pair address width: each hypertree layer
// manages 2^SPX_TREE_HEIGHT leaves, and tree addressing spans SPX_TREE_BITS levels.
pub const SPX_KP_ADDR_BITS: usize = SPX_TREE_BITS; // 22 — key pair address width
pub const SPX_CHAIN_ADDR_BITS: usize = 5; // ceil(log2(SPX_WOTS_LEN)) = ceil(log2(32))
pub const SPX_HASH_ADDR_BITS: usize = SPX_WOTS_LOGW; // 4 — one step per chain level

// --- Encoding lengths ---
pub const RANDOMNESS_LEN_FE: usize = 6;
pub const MESSAGE_LEN_FE: usize = 8;
pub const MSG_RANDOMNESS_LEN_FE: usize = 4;

// --- FORS message derivation (bit layout) ---
// bits  0-10  : leaf_idx      (SPX_TREE_HEIGHT = 11 bits)
// bits 11-15  : unused
// bits 16-37  : tree_address  (SPX_FULL_HEIGHT - SPX_TREE_HEIGHT = 22 bits)
// bits 38-39  : unused
// bits 40-175 : mhash         (SPX_FORS_MSG_BYTES = 17 bytes = 136 bits)
pub const SPX_LEAF_BITS: usize = SPX_TREE_HEIGHT; // 11
pub const SPX_TREE_BITS: usize = SPX_FULL_HEIGHT - SPX_TREE_HEIGHT; // 22
pub const SPX_FORS_MSG_BYTES: usize = 17; // (SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8
