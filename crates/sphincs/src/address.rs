use crate::{
    F, SPX_CHAIN_ADDR_BITS, SPX_D, SPX_FORS_HEIGHT, SPX_FORS_TREES, SPX_KP_ADDR_BITS, SPX_TREE_BITS, SPX_WOTS_LEN,
    SPX_WOTS_W,
};
use backend::PrimeField32;

// ADRS type codes (3 bits, values 0–6)
pub const WOTS_HASH: u32 = 0;
pub const WOTS_PK: u32 = 1;
pub const TREE: u32 = 2;
pub const FORS_TREE: u32 = 3;
pub const FORS_ROOTS: u32 = 4;
pub const WOTS_PRF: u32 = 5;
pub const FORS_PRF: u32 = 6;

// Derived bounds (as u32 for use in debug_assert)
const MAX_LAYER: u32 = (SPX_D - 1) as u32;
const MAX_TYPE: u32 = 6;
const MAX_TREE: u32 = (1u32 << SPX_TREE_BITS) - 1;
const MAX_KP_ADDR: u32 = (1u32 << SPX_KP_ADDR_BITS) - 1;
const MAX_CHAIN: u32 = (SPX_WOTS_LEN - 1) as u32;
// hash_address indexes steps 0..SPX_WOTS_W-2 (the verifier completes remaining steps,
// so the last starting step is SPX_WOTS_W-2 = 14, not SPX_WOTS_W-1 = 15).
const MAX_HASH: u32 = (SPX_WOTS_W - 2) as u32;
const MAX_TREE_IDX: u32 = (1u32 << SPX_FORS_HEIGHT) - 1;
const MAX_TREE_HT: u32 = SPX_FORS_HEIGHT as u32;

// Bit offsets within adrs0
const ADRS0_TYPE_SHIFT: u32 = 2;
const ADRS0_TREE_SHIFT: u32 = 2 + 3; // layer(2) + type(3)
// FORS-internal tree number (0..SPX_FORS_TREES-1) packed into adrs0's high bits, above
// tree_address. layer(2)+type(3)+tree_addr(22) = 27 bits, so fors_tree starts at bit 27.
// Max packed value (fors_tree=8, tree_addr=2^22-1) ≈ 0x47FF_FFFF < KoalaBear prime
// (0x7F00_0001), so this never wraps the field.
const ADRS0_FORS_TREE_SHIFT: u32 = 2 + 3 + SPX_TREE_BITS as u32; // = 27
const MAX_FORS_TREE: u32 = (SPX_FORS_TREES - 1) as u32;

// Bit offsets within adrs1 — WOTS / FORS_ROOTS layout
const ADRS1_CHAIN_SHIFT: u32 = SPX_KP_ADDR_BITS as u32;
const ADRS1_HASH_SHIFT: u32 = SPX_KP_ADDR_BITS as u32 + SPX_CHAIN_ADDR_BITS as u32;

// Bit offsets within adrs1 — TREE / FORS_TREE layout
const ADRS1_TREE_HT_SHIFT: u32 = SPX_FORS_HEIGHT as u32;

/// Three-field-element condensed ADRS for SPHINCS+ with our concrete parameters.
///
/// adrs0 bit layout (bits 0–30):
///   bits  1.. 0 : layer        (2 bits, values 0–SPX_D-1)
///   bits  4.. 2 : type         (3 bits, values 0–6)
///   bits 26.. 5 : tree_address (SPX_TREE_BITS = 22 bits) — hypertree subtree (idx_tree)
///   bits 30..27 : fors_tree    (4 bits, 0–SPX_FORS_TREES-1) [FORS_TREE / FORS_PRF only]
///
/// adrs1 bit layout — WOTS_HASH / WOTS_PRF / WOTS_PK / FORS_ROOTS:
///   bits SPX_KP_ADDR_BITS-1..0        : key_pair_address (22 bits)
///   bits +SPX_CHAIN_ADDR_BITS-1..     : chain_address    (5 bits)  [WOTS only]
///   bits +SPX_HASH_ADDR_BITS-1..      : hash_address     (4 bits)  [WOTS_HASH only]
///
/// adrs1 bit layout — TREE: (tree_height, tree_index) Merkle coordinate (TREE keeps the
///   coordinate in adrs1; adrs2 is unused).
///
/// adrs1 — FORS_TREE / FORS_PRF: holds key_pair_address = hypertree leaf (idx_leaf, 11 bits).
///
/// adrs2 bit layout — FORS_TREE only (zero for all other types): the (tree_height, tree_index)
///   Merkle coordinate, displaced here because adrs1 holds idx_leaf for FORS.
///   bits SPX_FORS_HEIGHT-1..0         : tree_index  (SPX_FORS_HEIGHT = 15 bits)
///   bits SPX_FORS_HEIGHT+3..SPX_FORS_HEIGHT : tree_height (4 bits)
///   bits 30..SPX_FORS_HEIGHT+4        : (unused)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Adrs {
    pub adrs0: F,
    pub adrs1: F,
    pub adrs2: F,
}

fn pack_adrs0(layer: u32, adrs_type: u32, tree_address: u32) -> F {
    debug_assert!(layer <= MAX_LAYER, "layer out of range");
    debug_assert!(adrs_type <= MAX_TYPE, "type out of range");
    debug_assert!(tree_address <= MAX_TREE, "tree_address out of range");
    F::new(layer | (adrs_type << ADRS0_TYPE_SHIFT) | (tree_address << ADRS0_TREE_SHIFT))
}

/// adrs0 for FORS types: like `pack_adrs0` (layer fixed to 0) but additionally packs the
/// FORS-internal tree number (0..SPX_FORS_TREES-1) into the high bits above tree_address.
fn pack_adrs0_fors(adrs_type: u32, tree_address: u32, fors_tree: u32) -> F {
    debug_assert!(adrs_type <= MAX_TYPE, "type out of range");
    debug_assert!(tree_address <= MAX_TREE, "tree_address out of range");
    debug_assert!(fors_tree <= MAX_FORS_TREE, "fors_tree out of range");
    F::new((adrs_type << ADRS0_TYPE_SHIFT) | (tree_address << ADRS0_TREE_SHIFT) | (fors_tree << ADRS0_FORS_TREE_SHIFT))
}

fn pack_adrs1_wots(kp_addr: u32, chain: u32, hash: u32) -> F {
    debug_assert!(kp_addr <= MAX_KP_ADDR, "key_pair_address out of range");
    debug_assert!(chain <= MAX_CHAIN, "chain_address out of range");
    debug_assert!(hash <= MAX_HASH, "hash_address out of range");
    F::new(kp_addr | (chain << ADRS1_CHAIN_SHIFT) | (hash << ADRS1_HASH_SHIFT))
}

fn pack_adrs1_tree(tree_height: u32, tree_index: u32) -> F {
    debug_assert!(tree_height <= MAX_TREE_HT, "tree_height out of range");
    debug_assert!(tree_index <= MAX_TREE_IDX, "tree_index out of range");
    F::new(tree_index | (tree_height << ADRS1_TREE_HT_SHIFT))
}

impl Adrs {
    /// WOTS_HASH: used for each individual hash step along a WOTS+ chain.
    /// chain_address selects the chain (0..SPX_WOTS_LEN-1); hash_address selects the step.
    pub fn wots_hash(layer: u32, tree_addr: u32, kp_addr: u32, chain: u32, hash: u32) -> Self {
        Self {
            adrs0: pack_adrs0(layer, WOTS_HASH, tree_addr),
            adrs1: pack_adrs1_wots(kp_addr, chain, hash),
            adrs2: F::new(0),
        }
    }

    /// WOTS_PK: used to compress the SPX_WOTS_LEN chain tips into a single public key.
    pub fn wots_pk(layer: u32, tree_addr: u32, kp_addr: u32) -> Self {
        Self {
            adrs0: pack_adrs0(layer, WOTS_PK, tree_addr),
            adrs1: pack_adrs1_wots(kp_addr, 0, 0),
            adrs2: F::new(0),
        }
    }

    /// TREE: used for XMSS hypertree internal Merkle nodes.
    /// The (tree_height, tree_index) Merkle coordinate stays in adrs1 (TREE layout); adrs2 unused.
    pub fn tree(layer: u32, tree_addr: u32, tree_height: u32, tree_index: u32) -> Self {
        Self {
            adrs0: pack_adrs0(layer, TREE, tree_addr),
            adrs1: pack_adrs1_tree(tree_height, tree_index),
            adrs2: F::new(0),
        }
    }

    /// FORS_TREE: used for FORS binary tree internal nodes and leaf hashing (height=0).
    /// `idx_tree`/`idx_leaf` are the hypertree position (tree_address / key_pair_address);
    /// `fors_tree` is the FORS-internal tree number (0..SPX_FORS_TREES-1).
    pub fn fors_tree(idx_tree: u32, idx_leaf: u32, fors_tree: u32, tree_height: u32, tree_index: u32) -> Self {
        Self {
            adrs0: pack_adrs0_fors(FORS_TREE, idx_tree, fors_tree),
            adrs1: F::new(idx_leaf),
            adrs2: pack_adrs1_tree(tree_height, tree_index),
        }
    }

    /// FORS_ROOTS: used to fold the SPX_FORS_TREES roots into the FORS public key.
    /// `idx_tree`/`idx_leaf` are the hypertree position; the per-step fold index lives in adrs2.
    pub fn fors_roots(idx_tree: u32, idx_leaf: u32, step: u32) -> Self {
        Self {
            adrs0: pack_adrs0(0, FORS_ROOTS, idx_tree),
            adrs1: F::new(idx_leaf),
            adrs2: F::new(step),
        }
    }

    /// WOTS_PRF: used to derive WOTS+ chain pre-images from SK.seed.
    pub fn wots_prf(layer: u32, tree_addr: u32, kp_addr: u32, chain: u32) -> Self {
        Self {
            adrs0: pack_adrs0(layer, WOTS_PRF, tree_addr),
            adrs1: pack_adrs1_wots(kp_addr, chain, 0),
            adrs2: F::new(0),
        }
    }

    /// FORS_PRF: used to derive FORS leaf secrets from SK.seed (height=0, index=leaf_index).
    /// `idx_tree`/`idx_leaf` are the hypertree position; `fors_tree` is the FORS-internal tree.
    pub fn fors_prf(idx_tree: u32, idx_leaf: u32, fors_tree: u32, leaf_index: u32) -> Self {
        Self {
            adrs0: pack_adrs0_fors(FORS_PRF, idx_tree, fors_tree),
            adrs1: F::new(idx_leaf),
            adrs2: pack_adrs1_tree(0, leaf_index),
        }
    }

    /// Return a copy with chain_address set to `chain` and hash_address zeroed.
    /// Only valid for WOTS_HASH / WOTS_PRF adrs (WOTS layout for adrs1).
    pub fn with_chain(self, chain: u32) -> Self {
        debug_assert!(chain <= MAX_CHAIN, "chain out of range");
        let kp_addr = self.adrs1.as_canonical_u32() & ((1 << ADRS1_CHAIN_SHIFT) - 1);
        Self {
            adrs0: self.adrs0,
            adrs1: F::new(kp_addr | (chain << ADRS1_CHAIN_SHIFT)),
            adrs2: self.adrs2,
        }
    }

    /// Return a copy with hash_address incremented by one.
    /// Only valid for WOTS_HASH adrs (WOTS layout for adrs1).
    pub fn next_hash_step(self) -> Self {
        let raw = self.adrs1.as_canonical_u32();
        let hash = (raw >> ADRS1_HASH_SHIFT) + 1;
        debug_assert!(hash <= MAX_HASH, "hash_address overflow");
        Self {
            adrs0: self.adrs0,
            adrs1: F::new((raw & ((1 << ADRS1_HASH_SHIFT) - 1)) | (hash << ADRS1_HASH_SHIFT)),
            adrs2: self.adrs2,
        }
    }

    /// Return a copy with hash_address set to `hash`.
    /// Only valid for WOTS_HASH adrs (WOTS layout for adrs1).
    pub fn with_hash_step(self, hash: u32) -> Self {
        debug_assert!(hash <= MAX_HASH, "hash_address out of range");
        let raw = self.adrs1.as_canonical_u32();
        Self {
            adrs0: self.adrs0,
            adrs1: F::new((raw & ((1 << ADRS1_HASH_SHIFT) - 1)) | (hash << ADRS1_HASH_SHIFT)),
            adrs2: self.adrs2,
        }
    }

    /// Mirror of ADRS.setTypeAndClear from FIPS 205: change the type field in adrs0 and zero adrs1/adrs2.
    pub fn set_type_and_clear(&mut self, adrs_type: u32) {
        debug_assert!(adrs_type <= MAX_TYPE);
        let raw = self.adrs0.as_canonical_u32();
        // Preserve layer (bits 1..0) and tree_address (bits 26..5); replace type (bits 4..2).
        let layer = raw & ((1 << ADRS0_TYPE_SHIFT) - 1);
        let tree = raw & !((1 << ADRS0_TREE_SHIFT) - 1);
        self.adrs0 = F::new(layer | (adrs_type << ADRS0_TYPE_SHIFT) | tree);
        self.adrs1 = F::new(0);
        self.adrs2 = F::new(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SPX_HASH_ADDR_BITS;

    fn unpack_adrs0(adrs: &Adrs) -> (u32, u32, u32) {
        let raw = adrs.adrs0.as_canonical_u32();
        let layer = raw & ((1 << ADRS0_TYPE_SHIFT) - 1);
        let adrs_type = (raw >> ADRS0_TYPE_SHIFT) & 0x7;
        let tree_addr = (raw >> ADRS0_TREE_SHIFT) & MAX_TREE;
        (layer, adrs_type, tree_addr)
    }

    #[test]
    fn test_wots_hash_roundtrip() {
        let layer = 2;
        let tree = MAX_TREE - 1;
        let kp = MAX_KP_ADDR;
        let chain = MAX_CHAIN;
        let hash = MAX_HASH;
        let adrs = Adrs::wots_hash(layer, tree, kp, chain, hash);

        let (l, t, tr) = unpack_adrs0(&adrs);
        assert_eq!(l, layer);
        assert_eq!(t, WOTS_HASH);
        assert_eq!(tr, tree);

        let raw1 = adrs.adrs1.as_canonical_u32();
        assert_eq!(raw1 & MAX_KP_ADDR, kp);
        assert_eq!((raw1 >> ADRS1_CHAIN_SHIFT) & MAX_CHAIN, chain);
        // Mask with (1<<SPX_HASH_ADDR_BITS)-1 to read all 4 bits, even though MAX_HASH=14
        assert_eq!((raw1 >> ADRS1_HASH_SHIFT) & ((1 << SPX_HASH_ADDR_BITS) - 1), hash);
    }

    #[test]
    fn test_wots_pk_roundtrip() {
        let adrs = Adrs::wots_pk(1, 0x1234, 0x5678);
        let (l, t, tr) = unpack_adrs0(&adrs);
        assert_eq!(l, 1);
        assert_eq!(t, WOTS_PK);
        assert_eq!(tr, 0x1234);
        // chain and hash must be zero for WOTS_PK
        let raw1 = adrs.adrs1.as_canonical_u32();
        assert_eq!(raw1 & MAX_KP_ADDR, 0x5678);
        assert_eq!((raw1 >> ADRS1_CHAIN_SHIFT) & MAX_CHAIN, 0);
        assert_eq!((raw1 >> ADRS1_HASH_SHIFT) & MAX_HASH, 0);
    }

    #[test]
    fn test_tree_roundtrip() {
        let adrs = Adrs::tree(0, 0x7FF, SPX_FORS_HEIGHT as u32, MAX_TREE_IDX);
        let (l, t, tr) = unpack_adrs0(&adrs);
        assert_eq!(l, 0);
        assert_eq!(t, TREE);
        assert_eq!(tr, 0x7FF);
        // TREE keeps (tree_height, tree_index) in adrs1; adrs2 unused.
        assert_eq!(adrs.adrs2.as_canonical_u32(), 0);
        let raw1 = adrs.adrs1.as_canonical_u32();
        assert_eq!(raw1 & MAX_TREE_IDX, MAX_TREE_IDX);
        assert_eq!((raw1 >> ADRS1_TREE_HT_SHIFT) & MAX_TREE_HT, SPX_FORS_HEIGHT as u32);
    }

    #[test]
    fn test_fors_tree_roundtrip() {
        // idx_tree=0x10, idx_leaf=0x5, fors_tree=8, height=7, tree_index=0x1234
        let adrs = Adrs::fors_tree(0x10, 0x5, 8, 7, 0x1234);
        let (l, t, tr) = unpack_adrs0(&adrs);
        assert_eq!(l, 0);
        assert_eq!(t, FORS_TREE);
        assert_eq!(tr, 0x10);
        // fors_tree number packed above tree_address in adrs0.
        assert_eq!((adrs.adrs0.as_canonical_u32() >> ADRS0_FORS_TREE_SHIFT) & 0xF, 8);
        // idx_leaf (key_pair_address) in adrs1.
        assert_eq!(adrs.adrs1.as_canonical_u32(), 0x5);
        // (height, index) in adrs2.
        let raw2 = adrs.adrs2.as_canonical_u32();
        assert_eq!(raw2 & MAX_TREE_IDX, 0x1234);
        assert_eq!((raw2 >> ADRS1_TREE_HT_SHIFT) & MAX_TREE_HT, 7);
    }

    #[test]
    fn test_fors_roots_roundtrip() {
        // idx_tree=0xABC, idx_leaf=0x7, step=3
        let adrs = Adrs::fors_roots(0xABC, 0x7, 3);
        let (l, t, tr) = unpack_adrs0(&adrs);
        assert_eq!(l, 0);
        assert_eq!(t, FORS_ROOTS);
        assert_eq!(tr, 0xABC);
        assert_eq!(adrs.adrs1.as_canonical_u32() & MAX_KP_ADDR, 0x7);
        assert_eq!(adrs.adrs2.as_canonical_u32(), 3);
    }

    #[test]
    fn test_wots_prf_roundtrip() {
        let adrs = Adrs::wots_prf(2, 0x1FF, MAX_KP_ADDR, MAX_CHAIN);
        let (l, t, tr) = unpack_adrs0(&adrs);
        assert_eq!(l, 2);
        assert_eq!(t, WOTS_PRF);
        assert_eq!(tr, 0x1FF);
        let raw1 = adrs.adrs1.as_canonical_u32();
        assert_eq!(raw1 & MAX_KP_ADDR, MAX_KP_ADDR);
        assert_eq!((raw1 >> ADRS1_CHAIN_SHIFT) & MAX_CHAIN, MAX_CHAIN);
        assert_eq!((raw1 >> ADRS1_HASH_SHIFT) & MAX_HASH, 0);
    }

    #[test]
    fn test_fors_prf_roundtrip() {
        // idx_tree=0x5, idx_leaf=0x1, fors_tree=4, leaf_index=MAX_TREE_IDX
        let adrs = Adrs::fors_prf(0x5, 0x1, 4, MAX_TREE_IDX);
        let (l, t, tr) = unpack_adrs0(&adrs);
        assert_eq!(l, 0);
        assert_eq!(t, FORS_PRF);
        assert_eq!(tr, 0x5);
        assert_eq!((adrs.adrs0.as_canonical_u32() >> ADRS0_FORS_TREE_SHIFT) & 0xF, 4);
        assert_eq!(adrs.adrs1.as_canonical_u32(), 0x1);
        // leaf_index lives in adrs2 (height=0).
        assert_eq!(adrs.adrs2.as_canonical_u32() & MAX_TREE_IDX, MAX_TREE_IDX);
        assert_eq!((adrs.adrs2.as_canonical_u32() >> ADRS1_TREE_HT_SHIFT) & MAX_TREE_HT, 0);
    }

    #[test]
    fn test_set_type_and_clear() {
        let mut adrs = Adrs::wots_prf(1, 0x1234, 0x5, 3);
        adrs.set_type_and_clear(WOTS_HASH);
        let (l, t, tr) = unpack_adrs0(&adrs);
        assert_eq!(l, 1);
        assert_eq!(t, WOTS_HASH);
        assert_eq!(tr, 0x1234);
        assert_eq!(adrs.adrs1.as_canonical_u32(), 0);
    }

    #[test]
    fn test_with_chain() {
        let base = Adrs::wots_hash(1, 0x10, 0x5, 0, 0);
        let chained = base.with_chain(7);
        // adrs0 unchanged
        assert_eq!(chained.adrs0, base.adrs0);
        // kp_addr preserved, chain=7, hash=0
        let raw = chained.adrs1.as_canonical_u32();
        assert_eq!(raw & MAX_KP_ADDR, 0x5);
        assert_eq!((raw >> ADRS1_CHAIN_SHIFT) & MAX_CHAIN, 7);
        assert_eq!((raw >> ADRS1_HASH_SHIFT) & MAX_HASH, 0);
    }

    #[test]
    fn test_next_hash_step() {
        let base = Adrs::wots_hash(0, 0, 0x3, 5, 0);
        let stepped = base.next_hash_step();
        assert_eq!(stepped.adrs0, base.adrs0);
        let raw = stepped.adrs1.as_canonical_u32();
        assert_eq!((raw >> ADRS1_CHAIN_SHIFT) & MAX_CHAIN, 5);
        assert_eq!((raw >> ADRS1_HASH_SHIFT) & ((1 << SPX_HASH_ADDR_BITS) - 1), 1);
        // step twice more
        let stepped2 = stepped.next_hash_step().next_hash_step();
        assert_eq!(
            (stepped2.adrs1.as_canonical_u32() >> ADRS1_HASH_SHIFT) & ((1 << SPX_HASH_ADDR_BITS) - 1),
            3
        );
    }

    #[test]
    fn test_distinct_types_distinct_adrs0() {
        let layer = 0;
        let tree = 0x1;
        let types = [WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF];
        let adrs0_vals: Vec<u32> = types
            .iter()
            .map(|&t| pack_adrs0(layer, t, tree).as_canonical_u32())
            .collect();
        let unique: std::collections::HashSet<u32> = adrs0_vals.iter().copied().collect();
        assert_eq!(unique.len(), types.len(), "type codes must be distinct in adrs0");
    }
}
