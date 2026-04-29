use backend::{PrimeCharacteristicRing, PrimeField32};
use serde::{Deserialize, Serialize};
use utils::poseidon16_compress_pair;

use crate::fors::ForsSignature;
use crate::hypertree::HypertreeSignature;
use crate::{
    DIGEST_SIZE, Digest, F, ForsPublicKey, ForsSecretKey, HypertreeSecretKey, MESSAGE_LEN_FE, SPX_FORS_HEIGHT,
    SPX_FORS_TREES, SPX_TREE_HEIGHT, fors, hypertree,
};

// poseidon hash of hex("message_input_extend") reduced mod KB_PRIME
fn digest_expand_domain_sep() -> Digest {
    let mut d = [F::ZERO; DIGEST_SIZE];
    d[0] = F::new(1298655175);
    d
}

#[derive(Debug)]
pub struct SphincsSecretKey {
    seed: [u8; 20],
    // cached material
    fors_key: ForsSecretKey,
    fors_pubkey: ForsPublicKey,
}

impl SphincsSecretKey {
    pub fn new(seed: [u8; 20]) -> Self {
        let fors_key = fors::fors_key_gen(seed).0;
        let fors_pub = fors_key.public_key();
        Self {
            seed,
            fors_key,
            fors_pubkey: fors_pub,
        }
    }

    pub fn public_key(&self) -> SphincsPublicKey {
        let hypertree_sk: HypertreeSecretKey = self.into();
        let hypertree_pk = hypertree_sk.public_key();
        SphincsPublicKey { root: hypertree_pk.0 }
    }

    pub fn seed(&self) -> [u8; 20] {
        self.seed
    }

    fn fors_pk(&self) -> ForsPublicKey {
        self.fors_pubkey
    }

    pub fn sign(&self, message: &[F; MESSAGE_LEN_FE]) -> Result<SphincsSig, Box<dyn std::error::Error>> {
        // Hash the message to a digest so that we can extract the tree and leaf indices for the FORS signature.
        let mut right: [F; 8] = Default::default();
        right[0] = message[8];
        let message_digest = poseidon16_compress_pair(&message[0..8].try_into().unwrap(), &right);

        let (leaf_idx, tree_address, fors_indices) = extract_digest_hash(&message_digest);

        let fors_sig = fors::fors_sign(&self.into(), &fors_indices);

        let fors_pk = self.fors_pk();

        let hypertree_sig: HypertreeSignature =
            hypertree::hypertree_sign(&self.into(), &fors_pk.0, leaf_idx, tree_address);

        Ok(SphincsSig {
            fors_sig,
            hypertree_sig,
        })
    }
}

impl From<&SphincsSecretKey> for ForsSecretKey {
    fn from(val: &SphincsSecretKey) -> Self {
        val.fors_key.clone()
    }
}

impl From<&SphincsSecretKey> for HypertreeSecretKey {
    fn from(val: &SphincsSecretKey) -> Self {
        hypertree::HypertreeSecretKey::new(val.seed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SphincsPublicKey {
    root: Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SphincsSig {
    pub fors_sig: ForsSignature,
    pub hypertree_sig: HypertreeSignature,
}

/// Expand the message digest into indices using two domain-separated Poseidon calls.
///
/// Call A: poseidon([DS,   0, ..], message_digest) → expanded_a[8]
///   expanded_a[0] bits 0..10 → leaf_idx   (11 bits)
///   expanded_a[1] bits 0..10 → lli1       (lower 11 bits of tree_address)
///   expanded_a[2] bits 0..10 → lli2       (upper 11 bits of tree_address)
///   expanded_a[3..7] bits 0..14 → fors_indices[0..4]  (15 bits each)
///
/// Call B: poseidon([DS+1, 0, ..], message_digest) → expanded_b[8]
///   expanded_b[0..3] bits 0..14 → fors_indices[5..8]  (15 bits each)
///
/// tree_address = lli1 | (lli2 << SPX_TREE_HEIGHT)
fn extract_digest_hash(digest: &Digest) -> (usize, usize, [usize; SPX_FORS_TREES]) {
    let (expanded_a, expanded_b) = expand_digest(digest);
    let leaf_mask = (1usize << SPX_TREE_HEIGHT) - 1;
    let fors_mask = (1usize << SPX_FORS_HEIGHT) - 1;

    let leaf_idx = expanded_a[0].as_canonical_u32() as usize & leaf_mask;
    let lli1 = expanded_a[1].as_canonical_u32() as usize & leaf_mask;
    let lli2 = expanded_a[2].as_canonical_u32() as usize & leaf_mask;
    let tree_address = lli1 | (lli2 << SPX_TREE_HEIGHT);

    let mut fors_indices = [0usize; SPX_FORS_TREES];
    for t in 0..5 {
        fors_indices[t] = expanded_a[3 + t].as_canonical_u32() as usize & fors_mask;
    }
    for t in 0..4 {
        fors_indices[5 + t] = expanded_b[t].as_canonical_u32() as usize & fors_mask;
    }

    (leaf_idx, tree_address, fors_indices)
}

fn expand_digest(digest: &Digest) -> (Digest, Digest) {
    let mut ds_a = digest_expand_domain_sep();
    let expanded_a = poseidon16_compress_pair(&ds_a, digest);
    ds_a[0] += F::ONE;
    let expanded_b = poseidon16_compress_pair(&ds_a, digest);
    (expanded_a, expanded_b)
}

/// Extract digest parts for zkDSL hint generation.
///
/// Returns `(leaf_indices, fors_indices, leaf_uppers, fors_uppers)` where:
///   leaf_indices[0..2] = leaf_idx, lli1, lli2  (lower 11 bits of expanded_a[0..2])
///   fors_indices[0..4] = lower 15 bits of expanded_a[3..7]
///   fors_indices[5..8] = lower 15 bits of expanded_b[0..3]
///   leaf_uppers[i]     = upper 20 bits of expanded_a[i]
///   fors_uppers[t]     = upper 16 bits of the corresponding expanded FE
pub fn extract_digest_parts(
    digest: &[F; DIGEST_SIZE],
) -> ([usize; 3], [usize; SPX_FORS_TREES], [usize; 3], [usize; SPX_FORS_TREES]) {
    let (expanded_a, expanded_b) = expand_digest(digest);
    let leaf_mask = (1usize << SPX_TREE_HEIGHT) - 1;
    let fors_mask = (1usize << SPX_FORS_HEIGHT) - 1;

    let leaf_indices = [
        expanded_a[0].as_canonical_u32() as usize & leaf_mask,
        expanded_a[1].as_canonical_u32() as usize & leaf_mask,
        expanded_a[2].as_canonical_u32() as usize & leaf_mask,
    ];
    let leaf_uppers = [
        expanded_a[0].as_canonical_u32() as usize >> SPX_TREE_HEIGHT,
        expanded_a[1].as_canonical_u32() as usize >> SPX_TREE_HEIGHT,
        expanded_a[2].as_canonical_u32() as usize >> SPX_TREE_HEIGHT,
    ];

    let mut fors_indices = [0usize; SPX_FORS_TREES];
    let mut fors_uppers = [0usize; SPX_FORS_TREES];
    for t in 0..5 {
        fors_indices[t] = expanded_a[3 + t].as_canonical_u32() as usize & fors_mask;
        fors_uppers[t] = expanded_a[3 + t].as_canonical_u32() as usize >> SPX_FORS_HEIGHT;
    }
    for t in 0..4 {
        fors_indices[5 + t] = expanded_b[t].as_canonical_u32() as usize & fors_mask;
        fors_uppers[5 + t] = expanded_b[t].as_canonical_u32() as usize >> SPX_FORS_HEIGHT;
    }

    (leaf_indices, fors_indices, leaf_uppers, fors_uppers)
}

impl SphincsPublicKey {
    pub fn verify(&self, message: &[F; MESSAGE_LEN_FE], sig: &SphincsSig) -> bool {
        let mut right: [F; 8] = Default::default();
        right[0] = message[8];
        let message_digest = poseidon16_compress_pair(&message[0..8].try_into().unwrap(), &right);

        let (leaf_idx, tree_address, fors_indices) = extract_digest_hash(&message_digest);

        let fors_pk = match fors::fors_verify(&sig.fors_sig, &fors_indices) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        hypertree::hypertree_verify(&sig.hypertree_sig, &fors_pk.0, leaf_idx, tree_address, &self.root)
    }

    pub fn root(&self) -> Digest {
        self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphincs_sign_verify() {
        let message = [F::new(0); MESSAGE_LEN_FE];
        let sk = SphincsSecretKey::new([0; 20]);
        let sig = sk.sign(&message).unwrap();
        let pk = sk.public_key();
        assert!(pk.verify(&message, &sig));
    }
}
