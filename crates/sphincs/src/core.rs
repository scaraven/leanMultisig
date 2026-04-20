use backend::PrimeField32;
use serde::{Deserialize, Serialize};
use utils::poseidon16_compress_pair;

use crate::fors::ForsSignature;
use crate::hypertree::HypertreeSignature;
use crate::{
    DIGEST_SIZE, Digest, F, ForsPublicKey, ForsSecretKey, HypertreeSecretKey, MESSAGE_LEN_FE, SPX_FORS_MSG_BYTES,
    SPX_LEAF_BITS, SPX_TREE_BITS, SPX_TREE_HEIGHT, fors, hypertree,
};

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

        let (leaf_idx, tree_address, mhash) = extract_digest_hash(&message_digest)?;

        let fors_indices = fors::extract_fors_indices(&mhash);
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

/// Extract the leaf_index, tree address and mhash values from the message digest.
///
/// The digest (8 field elements) is serialised as 8 consecutive little-endian
/// u32 values (32 bytes total). The bit layout within that byte buffer is:
///
///   bits  0  .. 10  : leaf_idx      (SPX_TREE_HEIGHT = 11 bits)
///   bits 11  .. 15  : unused
///   bits 16  .. 37  : tree_address  (SPX_FULL_HEIGHT - SPX_TREE_HEIGHT = 22 bits)
///   bits 38  .. 39  : unused
///   bits 40  .. 175 : mhash         (SPX_FORS_MSG_BYTES = 17 bytes = 136 bits)
fn extract_digest_hash(
    digest: &Digest,
) -> Result<(usize, usize, [u8; SPX_FORS_MSG_BYTES]), Box<dyn std::error::Error>> {
    // Serialise the digest into a flat 32-byte buffer (8 × LE u32).
    let mut buf = [0u8; 32];
    for (i, fe) in digest.iter().enumerate() {
        buf[i * 4..][..4].copy_from_slice(&fe.as_canonical_u32().to_le_bytes());
    }

    // --- leaf_idx: bits 0..10 (11 bits) ---
    let leaf_idx = {
        let window = u16::from_le_bytes([buf[0], buf[1]]);
        (window & ((1 << SPX_LEAF_BITS) - 1)) as usize
    };

    // --- tree_address: bits 16..37 (22 bits) ---
    let tree_address = {
        // Starts at byte 2, bit 0 within that byte. Spans at most 3 bytes (22 bits).
        let window = u32::from_le_bytes([buf[2], buf[3], buf[4], 0]);
        (window & ((1 << SPX_TREE_BITS) - 1)) as usize
    };

    // --- mhash: bits 40..175 → bytes 5..21 (17 bytes) ---
    let mhash: [u8; SPX_FORS_MSG_BYTES] = buf[5..5 + SPX_FORS_MSG_BYTES].try_into()?;

    Ok((leaf_idx, tree_address, mhash))
}

// Extract digest parts used for hint generation when running zkDSL
pub fn extract_digest_parts(
    digest: &[F; DIGEST_SIZE],
) -> (usize, usize, [u8; SPX_FORS_MSG_BYTES], usize, usize, usize) {
    let mut buf = [0u8; 32];
    for (i, fe) in digest.iter().enumerate() {
        buf[i * 4..][..4].copy_from_slice(&fe.as_canonical_u32().to_le_bytes());
    }

    let leaf_idx = {
        let window = u16::from_le_bytes([buf[0], buf[1]]);
        (window & ((1 << SPX_TREE_HEIGHT) - 1)) as usize
    };

    let tree_address = {
        let window = u32::from_le_bytes([buf[2], buf[3], buf[4], 0]);
        (window & ((1 << SPX_TREE_BITS) - 1)) as usize
    };

    let mhash: [u8; SPX_FORS_MSG_BYTES] = buf[5..5 + SPX_FORS_MSG_BYTES].try_into().unwrap();

    // FE[5] stores mhash bits 120..134 in bits 0..14; range-check the remaining top 16 bits.
    let fe5_upper = ((digest[5].as_canonical_u32() >> 15) & 0xFFFF) as usize;

    let fe0_unused = ((digest[0].as_canonical_u32() >> SPX_LEAF_BITS) & 0x1F) as usize;

    let fe1_unused = ((digest[1].as_canonical_u32() >> 6) & 0x3) as usize;

    (leaf_idx, tree_address, mhash, fe5_upper, fe0_unused, fe1_unused)
}

impl SphincsPublicKey {
    pub fn verify(&self, message: &[F; MESSAGE_LEN_FE], sig: &SphincsSig) -> bool {
        let mut right: [F; 8] = Default::default();
        right[0] = message[8];
        let message_digest = poseidon16_compress_pair(&message[0..8].try_into().unwrap(), &right);

        let (leaf_idx, tree_address, mhash) = extract_digest_hash(&message_digest).unwrap();

        let fors_indices = fors::extract_fors_indices(&mhash);
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
