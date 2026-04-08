use utils::poseidon16_compress_pair;

use crate::fors::ForsSignature;
use crate::hypertree::HypertreeSignature;
use crate::{
    Digest, F, ForsPublicKey, ForsSecretKey, HypertreeSecretKey, MESSAGE_LEN_FE, SPX_FORS_MSG_BYTES, fors, hypertree,
};

struct SphincsSecretKey {
    seed: [u8; 20],
    // cached material
    fors_key: ForsSecretKey,
}

impl SphincsSecretKey {
    pub fn new(seed: [u8; 20]) -> Self {
        let fors_key = fors::fors_key_gen(seed).0;
        Self { seed, fors_key }
    }

    pub fn public_key(&self) -> SphincsPublicKey {
        let hypertree_sk: HypertreeSecretKey = self.into();
        let hypertree_pk = hypertree_sk.public_key();
        SphincsPublicKey {
            root: hypertree_pk.0,
            fors_root: self.fors_key.public_key(),
        }
    }
}

impl Into<ForsSecretKey> for &SphincsSecretKey {
    fn into(self) -> ForsSecretKey {
        let fors_sk = fors::fors_key_gen(self.seed);
        fors_sk.0
    }
}

impl Into<HypertreeSecretKey> for &SphincsSecretKey {
    fn into(self) -> HypertreeSecretKey {
        hypertree::HypertreeSecretKey::new(self.seed)
    }
}

struct SphincsPublicKey {
    root: Digest,
    fors_root: ForsPublicKey,
}

struct SphincsSig {
    pub fors_sig: ForsSignature,
    pub hypertree_sig: HypertreeSignature,
}

// Extract the leaf_index, tree address and mhash values from the message digest
fn extract_digest_hash(digest: &Digest) -> (usize, usize, &[u8; SPX_FORS_MSG_BYTES]) {
    unimplemented!("extract_digest_hash: extract leaf index, tree address and mhash from the message digest")
}

impl SphincsSecretKey {
    pub fn sign(message: [F; MESSAGE_LEN_FE], sk: &SphincsSecretKey) -> SphincsSig {
        // Hash the message to a digest so that we can extract the tree and leaf indices for the FORS signature.
        let mut right: [F; 8] = Default::default();
        right[0] = message[8];
        let message_digest = poseidon16_compress_pair(&message[0..8].try_into().unwrap(), &right);

        let (leaf_idx, tree_address, mhash) = extract_digest_hash(&message_digest);

        let fors_indices = fors::extract_fors_indices(mhash);
        let fors_sig = fors::fors_sign(&sk.into(), &fors_indices);

        let pk = sk.public_key();

        let hypertree_sig: HypertreeSignature =
            hypertree::hypertree_sign(&sk.into(), &pk.fors_root.0, leaf_idx, tree_address);

        SphincsSig {
            fors_sig,
            hypertree_sig,
        }
    }
}
