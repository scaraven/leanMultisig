use backend::{PrimeCharacteristicRing, PrimeField32};
use rand::random;
use serde::{Deserialize, Serialize};
use utils::poseidon16_compress_pair;

use crate::address::Adrs;
use crate::fors::ForsSignature;
use crate::hypertree::HypertreeSignature;
use crate::{
    DIGEST_SIZE, Digest, F, HalfDigest, HypertreeSecretKey,
    MESSAGE_LEN_FE, MSG_RANDOMNESS_LEN_FE, SPX_FORS_HEIGHT, SPX_FORS_TREES, SPX_TREE_HEIGHT,
    fors, hypertree,
    wots::{half_to_full, truncate_half},
};

// ---------------------------------------------------------------------------
// Hash primitives
// ---------------------------------------------------------------------------

/// PRF: derive a HalfDigest from (pk_seed, sk_seed, adrs).
///
/// left  = [pk_seed[0..4] | adrs.adrs0, adrs.adrs1, 0, 0]
/// right = [sk_seed[0..4] | 0, 0, 0, 0]
pub fn prf(pk_seed: HalfDigest, sk_seed: HalfDigest, adrs: Adrs) -> HalfDigest {
    let mut left = [F::ZERO; DIGEST_SIZE];
    left[..4].copy_from_slice(&pk_seed);
    left[4] = adrs.adrs0;
    left[5] = adrs.adrs1;
    let right = half_to_full(sk_seed);
    truncate_half(poseidon16_compress_pair(&left, &right))
}

/// PRFmsg: derive the per-signature message randomness R.
///
/// left  = [sk_prf[0..4] | opt_rand[0..4]]
/// right = message[0..8]
pub fn prf_msg(sk_prf: HalfDigest, opt_rand: [F; MSG_RANDOMNESS_LEN_FE], message: &[F; MESSAGE_LEN_FE]) -> HalfDigest {
    let mut left = [F::ZERO; DIGEST_SIZE];
    left[..4].copy_from_slice(&sk_prf);
    left[4..8].copy_from_slice(&opt_rand);
    truncate_half(poseidon16_compress_pair(&left, message))
}

/// Hmsg: hash message with public-key context into a full Digest for index extraction.
///
/// call1_left  = [R[0..4] | pk_seed[0..4]]
/// call1_right = [pk_root[0..4] | message[0..4]]
/// call2_left  = [call1_output[0..4] | 0, 0, 0, 0]
/// call2_right = [message[4..8] | 0, 0, 0, 0]
pub fn hmsg(r: HalfDigest, pk_seed: HalfDigest, pk_root: HalfDigest, message: &[F; MESSAGE_LEN_FE]) -> Digest {
    let mut left1 = [F::ZERO; DIGEST_SIZE];
    left1[..4].copy_from_slice(&r);
    left1[4..8].copy_from_slice(&pk_seed);

    let mut right1 = [F::ZERO; DIGEST_SIZE];
    right1[..4].copy_from_slice(&pk_root);
    right1[4..8].copy_from_slice(&message[..4]);

    let mid = poseidon16_compress_pair(&left1, &right1);

    let left2 = half_to_full(truncate_half(mid));
    let mut right2 = [F::ZERO; DIGEST_SIZE];
    right2[..4].copy_from_slice(&message[4..8]);

    poseidon16_compress_pair(&left2, &right2)
}

// ---------------------------------------------------------------------------
// Key structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SphincsSecretKey {
    pub sk_seed: HalfDigest,
    pub sk_prf:  HalfDigest,
    pub pk_seed: HalfDigest,
    pub pk_root: HalfDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SphincsPublicKey {
    pub pk_seed: HalfDigest,
    pub pk_root: HalfDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SphincsSig {
    /// R = PRFmsg(sk_prf, opt_rand, message) — committed message randomness.
    pub r: HalfDigest,
    pub fors_sig: ForsSignature,
    pub hypertree_sig: HypertreeSignature,
}

impl SphincsSecretKey {
    pub fn new(sk_seed: HalfDigest, sk_prf: HalfDigest) -> Self {
        let pk_seed = truncate_half(poseidon16_compress_pair(&half_to_full(sk_seed), &half_to_full(sk_prf)));

        // Temporary shim: derive a legacy [u8; 20] seed from sk_seed so that fors/hypertree
        // (not yet updated) can still be constructed. Removed when those modules are updated.
        let legacy_seed = half_digest_to_legacy_seed(sk_seed);
        let hypertree_sk = HypertreeSecretKey::new(legacy_seed);
        let pk_root = hypertree_sk.public_key().0;

        Self { sk_seed, sk_prf, pk_seed, pk_root }
    }

    pub fn public_key(&self) -> SphincsPublicKey {
        SphincsPublicKey { pk_seed: self.pk_seed, pk_root: self.pk_root }
    }

    pub fn sign(&self, message: &[F; MESSAGE_LEN_FE]) -> Result<SphincsSig, Box<dyn std::error::Error>> {
        let opt_rand: [F; MSG_RANDOMNESS_LEN_FE] = random();
        let r = prf_msg(self.sk_prf, opt_rand, message);
        let message_digest = hmsg(r, self.pk_seed, self.pk_root, message);

        let (leaf_idx, tree_address, fors_indices) = extract_digest_hash(&message_digest);

        let legacy_seed = half_digest_to_legacy_seed(self.sk_seed);
        let (fors_sk, _) = fors::fors_key_gen(legacy_seed);
        let fors_sig = fors::fors_sign(&fors_sk, &fors_indices);
        let fors_pk = fors_sk.public_key();

        let hypertree_sig = hypertree::hypertree_sign(
            &HypertreeSecretKey::new(legacy_seed),
            &half_to_full(fors_pk.0),
            leaf_idx,
            tree_address,
        );

        Ok(SphincsSig { r, fors_sig, hypertree_sig })
    }
}

impl SphincsPublicKey {
    pub fn verify(&self, message: &[F; MESSAGE_LEN_FE], sig: &SphincsSig) -> bool {
        let message_digest = hmsg(sig.r, self.pk_seed, self.pk_root, message);

        let (leaf_idx, tree_address, fors_indices) = extract_digest_hash(&message_digest);

        let fors_pk = match fors::fors_verify(&sig.fors_sig, &fors_indices) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        hypertree::hypertree_verify(
            &sig.hypertree_sig,
            &half_to_full(fors_pk.0),
            leaf_idx,
            tree_address,
            &self.pk_root,
        )
    }

    pub fn root(&self) -> HalfDigest {
        self.pk_root
    }
}

// ---------------------------------------------------------------------------
// Temporary shim: convert HalfDigest → [u8; 20] legacy seed.
// Removed when fors.rs and hypertree.rs are updated to the new API.
// ---------------------------------------------------------------------------

fn half_digest_to_legacy_seed(hd: HalfDigest) -> [u8; 20] {
    let mut seed = [0u8; 20];
    for (i, fe) in hd.iter().enumerate() {
        seed[i * 4..(i + 1) * 4].copy_from_slice(&fe.as_canonical_u32().to_le_bytes());
    }
    seed
}

// ---------------------------------------------------------------------------
// Digest extraction (unchanged)
// ---------------------------------------------------------------------------

// poseidon hash of hex("message_input_extend") reduced mod KB_PRIME
fn digest_expand_domain_sep() -> Digest {
    let mut d = [F::ZERO; DIGEST_SIZE];
    d[0] = F::new(1298655175);
    d
}

fn expand_digest(digest: &Digest) -> (Digest, Digest) {
    let mut ds_a = digest_expand_domain_sep();
    let expanded_a = poseidon16_compress_pair(&ds_a, digest);
    ds_a[0] += F::ONE;
    let expanded_b = poseidon16_compress_pair(&ds_a, digest);
    (expanded_a, expanded_b)
}

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

/// Extract digest parts for zkDSL hint generation.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphincs_sign_verify() {
        let message = [F::new(0); MESSAGE_LEN_FE];
        let sk = SphincsSecretKey::new([F::new(0); 4], [F::new(1); 4]);
        let sig = sk.sign(&message).unwrap();
        let pk = sk.public_key();
        assert!(pk.verify(&message, &sig));
    }
}
