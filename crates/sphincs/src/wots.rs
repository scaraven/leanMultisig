use backend::*;
use rand::{CryptoRng, RngExt};
use serde::{Deserialize, Serialize};
use utils::{ToUsize, poseidon16_compress_pair};

use crate::*;

// SPHINCS+ WOTS+: V=32, w=16, TARGET_SUM=304, V_GRINDING=0.
// Self-contained — does not share code with the xmss crate.

const V: usize = SPX_WOTS_LEN; // 32
const W: usize = SPX_WOTS_LOGW; // 4 bits per index
const CHAIN_LENGTH: usize = SPX_WOTS_W; // 16

#[derive(Debug)]
pub struct WotsSecretKey {
    pub pre_images: [HalfDigest; V],
    public_key: WotsPublicKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WotsPublicKey(pub [HalfDigest; V]);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WotsSignature {
    #[serde(
        with = "backend::array_serialization",
        bound(serialize = "F: Serialize", deserialize = "F: Deserialize<'de>")
    )]
    pub chain_tips: [HalfDigest; V],
    pub randomness: [F; RANDOMNESS_LEN_FE],
}

impl WotsSecretKey {
    pub fn random(rng: &mut impl CryptoRng) -> Self {
        Self::new(rng.random())
    }

    pub fn new(pre_images: [HalfDigest; V]) -> Self {
        Self {
            pre_images,
            public_key: WotsPublicKey(std::array::from_fn(|i| {
                iterate_hash_half_from_half(pre_images[i], CHAIN_LENGTH - 1)
            })),
        }
    }

    pub const fn public_key(&self) -> &WotsPublicKey {
        &self.public_key
    }

    /// Sign a message with the WOTS+ secret key, using the provided randomness and ADRS.
    /// Precondition: the encoding must be valid (sum of indices == TARGET_SUM).
    /// Note: `message` must be a Digest (8 FEs). Hash external messages before calling.
    pub fn sign_with_randomness(
        &self,
        message: &Digest,
        adrs0: F,
        adrs1: F,
        randomness: [F; RANDOMNESS_LEN_FE],
    ) -> WotsSignature {
        let encoding = wots_encode(message, adrs0, adrs1, &randomness).unwrap();
        WotsSignature {
            chain_tips: std::array::from_fn(|i| {
                iterate_hash_half_from_half(self.pre_images[i], encoding[i] as usize)
            }),
            randomness,
        }
    }
}

impl WotsSignature {
    pub fn recover_public_key(&self, message: &Digest, adrs0: F, adrs1: F) -> Option<WotsPublicKey> {
        let encoding = wots_encode(message, adrs0, adrs1, &self.randomness)?;
        Some(WotsPublicKey(std::array::from_fn(|i| {
            iterate_hash_half_from_half(self.chain_tips[i], CHAIN_LENGTH - 1 - encoding[i] as usize)
        })))
    }
}

impl WotsPublicKey {
    pub fn hash(&self) -> HalfDigest {
        let init = truncate_half(poseidon16_compress_pair(&half_to_full(self.0[0]), &half_to_full(self.0[1])));
        self.0[2..].iter().fold(init, |acc, &chunk| {
            truncate_half(poseidon16_compress_pair(&half_to_full(acc), &half_to_full(chunk)))
        })
    }
}

/// Continue hashing from a 4-FE half-digest n more steps.
pub fn iterate_hash_half_from_half(a: HalfDigest, n: usize) -> HalfDigest {
    (0..n).fold(a, |acc, _| {
        truncate_half(poseidon16_compress_pair(&half_to_full(acc), &Default::default()))
    })
}

/// Extract the lower 4 FEs (slots 0–3) of a Digest as a HalfDigest.
#[inline]
pub fn truncate_half(d: Digest) -> HalfDigest {
    d[..HALF_DIGEST_SIZE].try_into().unwrap()
}

/// Place a 4-FE HalfDigest into the lower half of a full Digest: [h | 0,0,0,0].
#[inline]
pub fn half_to_full(h: HalfDigest) -> Digest {
    let mut d = Digest::default();
    d[..HALF_DIGEST_SIZE].copy_from_slice(&h);
    d
}

pub fn find_randomness_for_wots_encoding(
    message: &Digest,
    adrs0: F,
    adrs1: F,
    rng: &mut impl CryptoRng,
) -> ([F; RANDOMNESS_LEN_FE], [u8; V], usize) {
    let mut num_iters = 0;
    loop {
        num_iters += 1;
        let randomness = rng.random();
        if let Some(encoding) = wots_encode(message, adrs0, adrs1, &randomness) {
            return (randomness, encoding, num_iters);
        }
    }
}

/// Encode (message, adrs0, adrs1, randomness) into V chain indices.
///
/// Note: `message` must be a Digest (8 FEs). Hash external messages before calling.
///
/// Call A: poseidon(message[0..8], [randomness[0..6], adrs0, adrs1])
///
/// Extract 4 x 4-bit chunks from the bottom 16 bits of each of the 8 FEs (little-endian),
/// yielding exactly 32 indices. Valid iff sum of indices == TARGET_SUM.
pub fn wots_encode(message: &Digest, adrs0: F, adrs1: F, randomness: &[F; RANDOMNESS_LEN_FE]) -> Option<[u8; V]> {
    let mut input_right = [F::default(); 8];
    input_right[..RANDOMNESS_LEN_FE].copy_from_slice(randomness);
    input_right[RANDOMNESS_LEN_FE] = adrs0;
    input_right[RANDOMNESS_LEN_FE + 1] = adrs1;
    let compressed = poseidon16_compress_pair(message, &input_right);

    if compressed.iter().any(|&kb| kb == -F::ONE) {
        return None;
    }

    // Extract 4 chunks of W=4 bits from the bottom 16 bits of each FE (4 chunks × 8 FEs = 32).
    let mask = (1usize << W) - 1;
    let all_indices: [u8; V] = std::array::from_fn(|i| {
        let fe_idx = i / W;
        let chunk_idx = i % W;
        ((compressed[fe_idx].to_usize() >> (chunk_idx * W)) & mask) as u8
    });

    is_valid_encoding(&all_indices).then_some(all_indices)
}

fn is_valid_encoding(encoding: &[u8]) -> bool {
    encoding.len() == V + V_GRINDING
        && encoding.iter().all(|&x| (x as usize) < CHAIN_LENGTH)
        && encoding.iter().map(|&x| x as usize).sum::<usize>() == TARGET_SUM
        && encoding[V..].iter().all(|&x| x as usize == CHAIN_LENGTH - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wots_sign_recover_roundtrip() {
        let mut rng = rand::rng();

        let message = poseidon16_compress_pair(&Digest::default(), &Digest::default());
        let adrs0 = F::new(0);
        let adrs1 = F::new(0);

        let pre_images: [HalfDigest; SPX_WOTS_LEN] = std::array::from_fn(|i| {
            [F::new(i as u32), F::new((i as u32).wrapping_mul(17)), F::new(0), F::new(0)]
        });
        let sk = WotsSecretKey::new(pre_images);

        let (randomness, _encoding, _iters) =
            find_randomness_for_wots_encoding(&message, adrs0, adrs1, &mut rng);

        let sig = sk.sign_with_randomness(&message, adrs0, adrs1, randomness);
        let recovered = sig.recover_public_key(&message, adrs0, adrs1).expect("valid signature");

        assert_eq!(recovered, *sk.public_key());
    }
}
