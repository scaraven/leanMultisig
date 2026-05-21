use backend::*;
use rand::{CryptoRng, RngExt};
use serde::{Deserialize, Serialize};
use utils::{ToUsize, poseidon16_compress_pair};

use crate::*;

// SPHINCS+ WOTS+: V=32, w=16, TARGET_SUM=240, V_GRINDING=0.
// Self-contained — does not share code with the xmss crate.

const V: usize = SPX_WOTS_LEN; // 32
const W: usize = SPX_WOTS_LOGW; // 4 bits per index
const CHAIN_LENGTH: usize = SPX_WOTS_W; // 16

#[derive(Debug)]
pub struct WotsSecretKey {
    pub pre_images: [Digest; V],
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

    pub fn new(pre_images: [Digest; V]) -> Self {
        Self {
            pre_images,
            // Public key = level CHAIN_LENGTH: apply CHAIN_LENGTH total steps from pre_image.
            // iterate_hash_half always starts with 1 hash of the full pre_image (level-0),
            // then n more half_to_full hashes; so CHAIN_LENGTH total steps = CHAIN_LENGTH - 1 extra.
            public_key: WotsPublicKey(std::array::from_fn(|i| iterate_hash_half(pre_images[i], CHAIN_LENGTH - 1))),
        }
    }

    pub const fn public_key(&self) -> &WotsPublicKey {
        &self.public_key
    }

    /// Sign a message with the WOTS+ secret key, using the provided randomness for encoding.
    /// Precondition: the encoding must be valid (sum of indices == TARGET_SUM).
    /// Note: `message` must be a Digest (8 FEs). Hash external messages before calling.
    pub fn sign_with_randomness(
        &self,
        message: &Digest,
        layer_index: u32,
        randomness: [F; RANDOMNESS_LEN_FE],
    ) -> WotsSignature {
        let encoding = wots_encode(message, layer_index, &randomness).unwrap();
        WotsSignature {
            chain_tips: std::array::from_fn(|i| iterate_hash_half(self.pre_images[i], encoding[i] as usize)),
            randomness,
        }
    }
}

impl WotsSignature {
    pub fn recover_public_key(&self, message: &Digest, layer_index: u32) -> Option<WotsPublicKey> {
        let encoding = wots_encode(message, layer_index, &self.randomness)?;
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

/// Advance the chain from a full pre-image `a` by `n` steps under the upper-half convention.
///
/// Step 0 → level-0: always hash the pre-image once: left = pre_image (8 FEs), right = zeros.
///                    level-0 = upper 4 FEs of poseidon(pre_image, 0).
/// Step k → level-k: left = [0,0,0,0 | level-(k-1)], right = zeros.
///
/// Applying `n` steps returns level-n.  The full chain has CHAIN_LENGTH steps:
///   public key = iterate_hash_half(pre_image, CHAIN_LENGTH), all using the convention above.
///   signature tip for encoding e = iterate_hash_half(pre_image, e).
pub fn iterate_hash_half(a: Digest, n: usize) -> HalfDigest {
    // Level-0: hash the full pre-image once.
    let level0 = truncate_half(poseidon16_compress_pair(&a, &Default::default()));
    // Further levels use the upper-half convention.
    (0..n).fold(level0, |acc, _| {
        truncate_half(poseidon16_compress_pair(&half_to_full(acc), &Default::default()))
    })
}

/// Continue hashing from a 4-FE half-digest (already at some chain level) n more steps.
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
    layer_index: u32,
    rng: &mut impl CryptoRng,
) -> ([F; RANDOMNESS_LEN_FE], [u8; V], usize) {
    let mut num_iters = 0;
    loop {
        num_iters += 1;
        let randomness = rng.random();
        if let Some(encoding) = wots_encode(message, layer_index, &randomness) {
            return (randomness, encoding, num_iters);
        }
    }
}

/// Encode (message, layer_index, randomness) into V chain indices.
///
/// Note: `message` must be a Digest (8 FEs). Hash external messages before calling.
///
/// encoding_fe = poseidon(message[0..8] | [randomness[0..7], layer_index])
///
/// Extract 4 x 4-bit chunks from the bottom 16 bits of each of the 8 FEs (little-endian),
/// yielding exactly 32 indices. Valid iff sum of indices == TARGET_SUM.
pub fn wots_encode(message: &Digest, layer_index: u32, randomness: &[F; RANDOMNESS_LEN_FE]) -> Option<[u8; V]> {
    let mut input_right = [F::default(); 8];
    input_right[..RANDOMNESS_LEN_FE].copy_from_slice(randomness);
    input_right[RANDOMNESS_LEN_FE] = F::from_usize(layer_index as usize);
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

        // Deterministic, non-random-looking message digest.
        let message = poseidon16_compress_pair(&Digest::default(), &Digest::default());
        let layer_index = 0u32;

        // Deterministic secret key material so the test doesn't depend on RNG support for Digest.
        let pre_images: [Digest; SPX_WOTS_LEN] = std::array::from_fn(|i| {
            let mut d = Digest::default();
            d[0] = F::new(i as u32);
            d[1] = F::new((i as u32).wrapping_mul(17));
            d
        });
        let sk = WotsSecretKey::new(pre_images);

        let (randomness, _encoding, _iters) = find_randomness_for_wots_encoding(&message, layer_index, &mut rng);

        let sig = sk.sign_with_randomness(&message, layer_index, randomness);
        let recovered = sig.recover_public_key(&message, layer_index).expect("valid signature");

        assert_eq!(recovered, *sk.public_key());
    }
}
