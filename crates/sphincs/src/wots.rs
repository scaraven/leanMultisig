use backend::*;
use rand::{CryptoRng, RngExt};
use serde::{Deserialize, Serialize};
use utils::{ToUsize, poseidon16_compress_pair, to_little_endian_bits};

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
pub struct WotsPublicKey(pub [Digest; V]);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WotsSignature {
    #[serde(
        with = "backend::array_serialization",
        bound(serialize = "F: Serialize", deserialize = "F: Deserialize<'de>")
    )]
    pub chain_tips: [Digest; V],
    pub randomness: [F; RANDOMNESS_LEN_FE],
}

impl WotsSecretKey {
    pub fn random(rng: &mut impl CryptoRng) -> Self {
        Self::new(rng.random())
    }

    pub fn new(pre_images: [Digest; V]) -> Self {
        Self {
            pre_images,
            public_key: WotsPublicKey(std::array::from_fn(|i| iterate_hash(pre_images[i], CHAIN_LENGTH - 1))),
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
            chain_tips: std::array::from_fn(|i| iterate_hash(self.pre_images[i], encoding[i] as usize)),
            randomness,
        }
    }
}

impl WotsSignature {
    pub fn recover_public_key(&self, message: &Digest, layer_index: u32) -> Option<WotsPublicKey> {
        let encoding = wots_encode(message, layer_index, &self.randomness)?;
        Some(WotsPublicKey(std::array::from_fn(|i| {
            iterate_hash(self.chain_tips[i], CHAIN_LENGTH - 1 - encoding[i] as usize)
        })))
    }
}

impl WotsPublicKey {
    pub fn hash(&self) -> Digest {
        let init = poseidon16_compress_pair(&self.0[0], &self.0[1]);
        self.0[2..]
            .iter()
            .fold(init, |acc, chunk| poseidon16_compress_pair(&acc, chunk))
    }
}

/// Hash a digest n times: iterate_hash(x, 0) = x, iterate_hash(x, n) = hash^n(x).
pub fn iterate_hash(a: Digest, n: usize) -> Digest {
    (0..n).fold(a, |acc, _| poseidon16_compress_pair(&acc, &Default::default()))
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
/// A = poseidon(message[0..8] | [randomness[0..7], 0])
/// B = poseidon(A | [layer_index, 0, 0, 0, 0, 0, 0, 0])
///
/// Extract 4-bit chunks from B (24 bits per element, little-endian), take first 32.
/// Valid iff sum of indices == TARGET_SUM.
pub fn wots_encode(message: &Digest, layer_index: u32, randomness: &[F; RANDOMNESS_LEN_FE]) -> Option<[u8; V]> {
    // A = poseidon(message (8 fe), randomness (7 fe) + 1 zero pad)
    let mut a_input_right = [F::default(); 8];
    a_input_right[..RANDOMNESS_LEN_FE].copy_from_slice(randomness);
    let a = poseidon16_compress_pair(message, &a_input_right);

    // B = poseidon(A (8 fe), [layer_index, 0, 0, 0, 0, 0, 0, 0])
    let mut b_input_right = [F::default(); 8];
    b_input_right[0] = F::from_usize(layer_index as usize);
    let compressed = poseidon16_compress_pair(&a, &b_input_right);

    if compressed.iter().any(|&kb| kb == -F::ONE) {
        return None;
    }

    let all_indices: Vec<u8> = compressed
        .iter()
        .flat_map(|kb| to_little_endian_bits(kb.to_usize(), 24))
        .collect::<Vec<_>>()
        .chunks_exact(W)
        .take(V + V_GRINDING)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0u8, |acc, (i, &bit)| acc | (u8::from(bit) << i))
        })
        .collect();

    is_valid_encoding(&all_indices).then(|| all_indices.try_into().unwrap())
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

        let (randomness, _encoding, _iters) =
            find_randomness_for_wots_encoding(&message, layer_index, &mut rng);

        let sig = sk.sign_with_randomness(&message, layer_index, randomness);
        let recovered = sig.recover_public_key(&message, layer_index).expect("valid signature");

        assert_eq!(recovered, *sk.public_key());
    }
}
