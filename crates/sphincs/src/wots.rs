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
    /// Revealed mid-chain tips at full 8-FE width (see iterate_hash_full_from_full): keeping
    /// the full Poseidon state at the signing boundary makes the split sign+verify chain
    /// compose exactly with the unsplit keygen chain.
    #[serde(
        with = "backend::array_serialization",
        bound(serialize = "F: Serialize", deserialize = "F: Deserialize<'de>")
    )]
    pub chain_tips: [Digest; V],
    pub randomness: [F; RANDOMNESS_LEN_FE],
}

impl WotsSecretKey {
    /// Construct from pre-images, computing the public key with a tweaked chain hash.
    /// `base_adrs` must have type=WOTS_HASH, hash_address=0; chain_address is set per chain.
    pub fn new(pre_images: [HalfDigest; V], pk_seed: HalfDigest, base_adrs: Adrs) -> Self {
        Self {
            pre_images,
            public_key: WotsPublicKey(std::array::from_fn(|i| {
                // Full chain: expand the 4-FE pre-image, run all CHAIN_LENGTH-1 steps 8-FE
                // internally, then truncate the chain-final value to the 4-FE pubkey component.
                truncate_half(iterate_hash_full_from_full(
                    half_to_full(pre_images[i]),
                    CHAIN_LENGTH - 1,
                    pk_seed,
                    base_adrs.with_chain(i as u32),
                ))
            })),
        }
    }

    pub const fn public_key(&self) -> &WotsPublicKey {
        &self.public_key
    }

    /// Sign a message. `base_adrs` must have type=WOTS_HASH, hash_address=0.
    pub fn sign_with_randomness(
        &self,
        message: &Digest,
        adrs0: F,
        adrs1: F,
        randomness: [F; RANDOMNESS_LEN_FE],
        pk_seed: HalfDigest,
        base_adrs: Adrs,
    ) -> WotsSignature {
        let encoding = wots_encode(message, adrs0, adrs1, &randomness).unwrap();
        WotsSignature {
            chain_tips: std::array::from_fn(|i| {
                // Reveal the mid-chain tip at full 8-FE width (no truncation), so the verifier
                // resumes from the exact carried state and recovers the same pubkey.
                iterate_hash_full_from_full(
                    half_to_full(self.pre_images[i]),
                    encoding[i] as usize,
                    pk_seed,
                    base_adrs.with_chain(i as u32),
                )
            }),
            randomness,
        }
    }
}

impl WotsSignature {
    /// Recover the public key. `base_adrs` must have type=WOTS_HASH, hash_address=0.
    pub fn recover_public_key(
        &self,
        message: &Digest,
        adrs0: F,
        adrs1: F,
        pk_seed: HalfDigest,
        base_adrs: Adrs,
    ) -> Option<WotsPublicKey> {
        let encoding = wots_encode(message, adrs0, adrs1, &self.randomness)?;
        Some(WotsPublicKey(std::array::from_fn(|i| {
            // Resume from the full 8-FE revealed tip and run the remaining steps, then truncate
            // the chain-final value to the 4-FE pubkey component.
            truncate_half(iterate_hash_full_from_full(
                self.chain_tips[i],
                CHAIN_LENGTH - 1 - encoding[i] as usize,
                pk_seed,
                base_adrs.with_chain(i as u32).with_hash_step(encoding[i] as u32),
            ))
        })))
    }
}

impl WotsPublicKey {
    /// Compress all V chain tips into a single HalfDigest using a T-Sponge with replacement.
    ///
    /// Poseidon-16 in compression mode is used as a sponge (capacity 8 / rate 8): each
    /// compression absorbs a full 8-FE block of *two* chain tips by overwriting the rate, while
    /// the running accumulator lives in the capacity. This roughly halves the number of
    /// compressions versus a per-tip left-fold (V/2 = 16 calls for V=32). The structured IV is
    /// fed directly as the first compression's left input (no priming call):
    ///   IV    = [pk_seed[0..4] | adrs0, adrs1, 0, 0]   (fixed sponge tweak)
    ///   block = [tip_{2i}[0..4] | tip_{2i+1}[0..4]]
    ///   state = P16(state, block)                       (replace rate with block)
    /// The 8-FE Poseidon output is carried in full between calls; only the final squeeze
    /// truncates to a HalfDigest. V is even, so no padding block is needed.
    pub fn hash(&self, pk_seed: HalfDigest, adrs: crate::address::Adrs) -> HalfDigest {
        let mut iv = [F::ZERO; 8];
        iv[..4].copy_from_slice(&pk_seed);
        iv[4] = adrs.adrs0;
        iv[5] = adrs.adrs1;
        let mut block = [F::ZERO; 8];
        block[..4].copy_from_slice(&self.0[0]);
        block[4..8].copy_from_slice(&self.0[1]);
        let mut state = poseidon16_compress_pair(&iv, &block);
        for pair in self.0[2..].chunks_exact(2) {
            block[..4].copy_from_slice(&pair[0]);
            block[4..8].copy_from_slice(&pair[1]);
            state = poseidon16_compress_pair(&state, &block);
        }
        truncate_half(state)
    }
}

/// Run `n` WOTS+ chain steps on a full 8-FE state, keeping the full Poseidon output between
/// steps (no per-step truncation). This is the core of the 8-FE-internal chain: the high half
/// of each step's output is carried into the next step's right input rather than discarded and
/// re-zeroed.
///
/// `adrs` must have type=WOTS_HASH with the correct chain_address and hash_address=current step.
/// Each step increments hash_address via `adrs.next_hash_step()`.
///
/// The caller is responsible for the boundary conversions: expand a 4-FE start to
/// `[start | 0,0,0,0]` before the first step, and `truncate_half` the result only at the very
/// end of the *full* chain (the WOTS-pubkey component). Mid-chain values revealed in a
/// signature are kept full-width (8 FE) so that splitting the chain at signing composes
/// exactly with the unsplit keygen chain.
pub fn iterate_hash_full_from_full(a: Digest, n: usize, pk_seed: HalfDigest, adrs: Adrs) -> Digest {
    let mut current_adrs = adrs;
    (0..n).fold(a, |acc, _| {
        let mut left = [F::ZERO; DIGEST_SIZE];
        left[..4].copy_from_slice(&pk_seed);
        left[4] = current_adrs.adrs0;
        left[5] = current_adrs.adrs1;
        let result = poseidon16_compress_pair(&left, &acc);
        current_adrs = current_adrs.next_hash_step();
        result
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
            [
                F::new(i as u32),
                F::new((i as u32).wrapping_mul(17)),
                F::new(0),
                F::new(0),
            ]
        });
        let pk_seed = [F::ZERO; HALF_DIGEST_SIZE];
        let base_adrs = Adrs::wots_hash(0, 0, 0, 0, 0);
        let sk = WotsSecretKey::new(pre_images, pk_seed, base_adrs);

        let (randomness, _encoding, _iters) = find_randomness_for_wots_encoding(&message, adrs0, adrs1, &mut rng);

        let sig = sk.sign_with_randomness(&message, adrs0, adrs1, randomness, pk_seed, base_adrs);
        let recovered = sig
            .recover_public_key(&message, adrs0, adrs1, pk_seed, base_adrs)
            .expect("valid signature");

        assert_eq!(recovered, *sk.public_key());
    }
}
