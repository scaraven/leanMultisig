use crate::Digest;
use crate::fors::ForsSignature;
use crate::hypertree::HypertreeSignature;

struct SphincsSecretKey {
    seed: [u8; 20],
}

struct SphincsPublicKey {
    root: Digest,
}

struct SphincsSig {
    pub fors_sig: ForsSignature,
    pub hypertree_sig: HypertreeSignature,
}
