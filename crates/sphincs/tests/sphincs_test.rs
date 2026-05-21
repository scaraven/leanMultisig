use backend::*;
use sphincs::core::{SphincsPublicKey, SphincsSecretKey, SphincsSig};
use sphincs::*;

type F = KoalaBear;

#[test]
fn test_sphincs_sign_verify_deser() {
    let message: [F; MESSAGE_LEN_FE] = std::array::from_fn(|i| F::from_usize(i * 3 + 7));
    let sk_seed: [F; 4] = std::array::from_fn(|i| F::from_usize(i + 1));
    let sk_prf:  [F; 4] = std::array::from_fn(|i| F::from_usize(i + 5));

    let sk = SphincsSecretKey::new(sk_seed, sk_prf);
    let pk = sk.public_key();

    let sig = sk.sign(&message).unwrap();

    let pk_bytes = postcard::to_allocvec(&pk).unwrap();
    let pk2: SphincsPublicKey = postcard::from_bytes(&pk_bytes).unwrap();
    assert_eq!(pk, pk2);

    let sig_bytes = postcard::to_allocvec(&sig).unwrap();
    let sig2: SphincsSig = postcard::from_bytes(&sig_bytes).unwrap();
    assert_eq!(sig, sig2);

    assert!(pk.verify(&message, &sig2));
}
