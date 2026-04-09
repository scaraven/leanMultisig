use backend::*;
use sphincs::core::{SphincsPublicKey, SphincsSecretKey, SphincsSig};
use sphincs::*;

type F = KoalaBear;

#[test]
fn test_sphincs_sign_verify_deser() {
    let keygen_seed: [u8; 20] = std::array::from_fn(|i| i as u8);
    let message: [F; MESSAGE_LEN_FE] = std::array::from_fn(|i| F::from_usize(i * 3 + 7));

    let sk = SphincsSecretKey::new(keygen_seed);
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