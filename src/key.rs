use num_bigint::{BigUint};

pub trait PublicKey {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<BigUint>;
}

pub trait PrivateKey {
    fn decrypt(&self, ciphertext: &[BigUint]) -> Vec<u8>;
}