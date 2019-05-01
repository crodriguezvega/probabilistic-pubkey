use crate::errors::{Error};
use crate::key::{PublicKey, PrivateKey};
use crate::number;
use crate::prime;

use bitvec::{BitVec, BitSlice, BigEndian};
use num_bigint::{BigUint, BigInt, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::One;
use rand::thread_rng;
use std::ops::{Div, BitXor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlumGoldwasserPublicKey {
    n: BigUint
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlumGoldwasserPrivateKey {
    p: BigUint,
    q: BigUint,
    a: BigInt,
    b: BigInt
}

impl BlumGoldwasserPublicKey {
    pub fn n(&self) -> &BigUint {
        &self.n
    }
}

impl PublicKey for BlumGoldwasserPublicKey {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<BigUint> {
        let two = BigUint::from(2usize);

        /*
        Calculation of h should be like:
        let k = self.n.bits() - 1;
        let h = BigUint::from_usize(k).unwrap().bits() - 1;

        However, I will fix its value so that eaxh u8 is evenly partitioned.
        Otherwise, the result of the decryption does not match the input plaintext.
        I don't know what implications this has on the security of the scheme.
        */

        let h = 4usize;

        let mut x = find_quadratic_residue_mod(&self.n);
        let mask = BigUint::from(h.pow(2) - 1);

        let mut ciphertext = Vec::with_capacity(8 * plaintext.len());
        let bits: BitVec<BigEndian, u8> = plaintext.into();

        let mut chunks = bits.chunks(h);
        while let Some(chunk) = chunks.next() {
            x = x.modpow(&two, &self.n);
            let p = &x & &mask;            
            let m = to_biguint(&chunk);
            let c = p.bitxor(&m);
            ciphertext.push(c);
        }

        x = x.modpow(&two, &self.n);
        ciphertext.push(x);
        ciphertext
    }
}

impl BlumGoldwasserPrivateKey {
    pub fn p(&self) -> &BigUint {
        &self.p
    }

    pub fn q(&self) -> &BigUint {
        &self.q
    }

    pub fn a(&self) -> &BigInt {
        &self.a
    }

    pub fn b(&self) -> &BigInt {
        &self.b
    }
}

impl PrivateKey for BlumGoldwasserPrivateKey {
    fn decrypt(&self, ciphertext: &[BigUint]) -> Vec<u8> {
        let one = BigUint::one();
        let two = BigUint::from(2usize);
        let four = BigUint::from(4usize);

        let n = &self.p * &self.q;
        /*
        let k = n.bits() - 1;
        let h = BigUint::from_usize(k).unwrap().bits() - 1;
        */
        let h = 4usize;
        
        let mask = BigUint::from(h.pow(2) - 1);
        match ciphertext.last() {
            None => Vec::new(),
            Some(xtplus1) => {
                let len = ciphertext.len() - 1;
                let t = BigUint::from(len);
                let d1 = (&self.p + &one).div_floor(&four).modpow(&(&t + &one), &(&self.p - &one));
                let d2 = (&self.q + &one).div_floor(&four).modpow(&(&t + &one), &(&self.q - &one));
                let u = xtplus1.modpow(&d1, &self.p).to_bigint().unwrap();
                let v = xtplus1.modpow(&d2, &self.q).to_bigint().unwrap();

                let _p = self.p.to_bigint().unwrap();
                let _q = self.q.to_bigint().unwrap();
                let _n = n.to_bigint().unwrap();
                let mut x = (v * &self.a * _p + u * &self.b * _q).mod_floor(&_n).to_biguint().unwrap();

                let mut bits: BitVec<BigEndian, u8> = BitVec::new();
                for c in &ciphertext[..len] {
                    x = x.modpow(&two, &n);
                    let p = &x & &mask;
                    let m = p.bitxor(c);

                    let bit_vec = to_bitvec(&m);
                    let chunk = bit_vec.split_at(bit_vec.len() - h); 
                    for bit in chunk.1 { bits.push(bit); }
                }
                let plaintext: Vec<u8> = bits.into();
                plaintext
            }
        }
    }
}

pub fn generate_keys(byte_size: usize) -> Result<(BlumGoldwasserPublicKey, BlumGoldwasserPrivateKey), Error> {
    let p_bits = 8 * byte_size.div(2);
    let q_bits = 8 * (byte_size - byte_size.div(2));

    let (p, q) = generate_primes(p_bits, q_bits);

    match number::extended_euclidean_algorithm(&p, &q) {
        None => Err(Error::CouldNotGeneratePublicKey),
        Some((a, b)) => {
            let n = &p * &q;
            let public_key = BlumGoldwasserPublicKey { n };
            let private_key = BlumGoldwasserPrivateKey { p, q, a, b };
            Ok((public_key, private_key))
        }
    }
}

fn generate_primes(p_bits: usize, q_bits: usize) -> (BigUint, BigUint) {
    fn generate_prime_congruente_3mod4(bit_size: usize) -> (BigUint) {
        let three = BigUint::from(3usize);
        let four = BigUint::from(4usize);
        let mut prime = prime::generate_prime(bit_size);
        while prime.mod_floor(&four) != three {
            prime = prime::generate_prime(bit_size);
        }
        prime
    }

    let p = generate_prime_congruente_3mod4(p_bits);

    let mut q = generate_prime_congruente_3mod4(q_bits);
    while p == q {
        q = generate_prime_congruente_3mod4(q_bits);
    }

    (p, q)
}

fn find_quadratic_residue_mod(n: &BigUint) -> BigUint {
    let mut rng = thread_rng();
    let r = rng.gen_biguint_range(&BigUint::one(), &n); 
    r.modpow(&BigUint::from(2usize), n)
}

fn to_biguint(bits: &BitSlice) -> BigUint {
    let n = bits.iter().fold(0usize, |acc, bit| {
        acc*2 + if bit { 1 } else { 0 } 
    });

    BigUint::from(n)
}

fn to_bitvec(number: &BigUint) -> BitVec {
    number.to_bytes_be().into()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::key::{PublicKey, PrivateKey};
    use primal;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_encrypt_decrypt(plaintext in prop::array::uniform32(0u8..)) {
            match generate_keys(8) {
                Ok((public_key, private_key)) => {
                    let cyphertext = public_key.encrypt(&plaintext);
                    let decrypted_plaintext = private_key.decrypt(&cyphertext); 

                    prop_assert_eq!(decrypted_plaintext, plaintext)
                },
                _  => prop_assert_eq!(false, true)
            };
        }
    }
}