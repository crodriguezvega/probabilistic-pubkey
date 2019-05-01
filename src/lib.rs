//! # Probabilistic publick-key cryptography
//!
//! `probabilistic_pubkey` consists of implementations for the Goldwasser-Micali
//! and Blum-Goldwasser probabilistic public-key systems. 

extern crate bitvec;

#[macro_use]
extern crate failure;
extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;
extern crate rand;

#[cfg(test)]
extern crate primal;
#[cfg(test)]
#[macro_use]
extern crate proptest;

pub mod number;
pub mod prime;
pub mod errors;
pub mod key;
pub mod goldwasser_micali;
pub mod blum_goldwasser;