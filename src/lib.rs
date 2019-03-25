//! # My Crate
//!
//! `my_crate` is a collection of utilities to make performing certain
//! calculations more convenient.
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