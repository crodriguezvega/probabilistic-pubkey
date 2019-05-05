extern crate probabilisticpubkey;

use std::str;
use probabilisticpubkey::goldwasser_micali;
use probabilisticpubkey::key::{PublicKey, PrivateKey};

fn main() {
    let plaintext = b"hello world";

    match goldwasser_micali::generate_keys(8) {
        Ok((public_key, private_key)) => {
            let cyphertext = public_key.encrypt(plaintext);
            let decrypted_plaintext = private_key.decrypt(&cyphertext);
            
            println!("{}", str::from_utf8(&decrypted_plaintext).unwrap());
        },
        Err(err) => {
            eprintln!("{}", err);
            panic!(err)
        }
    };
}