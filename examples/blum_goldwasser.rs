extern crate probabilistic_pubkey;

fn main() {
    println!("Hello from an example!");
    let plaintext = 

    match generate_keys(8) {
        Ok((public_key, private_key)) => {
            let cyphertext = public_key.encrypt(&plaintext);
            let decrypted_plaintext = private_key.decrypt(&cyphertext); 
        },
        _  => prop_assert_eq!(false, true)
    };

}