use rand::{rngs::OsRng, RngCore, Rng};

use super::aes::{encrypt_aes_128_cbc, encrypt_aes_128_ecb, pkcs7_padding};

/// This function takes an input text, randomly prepends and postpends 5-10
/// random bytes each, before encrypting with either AES 128 ECB or CBC.
pub fn encryption_oracle(input: &[u8]) -> Vec<u8> {
    let key = random_key();
    let prepend = rand::thread_rng().gen_range(5..=10);
    let postpend = rand::thread_rng().gen_range(5..=10);

    let mut tmp_input = vec![];
    for _ in 0..prepend {
        tmp_input.push(rand::thread_rng().gen_range(0..=255) as u8);
    }
    tmp_input.extend_from_slice(input);
    for _ in 0..postpend {
        tmp_input.push(rand::thread_rng().gen_range(0..=255) as u8);
    }

    let input = pkcs7_padding(input, 16);

    if OsRng.next_u64() % 2 == 0 {
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);
        encrypt_aes_128_cbc(&input, &key, Some(&iv))
    } else {

        encrypt_aes_128_ecb(&input, &key)
    }
}

fn random_key() -> Vec<u8> {
    let mut key = [0u8; 16];
    OsRng.fill_bytes(&mut key);
    key.to_vec()
}

#[cfg(test)]
mod tests {
    use std::fs::read_to_string;

    use crate::set_1::aes::detect_aes_128_ecb;

    use super::encryption_oracle;


    #[test]
    fn random_encrypt() {
        let input = read_to_string("./data/set_1/ch6-solution.txt").unwrap();
        for _ in 0..10 {
            let output = encryption_oracle(input.as_bytes());
            // will be true ~50% of the time
            // Could use a seed to verify guesses
            let guess = detect_aes_128_ecb(&output);
        }
    }
}
