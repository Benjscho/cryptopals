use std::collections::HashSet;

use openssl::symm::{Cipher, decrypt};

pub fn decrypt_aes_128_ecb(data: &[u8], key: &[u8]) -> Vec<u8> {
    let c = Cipher::aes_128_ecb();
    decrypt(c, key, None, data).unwrap()
}

/// Indicates if the data was encrypted with aes 128 ecb. ECB is stateless
/// and deterministic. The same 16 byte plaintext block will always produce
/// the same 16 byte cipher text.
///
/// This means that if we can assume that some repeated plaintext blocks occur 
/// the same block offsets, then we can look for repeated ciphertext blocks 
/// to identify if this is the case.
pub fn detect_aes_128_ecb(data: &[u8]) -> bool {
    let mut blocks: HashSet<&[u8]> = HashSet::new();
    for i in (0..data.len()).step_by(16) {
        if blocks.contains(&data[i..i+16]) {
            return true;
        }
        blocks.insert(&data[i..i+16]);
    }
    false
}

#[cfg(test)]
mod tests {
    use std::{fs::read_to_string, str::from_utf8};

    use crate::{set_1::hex_to_base64::base64_to_bytes, byte_util::hex_decode};

    use super::*;

    #[test]
    fn decrypt_aes_128_ecb_happy() {
        let input = read_to_string("./data/set_1/ch7.txt").unwrap();
        let input = base64_to_bytes(&input.as_bytes());
        let key = "YELLOW SUBMARINE".as_bytes();
        let actual = decrypt_aes_128_ecb(&input, key);
        println!("{}", from_utf8(&actual).unwrap());
    }

    #[test]
    fn detect_aes_128_ecb_happy() {
        // this file has only one string encrypted with 128 aes ecb
        let data = read_to_string("./data/set_1/ch8.txt").unwrap();
        let expected = 1;
        let mut actual = 0;
        for d in data.lines() {
            let input = hex_decode(d.as_bytes());
            if detect_aes_128_ecb(&input) {
                actual += 1;
                println!("{}", d);
            }
        }
        assert_eq!(expected, actual);
    }
}
