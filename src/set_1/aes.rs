use openssl::symm::{Cipher, decrypt};

pub fn decrypt_aes_128_ecb(data: &[u8], key: &[u8]) -> Vec<u8> {
    let c = Cipher::aes_128_ecb();
    decrypt(c, key, None, data).unwrap()
}

#[cfg(test)]
mod tests {
    use std::{fs::read_to_string, str::from_utf8};

    use crate::set_1::hex_to_base64::base64_to_bytes;

    use super::*;

    #[test]
    fn name() {
        let input = read_to_string("./data/set_1/ch7.txt").unwrap();
        let input = base64_to_bytes(&input.as_bytes());
        let key = "YELLOW SUBMARINE".as_bytes();
        let actual = decrypt_aes_128_ecb(&input, key);
        println!("{}", from_utf8(&actual).unwrap());
    }
}
