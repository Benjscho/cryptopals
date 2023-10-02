use openssl::symm::{Cipher, Crypter, Mode};

/// Encrypts data given a key and an optional IV with AES 128 CBC mode.
pub fn encrypt_aes_128_cbc(input: &[u8], key: &[u8], iv: Option<&[u8]>) -> Vec<u8> {
    let mut res = vec![];
    let padded_input = pkcs7_padding(input, 16);

    let mut prev_block = match iv {
        Some(block) => block.to_owned(),
        None => vec![b'\0'; 16]
    };

    for i in (0..padded_input.len()).step_by(16) {
        let mut tmp = [b'\0'; 16];
        for j in 0..16 {
            tmp[j] = padded_input[i+j] ^ prev_block[j];
        }
        let ct = encrypt_aes_128_ecb(&tmp, &key);
        res.extend_from_slice(&ct);
        prev_block = ct;
    }

    res
}

pub fn decrypt_aes_128_cbc(input: &[u8], key: &[u8], iv: Option<&[u8]>) -> Vec<u8> {
    let mut res = vec![];

    let mut prev_block = match iv {
        Some(block) => block.to_owned(),
        None => vec![b'\0'; 16]
    };

    for i in (0..input.len()).step_by(16) {
        let tmp = input[i..i+16].to_vec();
        let mut ct = decrypt_aes_128_ecb(&tmp, &key);
        for j in 0..16 {
            ct[j] = ct[j] ^ prev_block[j];
        }
        res.extend_from_slice(&ct);
        prev_block = tmp;
    }

    res
}

pub fn encrypt_aes_128_ecb(data: &[u8], key: &[u8]) -> Vec<u8> {
    let c = Cipher::aes_128_ecb();
    let mut encrypter = Crypter::new(c, Mode::Encrypt, key, None).unwrap();
    let mut ciphertext = vec![0; data.len() * 2];
    encrypter.pad(false);
    encrypter.update(data, &mut ciphertext).unwrap();
    ciphertext.resize(16, b'\0');
    ciphertext
}

pub fn decrypt_aes_128_ecb(data: &[u8], key: &[u8]) -> Vec<u8> {
    let c = Cipher::aes_128_ecb();
    let mut encrypter = Crypter::new(c, Mode::Decrypt, key, None).unwrap();
    let mut ciphertext = vec![0; data.len() * 2];
    encrypter.pad(false);
    encrypter.update(data, &mut ciphertext).unwrap();
    ciphertext.resize(16, b'\0');
    ciphertext
}

fn pkcs7_padding(input: &[u8], block_length: usize) -> Vec<u8> {
    let mut res = vec![];

    for i in 0..input.len() {
        res.push(input[i]);
    }
    while res.len() % block_length != 0 {
        res.push(b'\x04');
    }

    res
}

#[cfg(test)]
mod tests {
    use std::{fs::read_to_string, str::from_utf8};

    use crate::byte_util::{hex_encode, hex_decode, base64_decode};

    use super::*;

    #[test]
    fn pkcs7_padding_happy() {
        let input = "YELLOW SUBMARINE".as_bytes();
        let expected = "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes();
        let actual = pkcs7_padding(&input, 20);
        assert_eq!(expected, actual);
    }

    #[test]
    fn aes_cbc_happy() {
        let input = "This is a 48-byte message (exactly 3 AES blocks)".as_bytes();
        let key = hex_decode("6c3ea0477630ce21a2ce334aa746c2cd".as_bytes());
        let iv = hex_decode("c782dc4c098c66cbd9cd27d825682c81".as_bytes());
        let expected = "d0a02b3836451753d493665d33f0e8862dea54cdb293abc7506939276772f8d5021c19216bad525c8579695d83ba2684".as_bytes();
        let actual = encrypt_aes_128_cbc(&input, &key, Some(&iv));
        assert_eq!(expected, hex_encode(&actual));
    }

    #[test]
    fn challenge_10() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let input = read_to_string("./data/set_2/ch10.txt").unwrap();
        let input = base64_decode(input.as_bytes());
        let result = decrypt_aes_128_cbc(&input, key, None);
        println!("{}", from_utf8(&result).unwrap());
    }
}
