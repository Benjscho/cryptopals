///! This module provides XOR functionality

use crate::set_1::hex_to_base64::*;

/// This function takes two equal-length buffers and produces their XOR
/// combination.
pub fn fixed_xor(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    let mut res = Vec::with_capacity(b1.len());
    for i in 0..b1.len() {
        res.push(b1[i] ^ b2[i]);
    }
    res
}

pub fn fixed_hex_xor(h1: &[u8], h2: &[u8]) -> Vec<u8> {
    fixed_xor(&hex_to_bytes(h1), &hex_to_bytes(h2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_xor_happy() {
        let b1 = "1c0111001f010100061a024b53535009181c".as_bytes();
        let b2 = "686974207468652062756c6c277320657965".as_bytes();
        let expected = "746865206b696420646f6e277420706c6179".as_bytes();
        let actual = bytes_to_hex(&fixed_hex_xor(b1, b2));
        assert_eq!(expected, actual);
    }
}
