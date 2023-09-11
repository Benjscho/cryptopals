use std::{cmp::min, collections::BinaryHeap};
use ordered_float::NotNan;

///! This module provides XOR functionality

use crate::set_1::hex_to_base64::*;

use super::single_byte_cipher::{solve_one_byte_cipher, english_score};

/// This function takes two equal-length buffers and produces their XOR
/// combination.
pub fn fixed_xor(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    let mut res = Vec::with_capacity(b1.len());
    for i in 0..b1.len() {
        res.push(b1[i] ^ b2[i]);
    }
    res
}

/// This function takes two differing length buffers and uses the second
/// as a repeating key to XOR them.
pub fn repeating_key_xor(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    let n = b1.len();
    let mut res = Vec::with_capacity(n);
    for i in 0..n {
        res.push(b1[i] ^ b2[i % b2.len()]);
    }
    res
}

pub fn fixed_hex_xor(h1: &[u8], h2: &[u8]) -> Vec<u8> {
    fixed_xor(&hex_to_bytes(h1), &hex_to_bytes(h2))
}

/// Calculate the Hamming distance of two buffers. This is just the number
/// of differing bits.
pub fn hamming_distance(b1: &[u8], b2: &[u8]) -> u32 {
    let mut res = 0;
    let n = min(b1.len(), b2.len());
    for i in 0..n {
        res += (b1[i] ^ b2[i]).count_ones();
    }
    res += b1.len().abs_diff(b2.len()) as u32 * 8;
    res
}

pub fn break_key_repeat_xor(input: &[u8]) -> Vec<u8> {
    let mut ks_cands = pick_keysize(input);
    let mut best_v = vec![];
    let mut max_score = i32::MIN;
    // Try the top 3 candidates
    for _ in 0..2 {
        let ks = ks_cands.pop().unwrap().1;
        eprintln!("Trying keysize: {}", ks);
        let mut blocks = Vec::with_capacity(ks);
        for i in 0..ks {
            let mut block = vec![];
            for j in (i..input.len()).step_by(ks) {
                block.push(input[j]);
            }
            blocks.push(block)
        }
        let mut key: Vec<u8> = vec![];
        for block in blocks {
            key.push(solve_one_byte_cipher(&block).1);
        }
        let text = repeating_key_xor(input, &key);
        let score = english_score(&text);
        if score > max_score {
            max_score = score;
            best_v = text;
        }
    }
    best_v
}

/// Pick the keysize for the encrypted text. Text needs to be at least 40
/// chars long. Returns a binary heap of tuples (normalized_score, keysize).
fn pick_keysize(input: &[u8]) -> BinaryHeap<(NotNan<f64>, usize)> {
    let mut heap = BinaryHeap::new();
    for ks in 2..=40 {
        let iters = 15;
        let mut scores = NotNan::<f64>::from(0);
        for i in 0..iters {
            scores +=
                NotNan::<f64>::from(hamming_distance(&input[ks*i..ks*(i + 1)], &input[ks*(i+1)..ks*(i+2)]))
                / NotNan::<f64>::from(ks as u32);
        }
        let score = scores / NotNan::<f64>::from(iters as u32);
        heap.push((-score, ks));
        println!("Giving score: {} for ks {}", score, ks);
    }
    heap
}

#[cfg(test)]
mod tests {
    use std::{fs::read_to_string, str::from_utf8};

    use super::*;

    // S1C2
    #[test]
    fn fixed_xor_happy() {
        let b1 = "1c0111001f010100061a024b53535009181c".as_bytes();
        let b2 = "686974207468652062756c6c277320657965".as_bytes();
        let expected = "746865206b696420646f6e277420706c6179".as_bytes();
        let actual = bytes_to_hex(&fixed_hex_xor(b1, b2));
        assert_eq!(expected, actual);
    }

    // S1C5
    #[test]
    fn repeating_key_xor_happy() {
        let b1 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes();
        let c = "ICE".as_bytes();
        let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f".as_bytes();
        let actual = bytes_to_hex(&repeating_key_xor(&b1, &c));
        assert_eq!(expected, actual);
    }

    #[test]
    fn hamming_distance_happy() {
        let b1 = "this is a test".as_bytes();
        let b2 = "wokka wokka!!!".as_bytes();
        let expected = 37;
        let actual = hamming_distance(b1, b2);
        assert_eq!(expected, actual);
    }

    #[test]
    fn break_key_repeat_xor_happy() {
        let input = read_to_string("./data/set_1/ch6.txt").unwrap();
        let input = base64_to_bytes(input.as_bytes());
        let expected = read_to_string("./data/set_1/ch6-solution.txt").unwrap();
        let actual = break_key_repeat_xor(&input);
    }
}
