use std::{str::from_utf8, vec, path::Path, fs::File, io::{BufReader, BufRead}};

use super::{fixed_xor::fixed_xor, hex_to_base64::hex_to_bytes};

/// Find one byte cipher candidates using a scoring of plaintext.
pub fn solve_one_byte_cipher(input: &[u8]) -> Vec<u8> {
    let mut max_score: i32 = i32::MIN;
    let mut candidate: u8 = 0;
    let mut candidate_pt: Vec<u8> = vec![];
    let buffer = hex_to_bytes(input);
    for c in 0..u8::MAX {
        let decrypted = xor_text(&buffer, c);
        let score = english_score(&decrypted);
        if score > max_score {
            max_score = score;
            candidate = c;
            candidate_pt = decrypted.clone();

            //eprintln!("New candidate key: {}, translated text: {}", &c, from_utf8(&decrypted).unwrap());
        }
    }
    candidate_pt
}

fn xor_text(input: &[u8], candidate: u8) -> Vec<u8> {
    let b2 = vec![candidate; input.len()];

    fixed_xor(input, &b2)
}

fn english_score(input: &[u8]) -> i32 {
    let mut score = 0;
    for b in input.iter() {
        match b {
            65..=90 | 97 ..=122 | 32 => score += 1,
            _ => score -= 20
        }
    }
    score
}

fn find_in_file(file: &Path) -> Vec<u8> {
    let mut reader = BufReader::new(File::open(file).expect("Can't open file."));
    let mut max_score = i32::MIN;
    let mut found_str = vec![];
    for line in reader.lines() {
        let candidate = solve_one_byte_cipher(&line.unwrap().as_bytes());
        let score = english_score(&candidate);
        if score > max_score {
            max_score = score;
            found_str = candidate;
        }
    }
    println!("Final candidate: {}", from_utf8(&found_str).unwrap());
    found_str
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_byte_cipher_happy() {
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".as_bytes();
        let expected = "Cooking MC's like a pound of bacon".as_bytes();
        let actual = solve_one_byte_cipher(&input);
        assert_eq!(expected, actual);
    }

    #[test]
    fn find_in_file_happy() {
        let file = Path::new("./data/set_1/ch4.txt");
        let expected = "Now that the party is jumping\n".as_bytes();
        let actual = find_in_file(file);
        assert_eq!(expected, actual);
    }
}
