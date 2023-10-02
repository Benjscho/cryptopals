///! This module is for byte utils used throughout the cryptopals challenges,
/// and initially created for Set 1.
///
/// Per the cryptopals Rule, we have to always operate on raw bytes, never
/// encoded strings.

const BASE64_CHAR_TABLE: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Convert hex strings to base64. If the string is valid hex returns the
/// converted string, otherwise fails and returns None.
pub fn hex_to_base64(input: &[u8]) -> Option<Vec<u8>> {
    let bytes = hex_decode(input);
    let result = base64_encode(&bytes);

    Some(result)
}

/// Convert an array of hex bytes into their binary representation.
pub fn hex_decode(hex: &[u8]) -> Vec<u8> {
    let mut res = vec![];
    for i in (0..hex.len()).step_by(2) {
        let b1 = hex_to_int(hex[i]);
        let b2 = hex_to_int(hex[i+1]);
        let b = (b1 << 4) | b2;
        res.push(b);
    }
    res
}

/// Convert a hex byte array back to its hex representation.
pub fn hex_encode(bytes: &[u8]) -> Vec<u8> {
    let mut res = vec![];
    for i in 0..bytes.len() {
        res.push(int_to_hex(bytes[i] >> 4));
        res.push(int_to_hex(bytes[i]));
    }
    res
}

/// Convert a hexadecimal byte to its binary representation. Panics if a
/// non-hex byte is input.
fn hex_to_int(hex: u8) -> u8 {
    match hex {
        48..=57  => hex - 48,      // 0-9
        65..=70  => hex - 65 + 10, // A-F
        97..=102 => hex - 97 + 10, // a-f
        _ => panic!()
    }
}

/// Converts the bottom four bits of a u8 into its hex char.
fn int_to_hex(int: u8) -> u8 {
    let int = int & 0b0000_1111;
    match int {
        0..=9 => int + 48,
        10..=15 => int + 87,
        _ => panic!()
    }
}

/// Convert an array of bytes into base64. We split the array into chunks of
/// 3 bytes (or 24 bits). From this, we then take four 6 bit groups. We then
/// prepend 0s to make these into four bytes. These bytes (each representing
/// a number 0 to 63) are then mapped to the base64 char table, and those u8
/// bytes are returned. The Base64 alphabet is specified in [RFC4648](https://datatracker.ietf.org/doc/html/rfc4648#section-4)
///
/// E.g., when converting "ABC":
/// A          B          C
/// 0100 0001  0100 0010  0100 0011
///
/// Split into four 6 bit groups:
/// 010000 010100 001001 000011
///
/// Padded back into bytes:
/// 0001_0000 0001_0100 0000_1001 0000_0011
///
/// Mapped to the base64 table as chars:
/// Q         U         J         D
///
/// Saved back as ASCII byte representation of those chars:
/// 01010001  01010101  01001010  01000100
pub fn base64_encode(bytes: &[u8]) -> Vec<u8> {
    let mut res = vec![];
    let n = bytes.len();
    let pad = n % 3;
    for i in (0..bytes.len()).step_by(3) {
        let b1 = bytes[i];
        res.push(byte_to_base64_char(b1 >> 2));
        if (i + 1) < n {
            let b2 = bytes[i+1];
            res.push(byte_to_base64_char((b1 << 4) | (b2 >> 4)));
            if (i + 2) < n {
                let b3 = bytes[i+2];
                res.push(byte_to_base64_char((b2 << 2) | (b3 >> 6)));
                res.push(byte_to_base64_char(b3))
            } else {
                res.push(byte_to_base64_char(b2 << 2));
            }
        } else {
            res.push(byte_to_base64_char(b1 << 6));
        }
    }

    // Add any padding bytes required.
    for _ in 0..pad {
        res.push(b'=');
    }

    res
}

/// Decode base64 strings into the resulting bytes.
pub fn base64_decode(input: &[u8]) -> Vec<u8> {
    let mut res = vec![];
    for i in (0..input.len()).step_by(4) {
        if input[i] == b'\n' {
            continue
        }
        let b1 = (base64_char_to_byte(input[i]) << 2) | (base64_char_to_byte(input[i + 1]) >> 4);
        res.push(b1);
        if input[i + 2] != b'=' {
            let b2 = (base64_char_to_byte(input[i + 1]) << 4) | (base64_char_to_byte(input[i + 2]) >> 2);
            res.push(b2);
            if input[i + 3] != b'=' {
                let b3 = (base64_char_to_byte(input[i + 2]) << 6) | base64_char_to_byte(input[i + 3]);
                res.push(b3);
            }
        }
    }
    res
}

/// Looks up the byte in the base64 char table.
fn byte_to_base64_char(byte: u8) -> u8 {
    // We want to ignore the top two bits
    BASE64_CHAR_TABLE[(byte & 0b0011_1111) as usize]
}

/// Reverse lookup, converts a base64 char to its decimal index.
fn base64_char_to_byte(char: u8) -> u8 {
    match char {
        65..=90 => char - 65,
        97..=122 => char - 97 + 26,
        48..=57 => char - 48 + 52,
        b'+' => 62,
        b'/' => 63,
        _ => panic!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // S1C1
    #[test]
    fn hex_to_base64_happy() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".as_bytes();
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".as_bytes();
        let actual = hex_to_base64(&input);
        assert_eq!(expected, actual.unwrap());
    }

    #[test]
    fn bytes_to_base64_happy() {
        let input = "ABC".as_bytes();
        let expected = "QUJD".as_bytes();
        let actual = base64_encode(&input);
        assert_eq!(expected, actual);
    }

    fn base64_to_bytes_happy() {
        let input = "QUJD".as_bytes();
        let expected = "ABC".as_bytes();
        let actual = base64_decode(&input);
        assert_eq!(expected, actual);
    }

    #[test]
    fn base64_to_bytes_happy_2() {
        let input = "YXNk".as_bytes();
        let expected = "asd".as_bytes();
        let actual = base64_decode(&input);
        assert_eq!(expected, actual);
    }

    #[test]
    fn base64_to_bytes_happy_3() {
        let input = "YXNkdWhmOTcxaDJARkEoUVdITkZtIkFTUEQiT3En".as_bytes();
        let expected = "asduhf971h2@FA(QWHNFm\"ASPD\"Oq'".as_bytes();
        let actual = base64_decode(&input);
        assert_eq!(expected, actual);
    }

    #[test]
    fn hex_to_bytes_happy() {
        let input = "17c0".as_bytes();
        let expected = vec![0b0001_0111, 0b1100_0000];
        let actual = hex_decode(&input);
        assert_eq!(expected, actual);
    }

    #[test]
    fn bytes_to_hex_happy() {
        let input = vec![0b0001_0111, 0b1100_0000];
        let expected = "17c0".as_bytes();
        let actual = hex_encode(&input);
        assert_eq!(expected, actual);
    }
}

