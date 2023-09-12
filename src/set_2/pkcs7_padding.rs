

fn pkcs7_padding(input: &[u8], block_length: usize) -> Vec<u8> {
    let mut res = vec![];

    for i in 0..input.len() {
        res.push(input[i]);
    }
    res.push(b'\x04');
    while res.len() % block_length != 0 {
        res.push(b'\x04');
    }

    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs7_padding_happy() {
        let input = "YELLOW SUBMARINE".as_bytes();
        let expected = "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes();
        let actual = pkcs7_padding(&input, 20);
        assert_eq!(expected, actual);
    }

}
