use encoding_rs::WINDOWS_1252;
use encoding_rs_io::DecodeReaderBytesBuilder;
use memchr::memmem;
use memchr::memmem::FindIter;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::io::{Cursor, Read};

pub const DEFAULT_XOR_KEYS: [u8; 3] = [0x2eu8, 0x69u8, 0x00u8];

const ALPHABET: &str = "abcdefhijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567899";

pub fn order_offsets(beacon_offsets: &[usize], eof_positions: &[usize]) -> Vec<usize> {
    let mut frequency = HashMap::new();

    for &offset in beacon_offsets.iter().chain(eof_positions) {
        *frequency.entry(offset).or_insert(0) += 1;
    }

    if frequency.len() <= 1 {
        return frequency.into_keys().collect();
    }

    let mut keys: Vec<_> = frequency.into_iter().collect();
    keys.sort_unstable_by(|a, b| {
        b.1.cmp(&a.1) // frequency descending
            .then_with(|| a.0.cmp(&b.0)) // Then value ascending
    });

    keys.into_iter().map(|(key, _)| key).collect()
}

pub fn get_most_common_xor_keys(data: &[u8]) -> Vec<u8> {
    let mut byte_counts: HashMap<u8, usize> = HashMap::new();

    for gram in data.chunks(4) {
        if gram.len() == 4 && gram[0] == gram[1] && gram[1] == gram[2] && gram[2] == gram[3] {
            *byte_counts.entry(gram[0]).or_insert(0) += 1;
        }
    }

    let default_keys: HashSet<u8> = DEFAULT_XOR_KEYS.iter().copied().collect();

    let mut freq_vec: Vec<(u8, usize)> = byte_counts.into_iter().collect();
    freq_vec.sort_unstable_by(|a, b| b.1.cmp(&a.1));

    freq_vec
        .into_iter()
        .map(|(byte, _)| byte)
        .filter(|&byte| !default_keys.contains(&byte))
        .collect()
}

pub fn xor(data: &[u8], key: u8) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());

    const CHUNK_SIZE: usize = 32;
    let mut chunk = [0u8; CHUNK_SIZE];

    for chunks in data.chunks(CHUNK_SIZE) {
        let len = chunks.len();
        for i in 0..len {
            chunk[i] = chunks[i] ^ key;
        }
        result.extend_from_slice(&chunk[..len]);
    }

    result
}

pub fn trim_null_terminator(bytes: &[u8]) -> Vec<u8> {
    let mut new_vec = Vec::from(bytes);
    if let Some(pos) = bytes.iter().rposition(|&b| b != 0) {
        new_vec.truncate(pos + 1)
    } else {
        // All bytes are null, clear the vector
        new_vec.clear()
    }
    new_vec
}

pub fn bytes_to_string(bytes: &[u8]) -> String {
    let slice = trim_null_terminator(bytes);
    let mut rdr = DecodeReaderBytesBuilder::new()
        .encoding(Some(WINDOWS_1252))
        .build(Cursor::new(&slice));
    let mut decoded_string = String::with_capacity(slice.len());
    rdr.read_to_string(&mut decoded_string)
        .expect("Failed to decode bytes to string");

    decoded_string
}

#[inline]
pub fn vec_to_hex(vec: &[u8]) -> String {
    if vec.is_empty() {
        return String::new();
    }
    let slice = trim_null_terminator(vec);
    let mut hex_string = String::with_capacity(slice.len() * 2);
    for byte in slice {
        let _ = write!(hex_string, "{byte:02x}");
    }
    hex_string
}

pub fn needle_in_haystack<'h, 'n>(
    haystack: &'h [u8],
    needle: &'n [u8],
    max_offset: Option<usize>,
) -> FindIter<'h, 'n> {
    if needle.is_empty() {
        return memmem::find_iter(&[], needle);
    }

    let max_index = std::cmp::min(max_offset.unwrap_or(haystack.len()), haystack.len());

    if max_index == haystack.len() {
        return memmem::find_iter(haystack, needle);
    }

    let sub_haystack = &haystack[0..max_index];
    memmem::find_iter(sub_haystack, needle)
}

pub fn xor_single_byte(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|&b| b ^ key).collect()
}

pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    if b.len() >= a.len() {
        a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect()
    } else {
        let mut result = Vec::with_capacity(a.len());
        for (i, &byte_a) in a.iter().enumerate() {
            let b_idx = i % b.len();
            result.push(byte_a ^ b[b_idx]);
        }
        result
    }
}

fn checksum8(uri: &str, n: i32) -> bool {
    if uri.len() < 4 {
        return false;
    } else {
        let mut sum8: i32 = 0;
        for byte in uri.as_bytes() {
            sum8 += *byte as i32;
        }
        if (sum8 % 256) == n {
            return true;
        }
    }
    false
}

pub fn generate_checksum(n: i32) -> String {
    let mut uri: String;
    let mut rng = rand::rng();
    loop {
        let mut chars: Vec<char> = Vec::new();
        for _ in 0..4 {
            chars.push(
                ALPHABET
                    .chars()
                    .nth(rng.random_range(0..ALPHABET.len()))
                    .unwrap(),
            );
        }
        uri = chars.into_iter().collect();
        if checksum8(&uri, n) {
            break;
        }
    }
    uri
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    hex::encode(result)
}
