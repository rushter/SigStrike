use crate::config::BeaconBlob;
use crate::datamodel::{ParsedBeacon, ParsedBeaconItems};
use crate::guardrails::find_guardrail_config;
use crate::utils::{
    DEFAULT_XOR_KEYS, get_most_common_xor_keys, hash_bytes, needle_in_haystack, order_offsets, xor,
};
use log::{debug, info};
use std::io::Error;

const SHELLCODE_END_MARKER: &[u8; 3] = b"\xFF\xFF\xFF";
const MAX_OFFSET: usize = 1024;
const MAX_BEACON_SIZE: usize = 4096;

const CONFIG_HEADER_PATTERN: &[u8; 7] = b"\x00\x01\x00\x01\x00\x02\x00";
const MIN_BEACON_FIELDS: usize = 5;

pub fn decrypt_beacon(data: &[u8], offset: usize) -> Option<Vec<u8>> {
    if offset + 16 >= data.len() {
        return None;
    }

    let key = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    let size = u32::from_le_bytes([
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]) ^ key;

    info!("Beacon size: {size}");
    if size == 0 {
        debug!("Beacon size is zero, returning None");
        return None;
    }

    let start_i = 2 + offset / 4;
    let end_i = (data.len() / 4) - 4;

    let mut decoded_data = Vec::with_capacity(1024);

    for i in start_i..end_i {
        let pos_a = i * 4;
        let pos_b = i * 4 + 4;

        if pos_b + 3 >= data.len() {
            break;
        }

        let a = u32::from_le_bytes([
            data[pos_a],
            data[pos_a + 1],
            data[pos_a + 2],
            data[pos_a + 3],
        ]) ^ key;

        let b = u32::from_le_bytes([
            data[pos_b],
            data[pos_b + 1],
            data[pos_b + 2],
            data[pos_b + 3],
        ]) ^ key;

        let c = a ^ b;
        decoded_data.extend_from_slice(&c.to_le_bytes());
    }
    Some(decoded_data)
}

fn find_beacon_offsets(data: &[u8], max_range: usize) -> Vec<usize> {
    let file_size = data.len();
    if file_size < 8 {
        return Vec::new();
    }

    let effective_max = std::cmp::min(max_range, file_size - 8);
    let mut result = Vec::new();

    for i in 0..effective_max {
        let nonce = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let size_bytes = u32::from_le_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]);

        let decoded_size = (nonce ^ size_bytes) as usize;
        if decoded_size + i + 8 == file_size {
            debug!("FOUND real_size, iter_nonce_offsets -> {i}");
            result.push(i);
        }
    }
    result
}

fn find_config_bytes(data: &[u8], xor_key: u8) -> Option<ParsedBeaconItems> {
    if data.is_empty() {
        return None;
    }

    let xorred_config_header = xor(CONFIG_HEADER_PATTERN, xor_key);
    let possible_offsets = needle_in_haystack(data, &xorred_config_header, None);
    for pos in possible_offsets {
        debug!("Found CONFIG_HEADER using xorkey: {xor_key:#x?} at position {pos}",);
        let max_pos = std::cmp::min(pos + MAX_BEACON_SIZE, data.len() - 1);
        let xorred_config = xor(&data[pos..max_pos], xor_key);
        let mut config = BeaconBlob {
            data: xorred_config,
            current_offset: 0,
        };
        let items = config.parse();
        if items.len() >= MIN_BEACON_FIELDS {
            return Some(items);
        }
    }
    None
}

fn extract_decrypted_beacon(data: &[u8]) -> Option<ParsedBeacon> {
    if data.is_empty() {
        return None;
    }

    let beacon_offsets = find_beacon_offsets(data, MAX_OFFSET);
    debug!("Beacon offsets found: {beacon_offsets:?}");
    let shellcode_offsets =
        needle_in_haystack(data, SHELLCODE_END_MARKER, Some(MAX_OFFSET)).collect::<Vec<usize>>();
    let shellcode_offsets: Vec<usize> = shellcode_offsets
        .iter()
        .map(|&offset| offset + SHELLCODE_END_MARKER.len())
        .collect();
    debug!("Shellcode offsets found: {shellcode_offsets:?}");

    let ordered_offsets = order_offsets(&beacon_offsets, &shellcode_offsets);
    for offset in &ordered_offsets {
        debug!("Beacon offset: {offset}");
        let decrypted_data = decrypt_beacon(data, *offset);
        let config = find_encrypted_config(decrypted_data.as_deref(), false);
        if let Some(parsed_config) = config {
            return Some(parsed_config);
        }
        if let Some(parsed_config) = find_encrypted_config(decrypted_data.as_deref(), true) {
            return Some(parsed_config);
        }
    }
    None
}

fn extract_unencrypted_beacon(data: &[u8]) -> Option<ParsedBeacon> {
    if data.is_empty() {
        return None;
    }

    let config = find_unencrypted_config(data, false);
    if let Some(parsed_config) = config {
        return Some(parsed_config);
    }
    if let Some(parsed_config) = find_unencrypted_config(data, true) {
        return Some(parsed_config);
    }
    None
}

/// Extracts a beacon configuration from the provided data.
/// This function attempts to find a beacon configuration in the data by first checking for decrypted beacons,
/// then unencrypted beacons, and finally guardrail configurations.
/// If no valid beacon configuration is found, it returns an error.
///
/// # Arguments
/// * `data` - A byte slice containing the data to search for beacon configurations.
///
/// # Returns
/// * `Ok(ParsedBeacon)` - If a valid beacon configuration is found.
/// * `Err(std::io::Error)` - If no valid beacon configuration is found or if an error occurs during processing.
///
pub fn extract_beacon(data: &[u8]) -> std::io::Result<ParsedBeacon> {
    debug!("Starting beacon extraction...");

    if data.is_empty() {
        return Err(Error::new(
            std::io::ErrorKind::InvalidInput,
            "Input data is empty",
        ));
    }

    let result = extract_decrypted_beacon(data)
        .or_else(|| {
            debug!("No decrypted beacon found, trying unencrypted beacon extraction...");
            extract_unencrypted_beacon(data)
        })
        .or_else(|| {
            debug!("No unencrypted beacon found, trying guardrail extraction...");
            find_guardrail_config(data)
        })
        .ok_or_else(|| Error::new(std::io::ErrorKind::NotFound, "No valid beacon found"));
    match result {
        Ok(mut parsed_beacon) => {
            info!("Beacon extraction successful");
            parsed_beacon.input_hash = Some(hash_bytes(data));
            Ok(parsed_beacon)
        }
        Err(e) => Err(e),
    }
}

fn find_config_with_data(
    data: Option<&[u8]>,
    all_xor_keys: bool,
    is_encrypted: bool,
) -> Option<ParsedBeacon> {
    let data = data?;

    let xor_keys = if all_xor_keys {
        &get_most_common_xor_keys(data)
    } else {
        &DEFAULT_XOR_KEYS.to_vec()
    };

    for &xor_key in xor_keys {
        if let Some(config_items) = find_config_bytes(data, xor_key) {
            info!("Found config with xor key: {xor_key:#x?}");
            return Some(ParsedBeacon {
                encrypted: is_encrypted,
                items: config_items,
                xor_key: Some(xor_key),
                guardrailed: false,
                guardrail_key: None,
                input_hash: None,
            });
        }
    }
    None
}

fn find_encrypted_config(
    decrypted_data: Option<&[u8]>,
    all_xor_keys: bool,
) -> Option<ParsedBeacon> {
    find_config_with_data(decrypted_data, all_xor_keys, true)
}

fn find_unencrypted_config(data: &[u8], all_xor_keys: bool) -> Option<ParsedBeacon> {
    find_config_with_data(Some(data), all_xor_keys, false)
}
