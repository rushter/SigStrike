use crate::config::BeaconBlob;
use crate::datamodel::ParsedBeacon;
use crate::extract::decrypt_beacon;
use crate::utils;
use log::{debug, info};
use num_enum::TryFromPrimitive;
use std::collections::HashMap;

const BEACON_CONFIG_PATCH_SIZE: usize = 6144;
const GUARD_PATCH_SIZE: usize = 2048;
const DEFAULT_BUFFER_SIZE: usize = 8192;

const GUARD_CONFIG_STARTS: [&[u8; 6]; 4] = [
    b"\x00\x05\x00\x01\x00\x02", // GUARD_USER
    b"\x00\x06\x00\x01\x00\x02", // GUARD_COMPUTER
    b"\x00\x07\x00\x01\x00\x02", // GUARD_DOMAIN
    b"\x00\x08\x00\x02\x00\x04", // GUARD_LOCAL_IP
];

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
enum GuardOption {
    User = 5,
    Computer = 6,
    Domain = 7,
    LocalIp = 8,
    PayloadChecksum = 9,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
enum SettingsType {
    None = 0,
    Short = 1,
    Int = 2,
    Ptr = 3,
}

#[derive(Debug, Clone)]
struct GuardrailSetting {
    option: GuardOption,
    value: Vec<u8>,
}

impl GuardrailSetting {
    pub fn parse(data: &[u8], offset: &mut usize) -> Option<Self> {
        if *offset + 6 > data.len() {
            return None;
        }

        let option = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
        let length = u16::from_be_bytes([data[*offset + 4], data[*offset + 5]]);

        *offset += 6;

        if *offset + length as usize > data.len() {
            return None;
        }

        let value = data[*offset..*offset + length as usize].to_vec();
        *offset += length as usize;
        let option = GuardOption::try_from(option).ok()?;

        Some(GuardrailSetting { option, value })
    }
}

#[derive(Debug, Clone)]
pub struct GuardrailMetadata {
    /// Masked raw beacon configuration
    pub masked_beacon_config: Vec<u8>,
    /// Single byte XOR key used to mask the beacon configuration. (0x2e by default unless modified beacon)
    pub beacon_xor_key: u8,
    /// Unmasked guardrail configuration
    pub checksum: u32,
}

#[derive(Debug, Clone)]
struct GuardrailResult {
    beacon_data: Vec<u8>,
    xor_key: String,
}

fn u32_from_be_bytes(bytes: &[u8]) -> u32 {
    if bytes.len() >= 4 {
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        0
    }
}

/// Group data into chunks of size n
fn grouper(data: &[u8], n: usize) -> Vec<Vec<u8>> {
    data.chunks(n)
        .map(|chunk| {
            let mut padded = chunk.to_vec();
            while padded.len() < n {
                padded.push(0);
            }
            padded
        })
        .collect()
}

fn payload_checksum(data: &[u8]) -> u32 {
    let mut n: u64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        n = (n + (byte as u64) * ((i % 3 + 1) as u64)) % 99999999;
    }
    n as u32
}

#[derive(Debug)]
struct XorKeyCandidateIterator<'a> {
    data: &'a [u8],
    current_keylen: usize,
    max_keylen: usize,
    current_candidates: Vec<Vec<u8>>,
}

impl<'a> XorKeyCandidateIterator<'a> {
    fn new(data: &'a [u8]) -> Self {
        XorKeyCandidateIterator {
            data,
            current_keylen: 2,
            max_keylen: 256,
            current_candidates: Vec::new(),
        }
    }

    fn find_candidates_for_keylen(&self, keylen: usize) -> Vec<Vec<u8>> {
        let mut counter: HashMap<Vec<u8>, usize> = HashMap::new();

        for chunk in self.data.chunks(DEFAULT_BUFFER_SIZE) {
            let grams = grouper(chunk, keylen);
            for gram in grams {
                *counter.entry(gram).or_insert(0) += 1;
            }
        }

        let mut counts: Vec<_> = counter.into_iter().collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1));

        let mut candidates = Vec::new();
        let mut first_count = 0;
        for (key, count) in counts.into_iter().take(2) {
            if count >= first_count {
                first_count = count;
                candidates.push(key);
            } else {
                break;
            }
        }

        candidates
    }
}

impl<'a> Iterator for XorKeyCandidateIterator<'a> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.current_candidates.is_empty() {
            return Some(self.current_candidates.remove(0));
        }

        while self.current_keylen <= self.max_keylen {
            let candidates = self.find_candidates_for_keylen(self.current_keylen);
            self.current_keylen += 1;

            if !candidates.is_empty() {
                self.current_candidates = candidates;
                return Some(self.current_candidates.remove(0));
            }
        }
        None
    }
}

fn iter_guardrail_configs(data: &[u8], xor_key: u8) -> Vec<GuardrailMetadata> {
    let xorred_config_starts: Vec<Vec<u8>> = GUARD_CONFIG_STARTS
        .iter()
        .map(|&start| utils::xor_single_byte(start, xor_key))
        .collect();

    let size = xorred_config_starts[0].len();
    let mut results = Vec::new();
    let mut offset = 0;

    while offset + size * 2 <= data.len() {
        let block = &data[offset..offset + size * 2];
        let a = &block[..size];
        let b = &block[size..];

        // Reverse a and XOR with b
        let mut a_reversed = a.to_vec();
        a_reversed.reverse();
        let xor_result = utils::xor_bytes(&a_reversed, b);

        if xorred_config_starts.contains(&xor_result) {
            debug!("Found guardrail config at offset: {offset}");

            let guard_config_offset = offset + 6;
            let beacon_config_offset = guard_config_offset.saturating_sub(BEACON_CONFIG_PATCH_SIZE);

            if beacon_config_offset + BEACON_CONFIG_PATCH_SIZE + GUARD_PATCH_SIZE <= data.len() {
                let masked_beacon_config = data[beacon_config_offset..beacon_config_offset + BEACON_CONFIG_PATCH_SIZE].to_vec();
                let masked_guard_config = data[beacon_config_offset + BEACON_CONFIG_PATCH_SIZE..beacon_config_offset + BEACON_CONFIG_PATCH_SIZE + GUARD_PATCH_SIZE].to_vec();

                let mut beacon_config_reversed = masked_beacon_config.clone();
                beacon_config_reversed.reverse();

                let temp_xor = utils::xor_bytes(&masked_guard_config, &beacon_config_reversed);
                let unmasked_guard_config = utils::xor_single_byte(&temp_xor, xor_key);

                let mut checksum = 0u32;
                let mut parse_offset = 0;

                while parse_offset + 2 <= unmasked_guard_config.len() {
                    if unmasked_guard_config[parse_offset] == 0 && unmasked_guard_config[parse_offset + 1] == 0 {
                        break;
                    }

                    if let Some(setting) = GuardrailSetting::parse(&unmasked_guard_config, &mut parse_offset) {
                        if setting.option == GuardOption::PayloadChecksum {
                            checksum = u32_from_be_bytes(&setting.value);
                            debug!("GuardPayloadChecksum = 0x{checksum:08x}");
                        }
                    } else {
                        break;
                    }
                }

                results.push(GuardrailMetadata {
                    checksum,
                    masked_beacon_config,
                    beacon_xor_key: 0x2e, // default key
                });
            }
        }
        offset += 1;
    }

    results
}

fn iter_guardrail_configs_with_beacon(data: &[u8]) -> Option<GuardrailResult> {
    for grconfig in iter_guardrail_configs(data, 0x8a) {
        let guarded_config = utils::xor_single_byte(&grconfig.masked_beacon_config, grconfig.beacon_xor_key);

        for xorkey in XorKeyCandidateIterator::new(&guarded_config) {
            let unguarded = utils::xor_bytes(&guarded_config, &xorkey);
            let checksum = payload_checksum(&unguarded) + 1;

            if grconfig.checksum == checksum {
                let xor_string = String::from_utf8_lossy(&xorkey);
                debug!("payload checksum: 0x{:08x} for xorkey: {:02x?}", checksum, &xor_string);
                return Some(GuardrailResult {
                    beacon_data: unguarded,
                    xor_key: xor_string.to_string(),
                });
            }
        }
    }
    None
}


fn search_guardrail_config(data: &[u8]) -> Option<ParsedBeacon> {
    if let Some(result) = iter_guardrail_configs_with_beacon(data) {
        let mut config = BeaconBlob {
            data: result.beacon_data,
            current_offset: 0,
        };
        info!("Guardrail config found");
        let config_items = config.parse();
        return Some(ParsedBeacon {
            encrypted: false,
            items: config_items,
            xor_key: None,
            guardrailed: true,
            guardrail_key: Some(result.xor_key),
            input_hash: None,
        });
    };
    None
}
pub fn find_guardrail_config(data: &[u8]) -> Option<ParsedBeacon> {
    let guardrail_data: &[u8];
    let decrypted_buffer: Vec<u8>;

    if let Some(decrypted_data) = decrypt_beacon(data, 0) {
        decrypted_buffer = decrypted_data;
        guardrail_data = &decrypted_buffer;
        if let Some(parsed_config) = search_guardrail_config(guardrail_data) {
            return Some(parsed_config);
        }
    }

    if let Some(parsed_config) = search_guardrail_config(data) {
        return Some(parsed_config);
    }

    None
}