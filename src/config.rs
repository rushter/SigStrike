// This module parse configuration settings of Cobalt Strike beacons.

use log::{debug, error, info};
use std::collections::HashMap;

use crate::datamodel::{BeaconSetting, ParsedBeaconItems, SettingsType};
use crate::values::ValueType;

pub struct BeaconBlob {
    pub data: Vec<u8>,
    pub current_offset: usize,
}

impl BeaconBlob {
    pub fn get_offset(&self) -> &[u8] {
        &self.data[self.current_offset..]
    }

    pub fn parse(&mut self) -> ParsedBeaconItems {
        info!("Parsing BeaconConfig with {} bytes", self.data.len());
        let mut result: ParsedBeaconItems = HashMap::new();
        self.current_offset = 0;
        loop {
            match self.parse_next_block() {
                Ok(block) => {
                    debug!("Parsed block: {block:?}");
                    let length = block.length;
                    result.insert(block.index, block.value);
                    if !self.advance_offset(length) {
                        break;
                    }
                }
                Err(e) => {
                    error!("Error parsing block: {e}");
                    if !self.skip_block() {
                        break;
                    }
                }
            };
        }
        if result.is_empty() {
            debug!("No valid settings found in beacon data.");
        }
        result
    }
    pub fn parse_next_block(&self) -> Result<SettingsBlock, &'static str> {
        let bytes = self.get_offset();
        if bytes.len() < 8 {
            return Err("Insufficient bytes to parse config block.");
        }

        let index = u16::from_be_bytes([bytes[0], bytes[1]]);
        let settings_type = SettingsType::try_from(u16::from_be_bytes([bytes[2], bytes[3]]))
            .map_err(|_| "Invalid SettingsType")?;
        let length = u16::from_be_bytes([bytes[4], bytes[5]]);
        let index_type =
            BeaconSetting::try_from(index).map_err(|_| "Invalid BeaconSetting index")?;

        Ok(SettingsBlock {
            index: BeaconSetting::try_from(index).map_err(|_| "Invalid BeaconSetting index")?,
            settings_type,
            length,
            value: ValueType::from_bytes(&bytes[6..], settings_type, index_type, length)?,
        })
    }

    fn advance_offset(&mut self, length: u16) -> bool {
        self.current_offset += 6 + length as usize;

        if self.current_offset + 2 <= self.data.len() {
            let next_bytes = &self.data[self.current_offset..self.current_offset + 2];
            if next_bytes == b"\x00\x00" {
                debug!(
                    "End of beacon data reached at offset {}",
                    self.current_offset
                );
                return false;
            }
        } else {
            debug!("Reached end of beacon data.");
            return false;
        }
        true
    }

    /// Advances past a block that could not be parsed, so one bad setting does
    /// not discard the rest of the config.
    fn skip_block(&mut self) -> bool {
        let bytes = self.get_offset();

        let skip = if bytes.len() >= 6 {
            6 + u16::from_be_bytes([bytes[4], bytes[5]]) as usize
        } else {
            bytes.len()
        };

        let next_offset = self.current_offset + skip;

        if next_offset + 6 > self.data.len() {
            debug!("Reached end of beacon data while skipping block.");
            return false;
        }

        self.current_offset = next_offset;
        true
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct SettingsBlock {
    pub index: BeaconSetting,
    pub settings_type: SettingsType,
    pub length: u16,
    pub value: ValueType,
}
