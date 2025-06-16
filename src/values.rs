use crate::datamodel::{BeaconSetting, BofAllocator, InjectExecutor, SettingsType, TransformStep};
use crate::flags::BeaconProtocol;
use crate::utils::{bytes_to_string, trim_null_terminator, vec_to_hex};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use log::error;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::io::{Cursor, Read};
use std::net::Ipv4Addr;
use std::string::String;

#[derive(Debug, Serialize)]
#[allow(dead_code)]
#[serde(untagged)]
pub enum ValueType {
    Short(u16),
    Int(u32),
    String(String),
    StringList(Vec<String>),
    TransformStep(Vec<(String, TransformArgument)>),
    None,
}

impl ValueType {
    pub fn from_bytes(
        bytes: &[u8],
        settings_type: SettingsType,
        beacon_setting: BeaconSetting,
        length: u16,
    ) -> Result<Self, &'static str> {
        match settings_type {
            SettingsType::Short => {
                if bytes.len() < 2 {
                    return Err("Insufficient bytes for Short value");
                }

                let value = u16::from_be_bytes([bytes[0], bytes[1]]);
                match beacon_setting {
                    BeaconSetting::SettingProtocol => BeaconProtocol::from_bits(value)
                        .map(|flags| ValueType::StringList(flags.to_values()))
                        .ok_or("Invalid BeaconProtocol value"),
                    BeaconSetting::SettingBofAllocator => BofAllocator::try_from(value)
                        .map_or_else(
                            |_| Ok(ValueType::Short(0)),
                            |allocator| Ok(ValueType::String(allocator.to_name())),
                        ),
                    _ => Ok(ValueType::Short(value)),
                }
            }
            SettingsType::Int => {
                if bytes.len() < 4 {
                    return Err("Insufficient bytes for Int value");
                }
                let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                match beacon_setting {
                    BeaconSetting::SettingDnsIdle => {
                        if value == 0 {
                            Ok(ValueType::String("0.0.0.0".to_string()))
                        } else {
                            let ipv4 = Ipv4Addr::from(value);
                            Ok(ValueType::String(ipv4.to_string()))
                        }
                    }
                    _ => Ok(ValueType::Int(value)),
                }
            }
            SettingsType::Ptr => {
                if bytes.len() < length as usize {
                    return Err("Insufficient bytes for Ptr value");
                }
                let slice = &bytes[..length as usize];
                let value = SliceConverter { bytes: slice }.convert(beacon_setting)?;
                Ok(value)
            }
            SettingsType::None => Err("No value type provided"),
        }
    }
}

pub struct SliceConverter<'a> {
    pub bytes: &'a [u8],
}

impl<'a> SliceConverter<'a> {
    fn to_string(&self) -> ValueType {
        ValueType::String(bytes_to_string(self.bytes))
    }

    fn to_hex_string(&self) -> ValueType {
        ValueType::String(vec_to_hex(self.bytes))
    }

    fn to_sha256(&self) -> ValueType {
        let slice = trim_null_terminator(self.bytes);

        let mut hasher = Sha256::new();
        hasher.update(slice);
        let result = hasher.finalize();

        let mut hex_string = String::with_capacity(result.len() * 2);
        for &byte in result.as_slice() {
            let _ = write!(hex_string, "{byte:02x}");
        }

        ValueType::String(hex_string)
    }

    pub fn convert(&self, setting: BeaconSetting) -> Result<ValueType, &'static str> {
        if self.bytes.is_empty() {
            return Ok(ValueType::None);
        }
        match setting {
            BeaconSetting::SettingProcinjStub
            | BeaconSetting::SettingSpawnto
            | BeaconSetting::SettingMaskedWatermark => Ok(self.to_hex_string()),
            BeaconSetting::SettingPubkey => Ok(self.to_sha256()),
            BeaconSetting::SettingC2Request => parse_transform_binary(self.bytes, "metadata")
                .map(ValueType::TransformStep)
                .map_err(|_| "Failed to parse C2Request step."),
            BeaconSetting::SettingC2Postreq => parse_transform_binary(self.bytes, "id")
                .map(ValueType::TransformStep)
                .map_err(|_| "Failed to parse C2Postreq step."),
            BeaconSetting::SettingC2Recover => parse_recover_binary(self.bytes)
                .map(ValueType::TransformStep)
                .map_err(|_| "Failed to parse C2Recover step."),
            BeaconSetting::SettingProcinjExecute => {
                Ok(ValueType::StringList(parse_execute_list(self.bytes)))
            }
            BeaconSetting::SettingProcinjTransformX86
            | BeaconSetting::SettingProcinjTransformX64 => Ok(ValueType::TransformStep(
                parse_process_injection_transform_steps(self.bytes),
            )),
            BeaconSetting::SettingGargleSections => {
                Ok(ValueType::StringList(parse_gargle(self.bytes)))
            }
            BeaconSetting::SettingSmbFrameHeader | BeaconSetting::SettingTcpFrameHeader => {
                let mut cursor = Cursor::new(self.bytes);
                let length = match cursor.read_u16::<BigEndian>() {
                    Ok(len) => len as usize,
                    Err(_) => return Err("Failed to read FrameHeader length"),
                };
                if length == 0 || length > self.bytes.len().saturating_sub(8) {
                    return Err("Invalid FrameHeader length");
                }
                let mut header = vec![0u8; length];
                if cursor.read_exact(&mut header).is_err() {
                    return Err("Failed to read FrameHeader data");
                }
                Ok(ValueType::String(vec_to_hex(&header)))
            }

            _ => Ok(self.to_string()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum TransformArgument {
    String(String),
    Bool(bool),
    Int(i32),
}

pub fn parse_transform_binary(
    bytes: &[u8],
    build: &str,
) -> std::io::Result<Vec<(String, TransformArgument)>> {
    let enable_steps = [
        TransformStep::Base64,
        TransformStep::Base64Url,
        TransformStep::Netbios,
        TransformStep::NetbiosU,
        TransformStep::UriAppend,
        TransformStep::Print,
        TransformStep::Mask,
    ];

    let argument_steps = [
        TransformStep::Header_,
        TransformStep::Header,
        TransformStep::Parameter,
        TransformStep::Parameter_,
        TransformStep::HostHeader_,
        TransformStep::Append,
        TransformStep::Prepend,
    ];
    let mut steps: Vec<(String, TransformArgument)> = Vec::new();
    let mut cursor = Cursor::new(bytes);
    loop {
        let val = cursor.read_u32::<BigEndian>()?;
        if val == 0 {
            break;
        }
        let step = match TransformStep::try_from(val) {
            Ok(s) => s,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unknown transform step: {val}"),
                ));
            }
        };
        let name = step.to_name();
        if step == TransformStep::Build {
            let build_type = cursor.read_u32::<BigEndian>()?;
            let build_value = match build_type {
                0 => build.to_string(),
                1 => "output".to_string(),
                _ => "UNKNOWN BUILD ARG".to_string(),
            };
            steps.push((name, TransformArgument::String(build_value)));
        } else if enable_steps.contains(&step) {
            steps.push((name, TransformArgument::Bool(true)));
        } else if argument_steps.contains(&step) {
            let length = cursor.read_u32::<BigEndian>()?;
            if length > 100 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Transform argument length exceeds maximum allowed size",
                ));
            }
            let mut arg = vec![0u8; length as usize];
            cursor.read_exact(&mut arg)?;
            let arg = bytes_to_string(&arg);
            steps.push((name, TransformArgument::String(arg.to_string())));
        } else {
            error!("Unknown transform step: {name}");
        }
    }

    Ok(steps)
}

fn parse_recover_binary(bytes: &[u8]) -> std::io::Result<Vec<(String, TransformArgument)>> {
    let mut steps: Vec<(String, TransformArgument)> = Vec::new();
    let mut cursor = Cursor::new(bytes);
    loop {
        let step = cursor.read_u32::<BigEndian>()?;
        if step == 0 {
            break;
        }
        match TransformStep::try_from(step) {
            Ok(TransformStep::Append) => {
                let length = cursor.read_u32::<BigEndian>()?;
                steps.push(("append".to_string(), TransformArgument::Int(length as i32)));
            }
            Ok(TransformStep::Prepend) => {
                let length = cursor.read_u32::<BigEndian>()?;
                steps.push(("prepend".to_string(), TransformArgument::Int(length as i32)));
            }
            Ok(TransformStep::Base64) => {
                steps.push(("base64".to_string(), TransformArgument::Bool(true)))
            }
            Ok(TransformStep::Print) => {
                steps.push(("print".to_string(), TransformArgument::Bool(true)))
            }
            Ok(TransformStep::Netbios) => {
                steps.push(("netbios".to_string(), TransformArgument::Bool(true)))
            }
            Ok(TransformStep::NetbiosU) => {
                steps.push(("netbiosu".to_string(), TransformArgument::Bool(true)))
            }
            Ok(TransformStep::Base64Url) => {
                steps.push(("base64url".to_string(), TransformArgument::Bool(true)))
            }
            Ok(TransformStep::Mask) => {
                steps.push(("mask".to_string(), TransformArgument::Bool(true)))
            }
            _ => error!("Unknown recover step: {step}"),
        }
    }
    Ok(steps)
}

fn parse_execute_list(data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut cursor = Cursor::new(data);

    while let Ok(byte) = cursor.read_u8() {
        if byte == 0 {
            break;
        }
        let inject = InjectExecutor::try_from(byte);
        if inject.is_err() {
            error!("Unknown InjectExecutor: {byte}");
            continue;
        }
        let inject = match inject {
            Ok(i) => i,
            Err(_) => {
                error!("Failed to parse inject executor");
                continue;
            }
        };
        if inject == InjectExecutor::CreateThread_ || inject == InjectExecutor::CreateRemoteThread_
        {
            let offset = match cursor.read_u16::<BigEndian>() {
                Ok(val) => val,
                Err(_) => {
                    error!("Failed to read s4 value");
                    continue;
                }
            };
            let length = match cursor.read_u32::<BigEndian>() {
                Ok(len) => len as usize,
                Err(_) => {
                    error!("Failed to read first length");
                    continue;
                }
            };
            if length == 0 || length > data.len() - cursor.position() as usize {
                error!("Invalid module name length: {length}");
                continue;
            }
            let module_bytes =
                &data[cursor.position() as usize..cursor.position() as usize + length];
            cursor.set_position(cursor.position() + length as u64);
            let module_name = String::from_utf8_lossy(module_bytes)
                .trim_end_matches('\0')
                .to_string();

            let length = match cursor.read_u32::<BigEndian>() {
                Ok(len) => len as usize,
                Err(_) => {
                    error!("Failed to read second length");
                    continue;
                }
            };
            if length == 0 || length > data.len() - cursor.position() as usize {
                error!("Invalid function name length: {length}");
                continue;
            }
            let function_bytes =
                &data[cursor.position() as usize..cursor.position() as usize + length];
            cursor.set_position(cursor.position() + length as u64);
            let function_name = String::from_utf8_lossy(function_bytes)
                .trim_end_matches('\0')
                .to_string();

            let mut export_spec = format!("{module_name}!{function_name}");
            if offset != 0 {
                export_spec += &format!("+0x{offset:x}");
            }
            result.push(format!(
                "{} \"{}\"",
                inject.to_name().trim_end_matches('_'),
                export_spec
            ));
        } else {
            result.push(inject.to_name());
        }
    }
    result
}

fn parse_process_injection_transform_steps(data: &[u8]) -> Vec<(String, TransformArgument)> {
    fn read_arg(cursor: &mut Cursor<&[u8]>, length: u32) -> Result<String, &'static str> {
        if length > 100 {
            return Err("Transform argument length exceeds maximum allowed size");
        };
        let mut arg = vec![0u8; length as usize];
        if cursor.read_exact(&mut arg).is_err() {
            return Err("Failed to read transform argument data");
        }
        Ok(arg.iter().map(|b| format!("{b:02x}")).collect())
    }

    let mut steps = Vec::new();
    let mut cursor = Cursor::new(data);
    if let Ok(length) = cursor.read_u32::<BigEndian>() {
        if length == 0 {
            steps.push((
                "append".to_string(),
                TransformArgument::String("".to_string()),
            ));
        } else {
            match read_arg(&mut cursor, length) {
                Ok(arg) => steps.push(("append".to_string(), TransformArgument::String(arg))),
                Err(e) => error!("Failed to read append argument: {e}"),
            }
        }
    }
    if let Ok(length) = cursor.read_u32::<BigEndian>() {
        if length == 0 {
            steps.push((
                "prepend".to_string(),
                TransformArgument::String("".to_string()),
            ));
        } else {
            match read_arg(&mut cursor, length) {
                Ok(arg) => steps.push(("prepend".to_string(), TransformArgument::String(arg))),
                Err(e) => error!("Failed to read prepend argument: {e}"),
            }
        }
    }
    steps
}

fn parse_gargle(data: &[u8]) -> Vec<String> {
    let mut addresses = Vec::new();
    let mut cursor = Cursor::new(data);
    while let Ok(start) = cursor.read_u32::<LittleEndian>() {
        let end = match cursor.read_u32::<LittleEndian>() {
            Ok(val) => val,
            Err(_) => {
                error!("Failed to read end address");
                break;
            }
        };
        if start == 0 && end == 0 {
            break;
        }
        addresses.push(format!("0x{start:x}-0x{end:x}"));
    }
    addresses
}
