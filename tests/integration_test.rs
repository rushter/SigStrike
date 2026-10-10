use std::fs::File;
use std::io::Read;
use zip::read::ZipArchive;

fn read_zip_to_memory(path: &str, password: &str) -> zip::result::ZipResult<Vec<Vec<u8>>> {
    let file = File::open(path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut result = Vec::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index_decrypt(i, password.as_bytes())?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        if buffer.is_empty() {
            continue;
        }
        result.push(buffer);
    }

    Ok(result)
}

#[test]
fn test_beacon_extraction() {
    let zip_path = "tests/data/beacons.zip";
    let password = "infected";
    match read_zip_to_memory(zip_path, password) {
        Ok(files) => {
            assert!(
                files.len() >= 6,
                "Expected at least 6 files in ZIP, found {}",
                files.len()
            );
            assert!(!files.is_empty(), "No files found in ZIP");
            for (i, content) in files.iter().enumerate() {
                let result = sigstrike::extract_beacon(content);
                assert!(result.is_ok(), "Failed to extract beacon from file {i}");
                let beacon = result.unwrap();
                assert!(
                    beacon.items.len() > 8,
                    "Extracted beacon data is empty for file {i}"
                );
            }
        }
        Err(e) => panic!("Error reading ZIP: {e:?}"),
    }
}

fn setting_block(index: u16, settings_type: u16, value: &[u8]) -> Vec<u8> {
    let mut block = Vec::new();
    block.extend_from_slice(&index.to_be_bytes());
    block.extend_from_slice(&settings_type.to_be_bytes());
    block.extend_from_slice(&(value.len() as u16).to_be_bytes());
    block.extend_from_slice(value);
    block
}

fn plain_config(blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut data = Vec::new();
    for block in blocks {
        data.extend_from_slice(block);
    }
    data.extend_from_slice(b"\x00\x00");
    data
}

#[test]
fn test_config_block_errors_do_not_stop_parsing() {
    let mut bad_block = setting_block(1, 1, &[0x00, 0x08]);
    bad_block[7] = 0x7f;

    let config = plain_config(&[
        bad_block,
        setting_block(2, 2, &[0x00, 0x00, 0x50, 0x00]),
        setting_block(3, 2, &[0x00, 0x00, 0x00, 0x3c]),
        setting_block(4, 2, &[0x00, 0x00, 0x02, 0x00]),
        setting_block(5, 2, &[0x00, 0x00, 0x00, 0x1e]),
        setting_block(6, 2, &[0x00, 0x00, 0x00, 0x01]),
    ]);

    let beacon = sigstrike::extract_beacon(&config).expect("Failed to extract config");
    assert_eq!(
        beacon.items.len(),
        5,
        "Every setting after the malformed block must survive"
    );
}

#[test]
fn test_config_last_block_is_parsed() {
    let config = plain_config(&[
        setting_block(1, 1, &[0x00, 0x08]),
        setting_block(2, 2, &[0x00, 0x00, 0x50, 0x00]),
        setting_block(3, 2, &[0x00, 0x00, 0x00, 0x3c]),
        setting_block(4, 2, &[0x00, 0x00, 0x02, 0x00]),
        setting_block(5, 2, &[0x00, 0x00, 0x00, 0x1e]),
        setting_block(6, 2, &[0x00, 0x00, 0x00, 0x01]),
    ]);

    let beacon = sigstrike::extract_beacon(&config).expect("Failed to extract config");
    assert_eq!(
        beacon.items.len(),
        6,
        "The setting right before the terminator must not be dropped"
    );
}
