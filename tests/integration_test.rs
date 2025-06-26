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
