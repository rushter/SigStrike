use crate::datamodel::ParsedBeacon;
use crate::extract;
use log::{error, info};
use std::io::{Read, Write};
use std::path::PathBuf;

fn read_file(file_path: &str) -> std::io::Result<ParsedBeacon> {
    let file = std::fs::File::open(file_path)?;
    let metadata = file.metadata()?;
    let file_size = metadata.len() as usize;

    let mut buffer = Vec::with_capacity(file_size);
    let mut reader = std::io::BufReader::new(file);
    reader.read_to_end(&mut buffer)?;

    let extracted_beacon = extract::extract_beacon(&buffer)?;
    Ok(extracted_beacon)
}

pub fn list_files(path: &str) -> Vec<String> {
    let mut files: Vec<String> = Vec::new();
    for entry in walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
    {
        if entry.file_type().is_file() {
            let file_path = entry.path().to_string_lossy().to_string();
            if file_path.ends_with(".DS_Store") {
                continue;
            }
            files.push(file_path);
        }
    }
    info!("Total files found: {}", files.len());
    files
}


pub fn process_files(file_paths: Vec<String>, output_path: Option<PathBuf>) -> std::io::Result<()> {
    let mut file_out: Box<dyn Write> = if let Some(output_path) = output_path {
        let file_out = std::fs::File::create(output_path)?;
        Box::new(file_out)
    } else {
        Box::new(std::io::stdout())
    };

    for file in file_paths.iter() {
        info!("Processing file: {}", file);
        match read_file(file) {
            Ok(beacon) => {
                let json = serde_json::to_string(&beacon)?;
                file_out.write_all(json.as_bytes())?;
                file_out.write_all(b"\n")?;
            }
            Err(e) => error!("Error reading file {}: {}", file, e),
        }
    }
    Ok(())
}


