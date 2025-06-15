use crate::{cli, extract};
use std::path::PathBuf;

/// This module provides a Python interface for extracting Cobalt Strike beacons from binary data.
///
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;


/// extract_beacon(data)
/// --
///
/// Extracts a Cobalt Strike beacon from the provided binary data.
/// Returns the extracted beacon in JSON format.
/// Raises Exception if extraction fails.
#[pyfunction]
fn extract_beacon(data: &[u8]) -> PyResult<String> {
    let result = extract::extract_beacon(data);

    match result {
        Ok(value) => {
            match serde_json::to_string(&value) {
                Ok(json) => Ok(json),
                Err(e) => Err(PyValueError::new_err(format!("Error serializing to JSON: {}", e))),
            }
        }
        Err(e) => Err(PyValueError::new_err(format!("Beacon extraction failed: {}", e))),
    }
}

#[pyfunction]
fn run_cli() -> PyResult<()> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    rt.block_on(cli::run_cli(1));
    Ok(())
}
/// Runs the crawler with the specified parameters.
/// --
///
/// Run the crawler with the given input and output paths, maximum concurrent requests, maximum retries, and timeout.
/// Stores results in the specified output path in JSONL format.
///
#[pyfunction]
#[pyo3(signature = (input_path, output_path, max_concurrent=100, max_retries=2, timeout=10))]
fn crawl(input_path: String, output_path: String, max_concurrent: usize, max_retries: usize, timeout: u64) -> PyResult<()> {
    let input_path = PathBuf::from(input_path);
    let output_path = PathBuf::from(output_path);
    let rt = tokio::runtime::Runtime::new().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let result = rt.block_on(crate::crawler::crawl(&input_path, &output_path, max_concurrent, max_retries, timeout));
    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(PyRuntimeError::new_err(format!("Crawl failed: {}", e))),
    }
}

#[pymodule]
fn _sigstrike(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract_beacon, m)?)?;
    m.add_function(wrap_pyfunction!(run_cli, m)?)?;
    m.add_function(wrap_pyfunction!(crawl, m)?)?;
    Ok(())
}