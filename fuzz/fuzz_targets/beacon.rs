#![no_main]

extern crate sigstrike;

use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let result =  sigstrike::extract_beacon(data);
    match result {
        Ok(decoded_data) => {
            assert!(!decoded_data.items.is_empty());
        },
        Err(_err) => {
            // Handle the error as needed, e.g., log it or ignore it
        }
    }
});
