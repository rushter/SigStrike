use bitflags::{bitflags, bitflags_match};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconProtocol(u16);

bitflags! {
    impl  BeaconProtocol: u16 {
        const HTTP  = 0b000000;
        const DNS   = 0b000001;
        const SMB   = 0b000010;
        const TCP   = 0b000100;
        const HTTPS = 0b001000;
        const BIND  = 0b010000;
    }

}

impl BeaconProtocol {
    pub fn to_values(&self) -> Vec<String> {
        // iter_names is not working for some reason
        let mut flag_names: Vec<String> = Vec::new();
        bitflags_match!(*self, {
            BeaconProtocol::HTTP => flag_names.push("HTTP".to_string()),
            BeaconProtocol::DNS => flag_names.push("DNS".to_string()),
            BeaconProtocol::SMB => flag_names.push("SMB".to_string()),
            BeaconProtocol::TCP => flag_names.push("TCP".to_string()),
            BeaconProtocol::HTTPS => flag_names.push("HTTPS".to_string()),
            BeaconProtocol::BIND => flag_names.push("BIND".to_string()),
            _ => flag_names.push("Unknown".to_string()),
        });
        flag_names
    }
}
