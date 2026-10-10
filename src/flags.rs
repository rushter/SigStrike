use bitflags::bitflags;

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
    pub fn to_values(self) -> Vec<String> {
        // HTTP is the zero-valued flag, so iter_names yields nothing for it.
        if self == BeaconProtocol::HTTP {
            return vec!["HTTP".to_string()];
        }

        let names: Vec<String> = self
            .iter_names()
            .map(|(name, _)| name.to_string())
            .collect();

        if names.is_empty() {
            vec!["Unknown".to_string()]
        } else {
            names
        }
    }
}
