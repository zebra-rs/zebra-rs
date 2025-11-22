use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

use crate::{IsisNeighborId, IsisSysId};

#[derive(Debug, Default)]
pub struct Nsap {
    pub afi: u8,
    pub area_id: Vec<u8>,
    pub sys_id: [u8; 6],
    pub nsel: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsapParseError(());

impl fmt::Display for NsapParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid NSAP address")
    }
}

impl fmt::Display for Nsap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02x}", self.afi)?;
        for (index, id) in self.area_id.iter().enumerate() {
            if index % 2 == 0 {
                write!(f, ".")?;
            }
            write!(f, "{:02x}", id)?;
        }
        write!(
            f,
            ".{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}.{:02x}",
            self.sys_id[0],
            self.sys_id[1],
            self.sys_id[2],
            self.sys_id[3],
            self.sys_id[4],
            self.sys_id[5],
            self.nsel,
        )
    }
}

impl Nsap {
    pub fn area_id(&self) -> Vec<u8> {
        let mut area_id = self.area_id.clone();
        area_id.insert(0, self.afi);
        area_id
    }

    pub fn sys_id(&self) -> IsisSysId {
        IsisSysId {
            id: [
                self.sys_id[0],
                self.sys_id[1],
                self.sys_id[2],
                self.sys_id[3],
                self.sys_id[4],
                self.sys_id[5],
            ],
        }
    }

    pub fn neighbor_id(&self) -> IsisNeighborId {
        IsisNeighborId {
            id: [
                self.sys_id[0],
                self.sys_id[1],
                self.sys_id[2],
                self.sys_id[3],
                self.sys_id[4],
                self.sys_id[5],
                self.nsel,
            ],
        }
    }
}

impl From<ParseIntError> for NsapParseError {
    fn from(_err: ParseIntError) -> Self {
        NsapParseError(())
    }
}

impl FromStr for Nsap {
    type Err = NsapParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts: Vec<&str> = s.split('.').collect();

        // Afi(1).AreaId(1).SysId(3).NSEL(1).
        // "49.0000.0000.0000.0001.00" means 6.
        if parts.len() < 6 {
            return Err(NsapParseError(()));
        }

        for part in &parts {
            if part.len() != 2 && part.len() != 4 {
                return Err(NsapParseError(()));
            }
        }

        // Parse AFI (1 octet)
        let afi = u8::from_str_radix(parts[0], 16)?;
        parts.remove(0);

        // Parse SysId (6 octets).
        let mut sys_id = IsisSysId::default();
        let parts_len = parts.len();

        let sys_id_str = parts[parts_len - 4];
        let sys_id_val = hex::decode(sys_id_str).map_err(|_| NsapParseError(()))?;
        sys_id.id[0] = sys_id_val[0];
        sys_id.id[1] = sys_id_val[1];

        let sys_id_str = parts[parts_len - 3];
        let sys_id_val = hex::decode(sys_id_str).map_err(|_| NsapParseError(()))?;
        sys_id.id[2] = sys_id_val[0];
        sys_id.id[3] = sys_id_val[1];

        let sys_id_str = parts[parts_len - 2];
        let sys_id_val = hex::decode(sys_id_str).map_err(|_| NsapParseError(()))?;
        sys_id.id[4] = sys_id_val[0];
        sys_id.id[5] = sys_id_val[1];

        // Parse NSEL (1 octet)
        let nsel = u8::from_str_radix(parts[parts.len() - 1], 16)?;

        // Remove SysId and NSEl.
        parts.truncate(parts.len() - 4);

        // Area ID (variable length 1..13 octets).
        let mut area_id = Vec::new();
        for part in &parts {
            if part.len() == 2 {
                let area = hex::decode(part).map_err(|_| NsapParseError(()))?;
                area_id.extend(area);
            } else if part.len() == 4 {
                let area = hex::decode(part).map_err(|_| NsapParseError(()))?;
                area_id.extend(area);
            }
        }
        if area_id.is_empty() || area_id.len() > 13 {
            return Err(NsapParseError(()));
        }

        Ok(Nsap {
            afi,
            area_id,
            sys_id: sys_id.id,
            nsel,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_valid_nsap(nsap_str: &str) {
        let nsap: Nsap = nsap_str.parse().expect("Failed to parse NSAP");
        let formatted_nsap = format!("{}", nsap);
        assert_eq!(formatted_nsap, nsap_str, "NSAP formatting mismatch");
    }

    fn is_invalid_nsap(nsap_str: &str) {
        let nsap = nsap_str.parse::<Nsap>();
        assert!(
            nsap.is_err(),
            "NSAP should not be parsed because of missing NSEL"
        );
    }

    #[test]
    fn test_valid_nsap() {
        is_valid_nsap("49.0000.0000.0000.0001.00");
        is_valid_nsap("49.0011.2222.0000.0000.000a.00");
        is_valid_nsap("49.5678.0123.4567.0002.01");
        is_valid_nsap("49.5678.01.0123.4567.0002.01");
        is_valid_nsap("49.0102.0304.0506.0708.090a.0b0c.0d.0000.0000.0001.00");
    }

    #[test]
    fn tset_invalid_nsap() {
        is_invalid_nsap("49.jil");
        is_invalid_nsap("49.0000.0000.0000.0001"); // Missing NSEL.
        is_invalid_nsap("49.000000.0000.0000.0001.00"); // 3 octet item.
        is_invalid_nsap("49.0000.00010.0000.0001.01"); // 5 chracter item.
        is_invalid_nsap("49.0102.0304.0506.0708.090a.0b0c.0d0e.0000.0000.0001.00");
        // 14 octet area id.
    }
}
