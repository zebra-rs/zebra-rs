use nom_derive::NomBE;
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Debug, Default, NomBE)]
pub struct LargeCommunity(pub Vec<LargeCommunityValue>);

impl LargeCommunity {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn push(&mut self, value: LargeCommunityValue) {
        self.0.push(value)
    }

    pub fn sort_uniq(&mut self) {
        let coms: BTreeSet<LargeCommunityValue> = self.0.iter().cloned().collect();
        self.0 = coms.into_iter().collect();
    }
}

impl fmt::Display for LargeCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let val = self
            .0
            .iter()
            .map(|x| x.to_str())
            .collect::<Vec<String>>()
            .join(" ");
        write!(f, "{val}")
    }
}

impl FromStr for LargeCommunity {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let com_strs: Vec<&str> = s.split(' ').collect();
        if com_strs.is_empty() {
            return Err(());
        }

        let mut coms = LargeCommunity::new();

        for s in com_strs.iter() {
            match LargeCommunityValue::from_str(s) {
                Some(c) => coms.push(c),
                None => return Err(()),
            }
        }
        coms.sort_uniq();
        Ok(coms)
    }
}

#[derive(Clone, Default, Debug, NomBE, PartialEq, Eq, PartialOrd, Ord)]
pub struct LargeCommunityValue {
    pub global: u32,
    pub local1: u32,
    pub local2: u32,
}

impl LargeCommunityValue {
    pub fn to_str(&self) -> String {
        format!("{}:{}:{}", self.global, self.local1, self.local2)
    }

    fn from_str(s: &str) -> Option<Self> {
        let com_strs: Vec<&str> = s.split(':').collect();
        if com_strs.len() == 3 {
            if let Ok(global) = com_strs[0].parse::<u32>() {
                if let Ok(local1) = com_strs[1].parse::<u32>() {
                    if let Ok(local2) = com_strs[2].parse::<u32>() {
                        return Some(Self {
                            global,
                            local1,
                            local2,
                        });
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn from_str() {
        let com = LargeCommunity::from_str("65538:655900:14560 100:102:103").unwrap();
        assert_eq!(format!("{}", com), "100:102:103 65538:655900:14560");

        let com = LargeCommunity::from_str("65538:655900 100:102:103");
        assert_eq!(com, None);
    }
}
