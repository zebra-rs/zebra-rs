use bitflags::bitflags;
use std::fmt;

bitflags! {
    #[derive(Clone)]
    pub struct AttributeFlags: u8 {
        const lOPTIONAL = 0x80;
        const TRANSITIVE = 0x40;
        const PARTIAL = 0x20;
        const EXTENDED = 0x10;
    }
}

impl AttributeFlags {
    pub fn is_extended(&self) -> bool {
        self.contains(AttributeFlags::EXTENDED)
    }
}

impl fmt::Display for AttributeFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut v: Vec<&str> = Vec::new();
        if self.contains(AttributeFlags::OPTIONAL) {
            v.push("OPTIONAL");
        }
        if self.contains(AttributeFlags::TRANSITIVE) {
            v.push("TRANSITIVE");
        }
        if self.contains(AttributeFlags::PARTIAL) {
            v.push("PARTIAL");
        }
        if self.contains(AttributeFlags::EXTENDED) {
            v.push("EXTENDED");
        }
        let v = v
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join("|");
        write!(f, "{v}")
    }
}
