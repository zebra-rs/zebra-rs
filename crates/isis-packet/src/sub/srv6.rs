use std::fmt::{Display, Formatter, Result};

use serde::{Deserialize, Serialize};

#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub enum Behavior {
    End,
    EndX,
    Resv(u16),
}

impl From<Behavior> for u16 {
    fn from(typ: Behavior) -> Self {
        use Behavior::*;
        match typ {
            End => 1,
            EndX => 5,
            Resv(v) => v,
        }
    }
}

impl From<u16> for Behavior {
    fn from(typ: u16) -> Self {
        use Behavior::*;
        match typ {
            1 => End,
            5 => EndX,
            v => Resv(v),
        }
    }
}

impl Display for Behavior {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use Behavior::*;
        match self {
            End => write!(f, "End"),
            EndX => write!(f, "End.X"),
            Resv(v) => write!(f, "Resv({})", v),
        }
    }
}
