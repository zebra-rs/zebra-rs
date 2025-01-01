use std::fmt::{Display, Formatter, Result};

use super::{Nexthop, NexthopMulti, NexthopProtect, NexthopUni};

impl Display for Nexthop {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Nexthop::Link(_) => {
                write!(f, "onlink")
            }
            Nexthop::Uni(uni) => {
                write!(f, "{}", uni)
            }
            Nexthop::Multi(multi) => {
                write!(f, "{}", multi)
            }
            Nexthop::List(pro) => {
                write!(f, "{}", pro)
            }
        }
    }
}

impl Display for NexthopUni {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "uni {}", self.addr)
    }
}

impl Display for NexthopMulti {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "multi")
    }
}

impl Display for NexthopProtect {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "protect")
    }
}
