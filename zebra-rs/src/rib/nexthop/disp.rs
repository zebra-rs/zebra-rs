// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::fmt::{Display, Formatter, Result};

use super::{Nexthop, NexthopList, NexthopMulti, NexthopUni};

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
        write!(f, "uni {}", self.addr)?;
        if !self.segs.is_empty() {
            write!(f, " encap")?;
            if let Some(encap_type) = &self.encap_type {
                write!(f, " {}", encap_type)?;
            }
            write!(f, " segs")?;
            for seg in &self.segs {
                write!(f, " {}", seg)?;
            }
        }
        Ok(())
    }
}

impl Display for NexthopMulti {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "multi")
    }
}

impl Display for NexthopList {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "protect")
    }
}
