use std::fmt;

#[derive(Debug, Clone)]
pub enum Action {
    Permit,
    Deny,
}

impl Action {
    pub fn from(s: &str) -> Option<Self> {
        match s {
            "permit" => Some(Action::Permit),
            "deny" => Some(Action::Deny),
            _ => None,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Permit => write!(f, "action"),
            Action::Deny => write!(f, "deny"),
        }
    }
}
