use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Permit,
    Deny,
}

impl TryFrom<&String> for Action {
    type Error = anyhow::Error;

    fn try_from(s: &String) -> Result<Self, Self::Error> {
        match s.as_str() {
            "permit" => Ok(Self::Permit),
            "deny" => Ok(Self::Deny),
            _ => Err(anyhow::Error::msg(format!("unknown action type {}", s))),
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
