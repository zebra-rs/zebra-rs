use std::fmt;

#[derive(Debug, Clone, Copy)]
pub enum Level {
    L1,
    L2,
}

impl Level {
    pub fn digit(&self) -> u8 {
        match self {
            Level::L1 => 1,
            Level::L2 => 2,
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Level::L1 => write!(f, "L1"),
            Level::L2 => write!(f, "L2"),
        }
    }
}

#[derive(Default, Debug)]
pub struct Levels<T> {
    pub l1: T,
    pub l2: T,
}

impl<T> Levels<T> {
    pub fn get(&self, level: &Level) -> &T {
        match level {
            Level::L1 => &self.l1,
            Level::L2 => &self.l2,
        }
    }

    pub fn get_mut(&mut self, level: &Level) -> &mut T {
        match level {
            Level::L1 => &mut self.l1,
            Level::L2 => &mut self.l2,
        }
    }
}

#[derive(Debug)]
pub enum IsLevel {
    L1,
    L2,
    L1L2,
}

impl fmt::Display for IsLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IsLevel::L1 => write!(f, "L1"),
            IsLevel::L2 => write!(f, "L2"),
            IsLevel::L1L2 => write!(f, "L1L2"),
        }
    }
}
