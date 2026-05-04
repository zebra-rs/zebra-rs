use std::fmt;

pub struct DisplayOpt<'a, T>(pub &'a Option<T>);

impl<T: fmt::Display> fmt::Display for DisplayOpt<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(v) => v.fmt(f),
            None => f.write_str("N/A"),
        }
    }
}
