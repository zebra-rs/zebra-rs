use std::fmt::{Display, Formatter, Result};

use crate::fib::FibRoute;

impl Display for FibRoute {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"FibRoute:
prefix: {}
entry:
rtype: {:?}
distance: {}
metric: {}"#,
            self.prefix, self.entry.rtype, self.entry.distance, self.entry.metric
        )
    }
}
