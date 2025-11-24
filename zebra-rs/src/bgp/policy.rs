use crate::policy::{PolicyList, PrefixSet};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InOut {
    Input,
    Output,
}

#[derive(Default, Debug)]
pub struct InOuts<T> {
    pub input: T,
    pub output: T,
}

impl<T> InOuts<T> {
    pub fn get(&self, direct: &InOut) -> &T {
        match direct {
            InOut::Input => &self.input,
            InOut::Output => &self.output,
        }
    }

    pub fn get_mut(&mut self, direct: &InOut) -> &mut T {
        match direct {
            InOut::Input => &mut self.input,
            InOut::Output => &mut self.output,
        }
    }
}

#[derive(Default, Debug)]
pub struct PrefixSetValue {
    pub name: Option<String>,
    pub prefix_set: Option<PrefixSet>,
}

#[derive(Default, Debug)]
pub struct PolicyListValue {
    pub name: Option<String>,
    pub policy_list: Option<PolicyList>,
}
