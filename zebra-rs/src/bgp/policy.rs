use crate::policy::PrefixSet;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InOut {
    In,
    Out,
}

#[derive(Default, Debug)]
pub struct InOuts<T> {
    pub input: T,
    pub output: T,
}

impl<T> InOuts<T> {
    pub fn get(&self, direct: &InOut) -> &T {
        match direct {
            InOut::In => &self.input,
            InOut::Out => &self.output,
        }
    }

    pub fn get_mut(&mut self, direct: &InOut) -> &mut T {
        match direct {
            InOut::In => &mut self.input,
            InOut::Out => &mut self.output,
        }
    }
}

#[derive(Default, Debug)]
pub struct PrefixSetValue {
    pub name: Option<String>,
    pub prefix: Option<PrefixSet>,
}
