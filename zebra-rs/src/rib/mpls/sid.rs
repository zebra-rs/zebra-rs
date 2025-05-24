pub enum SidType {
    Prefix,
    Adjacency,
}

pub struct Sid {
    pub label: u32,
    pub typ: SidType,
    pub index: Option<u32>,
}
