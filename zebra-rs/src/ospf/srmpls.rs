#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub enum SegmentRoutingMode {
    #[default]
    None,
    Mpls,
    Srv6,
}
