use isis_packet::IsisSysId;

pub use crate::spf::label_block::{LabelBlock, LabelConfig, LabelMap};

pub type IsisLabelMap = LabelMap<IsisSysId>;
