// Defined in /usr/include/linux/if_link.h
#[repr(u8)]
#[derive(Debug, Clone)]
pub enum AddrGenMode {
    Eui64,
    None,
    StableSecret,
    Random,
}

impl From<AddrGenMode> for u8 {
    fn from(mode: AddrGenMode) -> Self {
        match mode {
            AddrGenMode::Eui64 => 0,
            AddrGenMode::None => 1,
            AddrGenMode::StableSecret => 2,
            AddrGenMode::Random => 3,
        }
    }
}
