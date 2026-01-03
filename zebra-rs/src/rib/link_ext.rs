use netlink_packet_route::link::LinkFlags;

pub trait LinkFlagsExt {
    fn is_p2p(&self) -> bool;
    fn is_up(&self) -> bool;
    fn is_admin_up(&self) -> bool;
    fn is_lower_up(&self) -> bool;
    fn is_loopback(&self) -> bool;
}

impl LinkFlagsExt for LinkFlags {
    fn is_up(&self) -> bool {
        self.is_admin_up() && self.is_lower_up()
    }

    fn is_admin_up(&self) -> bool {
        (*self & LinkFlags::Up) == LinkFlags::Up
    }

    fn is_lower_up(&self) -> bool {
        (*self & LinkFlags::LowerUp) == LinkFlags::LowerUp
    }

    fn is_loopback(&self) -> bool {
        (*self & LinkFlags::Loopback) == LinkFlags::Loopback
    }

    fn is_p2p(&self) -> bool {
        (*self & LinkFlags::Pointopoint) == LinkFlags::Pointopoint
    }
}
