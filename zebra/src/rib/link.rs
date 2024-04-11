use super::os::message::OsLink;
use super::Rib;
use std::fmt::Write;
use tokio::sync::mpsc;

#[derive(Default, Debug)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub metric: u32,
}

#[derive(Default, Debug)]
pub struct LinkAddr {
    pub index: u32,
    pub secondary: bool,
}

impl Link {
    pub fn from(link: OsLink) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            metric: 1,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct LinkFlags {
    flags: u32,
}

// Interface lo
//   Hardware is Loopback
//   index 1 metric 1 mtu 65536
//   <UP,LOOPBACK>
//   VRF Binding: Not bound
//   Label switching is disabled
//   inet 127.0.0.1/8
//   inet6 ::1/128
//     input packets 966104480, bytes 1341696908979, dropped 0, multicast packets 0
//     input errors 0, length 0, overrun 0, CRC 0, frame 0, fifo 0, missed 0
//     output packets 966104480, bytes 229085764596, dropped 0
//     output errors 0, aborted 0, carrier 0, fifo 0, heartbeat 0, window 0
//     collisions 0
// Interface eth0
//   Hardware is Ethernet, address is 02:bd:18:c5:e1:14
//   index 2 metric 1 mtu 1500
//   <UP,BROADCAST,MULTICAST>
//   VRF Binding: Not bound
//   Label switching is disabled
//   inet 172.31.17.11/20
//   inet6 fe80::bd:18ff:fec5:e114/64
//     input packets 952254372, bytes 702873607754, dropped 6554, multicast packets 0
//     input errors 0, length 0, overrun 0, CRC 0, frame 0, fifo 0, missed 0
//     output packets 1482872126, bytes 125318461158, dropped 0
//     output errors 0, aborted 0, carrier 0, fifo 0, heartbeat 0, window 0
//     collisions 0

impl Rib {
    pub async fn link_show(&self, resp: mpsc::Sender<String>) {
        let mut buffer = String::new();
        for (_, link) in self.links.iter() {
            write!(&mut buffer, "Interface: {}\n", link.name).unwrap();
            write!(
                &mut buffer,
                "  index {} metric {} mtu {}\n",
                link.index, link.metric, link.mtu
            )
            .unwrap();
        }
        resp.send(buffer).await.unwrap();
    }
}
