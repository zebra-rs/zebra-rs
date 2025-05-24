use std::collections::HashMap;
use std::error::Error;
use std::fmt::Write;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use scan_fmt::scan_fmt;

#[derive(Default, Debug)]
pub(crate) struct LinkStats {
    link_name: String,
    rx_packets: u32,
    rx_bytes: u64,
    rx_errors: u32,
    rx_dropped: u32,
    rx_multicast: u32,
    rx_compressed: u32,
    rx_frame_errors: u32,
    rx_fifo_errors: u32,
    tx_packets: u32,
    tx_bytes: u64,
    tx_errors: u32,
    tx_dropped: u32,
    tx_compressed: u32,
    tx_carrier_errors: u32,
    tx_fifo_errors: u32,
    collisions: u32,
}

impl LinkStats {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn os_traffic_parse(version: i32, line: &str) -> Result<LinkStats, Box<dyn Error>> {
    let mut stats = LinkStats::new();
    if version == 3 {
        (
            stats.link_name,
            stats.rx_bytes,
            stats.rx_packets,
            stats.rx_errors,
            stats.rx_dropped,
            stats.rx_fifo_errors,
            stats.rx_frame_errors,
            stats.rx_compressed,
            stats.rx_multicast,
            stats.tx_bytes,
            stats.tx_packets,
            stats.tx_errors,
            stats.tx_dropped,
            stats.tx_fifo_errors,
            stats.collisions,
            stats.tx_carrier_errors,
            stats.tx_compressed,
        ) = scan_fmt!(
            line,
            "{}: {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
            String,
            u64,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u64,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32
        )?;
    } else if version == 2 {
        (
            stats.link_name,
            stats.rx_bytes,
            stats.rx_packets,
            stats.rx_errors,
            stats.rx_dropped,
            stats.rx_fifo_errors,
            stats.rx_frame_errors,
            stats.tx_bytes,
            stats.tx_packets,
            stats.tx_errors,
            stats.tx_dropped,
            stats.tx_fifo_errors,
            stats.collisions,
            stats.tx_carrier_errors,
        ) = scan_fmt!(
            line,
            "{}: {} {} {} {} {} {} {} {} {} {} {} {} {}",
            String,
            u64,
            u32,
            u32,
            u32,
            u32,
            u32,
            u64,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32
        )?;
    } else if version == 1 {
        (
            stats.link_name,
            stats.rx_packets,
            stats.rx_errors,
            stats.rx_dropped,
            stats.rx_fifo_errors,
            stats.rx_frame_errors,
            stats.tx_packets,
            stats.tx_errors,
            stats.tx_dropped,
            stats.tx_fifo_errors,
            stats.collisions,
            stats.tx_carrier_errors,
        ) = scan_fmt!(
            line,
            "{}: {} {} {} {} {} {} {} {} {} {} {}",
            String,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32,
            u32
        )?;
    }
    Ok(stats)
}

pub fn os_traffic_dump() -> impl Fn(&String, &mut String) {
    let mut stat_map = HashMap::new();
    if let Ok(lines) = read_lines("/proc/net/dev") {
        let mut lines = lines.map_while(Result::ok);
        if lines.next().is_some() {
            // Simply ignore first line.
        }
        let mut version = 1;
        if let Some(second) = lines.next() {
            if second.contains("compressed") {
                version = 3
            } else if second.contains("bytes") {
                version = 2;
            }
        }
        for line in lines {
            if let Ok(stats) = os_traffic_parse(version, &line) {
                stat_map.insert(stats.link_name.clone(), stats);
            }
        }
    }
    move |link_name: &String, buf: &mut String| {
        if let Some(stat) = stat_map.get(link_name) {
            writeln!(
                buf,
                "    input packets {}, bytes {}, dropped {}, multicast packets {}",
                stat.rx_packets, stat.rx_bytes, stat.rx_dropped, stat.rx_multicast
            )
            .unwrap();
            writeln!(
                buf,
                "    input errors {}, frame {}, fifo {}, compressed {}",
                stat.rx_errors, stat.rx_frame_errors, stat.rx_fifo_errors, stat.rx_compressed
            )
            .unwrap();
            writeln!(
                buf,
                "    output packets {}, bytes {}, dropped {}",
                stat.tx_packets, stat.tx_bytes, stat.tx_dropped
            )
            .unwrap();
            writeln!(
                buf,
                "    output errors {}, carrier {}, fifo {}, compressed {}",
                stat.tx_errors, stat.tx_carrier_errors, stat.tx_fifo_errors, stat.tx_compressed
            )
            .unwrap();
            writeln!(buf, "    collisions {}", stat.collisions).unwrap();
        }
    }
}
