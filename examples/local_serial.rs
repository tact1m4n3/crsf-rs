use std::{env, io, time::Duration};

use crsf::{Packet, PacketPayload, PacketReader};

fn main() {
    let path = env::args().nth(1).expect("no serial port supplied");
    let mut port = serialport::new(path, 115_200)
        .timeout(Duration::from_millis(20))
        .open()
        .expect("failed to open serial port");

    let mut buf = [0; 1024];
    let mut reader = PacketReader::new();
    loop {
        match port.read(buf.as_mut_slice()) {
            Ok(n) => {
                if n > 0 {
                    let mut remaining = &buf[..n];
                    while let (Some(raw_packet), consumed) = reader.push_bytes(remaining) {
                        match Packet::parse(raw_packet) {
                            Ok(packet) => match packet.payload {
                                PacketPayload::LinkStatistics(link_statistics) => {
                                    println!("{:?}", link_statistics);
                                }
                                PacketPayload::RcChannels(channels) => {
                                    println!("{:?}", channels);
                                }
                                _ => {}
                            },
                            Err(err) => eprintln!("{err}"),
                        };

                        remaining = &remaining[consumed..];
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => (),
            Err(e) => {
                eprintln!("{}", e);
                break;
            }
        }
    }
}
