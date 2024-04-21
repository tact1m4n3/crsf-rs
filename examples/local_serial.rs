use std::{env, fmt::write, io, time::Duration};

use crsf::{Packet, PacketReader};

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
                    let mut remaining = reader.push_bytes(&buf[..n]);
                    loop {
                        match reader.parse_packet() {
                            Some(Ok((_, packet))) => match packet {
                                Packet::LinkStatistics(link_statistics) => {
                                    println!("{:?}", link_statistics);
                                }
                                Packet::RcChannels(channels) => {
                                    println!("{:?}", channels);
                                }
                                _ => {}
                            },
                            Some(Err(err)) => eprintln!("{err}"),
                            None => break,
                        };
                        remaining = reader.push_bytes(remaining);
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
