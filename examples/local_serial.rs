use std::time::Duration;
use std::{env, io};

fn main() {
    let path = env::args().nth(1).expect("no serial port supplied");
    let mut port = serialport::new(path, 115_200)
        .timeout(Duration::from_millis(20))
        .open()
        .expect("failed to open serial port");

    let mut buf = [0; 1024];
    let mut parser = crsf::Parser::new(crsf::ParserConfig::default());
    loop {
        match port.read(buf.as_mut_slice()) {
            Ok(n @ 1..) => {
                for result in parser.iter_packets(&buf[..n]) {
                    match result {
                        Ok(crsf::Packet::LinkStatistics(link_stats)) => {
                            println!("{:?}", link_stats);
                        }
                        Ok(crsf::Packet::RcChannelsPacked(rc_channels)) => {
                            println!("{:?}", rc_channels);
                        }
                        Err(err) => {
                            println!("err: {:?}", err);
                        }
                        _ => {}
                    }
                }
            }
            Ok(0) => {
                eprintln!("EOF");
                break;
            }
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => (),
            Err(e) => {
                eprintln!("{}", e);
                break;
            }
        }
    }
}
