//! This crate provides a #\[no_std\] parser for the crossfire protocol.
//! # Usage
//! ### Packet Parsing
//! ```rust
//! use crsf::{Packet, PacketReader, PacketAddress, PacketType, RcChannelsPacked};
//!
//! let mut reader = PacketReader::new();
//! let data: &[&[u8]] = &[&[0xc8, 24, 0x16], &[0; 22], &[239]];
//! for (i, input_buf) in data.iter().enumerate() {
//!     for (j, result) in reader.iter_packets(input_buf).enumerate() {
//!         match result {
//!             Ok(Packet::RcChannelsPacked(rc_channels))=> assert_eq!(rc_channels, RcChannelsPacked([0u16; 16])),
//!             e => panic!("This data should parse succesfully: {e:?}, {i}, {j}"),
//!         }
//!     }
//! }
//! ```
//! ### Packet Construction
//! ```rust
//! use crsf::{PacketAddress, PacketType, RcChannelsPacked, Payload};
//!
//! let channels: [u16; 16] = [0xffff; 16];
//! let addr = PacketAddress::FlightController;
//! let payload = RcChannelsPacked(channels);
//!
//! // Import the `Payload` trait to construct a raw packet
//! let raw_packet = payload.to_raw_packet_with_sync(addr as u8).unwrap();
//! // ...
//! ```

#![no_std]

#[cfg(feature = "defmt")]
use defmt;

use snafu::prelude::*;

mod packet;
pub use packet::*;

mod reader;
pub use reader::*;

mod buffer;
mod crc8;
mod to_array;

pub const CRSF_MAX_LEN: usize = 64;
const CRSF_HEADER_LEN: usize = 2;
const CRSF_SYNC_BYTE: u8 = 0xC8;

/// Represents packet parsing errors
#[non_exhaustive]
#[derive(Debug, PartialEq, Snafu)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    #[snafu(display("No sync byte was found in the given buffer"))]
    NoSyncByte,
    #[snafu(display("Unknown type: {typ:#04x}, see PacketType enum for valid types"))]
    UnknownType { typ: u8 },
    #[snafu(display("Invalid length: {len}, should be between 2 and 62"))]
    InvalidLength { len: u8 },
    #[snafu(display("Crc checksum mismatch: expected {exp:#04x}, got {act:#04x}"))]
    CrcMismatch { exp: u8, act: u8 },
    #[snafu(display("A general buffer error relating to the parser occured"))]
    BufferError,
    #[snafu(display("Invalid payload data, could not parse packet"))]
    InvalidPayload,
}

#[cfg(test)]
mod tests {
    use crate::buffer::BytesReader;
    use crate::Error;
    use crate::LinkStatistics;
    use crate::Packet;
    use crate::PacketAddress;
    use crate::PacketReader;
    use crate::PacketType;
    use crate::Payload;
    use crate::RcChannelsPacked;

    #[test]
    fn test_bytes_reader() {
        let bytes: &[u8] = &[1, 2, 3, 4, 5];
        let mut reader = BytesReader::new(bytes);
        assert_eq!(reader.next(), Some(1));
        assert_eq!(reader.remaining(), &[2, 3, 4, 5]);
        assert_eq!(reader.next_n(2), &[2, 3]);
        assert_eq!(reader.remaining(), &[4, 5]);
        assert_eq!(reader.next(), Some(4));
        assert_eq!(reader.next(), Some(5));
        assert_eq!(reader.remaining(), &[]);
    }

    #[test]
    fn test_packet_reader_waiting_for_sync_byte() {
        let addr = PacketAddress::Handset;
        let mut reader = PacketReader::builder().sync(&[addr]).build();

        let typ = PacketType::RcChannelsPacked as u8;

        for _ in 0..2 {
            // Garbage
            assert!(matches!(
                reader.push_bytes(&[1, 2, 3]).0,
                Some(Err(Error::NoSyncByte))
            ));
            // More garbage
            assert!(matches!(
                reader.push_bytes(&[254, 255]).0,
                Some(Err(Error::NoSyncByte))
            ));
            // Sync
            assert!(reader.push_bytes(&[addr as u8]).0.is_none());
            // Len
            assert!(reader.push_bytes(&[24]).0.is_none());
            // Type
            assert!(reader.push_bytes(&[typ]).0.is_none());
            // Payload
            assert!(reader.push_bytes(&[0; 22]).0.is_none());

            // Checksum
            let result = reader.push_bytes(&[239]).0.expect("result expected");

            let raw_packet = result.expect("raw packet expected");
            let packet = raw_packet.to_packet().expect("packet expected");

            match packet {
                Packet::RcChannelsPacked(ch) => {
                    ch.0.iter().all(|&x| x == 0);
                }
                _ => panic!("unexpected packet type"),
            }
        }
    }

    #[test]
    fn test_parse_next_packet() {
        let mut reader = PacketReader::new();

        let addr = PacketAddress::FlightController;
        let typ = PacketType::RcChannelsPacked;

        // Sync
        assert!(reader.push_bytes(&[addr as u8]).0.is_none());
        // Len
        assert!(reader.push_bytes(&[24]).0.is_none());
        // Type
        assert!(reader.push_bytes(&[typ as u8]).0.is_none());
        // Payload
        assert!(reader.push_bytes(&[0; 22]).0.is_none());
        // Checksum
        let result = reader.push_bytes(&[239]).0.expect("result expected");

        let raw_packet = result.expect("raw packet expected");
        let packet = raw_packet.to_packet().expect("packet expected");

        match packet {
            Packet::RcChannelsPacked(ch) => {
                ch.0.iter().all(|&x| x == 0);
            }
            _ => panic!("unexpected packet type"),
        }
    }

    #[test]
    fn test_push_segments() {
        // similar to the doc-test at the top
        let mut reader = PacketReader::new();
        let data: &[&[u8]] = &[&[0xc8, 24, 0x16], &[0; 22], &[239]];
        for (i, input_buf) in data.iter().enumerate() {
            for (j, result) in reader.iter_packets(input_buf).enumerate() {
                match result {
                    Ok(Packet::RcChannelsPacked(rc_channels)) => {
                        assert_eq!(rc_channels, RcChannelsPacked([0u16; 16]))
                    }
                    e => panic!("This data should parse succesfully: {e:?}, {i}, {j}"),
                }
            }
        }
    }

    #[test]
    fn test_multiple_sync() {
        let mut reader = PacketReader::builder()
            .sync(&[PacketAddress::FlightController, PacketAddress::Broadcast])
            .build();

        let rc_channels1 = RcChannelsPacked([1000; 16]);
        let raw_packet1 = rc_channels1
            .to_raw_packet_with_sync(PacketAddress::FlightController as u8)
            .unwrap();

        let rc_channels2 = RcChannelsPacked([1500; 16]);
        let raw_packet2 = rc_channels2
            .to_raw_packet_with_sync(PacketAddress::Broadcast as u8)
            .unwrap();

        let rc_channels3 = RcChannelsPacked([2000; 16]); // Some other address here ---v
        let raw_packet3 = rc_channels3
            .to_raw_packet_with_sync(PacketAddress::Reserved1 as u8)
            .unwrap();

        let result1 = reader
            .push_bytes(raw_packet1.as_slice())
            .0
            .expect("result expected")
            .expect("raw packet expected");
        assert_eq!(
            result1.to_packet().expect("packet expected"),
            Packet::RcChannelsPacked(rc_channels1)
        );

        let result2 = reader
            .push_bytes(raw_packet2.as_slice())
            .0
            .expect("result expected")
            .expect("raw packet expected");
        assert_eq!(
            result2.to_packet().expect("packet expected"),
            Packet::RcChannelsPacked(rc_channels2)
        );

        let result3 = reader
            .push_bytes(raw_packet3.as_slice())
            .0
            .expect("result expected")
            .expect_err("Error expected");
        assert!(matches!(result3, Error::NoSyncByte));
    }

    #[test]
    fn test_parse_full_packet() {
        let mut reader = PacketReader::new();

        let addr = PacketAddress::FlightController;
        let typ = PacketType::RcChannelsPacked;

        let data = [
            // Sync
            addr as u8, // Len
            24,         // Type
            typ as u8,  // Payload
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Checksum
            239,
        ];

        let result = reader
            .push_bytes(data.as_slice())
            .0
            .expect("result expected");

        let raw_packet = result.expect("raw packet expected");
        let packet = raw_packet.to_packet().expect("packet expected");

        match packet {
            Packet::RcChannelsPacked(ch) => {
                ch.0.iter().all(|&x| x == 0);
            }
            _ => panic!("unexpected packet type"),
        }
    }

    #[test]
    fn test_parse_next_packet_with_validation_error() {
        let mut reader = PacketReader::new();

        let addr = PacketAddress::FlightController;

        // Sync
        assert!(reader.push_bytes(&[addr as u8]).0.is_none());
        // Len
        assert!(reader.push_bytes(&[24]).0.is_none());
        // Type
        assert!(reader
            .push_bytes(&[PacketType::RcChannelsPacked as u8])
            .0
            .is_none());
        // Payload
        assert!(reader.push_bytes(&[0; 22]).0.is_none());
        // Checksum
        let result = reader.push_bytes(&[42]).0.expect("result expected");

        assert!(matches!(
            result,
            Err(Error::CrcMismatch { act: 239, exp: 42 })
        ));
    }

    // This test does not make much sense since there is no "as_raw_packet_into_buf" method. Do we need that?
    // #[test]
    // fn test_packet_dump_in_small_buffer() {
    //     let packet = LinkStatistics {
    //         uplink_rssi_1: 16,
    //         uplink_rssi_2: 19,
    //         uplink_link_quality: 99,
    //         uplink_snr: -105,
    //         active_antenna: 1,
    //         rf_mode: 2,
    //         uplink_tx_power: 3,
    //         downlink_rssi: 8,
    //         downlink_link_quality: 88,
    //         downlink_snr: -108,
    //     };
    //     let mut buf = [0u8; 10];
    //     assert_eq!(
    //         packet.dump(&mut buf),
    //         Err(BufferLenError {
    //             expected: 14,
    //             actual: 10
    //         })
    //     );
    // }

    #[test]
    fn test_rc_channels_packet_dump() {
        let channels: [u16; 16] = [0x7FF; 16];
        let addr = PacketAddress::Transmitter;
        let packet = RcChannelsPacked(channels);

        let raw = packet.to_raw_packet_with_sync(addr as u8).unwrap();

        let mut expected_data: [u8; 26] = [0xff; 26];
        expected_data[0] = 0xee;
        expected_data[1] = 24;
        expected_data[2] = 0x16;
        expected_data[25] = 143;
        assert_eq!(&raw.as_slice(), &expected_data)
    }

    #[test]
    fn test_link_statistics_packet_dump() {
        let addr = PacketAddress::FlightController;

        let packet = LinkStatistics {
            uplink_rssi_1: 16,
            uplink_rssi_2: 19,
            uplink_link_quality: 99,
            uplink_snr: -105,
            active_antenna: 1,
            rf_mode: 2,
            uplink_tx_power: 3,
            downlink_rssi: 8,
            downlink_link_quality: 88,
            downlink_snr: -108,
        };

        let raw = packet.to_raw_packet_with_sync(addr as u8).unwrap();

        let expected_data = [0xc8, 12, 0x14, 16, 19, 99, 151, 1, 2, 3, 8, 88, 148, 252];
        assert_eq!(raw.as_slice(), expected_data.as_slice())
    }
}
