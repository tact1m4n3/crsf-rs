//! This crate provides a `no-std` parser for the CRSF protocol.
//! # Usage
//! ### Packet Parsing
//! ```rust
//! use crsf::{Parser, ParserConfig, Packet, RcChannelsPacked};
//!
//! let mut parser = Parser::new(ParserConfig::default());
//! let data: &[&[u8]] = &[&[0xc8, 24, 0x16], &[0; 22], &[239]];
//! for (i, input_buf) in data.iter().enumerate() {
//!     for (j, result) in parser.iter_packets(input_buf).enumerate() {
//!         match result {
//!             Ok(Packet::RcChannelsPacked(rc_channels))=> assert_eq!(rc_channels, RcChannelsPacked([0u16; 16])),
//!             e => panic!("This data should parse succesfully: {e:?}, {i}, {j}"),
//!         }
//!     }
//! }
//! ```
//! ### Packet Serialization
//! ```rust
//! use crsf::{RcChannelsPacked, PayloadDump, MAX_PACKET_LEN};
//!
//! let channels: [u16; 16] = [1500; 16];
//! let packet = RcChannelsPacked(channels);
//!
//! let mut buf: [u8; MAX_PACKET_LEN] = [0; MAX_PACKET_LEN];
//! let len = packet.dump(&mut buf).unwrap();
//! let data = &buf[..len];
//! // ...
//! ```

#![no_std]

mod packet;
pub use packet::*;

mod parser;
pub use parser::*;

mod util;

pub const SYNC_BYTE: u8 = 0xC8;
pub const MAX_PACKET_LEN: usize = 64;

pub(crate) const CRC8: crc::Crc<u8> = crc::Crc::<u8>::new(&crc::CRC_8_DVB_S2);
