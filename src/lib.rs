//! This crate provides a #\[no_std\] parser for the crossfire protocol.
//! # Usage
//! ### Packet Parsing
//! ```rust
//! use crsf::{Config, Packet, PacketReader, PacketAddress, PacketType, RcChannelsPacked};
//!
//! let mut reader = PacketReader::new(Config::default());
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
//! use crsf::{PacketAddress, PacketType, RcChannelsPacked, Payload, CRSF_SYNC_BYTE};
//!
//! let channels: [u16; 16] = [0xffff; 16];
//! let payload = RcChannelsPacked(channels);
//!
//! // Import the `Payload` trait to construct a raw packet
//! let raw_packet = payload.to_raw_packet().unwrap();
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
pub const CRSF_SYNC_BYTE: u8 = 0xC8;
const CRSF_HEADER_LEN: usize = 2;

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
