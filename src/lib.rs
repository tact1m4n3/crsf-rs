//! This crate provides a #\[no_std\] parser for the crossfire protocol.
//! # Usage
//! ### Packet Parsing
//! ```rust
//! use crsf::{PacketReader, PacketAddress, PacketType};
//!
//! let mut reader = PacketReader::new();
//!
//! let addr = PacketAddress::Controller;
//! let typ = PacketType::RcChannelsPacked;
//! ```
//! ### Packet Construction
//! ```rust
//! use crsf::{Packet, RcChannels, PacketAddress};
//!
//! let addr = PacketAddress::Controller;
//! let channels: [u16; 16] = [0xffff; 16];
//! let packet = Packet::RcChannels(RcChannels(channels));
//!
//! let mut buf = [0u8; Packet::MAX_LENGTH];
//! let len = packet.dump(&mut buf, addr);
//!
//! // ...
//! ```

#![no_std]

// TODO: top level crate packet reader examples redo

use crc::{Crc, CRC_8_DVB_S2};
#[cfg(feature = "defmt")]
use defmt;
use num_enum::TryFromPrimitive;
use snafu::prelude::*;

/// Used to calculate the CRC8 checksum
#[link_section = ".data"]
static CRC8: Crc<u8> = Crc::<u8>::new(&CRC_8_DVB_S2);

pub use packets::*;

mod packets;
mod to_array;

/// Represents a packet reader
pub struct PacketReader {
    buf: [u8; Packet::MAX_LENGTH],
    state: ReadState,
}

impl PacketReader {
    // Packet type and checksum bytes are mandatory
    const MIN_DATA_LENGTH: u8 = 2;
    // Number of bytes of packet type, payload and checksum
    const MAX_DATA_LENGTH: u8 = Packet::MAX_LENGTH as u8 - Self::MIN_DATA_LENGTH;

    /// Creates a new PacketReader struct
    pub const fn new() -> Self {
        Self {
            buf: [0; Packet::MAX_LENGTH],
            state: ReadState::WaitingForSync,
        }
    }

    /// Reads the first packet from the buffer
    pub fn push_bytes(&mut self, bytes: &[u8]) -> (Option<RawPacket>, usize) {
        let mut reader = BytesReader::new(bytes);
        let packet = loop {
            match self.state {
                ReadState::WaitingForSync => {
                    while let Some(addr_byte) = reader.next() {
                        if PacketAddress::try_from(addr_byte).is_ok() {
                            self.buf[0] = addr_byte;
                            self.state = ReadState::WaitingForLen;
                            break;
                        }
                    }
                    continue;
                }
                ReadState::WaitingForLen => {
                    if let Some(len_byte) = reader.next() {
                        match len_byte {
                            Self::MIN_DATA_LENGTH..=Self::MAX_DATA_LENGTH => {
                                self.buf[1] = len_byte;
                                self.state = ReadState::Reading {
                                    idx: Packet::HEADER_LENGTH,
                                    len: Packet::HEADER_LENGTH + len_byte as usize,
                                };
                            }
                            _ => self.state = ReadState::WaitingForSync,
                        }
                        continue;
                    }
                }
                ReadState::Reading { ref mut idx, len } => {
                    let data = reader.next_n(len - *idx);
                    self.buf[*idx..*idx + data.len()].copy_from_slice(data);
                    *idx += data.len();
                    if *idx >= len {
                        self.state = ReadState::WaitingForSync;
                        break Some(
                            RawPacket {
                                buf: &self.buf,
                                len,
                            }
                        );
                    }
                }
            }

            break None;
        };

        (packet, reader.consumed())
    }
}

/// Represents a raw packet (not parsed)
#[derive(Clone, Copy, Debug)]
pub struct RawPacket<'a> {
    buf: &'a [u8; Packet::MAX_LENGTH],
    len: usize,
}

impl<'a> RawPacket<'a> {
    /// Returns the packet data as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    // TODO: maybe add methods for getting the addr etc
}

/// Represents a parsed packet
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Packet {
    LinkStatistics(LinkStatistics),
    RcChannels(RcChannels),
}

impl Packet {
    /// Max crsf packet length
    pub const MAX_LENGTH: usize = 64;
    /// Crsf packet header length
    pub const HEADER_LENGTH: usize = 2;

    /// Parses a raw packet (returned by the packet reader)
    pub fn parse(raw_packet: RawPacket) -> Result<Packet, ParseError> {
        // TODO: use more constants instead of literals

        // not using raw_packet.as_slice() for the compiler to remove out of bounds checking
        let buf = raw_packet.buf;
        let len = raw_packet.len;

        let checksum_idx = len - 1;
        let checksum = CRC8.checksum(&buf[2..checksum_idx]);
        if checksum != buf[checksum_idx] {
            return Err(ParseError::ChecksumMismatch {
                expected: checksum,
                actual: buf[checksum_idx],
            });
        }

        let typ_byte = buf[2];
        if let Ok(typ) = PacketType::try_from(typ_byte) {
            let payload_data = if typ.is_extended() {
                &buf[5..len]
            } else {
                &buf[3..len]
            };

            match typ {
                PacketType::RcChannelsPacked => {
                    Ok(Packet::RcChannels(RcChannels::parse(payload_data)))
                }
                PacketType::LinkStatistics => {
                    Ok(Packet::LinkStatistics(LinkStatistics::parse(payload_data)))
                }
                _ => Err(ParseError::UnknownType { typ: typ_byte }),
            }
        } else {
            Err(ParseError::InvalidType { typ: typ_byte })
        }
    }

    /// Dumps the packet into a buffer
    pub fn dump(&self, buf: &mut [u8], addr: PacketAddress) -> Result<usize, BufferLenError> {
        // TODO: use more constants instead of literals

        let payload = match self {
            Packet::LinkStatistics(payload) => payload as &dyn Payload,
            Packet::RcChannels(payload) => payload as &dyn Payload,
        };

        let typ = payload.packet_type();
        let len_byte = payload.len() + if typ.is_extended() { 4 } else { 2 };
        let len = Packet::HEADER_LENGTH + len_byte as usize;

        if buf.len() < len {
            return Err(BufferLenError {
                expected: len,
                actual: buf.len(),
            });
        }

        buf[0] = addr as u8;
        buf[1] = len_byte;
        buf[2] = typ as u8;

        let payload_start = if typ.is_extended() { 5 } else { 3 };
        let checksum_idx = len - 1;
        payload.dump(&mut buf[payload_start..checksum_idx]);
        buf[checksum_idx] = CRC8.checksum(&buf[2..checksum_idx]);

        Ok(len)
    }
}

/// Represents packet parsing errors
#[non_exhaustive]
#[derive(Debug, PartialEq, Snafu)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ParseError {
    #[snafu(display("Unknown type: {typ:#04x}"))]
    UnknownType { typ: u8 },
    #[snafu(display("Invalid type: {typ:#04x}"))]
    InvalidType { typ: u8 },
    #[snafu(display("Checksum mismatch: expected {expected:#04x}, but got {actual:#04x}"))]
    ChecksumMismatch { expected: u8, actual: u8 },
}

/// Represents a buffer too small error
#[derive(Debug, PartialEq, Snafu)]
#[snafu(display(
    "Dump buffer too small: expected len of at least {expected} bytes, but got {actual} bytes"
))]
pub struct BufferLenError {
    expected: usize,
    actual: usize,
}

/// Represents all CRSF packet addresses
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum PacketAddress {
    Transmitter = 0xEE,
    Handset = 0xEA,
    Controller = 0xC8,
    Receiver = 0xEC,
}

/// Represents all CRSF packet types
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum PacketType {
    Gps = 0x02,
    Vario = 0x07,
    BatterySensor = 0x08,
    BaroAltitude = 0x09,
    LinkStatistics = 0x14,
    OpenTxSync = 0x10,
    RadioId = 0x3A,
    RcChannelsPacked = 0x16,
    Altitude = 0x1E,
    FlightMode = 0x21,
    DevicePing = 0x28,
    DeviceInfo = 0x29,
    ParameterSettingsEntry = 0x2B,
    ParameterRead = 0x2C,
    ParameterWrite = 0x2D,
    Command = 0x32,
    KissRequest = 0x78,
    KissResponse = 0x79,
    MspRequest = 0x7A,
    MspResponse = 0x7B,
    MspWrite = 0x7C,
    ArdupilotResponse = 0x80,
}

impl PacketType {
    pub fn is_extended(self) -> bool {
        self as u8 >= 0x28
    }
}

/// Represents a state machine for reading a CRSF packet
///
/// +---------------+   +---------------+   +---------+
/// | WatingForSync |-->| WaitingForLen |-->| Reading |
/// +---------------+   +---------------+   +---------+
///         ^                   |                |
///         |                   |                |
///         +-------------------+                |
///         +------------------------------------+
///
enum ReadState {
    WaitingForSync,
    WaitingForLen,
    Reading { idx: usize, len: usize },
}

struct BytesReader<'a> {
    buf: &'a [u8],
    idx: usize,
}

impl<'a> BytesReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, idx: 0 }
    }

    fn consumed(&self) -> usize {
        self.idx
    }

    fn next(&mut self) -> Option<u8> {
        if self.idx < self.buf.len() {
            let val = self.buf[self.idx];
            self.idx += 1;
            Some(val)
        } else {
            None
        }
    }

    fn next_n(&mut self, n: usize) -> &[u8] {
        let end_idx = (self.idx + n).min(self.buf.len());
        let data = &self.buf[self.idx..end_idx];
        self.idx = end_idx;
        data
    }
}

#[cfg(test)]
mod tests {
    use crate::BufferLenError;
    use crate::BytesReader;
    use crate::LinkStatistics;
    use crate::Packet;
    use crate::PacketAddress;

    use super::PacketReader;
    use super::PacketType;
    use super::ParseError;
    use super::RcChannels;

    #[test]
    fn test_bytes_reader() {
        let bytes: &[u8] = &[1, 2, 3, 4, 5];
        let mut reader = BytesReader::new(bytes);
        assert_eq!(reader.next(), Some(1));
        assert_eq!(reader.consumed(), 1);
        assert_eq!(reader.next_n(2), &[2, 3]);
        assert_eq!(reader.next(), Some(4));
        assert_eq!(reader.next(), Some(5));
        assert_eq!(reader.consumed(), 5);
    }

    #[test]
    fn test_parse_next_packet() {
        let mut reader = PacketReader::new();

        let addr = PacketAddress::Controller;
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
        assert!(matches!(
            reader.push_bytes(&[239]).0.map(|raw_packet| Packet::parse(raw_packet)).expect("packet expected"),
            Ok(Packet::RcChannels(RcChannels(channels))) if channels == [0; 16]
        ));
    }

    #[test]
    fn test_parse_full_packet() {
        let mut reader = PacketReader::new();

        let addr = PacketAddress::Controller;
        let typ = PacketType::RcChannelsPacked;

        let data = [
            // Sync
            addr as u8,
            // Len
            24,
            // Type
            typ as u8,
            // Payload
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // Checksum
            239,
        ];
        assert!(matches!(
            reader.push_bytes(&data).0.map(|raw_packet| Packet::parse(raw_packet)).expect("packet expected"),
            Ok(Packet::RcChannels(RcChannels(channels))) if channels == [0; 16]
        ));
    }
    #[test]
    fn test_parse_next_packet_with_validation_error() {
        let mut reader = PacketReader::new();

        let addr = PacketAddress::Controller;

        // Sync
        reader.push_bytes(&[addr as u8]);
        // Len
        reader.push_bytes(&[24]);
        // Type
        reader.push_bytes(&[PacketType::RcChannelsPacked as u8]);
        // Payload
        reader.push_bytes(&[0; 22]);
        // Checksum
        assert!(matches!(
            reader
                .push_bytes(&[42])
                .0
                .map(|raw_packet| Packet::parse(raw_packet))
                .expect("packet error expected"),
            Err(ParseError::ChecksumMismatch {
                expected: 239,
                actual: 42,
            }),
        ));
    }

    #[test]
    fn test_packet_dump_in_small_buffer() {
        let packet = Packet::LinkStatistics(LinkStatistics {
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
        });

        let mut buf = [0u8; 10];
        assert_eq!(
            packet.dump(&mut buf, PacketAddress::Controller),
            Err(BufferLenError {
                expected: 14,
                actual: 10
            })
        );
    }

    #[test]
    fn test_rc_channels_packet_dump() {
        let channels: [u16; 16] = [0x7FF; 16];
        let packet = Packet::RcChannels(RcChannels(channels));

        let mut buf = [0u8; Packet::MAX_LENGTH];
        let len = packet.dump(&mut buf, PacketAddress::Transmitter).unwrap();
        let mut expected_data: [u8; 26] = [0xff; 26];
        expected_data[0] = 0xee;
        expected_data[1] = 24;
        expected_data[2] = 0x16;
        expected_data[25] = 143;
        assert_eq!(&buf[..len], &expected_data)
    }

    #[test]
    fn test_link_statistics_packet_dump() {
        let packet = Packet::LinkStatistics(LinkStatistics {
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
        });

        let mut buf = [0u8; Packet::MAX_LENGTH];
        let len = packet.dump(&mut buf, PacketAddress::Controller).unwrap();
        let expected_data = [0xc8, 12, 0x14, 16, 19, 99, 151, 1, 2, 3, 8, 88, 148, 252];
        assert_eq!(&buf[..len], &expected_data)
    }
}
