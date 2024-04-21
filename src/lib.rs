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
//!
//! // Sync
//! reader.push_bytes(&[addr as u8]);
//! assert!(reader.parse_packet().is_none());
//! // Len
//! reader.push_bytes(&[24]);
//! assert!(reader.parse_packet().is_none());
//! // Type
//! reader.push_bytes(&[typ as u8]);
//! assert!(reader.parse_packet().is_none());
//! // Payload
//! reader.push_bytes(&[0; 22]);
//! assert!(reader.parse_packet().is_none());
//! // Checksum
//! reader.push_bytes(&[239]);
//!
//! match reader.parse_packet() {
//!     Some(Ok((addr, packet))) => {
//!         // ...
//!     }
//!     Some(Err(e)) => panic!("Packet expected instead of an error: {}", e),
//!     None => panic!("Packet expected"),
//! }
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

use crc::{Crc, CRC_8_DVB_S2};
#[cfg(feature = "defmt")]
use defmt;
use snafu::prelude::*;

pub use packets::*;

mod packets;

/// Reads crsf packets from a buffer (the only way to parse packets)
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

    /// Resets the current state
    pub fn reset(&mut self) {
        self.state = ReadState::WaitingForSync;
    }

    /// Pushes the given bytes into the buffer
    pub fn push_bytes<'a>(&mut self, bytes: &'a [u8]) -> &'a [u8] {
        if matches!(self.state, ReadState::ReadyForParsing { .. }) {
            self.reset();
        }

        let mut reader = BytesReader::new(bytes);
        while !reader.is_empty() {
            match self.state {
                ReadState::WaitingForSync => {
                    while let Some(addr_byte) = reader.next() {
                        if let Some(addr) = PacketAddress::from_u8(addr_byte) {
                            self.buf[0] = addr_byte;
                            self.state = ReadState::WaitingForLen { addr };
                            break;
                        }
                    }
                }
                ReadState::WaitingForLen { addr } => {
                    if let Some(len_byte) = reader.next() {
                        // idk if we should make an error for this
                        match len_byte {
                            Self::MIN_DATA_LENGTH..=Self::MAX_DATA_LENGTH => {
                                self.buf[1] = len_byte;
                                self.state = ReadState::Reading {
                                    addr,
                                    idx: Packet::HEADER_LENGTH,
                                    len: Packet::HEADER_LENGTH + len_byte as usize,
                                };
                            }
                            _ => self.reset(),
                        }
                    }
                }
                ReadState::Reading { addr, mut idx, len } => {
                    while idx < len {
                        if let Some(val) = reader.next() {
                            self.buf[idx] = val;
                            idx += 1;
                        } else {
                            break;
                        }
                    }

                    if idx < len {
                        self.state = ReadState::Reading { addr, idx, len };
                        break;
                    } else {
                        self.state = ReadState::ReadyForParsing { addr, len };
                    }
                }
                ReadState::ReadyForParsing { .. } => break,
            }
        }

        reader.remaining()
    }

    /// Returns the raw data of the current packet if available
    pub fn raw_packet_data(&self) -> Option<&[u8]> {
        if let ReadState::ReadyForParsing { len, .. } = self.state {
            Some(&self.buf[..len])
        } else {
            None
        }
    }

    /// Parses the current packet if available and returns it
    pub fn parse_packet(&self) -> Option<Result<(PacketAddress, Packet), PacketError>> {
        if let ReadState::ReadyForParsing { addr, len } = self.state {
            Some(Packet::parse(&self.buf[..len]).map(|packet| (addr, packet)))
        } else {
            None
        }
    }
}

/// Represents different kinds of packets
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

    /// Creates a raw packet from a packet
    pub fn dump(&self, buf: &mut [u8; Packet::MAX_LENGTH], addr: PacketAddress) -> usize {
        buf[0] = addr as u8;

        let payload = match self {
            Packet::LinkStatistics(payload) => payload as &dyn Payload,
            Packet::RcChannels(payload) => payload as &dyn Payload,
        };

        let len_byte = payload.len() + 2;
        let len = Packet::HEADER_LENGTH + len_byte as usize;
        buf[1] = len_byte;

        buf[2] = payload.packet_type() as u8;

        payload.dump(&mut buf[3..]);

        let checksum_idx = len - 1;
        buf[checksum_idx] = Self::calculate_checksum(&buf[2..checksum_idx]);

        len
    }

    fn parse(buf: &[u8]) -> Result<Packet, PacketError> {
        let checksum_idx = buf.len() - 1;
        let checksum = Self::calculate_checksum(&buf[2..checksum_idx]);
        if checksum != buf[checksum_idx] {
            return Err(PacketError::ChecksumMismatch {
                expected: checksum,
                actual: buf[checksum_idx],
            });
        }

        let raw_type = buf[2];
        let payload_data = &buf[3..];
        let packet = match PacketType::from_u8(raw_type) {
            Some(PacketType::RcChannelsPacked) => {
                Packet::RcChannels(RcChannels::parse(payload_data))
            }
            Some(PacketType::LinkStatistics) => {
                Packet::LinkStatistics(LinkStatistics::parse(payload_data))
            }
            _ => return Err(PacketError::UnknownType { typ: raw_type }),
        };

        Ok(packet)
    }

    fn calculate_checksum(data: &[u8]) -> u8 {
        let crc8_alg = Crc::<u8>::new(&CRC_8_DVB_S2);
        crc8_alg.checksum(data)
    }
}

/// Represents packet errors
#[non_exhaustive]
#[derive(Debug, PartialEq, Snafu)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PacketError {
    #[snafu(display("Invalid length: {len}"))]
    InvalidLength { len: u8 },
    #[snafu(display("Unknown type: {typ:#04x}"))]
    UnknownType { typ: u8 },
    #[snafu(display("Checksum mismatch: expected {expected:#04x} but was {actual:#04x}"))]
    ChecksumMismatch { expected: u8, actual: u8 },
}

/// Represents packet addresses
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketAddress {
    Transmitter = 0xEE,
    Handset = 0xEA,
    Controller = 0xC8,
    Receiver = 0xEC,
}

impl PacketAddress {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0xEE => Some(PacketAddress::Transmitter),
            0xEA => Some(PacketAddress::Handset),
            0xC8 => Some(PacketAddress::Controller),
            0xEC => Some(PacketAddress::Receiver),
            _ => None,
        }
    }
}

/// Crossfire packet types
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x02 => Some(PacketType::Gps),
            0x07 => Some(PacketType::Vario),
            0x08 => Some(PacketType::BatterySensor),
            0x09 => Some(PacketType::BaroAltitude),
            0x14 => Some(PacketType::LinkStatistics),
            0x10 => Some(PacketType::OpenTxSync),
            0x3A => Some(PacketType::RadioId),
            0x16 => Some(PacketType::RcChannelsPacked),
            0x1E => Some(PacketType::Altitude),
            0x21 => Some(PacketType::FlightMode),
            0x28 => Some(PacketType::DevicePing),
            0x29 => Some(PacketType::DeviceInfo),
            0x2B => Some(PacketType::ParameterSettingsEntry),
            0x2C => Some(PacketType::ParameterRead),
            0x2D => Some(PacketType::ParameterWrite),
            0x32 => Some(PacketType::Command),
            0x78 => Some(PacketType::KissRequest),
            0x79 => Some(PacketType::KissResponse),
            0x7A => Some(PacketType::MspRequest),
            0x7B => Some(PacketType::MspResponse),
            0x7C => Some(PacketType::MspWrite),
            0x80 => Some(PacketType::ArdupilotResponse),
            _ => None,
        }
    }
}

enum ReadState {
    WaitingForSync,
    WaitingForLen {
        addr: PacketAddress,
    },
    Reading {
        addr: PacketAddress,
        idx: usize,
        len: usize,
    },
    ReadyForParsing {
        addr: PacketAddress,
        len: usize,
    },
}

struct BytesReader<'a> {
    buf: &'a [u8],
    idx: usize,
}

impl<'a> BytesReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, idx: 0 }
    }

    fn is_empty(&self) -> bool {
        self.idx >= self.buf.len()
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

    fn remaining(&self) -> &'a [u8] {
        &self.buf[self.idx..]
    }
}

#[cfg(test)]
mod tests {
    use crate::BytesReader;
    use crate::LinkStatistics;
    use crate::Packet;
    use crate::PacketAddress;

    use super::PacketError;
    use super::PacketReader;
    use super::PacketType;
    use super::RcChannels;

    #[test]
    fn test_bytes_reader() {
        let bytes: &[u8] = &[1, 2, 3, 4, 5];
        let mut reader = BytesReader::new(bytes);
        assert_eq!(reader.next(), Some(1));
        assert_eq!(reader.remaining(), &[2, 3, 4, 5]);
        assert_eq!(reader.next(), Some(2));
        assert_eq!(reader.next(), Some(3));
        assert_eq!(reader.next(), Some(4));
        assert_eq!(reader.next(), Some(5));
        assert_eq!(reader.remaining(), &[]);
    }

    #[test]
    fn test_parse_next_packet() {
        let mut reader = PacketReader::new();

        let addr = PacketAddress::Controller;
        let typ = PacketType::RcChannelsPacked;

        // Sync
        reader.push_bytes(&[addr as u8]);
        assert!(reader.parse_packet().is_none());
        // Len
        reader.push_bytes(&[24]);
        assert!(reader.parse_packet().is_none());
        // Type
        reader.push_bytes(&[typ as u8]);
        assert!(reader.parse_packet().is_none());
        // Payload
        reader.push_bytes(&[0; 22]);
        assert!(reader.parse_packet().is_none());
        // Checksum
        reader.push_bytes(&[239]);

        match reader.parse_packet() {
            None => panic!("Packet expected"),
            Some(Ok((_, packet))) => {
                if let Packet::RcChannels(RcChannels(channels)) = packet {
                    assert_eq!(channels, [0; 16]);
                } else {
                    panic!("Packet was supposed to be of type rc channels");
                }
            }
            Some(Err(e)) => panic!("Packet expected instead of an error: {}", e),
        }
    }

    #[test]
    fn test_parse_next_packet_with_validation_error() {
        let mut parser = PacketReader::new();

        let addr = PacketAddress::Controller;

        // Sync
        parser.push_bytes(&[addr as u8]);
        // Len
        parser.push_bytes(&[24]);
        // Type
        parser.push_bytes(&[PacketType::RcChannelsPacked as u8]);
        // Payload
        parser.push_bytes(&[0; 22]);
        // Checksum
        parser.push_bytes(&[42]);

        match parser.parse_packet() {
            None | Some(Ok(_)) => panic!("Validation error expected"),
            Some(Err(e)) => {
                assert_eq!(
                    e,
                    PacketError::ChecksumMismatch {
                        expected: 239,
                        actual: 42
                    }
                )
            }
        }
    }

    #[test]
    fn test_packet_construction() {
        let addr = PacketAddress::Controller;

        let channels: [u16; 16] = [0; 16];
        let packet = Packet::RcChannels(RcChannels(channels));

        let mut buf = [0u8; Packet::MAX_LENGTH];
        let len = packet.dump(&mut buf, addr);

        let mut reader = PacketReader::new();
        reader.push_bytes(&buf[..len]);

        let (_, packet2) = reader.parse_packet().unwrap().unwrap();
        if let Packet::RcChannels(RcChannels(channels2)) = packet2 {
            assert_eq!(channels, channels2);
        } else {
            panic!("Wrong packet type");
        }
    }

    #[test]
    fn test_rc_channels_packet_into_raw() {
        let channels: [u16; 16] = [0xffff; 16];
        let packet = Packet::RcChannels(RcChannels(channels));

        let mut buf = [0u8; Packet::MAX_LENGTH];
        let len = packet.dump(&mut buf, PacketAddress::Transmitter);
        let mut expected_data: [u8; 26] = [0xff; 26];
        expected_data[0] = 0xee;
        expected_data[1] = 24;
        expected_data[2] = 0x16;
        expected_data[25] = 143;
        assert_eq!(&buf[..len], &expected_data)
    }

    #[test]
    fn test_link_statistics_packet_into_raw() {
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
        let len = packet.dump(&mut buf, PacketAddress::Controller);
        let expected_data = [0xc8, 12, 0x14, 16, 19, 99, 151, 1, 2, 3, 8, 88, 148, 252];
        assert_eq!(&buf[..len], &expected_data)
    }
}
