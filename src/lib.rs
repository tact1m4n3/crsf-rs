//! This crate provides a #\[no_std\] parser for the crossfire protocol.
//! # Usage
//! ### Packet Parsing
//! ```rust
//! use crsf::{Packet, PacketReader, PacketAddress, PacketType};
//!
//! let mut reader = PacketReader::new();
//! let data: &[&[u8]] = &[&[0xc8, 24, 0x16], &[0; 22], &[239]];
//! for input_buf in data {
//!     let mut buf: &[u8] = input_buf;
//!     while !buf.is_empty() {
//!         let consumed = match reader.push_bytes(buf) {
//!             (Some(raw_packet), n) => {
//!                 let packet = Packet::parse(raw_packet).expect("valid packet");
//!                 n
//!             }
//!             (None, n) => n,
//!         };
//!         buf = &buf[consumed..];
//!     }
//! }
//!
//! let addr = PacketAddress::FlightController;
//! let typ = PacketType::RcChannelsPacked;
//! ```
//! ### Packet Construction
//! ```rust
//! use crsf::{Packet, PacketAddress, PacketPayload, RcChannels};
//!
//! let channels: [u16; 16] = [0xffff; 16];
//! let packet = Packet::new(
//!     PacketAddress::FlightController,
//!     PacketPayload::RcChannels(RcChannels(channels))
//! );
//!
//! let mut buf = [0u8; Packet::MAX_LENGTH];
//! let packet_len = packet.dump(&mut buf).expect("dumped packet");
//! let packet_data = &buf[..packet_len];
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

use buffer::{Buf, BytesReader};
pub use packets::*;

mod buffer;
mod packets;
mod to_array;

/// Represents a packet reader
pub struct PacketReader {
    buf: Buf<{ Packet::MAX_LENGTH }>,
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
            buf: Buf::new(),
            state: ReadState::WaitingForSync,
        }
    }

    /// Resets reader's state
    ///
    /// Useful in situations when timeout is triggered but a packet is not parsed
    pub fn reset(&mut self) {
        self.buf.clear();
        self.state = ReadState::WaitingForSync;
    }

    /// Reads the first packet from the buffer
    pub fn push_bytes(&mut self, bytes: &[u8]) -> (Option<RawPacket>, usize) {
        let mut reader = BytesReader::new(bytes);
        let packet = loop {
            match self.state {
                ReadState::WaitingForSync => {
                    while let Some(addr_byte) = reader.next() {
                        if let Ok(addr) = PacketAddress::try_from(addr_byte) {
                            self.buf.clear();
                            self.buf.push(addr_byte);
                            self.state = ReadState::WaitingForLen { addr };
                            break;
                        }
                    }
                    if reader.is_empty() {
                        break None;
                    } else {
                        continue;
                    }
                }
                ReadState::WaitingForLen { addr } => {
                    if let Some(len_byte) = reader.next() {
                        match len_byte {
                            Self::MIN_DATA_LENGTH..=Self::MAX_DATA_LENGTH => {
                                self.buf.push(len_byte);
                                self.state = ReadState::Reading {
                                    addr,
                                    len: Packet::HEADER_LENGTH + len_byte as usize,
                                };
                            }
                            _ => self.state = ReadState::WaitingForSync,
                        }
                        continue;
                    }
                }
                ReadState::Reading { addr, len } => {
                    let data = reader.next_n(len - self.buf.len());
                    self.buf.push_bytes(data);
                    if self.buf.len() >= len {
                        self.state = ReadState::WaitingForSync;
                        break Some(
                            RawPacket {
                                addr,
                                buf: self.buf.data(),
                                len: self.buf.len(),
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

impl Default for PacketReader {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents a raw packet (not parsed)
#[derive(Clone, Copy, Debug)]
pub struct RawPacket<'a> {
    addr: PacketAddress,
    buf: &'a [u8; Packet::MAX_LENGTH],
    len: usize,
}

impl<'a> RawPacket<'a> {
    /// Returns the packet data as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn addr(&self) -> PacketAddress {
        self.addr
    }
}

/// Represents a packet payload data
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum PacketPayload {
    LinkStatistics(LinkStatistics),
    RcChannels(RcChannels),
}

/// Represents a parsed packet
pub struct Packet {
    pub addr: PacketAddress,
    pub payload: PacketPayload,
}

impl Packet {
    /// Max crsf packet length
    pub const MAX_LENGTH: usize = 64;
    /// Crsf packet header length
    pub const HEADER_LENGTH: usize = 2;

    /// Creates new packet with address and payload
    pub fn new(addr: PacketAddress, payload: PacketPayload) -> Self {
        Self { addr, payload }
    }

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

            let payload = match typ {
                PacketType::RcChannelsPacked => {
                    PacketPayload::RcChannels(RcChannels::parse(payload_data))
                }
                PacketType::LinkStatistics => {
                    PacketPayload::LinkStatistics(LinkStatistics::parse(payload_data))
                }
                _ => return Err(ParseError::UnknownType { typ: typ_byte }),
            };
            Ok(Packet {
                addr: raw_packet.addr,
                payload,
            })
        } else {
            Err(ParseError::InvalidType { typ: typ_byte })
        }
    }

    /// Dumps the packet into a buffer
    pub fn dump(&self, buf: &mut [u8]) -> Result<usize, BufferLenError> {
        // TODO: use more constants instead of literals

        let payload = match &self.payload {
            PacketPayload::LinkStatistics(payload) => payload as &dyn Payload,
            PacketPayload::RcChannels(payload) => payload as &dyn Payload,
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

        buf[0] = self.addr as u8;
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
    Broadcast = 0x00,
    Usb = 0x10,
    Bluetooth = 0x12,
    TbsCorePnpPro = 0x80,
    Reserved1 = 0x8A,
    CurrentSensor = 0xC0,
    Gps = 0xC2,
    TbsBlackbox = 0xC4,
    FlightController = 0xC8,
    Reserved2 = 0xCA,
    RaceTag = 0xCC,
    Handset = 0xEA,
    Receiver = 0xEC,
    Transmitter = 0xEE,
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
    Heartbeat = 0x0B,
    LinkStatistics = 0x14,
    RcChannelsPacked = 0x16,
    SubsetRcChannelsPacked = 0x17,
    LinkRxId = 0x1C,
    LinkTxId = 0x1D,
    Attitude = 0x1E,
    FlightMode = 0x21,
    DevicePing = 0x28,
    DeviceInfo = 0x29,
    ParameterSettingsEntry = 0x2B,
    ParameterRead = 0x2C,
    ParameterWrite = 0x2D,
    ElrsStatus = 0x2E,
    Command = 0x32,
    RadioId = 0x3A,
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
    WaitingForLen { addr: PacketAddress },
    Reading { addr: PacketAddress, len: usize },
}

#[cfg(test)]
mod tests {
    use crate::BufferLenError;
    use crate::BytesReader;
    use crate::LinkStatistics;
    use crate::Packet;
    use crate::PacketAddress;
    use crate::PacketPayload;
    use crate::PacketReader;
    use crate::PacketType;
    use crate::ParseError;
    use crate::RcChannels;

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
    fn test_packet_reader_waiting_for_sync_byte() {
        let mut reader = PacketReader::new();
        let typ = PacketType::RcChannelsPacked;

        for _ in 0..2 {
            // Garbage
            assert!(reader.push_bytes(&[1, 2, 3]).0.is_none());
            // More garbage
            assert!(reader.push_bytes(&[254, 255]).0.is_none());
            // Sync
            assert!(reader.push_bytes(&[PacketAddress::Handset as u8]).0.is_none());
            // Len
            assert!(reader.push_bytes(&[24]).0.is_none());
            // Type
            assert!(reader.push_bytes(&[typ as u8]).0.is_none());
            // Payload
            assert!(reader.push_bytes(&[0; 22]).0.is_none());
            // Checksum
            assert!(matches!(
                reader.push_bytes(&[239]).0.map(|raw_packet| Packet::parse(raw_packet)).expect("packet expected"),
                Ok(Packet {
                    addr: PacketAddress::Handset,
                    payload: PacketPayload::RcChannels(RcChannels(channels))
                }) if channels == [0; 16]
            ));
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
        assert!(matches!(
            reader.push_bytes(&[239]).0.map(|raw_packet| Packet::parse(raw_packet)).expect("packet expected"),
            Ok(Packet {
                addr: PacketAddress::FlightController,
                payload: PacketPayload::RcChannels(RcChannels(channels))
            }) if channels == [0; 16]
        ));
    }

    #[test]
    fn test_parse_full_packet() {
        let mut reader = PacketReader::new();

        let addr = PacketAddress::FlightController;
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
            Ok(Packet {
                addr: PacketAddress::FlightController,
                payload: PacketPayload::RcChannels(RcChannels(channels))
            }) if channels == [0; 16]
        ));
    }

    #[test]
    fn test_parse_next_packet_with_validation_error() {
        let mut reader = PacketReader::new();

        let addr = PacketAddress::FlightController;

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
        let packet = Packet::new(
            PacketAddress::FlightController,
            PacketPayload::LinkStatistics(LinkStatistics {
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
            })
        );

        let mut buf = [0u8; 10];
        assert_eq!(
            packet.dump(&mut buf),
            Err(BufferLenError {
                expected: 14,
                actual: 10
            })
        );
    }

    #[test]
    fn test_rc_channels_packet_dump() {
        let channels: [u16; 16] = [0x7FF; 16];
        let packet = Packet::new(
            PacketAddress::Transmitter,
            PacketPayload::RcChannels(RcChannels(channels))
        );

        let mut buf = [0u8; Packet::MAX_LENGTH];
        let len = packet.dump(&mut buf).unwrap();
        let mut expected_data: [u8; 26] = [0xff; 26];
        expected_data[0] = 0xee;
        expected_data[1] = 24;
        expected_data[2] = 0x16;
        expected_data[25] = 143;
        assert_eq!(&buf[..len], &expected_data)
    }

    #[test]
    fn test_link_statistics_packet_dump() {
        let packet = Packet::new(
            PacketAddress::FlightController,
            PacketPayload::LinkStatistics(LinkStatistics {
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
            })
        );

        let mut buf = [0u8; Packet::MAX_LENGTH];
        let len = packet.dump(&mut buf).unwrap();
        let expected_data = [0xc8, 12, 0x14, 16, 19, 99, 151, 1, 2, 3, 8, 88, 148, 252];
        assert_eq!(&buf[..len], &expected_data)
    }
}
