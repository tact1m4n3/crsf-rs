//! This crate provides a #\[no_std\] parser for the crossfire protocol.
//! # Usage
//! ### Packet Parsing
//! ```rust
//! use crsf::{PacketAddress, PacketReader, PacketType};
//!
//! let mut reader = PacketReader::default();
//!
//! let addr = PacketAddress::FlightController;
//! let typ = PacketType::RcChannelsPacked;
//! ```
//! ### Packet Construction
//! ```rust
//! use crsf::{Packet, PacketAddress, PacketPayload, PACKET_MAX_LENGTH, RcChannels};
//!
//! let channels: [u16; 16] = [0xffff; 16];
//! let packet = Packet {
//!     address: PacketAddress::FlightController,
//!     payload: PacketPayload::RcChannels(RcChannels(channels))
//! };
//!
//! let mut buf = [0u8; PACKET_MAX_LENGTH];
//! let len = packet.dump(&mut buf);
//!
//! // ...
//! ```

#![no_std]

// TODO: top level crate packet reader examples redo

use bitflags::bitflags;
use crc::{Crc, CRC_8_DVB_S2};
#[cfg(feature = "defmt")]
use defmt;
use num_enum::TryFromPrimitive;
use snafu::prelude::*;

/// Used to calculate the CRC8 checksum
#[link_section = ".data"]
static CRC8: Crc<u8> = Crc::<u8>::new(&CRC_8_DVB_S2);

mod buffer;
use buffer::Buf;
mod packets;
pub use packets::*;
mod to_array;

/// Max crsf packet length
pub const PACKET_MAX_LENGTH: usize = 64;

/// Represents a packet reader
pub struct PacketReader<T: Copy + PacketAddressEncoder, A: PacketAddressDecoder<T>> {
    buf: Buf<PACKET_MAX_LENGTH>,
    initial_state: ReadState<T>,
    state: Option<ReadState<T>>,
    address_decoder: A,
}

impl PacketReader<(), NoPacketAddressDecoder> {
    /// Creates a new PacketReader struct that does not expect a sync byte.
    pub fn without_sync() -> PacketReader<(), NoPacketAddressDecoder> {
        let initial_state = ReadState::WaitingForLen { addr: () };
        PacketReader::<(), NoPacketAddressDecoder> {
            buf: Buf::new(),
            initial_state,
            state: Some(initial_state),
            address_decoder: NoPacketAddressDecoder,
        }
    }
}

impl Default for PacketReader<PacketAddress, KnownPacketAddressDecoder> {
    /// Creates a new PacketReader struct that expects default sync byte (0xC8)
    /// as a packet marker
    fn default() -> PacketReader<PacketAddress, KnownPacketAddressDecoder> {
        let initial_state = ReadState::WaitingForSync;
        PacketReader {
            buf: Buf::new(),
            initial_state,
            state: Some(initial_state),
            address_decoder: KnownPacketAddressDecoder::new(&[PacketAddress::FlightController]),
        }
    }
}

impl PacketReader<PacketAddress, KnownPacketAddressDecoder> {
    /// Creates a new PacketReader struct with custom addresses
    pub fn with_addresses(
        addresses: &[PacketAddress],
    ) -> PacketReader<PacketAddress, KnownPacketAddressDecoder> {
        let initial_state = ReadState::WaitingForSync;
        PacketReader {
            buf: Buf::new(),
            initial_state,
            state: Some(initial_state),
            address_decoder: KnownPacketAddressDecoder::new(addresses),
        }
    }
}

impl<T: Copy + PacketAddressEncoder, A: PacketAddressDecoder<T>> PacketReader<T, A> {
    // Packet type and checksum bytes are mandatory
    const MIN_DATA_LENGTH: u8 = 2;
    // Number of bytes of packet type, payload and checksum
    const MAX_DATA_LENGTH: u8 = PACKET_MAX_LENGTH as u8 - Self::MIN_DATA_LENGTH;

    /// Resets reader
    ///
    /// Useful in situations when timeout is triggered and a packet is not parsed
    pub fn reset(&mut self) {
        self.state = Some(self.initial_state);
        self.buf.clear();
    }

    /// Reads the first packet from the buffer
    pub fn push_bytes(&mut self, bytes: &[u8]) -> (Option<RawPacket<T>>, usize) {
        let mut reader = BytesReader::new(bytes);
        let packet = loop {
            match self.state {
                None => {
                    // We cannot clear buffer when constructing `RawPacket` as `RawPacket` borrows it.
                    // Owned version of `RawPacket` should solve this.
                    self.reset();
                }
                Some(ReadState::WaitingForSync) => {
                    while let Some(addr_byte) = reader.next() {
                        if let Some(addr) = self.address_decoder.decode(addr_byte) {
                            self.buf.push(addr_byte);
                            self.state = Some(ReadState::WaitingForLen { addr });
                            break;
                        }
                    }
                    if reader.is_empty() {
                        break None;
                    } else {
                        continue;
                    }
                }
                Some(ReadState::WaitingForLen { addr }) => {
                    if let Some(len_byte) = reader.next() {
                        match len_byte {
                            Self::MIN_DATA_LENGTH..=Self::MAX_DATA_LENGTH => {
                                self.buf.push(len_byte);
                                self.state = Some(ReadState::Reading {
                                    addr,
                                    len: addr.header_len() + len_byte as usize,
                                });
                            }
                            _ => {
                                self.state = Some(ReadState::WaitingForSync);
                                self.buf.clear();
                            }
                        }
                        continue;
                    }
                }
                Some(ReadState::Reading { addr, len }) => {
                    let data = reader.next_n(len - self.buf.len());
                    self.buf.push_bytes(data);
                    if self.buf.len() >= len {
                        self.state = None;
                        break Some(
                            RawPacket {
                                address: addr,
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

/// Represents a raw packet (not parsed)
#[derive(Clone, Copy, Debug)]
pub struct RawPacket<'a, T> {
    address: T,
    buf: &'a [u8; PACKET_MAX_LENGTH],
    len: usize,
}

impl<'a, T> RawPacket<'a, T> {
    /// Returns the packet data as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    // TODO: maybe add methods for getting the addr etc
}

/// Represents a parsed packet
#[derive(Clone, Debug)]
pub struct Packet<T: PacketAddressEncoder> {
    pub address: T,
    pub payload: PacketPayload,
}

#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum PacketPayload {
    LinkStatistics(LinkStatistics),
    RcChannels(RcChannels),
}

impl Packet<()> {
    pub fn without_address(payload: PacketPayload) -> Self {
        Self {
            address: (),
            payload,
        }
    }
}

impl Packet<PacketAddress> {
    pub fn new(address: PacketAddress, payload: PacketPayload) -> Self {
        Self {
            address,
            payload,
        }
    }
}

impl<T: PacketAddressEncoder> Packet<T> {
    /// Parses a raw packet (returned by the packet reader)
    pub fn parse(raw_packet: RawPacket<T>) -> Result<Self, ParseError> {
        // TODO: use more constants instead of literals

        // not using raw_packet.as_slice() for the compiler to remove out of bounds checking
        let buf = raw_packet.buf;
        let len = raw_packet.len;

        let header_len = raw_packet.address.header_len();
        let checksum_idx = len - 1;
        let checksum = CRC8.checksum(&buf[header_len..checksum_idx]);
        if checksum != buf[checksum_idx] {
            return Err(ParseError::ChecksumMismatch {
                expected: checksum,
                actual: buf[checksum_idx],
            });
        }

        let typ_byte = buf[header_len];
        if let Ok(typ) = PacketType::try_from(typ_byte) {
            let payload_data = if typ.is_extended() {
                &buf[header_len + 3..len - 1]
            } else {
                &buf[header_len + 1..len - 1]
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
                address: raw_packet.address,
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
        let header_len = self.address.header_len();
        let len = header_len + len_byte as usize;

        if buf.len() < len {
            return Err(BufferLenError {
                expected: len,
                actual: buf.len(),
            });
        }

        let mut ix = 0;
        if let Some(addr) = self.address.encode() {
            buf[ix] = addr;
            ix += 1;
        }
        buf[ix] = len_byte;
        ix += 1;
        buf[ix] = typ as u8;
        ix += 1;

        let payload_start = if typ.is_extended() { ix + 2 } else { ix };
        let checksum_idx = len - 1;
        payload.dump(&mut buf[payload_start..checksum_idx]);
        buf[checksum_idx] = CRC8.checksum(&buf[header_len..checksum_idx]);

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

pub trait PacketAddressEncoder {
    fn header_len(&self) -> usize {
        if self.encode().is_some() {
            2
        } else {
            1
        }
    }

    fn encode(&self) -> Option<u8>;
}

impl PacketAddressEncoder for () {
    fn encode(&self) -> Option<u8> {
        None
    }
}

impl PacketAddressEncoder for PacketAddress {
    fn encode(&self) -> Option<u8> {
        Some(*self as u8)
    }
}

pub trait PacketAddressDecoder<T: Copy> {
    fn decode(&self, c: u8) -> Option<T>;
}

pub struct NoPacketAddressDecoder;

impl PacketAddressDecoder<()> for NoPacketAddressDecoder {
    fn decode(&self, _: u8) -> Option<()> {
        Some(())
    }
}

pub struct KnownPacketAddressDecoder {
    flags: PacketAddressFlags,
}

impl KnownPacketAddressDecoder {
    fn new(addresses: &[PacketAddress]) -> Self {
        let flags = addresses.iter()
            .map(|addr| PacketAddressFlags::from_address(*addr))
            .reduce(|flags, f| flags | f)
            .expect("non-empty packet addresses");
        Self { flags }
    }
}

bitflags! {
    struct PacketAddressFlags: u16 {
        const BROADCAST = 1;
        const USB = 1 << 1;
        const BLUETOOTH = 1 << 2;
        const TBS_CORE_PNP_PRO = 1 << 3;
        const RESERVED1 = 1 << 4;
        const CURRENT_SENSOR = 1 << 5;
        const GPS = 1 << 6;
        const TBS_BLACKBOX = 1 << 7;
        const FLIGHT_CONTROLLER = 1 << 8;
        const RESERVED2 = 1 << 9;
        const RACE_TAG = 1 << 10;
        const HANDSET =  1 << 11;
        const RECEIVER = 1 << 12;
        const TRANSMITTER = 1 << 13;
    }
}

impl PacketAddressFlags {
    fn from_address(address: PacketAddress) -> Self {
        use PacketAddress::*;

        match address {
            Broadcast => PacketAddressFlags::BROADCAST,
            Usb => PacketAddressFlags::USB,
            Bluetooth => PacketAddressFlags::BLUETOOTH,
            TbsCorePnpPro => PacketAddressFlags::TBS_CORE_PNP_PRO,
            Reserved1 => PacketAddressFlags::RESERVED1,
            CurrentSensor => PacketAddressFlags::CURRENT_SENSOR,
            Gps => PacketAddressFlags::GPS,
            TbsBlackbox => PacketAddressFlags::TBS_BLACKBOX,
            FlightController => PacketAddressFlags::FLIGHT_CONTROLLER,
            Reserved2 => PacketAddressFlags::RESERVED2,
            RaceTag => PacketAddressFlags::RACE_TAG,
            Handset => PacketAddressFlags::HANDSET,
            Receiver => PacketAddressFlags::RECEIVER,
            Transmitter => PacketAddressFlags::TRANSMITTER,
        }
    }
}

impl PacketAddressDecoder<PacketAddress> for KnownPacketAddressDecoder {
    fn decode(&self, c: u8) -> Option<PacketAddress> {
        PacketAddress::try_from(c).ok()
            .filter(|&addr| self.flags.contains(PacketAddressFlags::from_address(addr)))
    }
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
#[derive(Clone, Copy, Debug)]
enum ReadState<T: Copy + PacketAddressEncoder> {
    WaitingForSync,
    WaitingForLen { addr: T },
    Reading { addr: T, len: usize },
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

    fn is_empty(&self) -> bool {
        self.idx == self.buf.len()
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
    use crate::PACKET_MAX_LENGTH;
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
    fn test_packet_reader_parse_packet_parts() {
        let mut reader = PacketReader::default();

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
                address: PacketAddress::FlightController,
                payload: PacketPayload::RcChannels(RcChannels(channels)),
            }) if channels == [0; 16]
        ));
    }

    #[test]
    fn test_packet_reader_parse_packet_full() {
        let mut reader = PacketReader::default();

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
                address: PacketAddress::FlightController,
                payload: PacketPayload::RcChannels(RcChannels(channels)),
            }) if channels == [0; 16]
        ));
    }

    #[test]
    fn test_packet_reader_waiting_for_sync() {
        let mut reader = PacketReader::with_addresses(
            &[PacketAddress::Transmitter, PacketAddress::Handset]
        );
        let typ = PacketType::RcChannelsPacked;

        // Garbage
        assert!(reader.push_bytes(&[0, 1, 2, 3]).0.is_none());
        // More garbage
        assert!(reader.push_bytes(&[PacketAddress::FlightController as u8, PacketAddress::Receiver as u8]).0.is_none());
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
                address: PacketAddress::Handset,
                payload: PacketPayload::RcChannels(RcChannels(channels)),
            }) if channels == [0; 16]
        ));

        // Garbage again
        assert!(reader.push_bytes(&[42, 34]).0.is_none());
        // Sync
        assert!(reader.push_bytes(&[PacketAddress::Transmitter as u8]).0.is_none());
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
                address: PacketAddress::Transmitter,
                payload: PacketPayload::RcChannels(RcChannels(channels)),
            }) if channels == [0; 16]
        ));
    }

    #[test]
    fn test_packet_reader_parse_packet_without_sync_byte() {
        let mut reader = PacketReader::without_sync();

        let typ = PacketType::RcChannelsPacked;

        let data = [
            // Len
            24,
            // Type
            typ as u8,
            // Payload
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // Checksum
            239,
        ];
        let res = reader.push_bytes(&data).0.map(|raw_packet| Packet::parse(raw_packet));
        assert!(matches!(
            res.expect("packet expected"),
            // reader.push_bytes(&data).0.map(|raw_packet| Packet::parse(raw_packet)).expect("packet expected"),
            Ok(Packet {
                address: (),
                payload: PacketPayload::RcChannels(RcChannels(channels)),
            }) if channels == [0; 16]
        ));
    }

    #[test]
    fn test_parse_next_packet_with_validation_error() {
        let mut reader = PacketReader::default();

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
        let packet = Packet {
            address: PacketAddress::FlightController,
            payload: PacketPayload::LinkStatistics(LinkStatistics {
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
            }),
        };

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
            PacketPayload::RcChannels(RcChannels(channels)),
        );

        let mut buf = [0u8; PACKET_MAX_LENGTH];
        let len = packet.dump(&mut buf).unwrap();
        let mut expected_data: [u8; 26] = [0xff; 26];
        expected_data[0] = 0xee;
        expected_data[1] = 24;
        expected_data[2] = 0x16;
        expected_data[25] = 143;
        assert_eq!(&buf[..len], &expected_data)
    }

    #[test]
    fn test_rc_channels_packet_dump_no_address() {
        let channels: [u16; 16] = [0xffff; 16];
        let packet = Packet::without_address(
            PacketPayload::RcChannels(RcChannels(channels)),
        );

        let mut buf = [0u8; PACKET_MAX_LENGTH];
        let len = packet.dump(&mut buf).unwrap();
        let mut expected_data: [u8; 25] = [0xff; 25];
        expected_data[0] = 24;
        expected_data[1] = 0x16;
        expected_data[24] = 143;
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

        let mut buf = [0u8; PACKET_MAX_LENGTH];
        let len = packet.dump(&mut buf).unwrap();
        let expected_data = [0xc8, 12, 0x14, 16, 19, 99, 151, 1, 2, 3, 8, 88, 148, 252];
        assert_eq!(&buf[..len], &expected_data)
    }
}
