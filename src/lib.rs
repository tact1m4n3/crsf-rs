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
//! let raw_packet = payload.into_raw_packet_with_sync(addr as u8).unwrap();
//! // ...
//! ```

#![no_std]

// TODO: top level crate packet reader examples redo

pub use address::PacketAddress;
use address::PacketAddressFlags;
#[cfg(feature = "defmt")]
use defmt;
use num_enum::TryFromPrimitive;
use snafu::prelude::*;

mod address;
mod to_array;

mod buffer;
use buffer::BytesReader;
mod crc8;
use crc8::Crc8;

mod raw_packet;
pub use raw_packet::*;
mod packets;
pub use packets::*;

pub const CRSF_MAX_LEN: usize = 64;
const CRSF_HEADER_LEN: usize = 2;
const CRSF_SYNC_BYTE: u8 = 0xC8;

/// Represents a state machine for reading a CRSF packet
///
/// +--------------+   +-------------+   +---------+
/// | AwaitingSync |-->| AwaitingLen |-->| Reading |
/// +--------------+   +-------------+   +---------+
///         ^                   |                |
///         |                   |                |
///         +-------------------+                |
///         +------------------------------------+
///
enum ReadState {
    AwaitingSync,
    AwaitingLen,
    Reading,
}

/// Represents a packet reader
pub struct PacketReader {
    state: ReadState,
    raw: RawPacket,
    digest: Crc8,
    config: Config,
}

impl Default for PacketReader {
    /// Creates a new PacketReader with the default configuration
    fn default() -> Self {
        Self {
            state: ReadState::AwaitingSync,
            raw: RawPacket::empty(),
            digest: Crc8::new(),
            config: Config::default(),
        }
    }
}

pub struct PacketReaderBuilder {
    config: Config,
}

impl PacketReaderBuilder {
    pub fn sync(mut self, sync: &[PacketAddress]) -> Self {
        let mut sync_byte = PacketAddressFlags::empty();
        for addr in sync {
            sync_byte |= PacketAddressFlags::from_address(*addr);
        }
        self.config.sync = sync_byte;
        self
    }

    pub fn type_check(mut self, type_check: bool) -> Self {
        self.config.type_check = type_check;
        self
    }

    pub fn build(self) -> PacketReader {
        PacketReader {
            state: ReadState::AwaitingSync,
            raw: RawPacket::empty(),
            digest: Crc8::new(),
            config: self.config,
        }
    }
}

pub struct Config {
    /// Sync byte to use for finding the start of a frame. Default is `0xC8`
    sync: PacketAddressFlags,

    /// Whether to ensure the type byte is a valid PacketType enum value. Default is `true`.
    type_check: bool,
}

impl Config {
    // Not using default trait because it is not const
    const fn default() -> Self {
        Self {
            sync: PacketAddressFlags::FLIGHT_CONTROLLER,
            type_check: true,
        }
    }
}

impl PacketReader {
    // Minimum data length, must include type and crc bytes
    const MIN_LEN_BYTE: u8 = 2;
    // Maximum data length, includes type, payload and crc bytes
    const MAX_LEN_BYTE: u8 = CRSF_MAX_LEN as u8 - Self::MIN_LEN_BYTE;

    /// Creates a new PacketReader struct
    pub const fn new() -> Self {
        Self {
            state: ReadState::AwaitingSync,
            raw: RawPacket::empty(),
            digest: Crc8::new(),
            config: Config::default(),
        }
    }

    pub const fn builder() -> PacketReaderBuilder {
        PacketReaderBuilder {
            config: Config {
                sync: PacketAddressFlags::FLIGHT_CONTROLLER,
                type_check: true,
            },
        }
    }

    /// Resets reader's state
    ///
    /// Useful in situations when timeout is triggered but a packet is not parsed
    pub fn reset(&mut self) {
        self.state = ReadState::AwaitingSync;
        self.raw.len = 0; // Soft-reset the buffer
        self.digest.reset();
    }

    /// Reads the first packet from the buffer
    pub fn push_bytes<'r, 'b>(
        &'r mut self,
        bytes: &'b [u8],
    ) -> (Option<Result<&'r RawPacket, CrsfError>>, &'b [u8]) {
        let mut reader = BytesReader::new(bytes);
        let packet = 'state_machine: loop {
            match self.state {
                ReadState::AwaitingSync => {
                    while let Some(sync_byte) = reader.next() {
                        if self.config.sync.contains_u8(sync_byte) {
                            self.raw.buf[0] = sync_byte;
                            self.state = ReadState::AwaitingLen;
                            continue 'state_machine;
                        }
                    }

                    if reader.is_empty() {
                        break Some(Err(CrsfError::NoSyncByte));
                    }
                }
                ReadState::AwaitingLen => {
                    let Some(len_byte) = reader.next() else {
                        break None;
                    };
                    match len_byte {
                        Self::MIN_LEN_BYTE..=Self::MAX_LEN_BYTE => {
                            self.raw.buf[1] = len_byte;
                            self.raw.len = CRSF_HEADER_LEN;
                            self.state = ReadState::Reading;
                        }
                        _ => {
                            self.reset();
                            break Some(Err(CrsfError::InvalidLength { len: len_byte }));
                        }
                    }
                }
                ReadState::Reading => {
                    if reader.is_empty() {
                        break None;
                    }

                    let final_len = self.raw.buf[1] as usize + CRSF_HEADER_LEN;
                    let data = reader.next_n(final_len - self.raw.len);
                    self.raw.buf[self.raw.len..self.raw.len + data.len()].copy_from_slice(data);
                    self.raw.len += data.len();

                    // Validate that type is in PacketType enum
                    if let Some(type_byte) = self.raw.buf.get(2).copied() {
                        if self.config.type_check && PacketType::try_from(type_byte).is_err()
                        {
                            self.reset();
                            break Some(Err(CrsfError::UnknownType {
                                typ: type_byte,
                            }));
                        }
                    }

                    // If we have received the CRC byte, do not use it in the digest
                    if self.raw.len == final_len {
                        self.digest.compute(&data[..data.len() - 1]);
                        let act_crc = self.digest.get_checksum();
                        let exp_crc = self.raw.buf[self.raw.len - 1];
                        if act_crc != exp_crc {
                            self.reset();
                            break Some(Err(CrsfError::CrcMismatch {
                                exp: exp_crc,
                                act: act_crc,
                            }));
                        }
                    } else {
                        self.digest.compute(data);
                    }

                    if self.raw.len >= final_len {
                        self.digest.reset();
                        self.state = ReadState::AwaitingSync;
                        break Some(Ok(&self.raw));
                    }
                }
            }
        };

        (packet, reader.remaining())
    }

    /// Returns an interator over the given buffer. If the buffer contains packet of a valid format,
    /// the iterator will return `Ok(RawPacket)`. If the buffer contains invalid packets, the iterator
    /// will return `Err(CrsfError)`. If the buffer is too small to parse, the iterator will yield.
    /// Once the iterator yields, all bytes in the buffer have been consumed.
    ///
    /// To get an iterator that returns `Packet`, use `iter_packets`.
    pub fn iter_raw_packets<'a, 'b>(&'a mut self, buf: &'b [u8]) -> IterRawPackets<'a, 'b> {
        IterRawPackets { parser: self, buf }
    }

    /// Returns an iterator over the given buffer. If the buffer contains packets of a valid format,
    /// the iterator will return `Ok(Packet)`. If the buffer contains invalid packets, the iterator
    /// will return `Err(CrsfError)`. If the buffer is too small to parse, the iterator will yield.
    /// Once the iterator yields, all bytes in the buffer have been consumed.
    ///
    /// To get an iterator that returns `RawPacket`, use `iter_raw_packets`.
    pub fn iter_packets<'a, 'b>(&'a mut self, buf: &'b [u8]) -> IterPackets<'a, 'b> {
        IterPackets { parser: self, buf }
    }
}


/// An iterator over a buffer that yield `RawPacket` instances, or `CrsfError` in case of currupt data.
/// This iterator will consume the and process the entire buffer. For an iterator that also parses the
/// packets into `Packet` instances, use `IterPackets` instead.
pub struct IterRawPackets<'a, 'b> {
    parser: &'a mut PacketReader,
    buf: &'b [u8],
}

impl<'a, 'b> Iterator for IterRawPackets<'a, 'b> {
    type Item = Result<RawPacket, CrsfError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        let result;
        (result, self.buf) = self.parser.push_bytes(self.buf);
        result.map(|raw| raw.cloned())
    }
}

/// An iterator over a buffer that return parsed `Packet` instances, or `CrsfError` in case of currupt data.
/// This iterator will consume the and process the entire buffer.
pub struct IterPackets<'a, 'b> {
    parser: &'a mut PacketReader,
    buf: &'b [u8],
}

impl<'a, 'b> Iterator for IterPackets<'a, 'b> {
    type Item = Result<Packet, CrsfError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        let result;
        (result, self.buf) = self.parser.push_bytes(self.buf);
        result.map(|res| match res {
            Ok(raw) => raw.into_packet(),
            Err(err) => Err(err),
        })
    }
}


/// Represents packet parsing errors
#[non_exhaustive]
#[derive(Debug, PartialEq, Snafu)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CrsfError {
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

/// Represents a packet payload data
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum Packet {
    LinkStatistics(LinkStatistics),
    RcChannelsPacked(RcChannelsPacked),
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

#[cfg(test)]
mod tests {
    use crate::address::PacketAddress;
    use crate::BytesReader;
    use crate::CrsfError;
    use crate::LinkStatistics;
    use crate::Packet;
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
                Some(Err(CrsfError::NoSyncByte))
            ));
            // More garbage
            assert!(matches!(
                reader.push_bytes(&[254, 255]).0,
                Some(Err(CrsfError::NoSyncByte))
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
            let packet = raw_packet.into_packet().expect("packet expected");

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
        let packet = raw_packet.into_packet().expect("packet expected");

        match packet {
            Packet::RcChannelsPacked(ch) => {
                ch.0.iter().all(|&x| x == 0);
            }
            _ => panic!("unexpected packet type"),
        }
    }


    #[test]
    fn test_push_segments() { // similar to the doc-test at the top
        
        let mut reader = PacketReader::new();
        let data: &[&[u8]] = &[&[0xc8, 24, 0x16], &[0; 22], &[239]];
        for (i, input_buf) in data.iter().enumerate() {
            for (j, result) in reader.iter_packets(input_buf).enumerate() {
                match result {
                    Ok(Packet::RcChannelsPacked(rc_channels))=> assert_eq!(rc_channels, RcChannelsPacked([0u16; 16])),
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
            .into_raw_packet_with_sync(PacketAddress::FlightController as u8)
            .unwrap();

        let rc_channels2 = RcChannelsPacked([1500; 16]);
        let raw_packet2 = rc_channels2
            .into_raw_packet_with_sync(PacketAddress::Broadcast as u8)
            .unwrap();

        let rc_channels3 = RcChannelsPacked([2000; 16]); // Some other address here ---v
        let raw_packet3 = rc_channels3
            .into_raw_packet_with_sync(PacketAddress::Reserved1 as u8)
            .unwrap();

        let result1 = reader
            .push_bytes(raw_packet1.as_slice())
            .0
            .expect("result expected")
            .expect("raw packet expected");
        assert_eq!(
            result1.into_packet().expect("packet expected"),
            Packet::RcChannelsPacked(rc_channels1)
        );

        let result2 = reader
            .push_bytes(raw_packet2.as_slice())
            .0
            .expect("result expected")
            .expect("raw packet expected");
        assert_eq!(
            result2.into_packet().expect("packet expected"),
            Packet::RcChannelsPacked(rc_channels2)
        );

        let result3 = reader
            .push_bytes(raw_packet3.as_slice())
            .0
            .expect("result expected")
            .expect_err("Error expected");
        assert!(matches!(result3, CrsfError::NoSyncByte));
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
        let packet = raw_packet.into_packet().expect("packet expected");

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
            Err(CrsfError::CrcMismatch { act: 239, exp: 42 })
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

        let raw = packet.into_raw_packet_with_sync(addr as u8).unwrap();

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

        let raw = packet.into_raw_packet_with_sync(addr as u8).unwrap();

        let expected_data = [0xc8, 12, 0x14, 16, 19, 99, 151, 1, 2, 3, 8, 88, 148, 252];
        assert_eq!(raw.as_slice(), expected_data.as_slice())
    }
}
