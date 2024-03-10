#![no_std]

use crc::{Crc, CRC_8_DVB_S2};
#[cfg(feature = "defmt")]
use defmt;
use snafu::prelude::*;

use buffer::CircularBuffer;

pub use packets::*;

mod buffer;
mod packets;

pub const MAX_PACKET_LENGTH: usize = 64;
pub const PACKET_HEADER_LENGTH: usize = 2;

pub struct PacketParser<const C: usize> {
    buf: CircularBuffer<C>,
}

impl<const C: usize> PacketParser<C> {
    // Packet type and checksum bytes are mandatory
    const MIN_DATA_LENGTH: u8 = 2;
    // Number of bytes of packet type, payload and checksum
    const MAX_DATA_LENGTH: u8 = MAX_PACKET_LENGTH as u8 - Self::MIN_DATA_LENGTH;

    pub const fn new() -> Self {
        Self {
            buf: CircularBuffer::new(),
        }
    }

    pub fn clear(&mut self) {
        self.buf.clear();
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) {
        bytes.iter().for_each(|&val| {
            self.buf.push_back(val);
        });
    }

    pub fn next_raw_packet(&mut self) -> Option<Result<RawPacket, PacketError>> {
        self.sync();

        if self.buf.len() < PACKET_HEADER_LENGTH {
            return None;
        }

        let len_byte = self.buf.peek_front(1).unwrap();
        if !(Self::MIN_DATA_LENGTH..=Self::MAX_DATA_LENGTH).contains(&len_byte) {
            for _ in 0..PACKET_HEADER_LENGTH {
                self.buf.pop_front();
            }
            return Some(Err(PacketError::InvalidLength { len: len_byte }));
        }
        let len = PACKET_HEADER_LENGTH + len_byte as usize;

        if len > self.buf.len() {
            return None;
        }

        let mut data: [u8; MAX_PACKET_LENGTH] = [0; MAX_PACKET_LENGTH];
        for c in data.iter_mut() {
            *c = self.buf.pop_front().unwrap_or(0);
        }

        Some(Ok(RawPacket { data, len }))
    }

    pub fn next_packet(&mut self) -> Option<Result<(PacketAddress, Packet), PacketError>> {
        self.next_raw_packet().map(|raw_packet| match raw_packet {
            Ok(raw_packet) => {
                let destination = PacketAddress::from_u8(raw_packet.data[0]).unwrap();
                let packet = Packet::from_raw(&raw_packet)?;
                Ok((destination, packet))
            },
            Err(err) => Err(err),
        })
    }

    fn sync(&mut self) {
        while self
            .buf
            .peek_front(0)
            .is_some_and(|val| PacketAddress::from_u8(val).is_none())
        {
            self.buf.pop_front();
        }
    }
}

#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Packet {
    LinkStatistics(LinkStatistics),
    RcChannels(RcChannels),
}

impl Packet {
    pub fn from_raw(raw_packet: &RawPacket) -> Result<Self, PacketError> {
        let data = raw_packet.data();

        let checksum_idx = data.len() - 1;
        let checksum = Self::calculate_checksum(&data[2..checksum_idx]);
        if checksum != data[checksum_idx] {
            return Err(PacketError::ChecksumMismatch {
                expected: checksum,
                actual: data[checksum_idx],
            });
        }

        let raw_type = data[2];
        match PacketType::from_u8(raw_type) {
            Some(PacketType::RcChannelsPacked) => Ok(Packet::RcChannels(unsafe {
                RcChannels::parse_unchecked(&data[3..])
            })),
            Some(PacketType::LinkStatistics) => Ok(Packet::LinkStatistics(unsafe {
                LinkStatistics::parse_unchecked(&data[3..])
            })),
            _ => Err(PacketError::UnknownType { raw_type }),
        }
    }

    pub fn into_raw(&self, addr: PacketAddress) -> RawPacket {
        let mut data: [u8; MAX_PACKET_LENGTH] = [0; MAX_PACKET_LENGTH];

        data[0] = addr as u8;
        match self {
            Packet::LinkStatistics(payload) => {
                let len_byte = LinkStatistics::PAYLOAD_LENGTH + 2;
                let len = PACKET_HEADER_LENGTH + len_byte as usize;
                data[1] = len_byte;

                data[2] = PacketType::LinkStatistics as u8;

                unsafe { payload.write_unchecked(&mut data[3..]) }

                let checksum_idx = len - 1;
                data[checksum_idx] = Self::calculate_checksum(&data[2..checksum_idx]);

                RawPacket { data, len }
            }
            Packet::RcChannels(payload) => {
                let len_byte = RcChannels::PAYLOAD_LENGTH + 2;
                let len = PACKET_HEADER_LENGTH + len_byte as usize;
                data[1] = len_byte;

                data[2] = PacketType::RcChannelsPacked as u8;

                unsafe { payload.write_unchecked(&mut data[3..]) }

                let checksum_idx = len - 1;
                data[checksum_idx] = Self::calculate_checksum(&data[2..checksum_idx]);

                RawPacket { data, len }
            }
        }
    }

    fn calculate_checksum(data: &[u8]) -> u8 {
        let crc8_alg = Crc::<u8>::new(&CRC_8_DVB_S2);
        crc8_alg.checksum(data)
    }
}

#[derive(Clone, Debug)]
pub struct RawPacket {
    data: [u8; MAX_PACKET_LENGTH],
    len: usize,
}

impl RawPacket {
    pub fn data(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

#[non_exhaustive]
#[derive(Debug, PartialEq, Snafu)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PacketError {
    #[snafu(display("Invalid length: {len}"))]
    InvalidLength { len: u8 },
    #[snafu(display("Unknown type: {raw_type:#04x}"))]
    UnknownType { raw_type: u8 },
    #[snafu(display("Checksum mismatch: expected {expected:#04x} but was {actual:#04x}"))]
    ChecksumMismatch { expected: u8, actual: u8 },
}

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

#[cfg(test)]
mod tests {
    use crate::Packet;
    use crate::PacketAddress;

    use super::PacketError;
    use super::PacketParser;
    use super::PacketType;
    use super::RcChannels;

    #[test]
    fn test_parse_next_packet() {
        let mut parser = PacketParser::<1024>::new();

        let addr = PacketAddress::Controller;
        let typ = PacketType::RcChannelsPacked;

        // Sync
        parser.push_bytes(&[addr as u8]);
        assert!(matches!(parser.next_packet(), None));
        // Len
        parser.push_bytes(&[24]);
        assert!(matches!(parser.next_packet(), None));
        // Type
        parser.push_bytes(&[typ as u8]);
        assert!(matches!(parser.next_packet(), None));
        // Payload
        parser.push_bytes(&[0; 22]);
        assert!(matches!(parser.next_packet(), None));
        // Checksum
        parser.push_bytes(&[239]);

        match parser.next_packet() {
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
        assert!(matches!(parser.next_packet(), None));
    }

    #[test]
    fn test_parse_next_packet_with_validation_error() {
        let mut parser = PacketParser::<1024>::new();

        let addr = PacketAddress::Controller;

        // Sync
        parser.push_bytes(&[addr as u8]);
        assert!(matches!(parser.next_packet(), None));
        // Len
        parser.push_bytes(&[24]);
        assert!(matches!(parser.next_packet(), None));
        // Type
        parser.push_bytes(&[PacketType::RcChannelsPacked as u8]);
        assert!(matches!(parser.next_packet(), None));
        // Payload
        parser.push_bytes(&[0; 22]);
        assert!(matches!(parser.next_packet(), None));
        // Checksum
        parser.push_bytes(&[42]);

        match parser.next_packet() {
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
        assert!(matches!(parser.next_packet(), None));
    }

    #[test]
    fn test_parse_next_packet_with_zero_len() {
        let mut parser = PacketParser::<1024>::new();

        let addr = PacketAddress::Controller;

        // Sync
        parser.push_bytes(&[addr as u8]);
        assert!(matches!(parser.next_packet(), None));
        // Len
        parser.push_bytes(&[0]);
        match parser.next_packet() {
            None | Some(Ok(_)) => panic!("Validation error expected"),
            Some(Err(e)) => {
                assert_eq!(e, PacketError::InvalidLength { len: 0 })
            }
        }
        assert!(matches!(parser.next_packet(), None));
    }

    #[test]
    fn test_parse_next_packet_with_max_len() {
        let mut parser = PacketParser::<1024>::new();

        let addr = PacketAddress::Controller;

        // Sync
        parser.push_bytes(&[addr as u8]);
        assert!(matches!(parser.next_packet(), None));
        // Len
        parser.push_bytes(&[62]);
        // Type
        parser.push_bytes(&[0xff]);
        // Payload
        parser.push_bytes(&[0; 60]);
        // Checksum
        parser.push_bytes(&[33]);
        match parser.next_packet() {
            None | Some(Ok(_)) => panic!("Validation error expected"),
            Some(Err(e)) => {
                assert_eq!(e, PacketError::UnknownType { raw_type: 0xff })
            }
        }
        assert!(matches!(parser.next_packet(), None));
    }

    #[test]
    fn test_parse_next_packet_with_too_big_len() {
        let mut parser = PacketParser::<1024>::new();

        // Sync
        parser.push_bytes(&[0xc8]);
        assert!(matches!(parser.next_packet(), None));
        // Len
        parser.push_bytes(&[63]);
        match parser.next_packet() {
            None | Some(Ok(_)) => panic!("Validation error expected"),
            Some(Err(e)) => {
                assert_eq!(e, PacketError::InvalidLength { len: 63 })
            }
        }
        assert!(matches!(parser.next_packet(), None));
    }

    #[test]
    fn test_packet_construction() {
        let addr = PacketAddress::Controller;

        let channels: [u16; 16] = [0; 16];
        let packet = Packet::RcChannels(RcChannels(channels));

        let raw_packet = packet.into_raw(addr);

        let packet2 = Packet::from_raw(&raw_packet).unwrap();
        if let Packet::RcChannels(RcChannels(channels2)) = packet2 {
            assert_eq!(channels, channels2);
        }
    }
}
