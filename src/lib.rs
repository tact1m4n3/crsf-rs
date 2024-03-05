#![no_std]

use crc::{Crc, CRC_8_DVB_S2};
#[cfg(feature = "defmt")]
use defmt;
use snafu::prelude::*;

use buffer::CircularBuffer;

pub use payloads::*;

mod buffer;
mod payloads;

#[derive(Default)]
pub struct CrsfPacketParser {
    buf: CircularBuffer<{ 4 * Packet::MAX_LENGTH }>,
}

impl CrsfPacketParser {
    // Sync and length bytes
    const HEADER_LENGTH: usize = 2;
    // Packet type and checksum bytes are mandatory
    const MIN_DATA_LENGTH: u8 = 2;
    // Number of bytes of packet type, payload and checksum
    const MAX_DATA_LENGTH: u8 = Packet::MAX_LENGTH as u8 - Self::MIN_DATA_LENGTH;

    pub fn push_bytes(&mut self, bytes: &[u8]) {
        bytes.iter().for_each(|&val| {
            self.buf.push_back(val);
        });
    }

    pub fn clear_buffer(&mut self) {
        self.buf.clear();
    }

    pub fn next_packet(&mut self) -> Option<Result<Packet, PacketError>> {
        self.sync();

        if self.buf.len() < Self::HEADER_LENGTH {
            return None;
        }

        let data_len = self.buf.peek_front(1).unwrap();
        if !(Self::MIN_DATA_LENGTH..=Self::MAX_DATA_LENGTH).contains(&data_len) {
            self.buf.clear();
            return Some(Err(PacketError::InvalidDataLength { len: data_len }));
        }
        let total_len = Self::HEADER_LENGTH + data_len as usize;

        if total_len > self.buf.len() {
            return None;
        }

        let mut data: [u8; Packet::MAX_LENGTH] = [0; Packet::MAX_LENGTH];
        for i in 0..total_len {
            data[i] = self.buf.pop_front().unwrap_or(0);
        }

        Some(Packet::new(data))
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

#[derive(Debug)]
pub struct Packet {
    data: [u8; Packet::MAX_LENGTH],
    len: usize,
    addr: PacketAddress,
    typ: PacketType,
}

impl Packet {
    pub const MAX_LENGTH: usize = 64;

    pub fn new(data: [u8; Packet::MAX_LENGTH]) -> Result<Self, PacketError> {
        let len = (u8::from_le(data[1]) as usize + 2).min(Packet::MAX_LENGTH);

        let raw_addr = u8::from_le(data[0]);
        let addr = if let Some(addr) = PacketAddress::from_u8(raw_addr) {
            addr
        } else {
            return Err(PacketError::InvalidAddress { raw_addr });
        };

        let raw_type = u8::from_le(data[2]);
        let typ = if let Some(typ) = PacketType::from_u8(raw_type) {
            typ
        } else {
            return Err(PacketError::InvalidType { raw_type });
        };

        // NOTE: should we convert checksum to target endian? I don't think so but maybe I am wrong
        let checksum_idx = len - 1;
        let checksum = Self::calculate_checksum(&data[2..checksum_idx]);
        if checksum != data[checksum_idx] {
            return Err(PacketError::ChecksumMismatch {
                expected: u8::from_le(checksum),
                actual: u8::from_le(data[checksum_idx]),
            });
        }

        Ok(Self {
            data,
            len,
            addr,
            typ,
        })
    }

    pub fn new_from_slice(data_slc: &[u8]) -> Result<Self, PacketError> {
        let mut data: [u8; Packet::MAX_LENGTH] = [0; Packet::MAX_LENGTH];
        data[..data_slc.len().min(Packet::MAX_LENGTH)].copy_from_slice(data_slc);
        Self::new(data)
    }

    pub fn new_from_parts(addr: PacketAddress, payload: &PacketPayload) -> Self {
        let mut data: [u8; Packet::MAX_LENGTH] = [0; Packet::MAX_LENGTH];
        data[0] = u8::to_le(addr as u8);
        match payload {
            PacketPayload::LinkStatistics(payload) => {
                let len_byte = LinkStatistics::PAYLOAD_LENGTH + 2;
                let len = len_byte as usize + 2;
                data[1] = u8::to_le(len_byte);

                let typ = PacketType::LinkStatistics;
                data[2] = u8::to_le(typ as u8);

                unsafe { payload.write_unchecked(&mut data[3..]) }

                let checksum_idx = len - 1;
                data[checksum_idx] = Self::calculate_checksum(&data[2..checksum_idx]);

                Self {
                    data,
                    len,
                    addr,
                    typ,
                }
            }
            PacketPayload::RcChannels(payload) => {
                let len_byte = RcChannels::PAYLOAD_LENGTH + 2;
                let len = len_byte as usize + 2;
                data[1] = u8::to_le(len_byte);

                let typ = PacketType::RcChannelsPacked;
                data[2] = u8::to_le(typ as u8);

                unsafe { payload.write_unchecked(&mut data[3..]) }

                let checksum_idx = len - 1;
                data[checksum_idx] = Self::calculate_checksum(&data[2..checksum_idx]);

                Self {
                    data,
                    len,
                    addr,
                    typ,
                }
            }
        }
    }

    pub fn addr(&self) -> PacketAddress {
        self.addr
    }

    pub fn typ(&self) -> PacketType {
        self.typ
    }

    pub fn raw_payload(&self) -> &[u8] {
        &self.data[3..self.len]
    }

    pub fn raw_data(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn parse_payload(&self) -> Option<PacketPayload> {
        match self.typ {
            PacketType::LinkStatistics => Some(PacketPayload::LinkStatistics(unsafe {
                LinkStatistics::parse_unchecked(self.raw_payload())
            })),
            PacketType::RcChannelsPacked => Some(PacketPayload::RcChannels(unsafe {
                RcChannels::parse_unchecked(self.raw_payload())
            })),
            _ => None,
        }
    }

    fn calculate_checksum(data: &[u8]) -> u8 {
        let crc8_alg = Crc::<u8>::new(&CRC_8_DVB_S2);
        crc8_alg.checksum(data)
    }
}

#[non_exhaustive]
#[derive(Debug, PartialEq, Snafu)]
#[cfg_attr(feature = "defmt", defive(defmt::Format))]
pub enum PacketError {
    #[snafu(display("Invalid packet address: {raw_addr:#04x}"))]
    InvalidAddress { raw_addr: u8 },
    #[snafu(display("Invalid packet type: {raw_type:#04x}"))]
    InvalidType { raw_type: u8 },
    #[snafu(display("Checksum mismatch: expected {expected:#04x} but was {actual:#04x}"))]
    ChecksumMismatch { expected: u8, actual: u8 },
    #[snafu(display("Invalid data length: {len}"))]
    InvalidDataLength { len: u8 },
}

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
    use crate::PacketPayload;

    use super::CrsfPacketParser;
    use super::PacketError;
    use super::PacketType;
    use super::RcChannels;

    #[test]
    fn test_parse_next_packet() {
        let mut parser = CrsfPacketParser::default();

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
            Some(Ok(packet)) => {
                assert_eq!(packet.addr(), addr);
                assert_eq!(packet.typ(), typ);
                if let Some(PacketPayload::RcChannels(RcChannels(channels))) =
                    packet.parse_payload()
                {
                    assert_eq!(channels, [0; 16]);
                } else {
                    panic!("Packet was supposed to have a rc channels as payload")
                }
            }
            Some(Err(e)) => panic!("Packet expected instead of an error: {}", e),
        }
        assert!(matches!(parser.next_packet(), None));
    }

    #[test]
    fn test_parse_next_packet_with_validation_error() {
        let mut parser = CrsfPacketParser::default();

        // Sync
        parser.push_bytes(&[0xc8]);
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
        let mut parser = CrsfPacketParser::default();

        // Sync
        parser.push_bytes(&[0xc8]);
        assert!(
            matches!(parser.next_packet(), None)
        );
        // Len
        parser.push_bytes(&[0]);
        match parser.next_packet() {
            None | Some(Ok(_)) => panic!("Validation error expected"),
            Some(Err(e)) => {
                assert_eq!(e, PacketError::InvalidDataLength { len: 0 })
            }
        }
        assert!(
            matches!(parser.next_packet(), None)
        );
    }

    #[test]
    fn test_parse_next_packet_with_max_len() {
        let mut parser = CrsfPacketParser::default();

        // Sync
        parser.push_bytes(&[0xc8]);
        assert!(
            matches!(parser.next_packet(), None)
        );
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
                assert_eq!(e, PacketError::InvalidType { raw_type: 0xff })
            }
        }
        assert!(
            matches!(parser.next_packet(), None)
        );
    }

    #[test]
    fn test_parse_next_packet_with_too_big_len() {
        let mut parser = CrsfPacketParser::default();

        // Sync
        parser.push_bytes(&[0xc8]);
        assert!(
            matches!(parser.next_packet(), None)
        );
        // Len
        parser.push_bytes(&[63]);
        match parser.next_packet() {
            None | Some(Ok(_)) => panic!("Validation error expected"),
            Some(Err(e)) => {
                assert_eq!(e, PacketError::InvalidDataLength { len: 63 })
            }
        }
        assert!(
            matches!(parser.next_packet(), None)
        );
    }

    #[test]
    fn test_packet_construction() {
        let addr = PacketAddress::Controller;
        let typ = PacketType::RcChannelsPacked;

        let channels: [u16; 16] = [0; 16];
        let payload = PacketPayload::RcChannels(RcChannels(channels));

        let packet = Packet::new_from_parts(addr, &payload);

        assert_eq!(packet.addr, addr);
        assert_eq!(packet.typ, typ);

        let packet2 = Packet::new_from_slice(packet.raw_data()).unwrap();
        assert_eq!(packet2.addr, addr);
        assert_eq!(packet2.typ, typ);
        if let Some(PacketPayload::RcChannels(RcChannels(channels2))) = packet2.parse_payload() {
            assert_eq!(channels, channels2);
        }
    }
}
