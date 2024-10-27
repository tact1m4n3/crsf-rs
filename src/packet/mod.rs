//! This module contains defines the behavior of a Payload, and provides implementations for
//! various payloads used in the CRSF protocol.

mod link_statistics;
pub use link_statistics::LinkStatistics;

mod rc_channels_packed;
pub use rc_channels_packed::RcChannelsPacked;

mod device_ping;
pub use device_ping::DevicePing;

use crate::{ParseError, CRC8, SYNC_BYTE};
use num_enum::TryFromPrimitive;
use snafu::Snafu;

/// Wrapper struct for the raw data of a packet with valid length and checksum.
pub struct RawPacket<'a>(pub(crate) &'a [u8]);

impl RawPacket<'_> {
    /// Returns the inner data
    pub fn data(&self) -> &[u8] {
        self.0
    }
}

/// Enum of implemented packets.
#[non_exhaustive]
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Packet {
    LinkStatistics(LinkStatistics),
    RcChannelsPacked(RcChannelsPacked),
    Extended {
        dst: PacketAddress,
        src: PacketAddress,
        packet: ExtendedPacket,
    },
}

/// Enum of implemented extended packets.
#[non_exhaustive]
#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ExtendedPacket {
    DevicePing(DevicePing),
}

impl Packet {
    /// Parses a `RawPacket`
    pub fn parse(raw_packet: RawPacket<'_>) -> Result<Self, ParseError> {
        let data = raw_packet.data();

        let typ = if let Ok(typ) = PacketType::try_from_primitive(data[2]) {
            typ
        } else {
            return Err(ParseError::InvalidType { typ: data[2] });
        };

        let payload = &data[3..data.len() - 1];
        match typ {
            PacketType::RcChannelsPacked => {
                Ok(Packet::RcChannelsPacked(RcChannelsPacked::parse(payload)))
            }
            PacketType::LinkStatistics => {
                Ok(Packet::LinkStatistics(LinkStatistics::parse(payload)))
            }
            typ if typ.is_extended() => {
                let dst = PacketAddress::try_from_primitive(payload[0])
                    .map_err(|_| ParseError::InvalidAddress { addr: payload[0] })?;
                let src = PacketAddress::try_from_primitive(payload[1])
                    .map_err(|_| ParseError::InvalidAddress { addr: payload[1] })?;
                let _payload = &payload[2..];
                match typ {
                    PacketType::DevicePing => Ok(Packet::Extended {
                        dst,
                        src,
                        packet: ExtendedPacket::DevicePing(DevicePing),
                    }),
                    _ => Err(ParseError::UnimplementedType { typ }),
                }
            }
            _ => Err(ParseError::UnimplementedType { typ }),
        }
    }
}

/// Enum of all CRSF packet addresses.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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

/// Enum of all CRSF packet types.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    /// Returns `true` if the current packet is extended otherwise `false`.
    pub fn is_extended(self) -> bool {
        self as u8 >= 0x28
    }
}

/// This trait is implemented for all packet types.
#[allow(clippy::len_without_is_empty)]
pub trait Payload {
    /// Returns the length required to store the payload.
    fn len(&self) -> usize;

    /// Returns the type of the packet.
    fn typ(&self) -> PacketType;

    /// Encodes the payload into a mutable slice. This does not include the `sync`, `len`, `type`, or
    /// `crc` bytes. Assumes the length of the buffer to be at least larger than the payload size.
    fn encode(&self, buf: &mut [u8]);
}

#[allow(clippy::len_without_is_empty)]
pub trait PayloadDump: Payload {
    /// Dumps the packet into a mutable slice.
    fn dump(&self, buf: &mut [u8]) -> Result<usize, DumpError> {
        self.dump_with_sync(buf, SYNC_BYTE)
    }

    /// Dumps the packet into a mutable slice using a custom sync byte.
    fn dump_with_sync(&self, buf: &mut [u8], sync_byte: u8) -> Result<usize, DumpError> {
        let payload_len = self.len();
        let total_len = payload_len + 4;
        if buf.len() < total_len {
            return Err(DumpError {
                expected_buf_len: total_len,
            });
        }

        buf[0] = sync_byte;
        buf[1] = payload_len as u8 + 2;
        buf[2] = self.typ() as u8;
        self.encode(&mut buf[3..total_len - 1]);
        buf[total_len - 1] = CRC8.checksum(&buf[2..total_len - 1]);

        Ok(total_len)
    }
}

#[allow(clippy::len_without_is_empty)]
pub trait ExtendedPayloadDump: Payload {
    /// Dumps the packet into a mutable slice.
    fn dump(
        &self,
        buf: &mut [u8],
        dst: PacketAddress,
        src: PacketAddress,
    ) -> Result<usize, DumpError> {
        self.dump_with_sync(buf, SYNC_BYTE, dst, src)
    }

    /// Dumps the packet into a mutable slice using a custom sync byte.
    fn dump_with_sync(
        &self,
        buf: &mut [u8],
        sync_byte: u8,
        dst: PacketAddress,
        src: PacketAddress,
    ) -> Result<usize, DumpError> {
        let payload_len = self.len();
        let total_len = payload_len + 6;
        if buf.len() < total_len {
            return Err(DumpError {
                expected_buf_len: total_len,
            });
        }

        buf[0] = sync_byte;
        buf[1] = payload_len as u8 + 4;
        buf[2] = self.typ() as u8;
        buf[3] = dst as u8;
        buf[4] = src as u8;
        self.encode(&mut buf[5..total_len - 1]);
        buf[total_len - 1] = CRC8.checksum(&buf[2..total_len - 1]);

        Ok(total_len)
    }
}

/// Buffer too small error for `Packet` dump.
#[derive(Debug, PartialEq, Snafu)]
#[snafu(display("Dump buffer length too small: expected at least {expected_buf_len} bytes"))]
pub struct DumpError {
    pub expected_buf_len: usize,
}

#[cfg(test)]
mod tests {
    use crate::{
        DevicePing, ExtendedPacket, ExtendedPayloadDump, LinkStatistics, Packet, PacketAddress,
        PayloadDump, RawPacket, RcChannelsPacked, MAX_PACKET_LEN, SYNC_BYTE,
    };

    #[test]
    fn test_rc_channels_packed_dump_and_parse() {
        let mut expected_data: [u8; 26] = [0xff; 26];
        expected_data[0] = SYNC_BYTE;
        expected_data[1] = 24;
        expected_data[2] = 0x16;
        expected_data[25] = 143;

        let orig = RcChannelsPacked([0x7FF; 16]);
        let mut buf = [0u8; MAX_PACKET_LEN];
        let len = orig.dump(&mut buf).unwrap();

        assert_eq!(&buf[..len], expected_data.as_slice());

        let result = Packet::parse(RawPacket(&buf[..len]));
        assert_eq!(result, Ok(Packet::RcChannelsPacked(orig)));
    }

    #[test]
    fn test_link_statistics_dump_and_parse() {
        let expected_data = [
            SYNC_BYTE, 12, 0x14, 16, 19, 99, 151, 1, 2, 3, 8, 88, 148, 252,
        ];

        let orig = LinkStatistics {
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

        let mut buf = [0u8; MAX_PACKET_LEN];
        let len = orig.dump(&mut buf).unwrap();

        assert_eq!(&buf[..len], expected_data.as_slice());

        let result = Packet::parse(RawPacket(&buf[..len]));
        assert_eq!(result, Ok(Packet::LinkStatistics(orig)));
    }

    #[test]
    fn test_device_ping_dump_and_parse() {
        let expected_data = [
            SYNC_BYTE,
            0x04,
            0x28,
            PacketAddress::Broadcast as u8,
            PacketAddress::Handset as u8,
            0x54,
        ];

        let orig = DevicePing;
        let mut buf = [0u8; MAX_PACKET_LEN];
        let len = orig
            .dump(&mut buf, PacketAddress::Broadcast, PacketAddress::Handset)
            .unwrap();

        assert_eq!(&buf[..len], expected_data.as_slice());

        let result = Packet::parse(RawPacket(&buf[..len]));
        assert_eq!(
            result,
            Ok(Packet::Extended {
                dst: PacketAddress::Broadcast,
                src: PacketAddress::Handset,
                packet: ExtendedPacket::DevicePing(orig)
            })
        );
    }
}
