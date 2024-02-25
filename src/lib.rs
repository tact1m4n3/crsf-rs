#![no_std]

extern crate bitfield;
extern crate crc;

use core::marker::PhantomData;

use bitfield::{bitfield, BitRangeMut};
use buffer::CircularBuffer;
use crc::{Crc, CRC_8_DVB_S2};

mod buffer;

#[derive(Default)]
pub struct CrsfPacketParser {
    buf: CircularBuffer<{ 4 * Packet::MAX_LENGTH }>,
}

impl CrsfPacketParser {
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        bytes.iter().for_each(|&val| {
            self.buf.push_back(val);
        });
    }

    pub fn next_packet(&mut self) -> Option<Packet> {
        loop {
            self.sync();

            if self.buf.len() < 2 {
                break None;
            }

            let len =
                (u8::from_le(self.buf.peek_front(1).unwrap()) as usize + 2).min(Packet::MAX_LENGTH);

            if len >= self.buf.len() {
                break None;
            }

            let mut data: [u8; Packet::MAX_LENGTH] = [0; Packet::MAX_LENGTH];
            for i in 0..len {
                data[i] = self.buf.pop_front().unwrap_or(0);
            }

            if let Some(packet) = Packet::parse(&data[..len]) {
                break Some(packet);
            }
        }
    }

    fn sync(&mut self) {
        while self
            .buf
            .peek_front(0)
            .is_some_and(|val| Destination::from_u8(val).is_none())
        {
            self.buf.pop_front();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Destination {
    Transmitter = 0xEE,
    Handset = 0xEA,
    Controller = 0xC8,
    Receiver = 0xEC,
}

impl Destination {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0xEE => Some(Destination::Transmitter),
            0xEA => Some(Destination::Handset),
            0xC8 => Some(Destination::Controller),
            0xEC => Some(Destination::Receiver),
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

#[derive(Debug, Clone)]
pub enum Packet {
    LinkStatistics(LinkStatistics),
    RcChannelsPacked(RcChannelsPacked),
}

impl Packet {
    pub const MAX_LENGTH: usize = 64;

    pub fn new_rc_channel_packet(dest: Destination, channel_vals: &[u16]) -> [u8; 26] {
        let mut buf: [u8; 26] = [0; 26];
        buf[0] = dest as u8;
        buf[1] = 0x18;
        buf[2] = PacketType::RcChannelsPacked as u8;
        let mut a = RcChannelsRaw(&mut buf[3..=24]);
        for (index, val) in channel_vals.iter().enumerate() {
            a.set_bit_range(11 * (index + 1) - 1, 11 * index, *val);
        }
        let crc8_alg = Crc::<u8>::new(&CRC_8_DVB_S2);
        buf[25] = crc8_alg.checksum(&buf[2..buf.len()-1]);
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if !Self::validate(data) {
            return None;
        }

        let len = data.len();
        let payload = &data[3..len - 1];
        if let Some(typ) = PacketType::from_u8(u8::from_le(data[2])) {
            match typ {
                PacketType::LinkStatistics => {
                    Some(Packet::LinkStatistics(LinkStatistics::parse(payload)))
                }
                PacketType::RcChannelsPacked => {
                    Some(Packet::RcChannelsPacked(RcChannelsPacked::parse(payload)))
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn validate(data: &[u8]) -> bool {
        let len = data.len();
        let crc8_alg = Crc::<u8>::new(&CRC_8_DVB_S2);
        let crc8 = crc8_alg.checksum(&data[2..len - 1]);
        crc8 == data[len - 1]
    }
}

#[derive(Debug, Clone)]
pub struct LinkStatistics {
    pub uplink_rssi: i16,
    pub uplink_lq: u8,
    pub downlink_rssi: i16,
    pub downlink_lq: u8,
    pub rf_mode: u8,
    pub uplink_tx_power: u8,
}

impl LinkStatistics {
    pub fn parse(data: &[u8]) -> Self {
        let antenna = u8::from_le(data[4]);

        Self {
            uplink_rssi: if antenna == 0 {
                -(u8::from_le(data[0]) as i16)
            } else {
                -(u8::from_le(data[1]) as i16)
            },
            uplink_lq: u8::from_le(data[2]),
            downlink_rssi: -(u8::from_le(data[7]) as i16),
            downlink_lq: u8::from_le(data[8]),
            rf_mode: u8::from_le(data[5]),
            uplink_tx_power: u8::from_le(data[6]),
        }
    }
}

bitfield! {
    struct RcChannelsRaw([u8]);
    u16;
    ch0, _: 10, 0;
    ch1, _: 21, 11;
    ch2, _: 32, 22;
    ch3, _: 43, 33;
    ch4, _: 54, 44;
    ch5, _: 65, 55;
    ch6, _: 76, 66;
    ch7, _: 87, 77;
    ch8, _: 98, 88;
    ch9, _: 109, 99;
    ch10, _: 120, 110;
    ch11, _: 131, 121;
    ch12, _: 142, 132;
    ch13, _: 153, 143;
    ch14, _: 164, 154;
    ch15, _: 175, 165;
}

#[derive(Debug, Clone)]
pub struct RcChannelsPacked([u16; 16]);

impl RcChannelsPacked {
    pub const CHANNEL_VALUE_MIN: u16 = 172;
    pub const CHANNEL_VALUE_1000: u16 = 191;
    pub const CHANNEL_VALUE_MID: u16 = 992;
    pub const CHANNEL_VALUE_2000: u16 = 1792;
    pub const CHANNEL_VALUE_MAX: u16 = 1811;

    pub fn parse(data: &[u8]) -> Self {
        let channels_raw = RcChannelsRaw(data);

        Self([
            u16::from_le(channels_raw.ch0()),
            u16::from_le(channels_raw.ch1()),
            u16::from_le(channels_raw.ch2()),
            u16::from_le(channels_raw.ch3()),
            u16::from_le(channels_raw.ch4()),
            u16::from_le(channels_raw.ch5()),
            u16::from_le(channels_raw.ch6()),
            u16::from_le(channels_raw.ch7()),
            u16::from_le(channels_raw.ch8()),
            u16::from_le(channels_raw.ch9()),
            u16::from_le(channels_raw.ch10()),
            u16::from_le(channels_raw.ch11()),
            u16::from_le(channels_raw.ch12()),
            u16::from_le(channels_raw.ch13()),
            u16::from_le(channels_raw.ch14()),
            u16::from_le(channels_raw.ch15()),
        ])
    }
}

impl core::ops::Deref for RcChannelsPacked {
    type Target = [u16; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for RcChannelsPacked {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub trait ChannelMapper {
    fn map(val: u16) -> i32;
}

pub struct DefaultChannelsMapper;

impl ChannelMapper for DefaultChannelsMapper {
    #[rustfmt::skip]
    fn map(val: u16) -> i32 {
        1000
            + (val.saturating_sub(RcChannelsPacked::CHANNEL_VALUE_1000) as i32 * (2000 - 1000) * 2
            / (RcChannelsPacked::CHANNEL_VALUE_2000 - RcChannelsPacked::CHANNEL_VALUE_1000) as i32 + 1) / 2
    }
}

#[derive(Clone)]
pub struct RcChannelsMapped<M: ChannelMapper> {
    channels: [i32; 16],
    _phantom: PhantomData<M>,
}

impl<M: ChannelMapper> RcChannelsMapped<M> {
    pub fn new(channels: RcChannelsPacked) -> Self {
        Self {
            channels: [
                M::map(channels.0[0]),
                M::map(channels.0[1]),
                M::map(channels.0[2]),
                M::map(channels.0[3]),
                M::map(channels.0[4]),
                M::map(channels.0[5]),
                M::map(channels.0[6]),
                M::map(channels.0[7]),
                M::map(channels.0[8]),
                M::map(channels.0[9]),
                M::map(channels.0[10]),
                M::map(channels.0[11]),
                M::map(channels.0[12]),
                M::map(channels.0[13]),
                M::map(channels.0[14]),
                M::map(channels.0[15]),
            ],
            _phantom: PhantomData,
        }
    }
}

impl<M: ChannelMapper> core::fmt::Debug for RcChannelsMapped<M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("RcChannelsMapped").field(&self.channels).finish()
    }
}

impl<M: ChannelMapper> core::ops::Deref for RcChannelsMapped<M> {
    type Target = [i32; 16];

    fn deref(&self) -> &Self::Target {
        &self.channels
    }
}

impl<M: ChannelMapper> core::ops::DerefMut for RcChannelsMapped<M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.channels
    }
}

#[cfg(test)]
mod tests {

    use crate::{Destination, Packet};

    use super::RcChannelsPacked;

    #[test]
    fn test_parse_rc_channels() {
        assert_eq!(
            RcChannelsPacked::parse(&[0; 22]).0,
            [0; 16]
        );
        assert_eq!(
            RcChannelsPacked::parse(&[0xff; 22]).0,
            [2047; 16]
        );
    }

    #[test]
    fn test_pack_rc_channel_packet() {
        let buf = Packet::new_rc_channel_packet(Destination::Transmitter, &[1000;16]);
        let parse_result = Packet::parse(&buf);
        assert!(parse_result.is_some());
        let packet = parse_result.unwrap();
        match packet{
            Packet::RcChannelsPacked(x) => {
                x.iter().for_each(|y |{
                    assert_eq!(*y,1000);
                });
            },
            _ => panic!("failed")
        }
    }
}
