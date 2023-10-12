#![no_std]

use bitfield::bitfield;
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

#[derive(Debug, Clone, Copy)]
pub enum Packet {
    LinkStatistics(LinkStatistics),
    RcChannelsPacked(RcChannelsPacked),
}

impl Packet {
    pub const MAX_LENGTH: usize = 64;

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
        if crc8 == data[len - 1] {
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, Copy)]
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
    ch7, _: 80, 77;
    ch8, _: 90, 88;
    ch9, _: 100, 99;
    ch10, _: 120, 110;
    ch11, _: 131, 121;
    ch12, _: 142, 132;
    ch13, _: 153, 143;
    ch14, _: 164, 154;
    ch15, _: 175, 165;
}

#[derive(Debug, Clone, Copy)]
pub struct RcChannelsPacked(pub [u16; 16]);

impl RcChannelsPacked {
    pub fn parse(data: &[u8]) -> Self {
        let channels_raw = RcChannelsRaw(data);

        Self([
            Self::map_chan(u16::from_le(channels_raw.ch0())),
            Self::map_chan(u16::from_le(channels_raw.ch1())),
            Self::map_chan(u16::from_le(channels_raw.ch2())),
            Self::map_chan(u16::from_le(channels_raw.ch3())),
            Self::map_chan(u16::from_le(channels_raw.ch4())),
            Self::map_chan(u16::from_le(channels_raw.ch5())),
            Self::map_chan(u16::from_le(channels_raw.ch6())),
            Self::map_chan(u16::from_le(channels_raw.ch7())),
            Self::map_chan(u16::from_le(channels_raw.ch8())),
            Self::map_chan(u16::from_le(channels_raw.ch9())),
            Self::map_chan(u16::from_le(channels_raw.ch10())),
            Self::map_chan(u16::from_le(channels_raw.ch11())),
            Self::map_chan(u16::from_le(channels_raw.ch12())),
            Self::map_chan(u16::from_le(channels_raw.ch13())),
            Self::map_chan(u16::from_le(channels_raw.ch14())),
            Self::map_chan(u16::from_le(channels_raw.ch15())),
        ])
    }

    const fn map_chan(x: u16) -> u16 {
        (1000 + (((x as u32).saturating_sub(191)) * (2000 - 1000) * 2 / (1792 - 191) + 1) / 2)
            as u16
    }
}
