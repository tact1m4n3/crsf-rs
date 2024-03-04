use bitfield::bitfield;

use core::marker::PhantomData;

#[derive(Debug)]
pub struct RcChannels(pub [u16; 16]);

impl RcChannels {
    pub const CHANNEL_VALUE_MIN: u16 = 172;
    pub const CHANNEL_VALUE_1000: u16 = 191;
    pub const CHANNEL_VALUE_MID: u16 = 992;
    pub const CHANNEL_VALUE_2000: u16 = 1792;
    pub const CHANNEL_VALUE_MAX: u16 = 1811;

    pub(crate) const PAYLOAD_LENGTH: u8 = 22;

    pub(crate) unsafe fn parse_unchecked(data: &[u8]) -> Self {
        let raw_channels = RcChannelsPacked(data);

        Self([
            u16::from_le(raw_channels.ch0()),
            u16::from_le(raw_channels.ch1()),
            u16::from_le(raw_channels.ch2()),
            u16::from_le(raw_channels.ch3()),
            u16::from_le(raw_channels.ch4()),
            u16::from_le(raw_channels.ch5()),
            u16::from_le(raw_channels.ch6()),
            u16::from_le(raw_channels.ch7()),
            u16::from_le(raw_channels.ch8()),
            u16::from_le(raw_channels.ch9()),
            u16::from_le(raw_channels.ch10()),
            u16::from_le(raw_channels.ch11()),
            u16::from_le(raw_channels.ch12()),
            u16::from_le(raw_channels.ch13()),
            u16::from_le(raw_channels.ch14()),
            u16::from_le(raw_channels.ch15()),
        ])
    }

    pub(crate) unsafe fn write_unchecked(&self, data: &mut [u8]) {
        use bitfield::BitRangeMut;

        let mut raw_channels = RcChannelsPacked(data);
        for (i, val) in self.0.iter().enumerate() {
            raw_channels.set_bit_range(11 * (i + 1) - 1, 11 * i, val.to_le());
        }
    }
}

impl core::ops::Deref for RcChannels {
    type Target = [u16; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for RcChannels {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

bitfield! {
    struct RcChannelsPacked([u8]);
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

// THOUGHT: MAYBE ADD AN INVERSE MAPPING FUNCTION
pub trait ChannelMapper {
    fn map(val: u16) -> i32;
}

pub struct DefaultChannelsMapper;

impl ChannelMapper for DefaultChannelsMapper {
    #[rustfmt::skip]
    fn map(val: u16) -> i32 {
        1000
            + (val.saturating_sub(RcChannels::CHANNEL_VALUE_1000) as i32 * (2000 - 1000) * 2
            / (RcChannels::CHANNEL_VALUE_2000 - RcChannels::CHANNEL_VALUE_1000) as i32 + 1) / 2
    }
}

pub struct RcChannelsMapped<M: ChannelMapper> {
    channels: [i32; 16],
    _phantom: PhantomData<M>,
}

impl<M: ChannelMapper> RcChannelsMapped<M> {
    pub fn new(channels: &RcChannels) -> Self {
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
        f.debug_tuple("RcChannelsMapped")
            .field(&self.channels)
            .finish()
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
    use crate::{Packet, RcChannels};

    #[test]
    fn test_rc_channels_write_and_parse() {
        let mut original = RcChannels([0; 16]);
        for i in 0..16 {
            original[i] = i as u16 * 10;
        }

        let mut data = [0u8; Packet::MAX_LENGTH];
        unsafe { original.write_unchecked(&mut data) }

        let parsed = unsafe { RcChannels::parse_unchecked(&data) };
        for i in 0..16 {
            assert_eq!(parsed[i], i as u16 * 10);
        }
    }
}
