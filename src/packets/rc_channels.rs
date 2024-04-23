use crate::{
    to_array::{mut_array_start, ref_array_start},
    PacketType, Payload,
};

/// Stores RcChannelsPacked packet data
#[derive(Clone, Debug)]
pub struct RcChannels(pub [u16; 16]);

impl RcChannels {
    /// Minimum channel value
    pub const CHANNEL_VALUE_MIN: u16 = 172;
    /// Channel value coresponding to 1000 in betaflight
    pub const CHANNEL_VALUE_1000: u16 = 191;
    /// Middle channel value
    pub const CHANNEL_VALUE_MID: u16 = 992;
    /// Channel value coresponding to 2000 in betaflight
    pub const CHANNEL_VALUE_2000: u16 = 1792;
    /// Max channel value
    pub const CHANNEL_VALUE_MAX: u16 = 1811;

    pub const CHANNEL_11_BITS: u16 = 0x7FF;

    pub(crate) const PAYLOAD_LENGTH: u8 = 22;

    pub(crate) fn parse(data: &[u8]) -> Self {
        // Ensure fixed-size array to allow compiler to check
        // that all literal indexes are within bounds.
        let data = ref_array_start::<{ Self::PAYLOAD_LENGTH as usize }>(data).unwrap();

        // Convert u8 to u16 to make room for bit shifting
        let data: [u16; Self::PAYLOAD_LENGTH as usize] = core::array::from_fn(|i| data[i] as u16);

        // Initialize all channels to 11 high bits for masking
        let mut ch = [Self::CHANNEL_11_BITS; 16];

        ch[0] &= data[0] | data[1] << 8;
        ch[1] &= data[1] >> 3 | data[2] << 5;
        ch[2] &= data[2] >> 6 | data[3] << 2 | data[4] << 10;
        ch[3] &= data[4] >> 1 | data[5] << 7;
        ch[4] &= data[5] >> 4 | data[6] << 4;
        ch[5] &= data[6] >> 7 | data[7] << 1 | data[8] << 9;
        ch[6] &= data[8] >> 2 | data[9] << 6;
        ch[7] &= data[9] >> 5 | data[10] << 3;
        ch[8] &= data[11] | data[12] << 8;
        ch[9] &= data[12] >> 3 | data[13] << 5;
        ch[10] &= data[13] >> 6 | data[14] << 2 | data[15] << 10;
        ch[11] &= data[15] >> 1 | data[16] << 7;
        ch[12] &= data[16] >> 4 | data[17] << 4;
        ch[13] &= data[17] >> 7 | data[18] << 1 | data[19] << 9;
        ch[14] &= data[19] >> 2 | data[20] << 6;
        ch[15] &= data[20] >> 5 | data[21] << 3;

        RcChannels(ch)
    }
}

impl Payload for RcChannels {
    fn len(&self) -> u8 {
        Self::PAYLOAD_LENGTH
    }

    fn packet_type(&self) -> PacketType {
        PacketType::RcChannelsPacked
    }

    fn dump(&self, data: &mut [u8]) {
        // Ensure fixed-size array to allow compiler to check
        // that all literal indexes are within bounds.
        let data = mut_array_start::<{ Self::PAYLOAD_LENGTH as usize }>(data).unwrap();

        // Short-hand naming
        let ch = &self.0;

        // Send correctly formatted data if all channels are within bounds
        if self.0.iter().all(|ch| *ch <= Self::CHANNEL_11_BITS) {
            data[0] = (ch[0]) as u8;
            data[1] = (ch[0] >> 8 | ch[1] << 3) as u8;
            data[2] = (ch[1] >> 5 | ch[2] << 6) as u8;
            data[3] = (ch[2] >> 2) as u8;
            data[4] = (ch[2] >> 10 | ch[3] << 1) as u8;
            data[5] = (ch[3] >> 7 | ch[4] << 4) as u8;
            data[6] = (ch[4] >> 4 | ch[5] << 7) as u8;
            data[7] = (ch[5] >> 1) as u8;
            data[8] = (ch[5] >> 9 | ch[6] << 2) as u8;
            data[9] = (ch[6] >> 6 | ch[7] << 5) as u8;
            data[10] = (ch[7] >> 3) as u8;
            data[11] = (ch[8]) as u8;
            data[12] = (ch[8] >> 8 | ch[9] << 3) as u8;
            data[13] = (ch[9] >> 5 | ch[10] << 6) as u8;
            data[14] = (ch[10] >> 2) as u8;
            data[15] = (ch[10] >> 10 | ch[11] << 1) as u8;
            data[16] = (ch[11] >> 7 | ch[12] << 4) as u8;
            data[17] = (ch[12] >> 4 | ch[13] << 7) as u8;
            data[18] = (ch[13] >> 1) as u8;
            data[19] = (ch[13] >> 9 | ch[14] << 2) as u8;
            data[20] = (ch[14] >> 6 | ch[15] << 5) as u8;
            data[21] = (ch[15] >> 3) as u8;

        // If *any* channel is out of bounds, clamp *everything* to the maximum value
        } else {
            data.iter_mut().for_each(|e| *e = Self::CHANNEL_11_BITS as u8);
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

#[cfg(test)]
mod tests {
    use crate::packets::Payload;
    use crate::{Packet, RcChannels};

    #[test]
    fn test_rc_channels_write_and_parse() {
        let mut original = RcChannels([0; 16]);
        for i in 0..16 {
            original[i] = i as u16 * 10;
        }

        let mut data = [0u8; Packet::MAX_LENGTH];
        original.dump(&mut data);

        let parsed = RcChannels::parse(&data);
        for i in 0..16 {
            assert_eq!(parsed[i], i as u16 * 10);
        }
    }
}
