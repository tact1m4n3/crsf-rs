use crate::{Payload, PacketType};

/// Stores LinkStatistics packet data
#[derive(Clone, Debug)]
pub struct LinkStatistics {
    pub uplink_rssi_1: u8,
    pub uplink_rssi_2: u8,
    pub uplink_link_quality: u8,
    pub uplink_snr: i8,
    pub active_antenna: u8,
    pub rf_mode: u8,
    pub uplink_tx_power: u8,
    pub downlink_rssi: u8,
    pub downlink_link_quality: u8,
    pub downlink_snr: i8,
}

impl LinkStatistics {
    pub(crate) const PAYLOAD_LENGTH: u8 = 10;

    pub(crate) fn parse(data: &[u8]) -> Self {
        Self {
            uplink_rssi_1: data[0],
            uplink_rssi_2: data[1],
            uplink_link_quality: data[2],
            uplink_snr: data[3] as i8,
            active_antenna: data[4],
            rf_mode: data[5],
            uplink_tx_power: data[6],
            downlink_rssi: data[7],
            downlink_link_quality: data[8],
            downlink_snr: data[9] as i8,
        }
    }
}

impl Payload for LinkStatistics {
    fn len(&self) -> u8 { Self::PAYLOAD_LENGTH }

    fn packet_type(&self) -> PacketType { PacketType::LinkStatistics }

    fn dump(&self, data: &mut [u8]) {
        data[0] = self.uplink_rssi_1;
        data[1] = self.uplink_rssi_2;
        data[2] = self.uplink_link_quality;
        data[3] = self.uplink_snr as u8;
        data[4] = self.active_antenna;
        data[5] = self.rf_mode;
        data[6] = self.uplink_tx_power;
        data[7] = self.downlink_rssi;
        data[8] = self.downlink_link_quality;
        data[9] = self.downlink_snr as u8;
    }
}

#[cfg(test)]
mod tests {
    use crate::{LinkStatistics, Packet};
    use crate::packets::Payload;

    #[test]
    fn test_link_statistics_write_and_parse() {
        let original = LinkStatistics {
            uplink_rssi_1: 100,
            uplink_rssi_2: 98,
            uplink_link_quality: 100,
            uplink_snr: -65,
            active_antenna: 0,
            rf_mode: 1,
            uplink_tx_power: 2,
            downlink_rssi: 120,
            downlink_link_quality: 98,
            downlink_snr: -68,
        };

        let mut data = [0u8; Packet::MAX_LENGTH];
        original.dump(&mut data);

        assert_eq!(data[0], 100_u8.to_le());
        assert_eq!(data[1], 98_u8.to_le());
        assert_eq!(data[2], 100_u8.to_le());
        assert_eq!(data[3], -(65_i8.to_le()) as u8);
        assert_eq!(data[4], 0_u8.to_le());
        assert_eq!(data[5], 1_u8.to_le());
        assert_eq!(data[6], 2_u8.to_le());
        assert_eq!(data[7], 120_u8.to_le());
        assert_eq!(data[8], 98_u8.to_le());
        assert_eq!(data[9], -(68_i8.to_le()) as u8);

        let parsed = LinkStatistics::parse(&data);

        assert_eq!(parsed.uplink_rssi_1, 100);
        assert_eq!(parsed.uplink_rssi_2, 98);
        assert_eq!(parsed.uplink_link_quality, 100);
        assert_eq!(parsed.uplink_snr, -65);
        assert_eq!(parsed.active_antenna, 0);
        assert_eq!(parsed.rf_mode, 1);
        assert_eq!(parsed.uplink_tx_power, 2);
        assert_eq!(parsed.downlink_rssi, 120);
        assert_eq!(parsed.downlink_link_quality, 98);
        assert_eq!(parsed.downlink_snr, -68);
    }
}
