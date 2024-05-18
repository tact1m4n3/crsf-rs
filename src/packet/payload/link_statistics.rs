//! LinkStatistics packet and related functions/implementations

use crate::{
    to_array::{mut_array_start, ref_array_start},
    Error, PacketType, Payload,
};

/// Represents a LinkStatistics packet
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(missing_docs)]
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

const LEN: usize = LinkStatistics::LEN;

/// The raw decoder (parser) for the LinkStatistics packet.
pub fn raw_decode(data: &[u8; LEN]) -> LinkStatistics {
    LinkStatistics {
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

/// The raw encoder (serializer) for the LinkStatistics packet.
pub fn raw_encode(link_statistics: &LinkStatistics, data: &mut [u8; LEN]) {
    data[0] = link_statistics.uplink_rssi_1;
    data[1] = link_statistics.uplink_rssi_2;
    data[2] = link_statistics.uplink_link_quality;
    data[3] = link_statistics.uplink_snr as u8;
    data[4] = link_statistics.active_antenna;
    data[5] = link_statistics.rf_mode;
    data[6] = link_statistics.uplink_tx_power;
    data[7] = link_statistics.downlink_rssi;
    data[8] = link_statistics.downlink_link_quality;
    data[9] = link_statistics.downlink_snr as u8;
}

impl Payload for LinkStatistics {
    const LEN: usize = 10;

    fn packet_type(&self) -> PacketType {
        PacketType::LinkStatistics
    }

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        let data: &[u8; LEN] = ref_array_start(buf).ok_or(Error::BufferError)?;

        Ok(raw_decode(data))
    }

    fn encode<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let data: &mut [u8; LEN] = mut_array_start(buf).ok_or(Error::BufferError)?;

        raw_encode(self, data);

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::LinkStatistics;
    use crate::Payload;

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

        let raw = original.to_raw_packet().unwrap();

        let data = raw.payload().unwrap();

        assert_eq!(data[0], 100_u8);
        assert_eq!(data[1], 98_u8);
        assert_eq!(data[2], 100_u8);
        assert_eq!(data[3], -(65_i8) as u8);
        assert_eq!(data[4], 0_u8);
        assert_eq!(data[5], 1_u8);
        assert_eq!(data[6], 2_u8);
        assert_eq!(data[7], 120_u8);
        assert_eq!(data[8], 98_u8);
        assert_eq!(data[9], -(68_i8) as u8);

        let parsed = LinkStatistics::decode(&data).unwrap();

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
