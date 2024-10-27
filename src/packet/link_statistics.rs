use crate::{PacketType, Payload, PayloadDump};

/// `LinkStatistics` payload type
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

const LEN: usize = 10;

impl LinkStatistics {
    /// Parses a `LinkStatistics` payload (assumes it to be valid).
    pub(crate) fn parse(data: &[u8]) -> Self {
        let data: &[u8; LEN] = crate::util::ref_array_start(data).expect("buffer length mismatch");

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
}

impl Payload for LinkStatistics {
    fn len(&self) -> usize {
        LEN
    }

    fn typ(&self) -> PacketType {
        PacketType::LinkStatistics
    }

    fn encode(&self, data: &mut [u8]) {
        let data: &mut [u8; LEN] =
            crate::util::mut_array_start(data).expect("buffer length mismatch");

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

impl PayloadDump for LinkStatistics {}
