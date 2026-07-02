use crate::{PacketType, Payload, PayloadDump};

/// `BatterySensor` payload type
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BatterySensor {
    /// Voltage (LSB = 10 µV)
    pub voltage: i16,
    /// Current (LSB = 10 µA)
    pub current: i16,
    /// Capacity used (mAh)
    pub capacity_used: u32,
    /// Battery remaining (percent)
    pub remaining: u8,
}

const LEN: usize = size_of::<BatterySensor>();

impl BatterySensor {
    /// Parses a `BatterySensor` payload.
    pub(crate) fn parse(data: &[u8]) -> Option<Self> {
        let data: &[u8; LEN] = crate::util::ref_array_start(data)?;

        Some(BatterySensor {
            voltage: i16::from_be_bytes([data[0], data[1]]),
            current: i16::from_be_bytes([data[2], data[3]]),
            capacity_used: u32::from_be_bytes([0, data[4], data[5], data[6]]),
            remaining: data[7],
        })
    }
}

impl Payload for BatterySensor {
    fn len(&self) -> usize {
        LEN
    }

    fn typ(&self) -> PacketType {
        PacketType::BatterySensor
    }

    fn encode(&self, data: &mut [u8]) {
        let data: &mut [u8; LEN] =
            crate::util::mut_array_start(data).expect("buffer length mismatch");
        data[0..2].copy_from_slice(&self.voltage.to_be_bytes());
        data[2..4].copy_from_slice(&self.current.to_be_bytes());
        data[4..7].copy_from_slice(&self.capacity_used.to_be_bytes()[1..4]);
        data[7] = self.remaining;
    }
}

impl PayloadDump for BatterySensor {}
