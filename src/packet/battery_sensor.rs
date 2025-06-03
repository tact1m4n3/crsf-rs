use {
    crate::{PacketType, Payload, PayloadDump},
    bitfields::bitfield,
};

/// `BatterySensor` payload type
#[bitfield(u64)]
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(missing_docs)]
pub struct BatterySensor {
    /// Voltage (LSB = 10 µV)
    voltage: u16,
    /// Current (LSB = 10 µA)
    current: u16,
    /// Capacity used (mAh)
    #[bits(24)]
    capacity_used: u32,
    /// Battery remaining (percent)
    remaining: u8,
}

const LEN: usize = size_of::<BatterySensor>();

impl BatterySensor {
    /// Parses a `BatterySensor` payload (assumes it to be valid).
    pub(crate) fn parse(data: &[u8]) -> Self {
        let data: &[u8; LEN] = crate::util::ref_array_start(data).expect("buffer length mismatch");

        BatterySensor::from_bits(u64::from_be_bytes(*data))
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

        *data = self.into_bits().to_be_bytes();
    }
}

impl PayloadDump for BatterySensor {}
