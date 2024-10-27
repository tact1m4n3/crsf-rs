use crate::{ExtendedPayloadDump, PacketType, Payload};

/// `DevicePing` payload type
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DevicePing;

impl Payload for DevicePing {
    fn len(&self) -> usize {
        0
    }

    fn typ(&self) -> PacketType {
        PacketType::DevicePing
    }

    fn encode(&self, _data: &mut [u8]) {}
}

impl ExtendedPayloadDump for DevicePing {}
