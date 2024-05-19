//! DevicePing packet and related functions/implementations

/// Represents a DevicePing packet
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(missing_docs)]
pub struct DevicePing;

pub const LEN: usize = 0;

/// The raw decoder (parser) for the DevicePing packet.
pub fn raw_decode(_data: &[u8; LEN]) -> DevicePing {
    DevicePing
}

/// The raw encoder (serializer) for the DevicePing packet.
pub fn raw_encode(_device_ping: &DevicePing, _data: &mut [u8; LEN]) {}

impl_extended_payload!(DevicePing, LEN);

#[cfg(test)]
mod tests {
    use super::DevicePing;
    use crate::{AnyPayload, ExtendedPayload, PacketAddress};

    #[test]
    fn test_device_ping_write_and_parse() {
        let original = DevicePing;

        let raw = original
            .to_raw_packet(PacketAddress::Broadcast, PacketAddress::FlightController)
            .unwrap();

        let data = raw.payload().unwrap();
        assert!(raw.is_extended());
        assert_eq!(data.len(), 0);

        let parsed = DevicePing::decode(data).unwrap();

        assert_eq!(parsed, DevicePing);
    }
}
