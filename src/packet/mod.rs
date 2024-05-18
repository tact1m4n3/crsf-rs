use crate::{Error, CRSF_MAX_LEN};

mod address;
pub use address::*;

mod typ;
pub use typ::*;

mod payload;
pub use payload::*;

/// Represents a packet
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Packet {
    LinkStatistics(LinkStatistics),
    RcChannelsPacked(RcChannelsPacked),
}

/// Represents a raw packet (not parsed)
#[derive(Clone, Copy, Debug)]
pub struct RawPacket {
    pub(crate) buf: [u8; CRSF_MAX_LEN],
    pub(crate) len: usize,
}

impl RawPacket {
    pub(crate) const fn empty() -> RawPacket {
        RawPacket {
            buf: [0u8; CRSF_MAX_LEN],
            len: 0,
        }
    }

    /// Create a new RawPacket from the given slice. The slice must be
    /// at most `CRSF_MAX_LEN`bytes long.
    pub fn new(slice: &[u8]) -> Result<RawPacket, Error> {
        let mut packet = RawPacket {
            buf: [0u8; CRSF_MAX_LEN],
            len: slice.len(),
        };

        packet
            .buf
            .get_mut(..slice.len())
            .ok_or(Error::BufferError)?
            .copy_from_slice(slice);

        Ok(packet)
    }

    /// Get the slice of the raw packets buffer
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len.min(CRSF_MAX_LEN)]
    }

    /// Get the payload section of the raw packet
    pub fn payload(&self) -> Result<&[u8], Error> {
        match (self.is_extended(), self.as_slice()) {
            // Skip the [sync], [len], [type], [src], [dst] and [crc] bytes
            (true, [_, _, _, _, _, payload @ .., _]) => Ok(payload),
            // Skip the [sync], [len], [type] and [crc] bytes
            (false, [_, _, _, payload @ .., _]) => Ok(payload),
            _ => Err(Error::BufferError),
        }
    }

    /// Check if the packet is an extended format packet
    pub fn is_extended(&self) -> bool {
        // Skip the [sync], [len], [type] and [crc] bytes
        if let [_, _, ty, ..] = self.as_slice() {
            ty >= &0x28
        } else {
            false
        }
    }

    /// Get the source and destination addresses of the packet.
    /// This is only valid for extended packets, and will
    /// return an error otherwise
    pub fn dst_src(&self) -> Result<(PacketAddress, PacketAddress), Error> {
        if self.is_extended() {
            if let [_, _, _, dst, src, ..] = self.as_slice() {
                match (PacketAddress::try_from(*dst), PacketAddress::try_from(*src)) {
                    (Ok(dst), Ok(src)) => Ok((dst, src)),
                    _ => Err(Error::InvalidPayload),
                }
            } else {
                Err(Error::BufferError)
            }
        } else {
            // NOTE Not sure what the error here should be
            Err(Error::UnknownType { typ: 0 })
        }
    }

    /// Convert the raw packet into a parsed packet
    pub fn to_packet(&self) -> Result<Packet, Error> {
        let payload = self.payload()?;
        match PacketType::try_from(self.buf[2]) {
            Ok(PacketType::RcChannelsPacked) => {
                RcChannelsPacked::decode(payload).map(Packet::RcChannelsPacked)
            }
            Ok(PacketType::LinkStatistics) => {
                LinkStatistics::decode(payload).map(Packet::LinkStatistics)
            }
            _ => Err(Error::UnknownType { typ: self.buf[2] }),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{LinkStatistics, PacketAddress, Payload, RcChannelsPacked};

    #[test]
    fn test_rc_channels_packet_dump() {
        let channels: [u16; 16] = [0x7FF; 16];
        let addr = PacketAddress::Transmitter;
        let packet = RcChannelsPacked(channels);

        let raw = packet.to_raw_packet_with_sync(addr as u8).unwrap();

        let mut expected_data: [u8; 26] = [0xff; 26];
        expected_data[0] = 0xee;
        expected_data[1] = 24;
        expected_data[2] = 0x16;
        expected_data[25] = 143;
        assert_eq!(&raw.as_slice(), &expected_data)
    }

    #[test]
    fn test_link_statistics_packet_dump() {
        let addr = PacketAddress::FlightController;

        let packet = LinkStatistics {
            uplink_rssi_1: 16,
            uplink_rssi_2: 19,
            uplink_link_quality: 99,
            uplink_snr: -105,
            active_antenna: 1,
            rf_mode: 2,
            uplink_tx_power: 3,
            downlink_rssi: 8,
            downlink_link_quality: 88,
            downlink_snr: -108,
        };

        let raw = packet.to_raw_packet_with_sync(addr as u8).unwrap();

        let expected_data = [0xc8, 12, 0x14, 16, 19, 99, 151, 1, 2, 3, 8, 88, 148, 252];
        assert_eq!(raw.as_slice(), expected_data.as_slice())
    }
}
