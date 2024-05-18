use crate::{
    address::PacketAddress, CrsfError, LinkStatistics, Packet, PacketType, Payload,
    RcChannelsPacked, CRSF_MAX_LEN,
};

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
    pub fn new(slice: &[u8]) -> Result<RawPacket, CrsfError> {
        let mut packet = RawPacket {
            buf: [0u8; CRSF_MAX_LEN],
            len: slice.len(),
        };

        packet
            .buf
            .get_mut(..slice.len())
            .ok_or(CrsfError::BufferError)?
            .copy_from_slice(slice);

        Ok(packet)
    }

    /// Get the slice of the raw packets buffer
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len.min(CRSF_MAX_LEN)]
    }

    /// Get the payload section of the raw packet
    pub fn payload(&self) -> Result<&[u8], CrsfError> {
        match (self.is_extended(), self.as_slice()) {
            // Skip the [sync], [len], [type], [src], [dst] and [crc] bytes
            (true, [_, _, _, _, _, payload @ .., _]) => Ok(payload),
            // Skip the [sync], [len], [type] and [crc] bytes
            (false, [_, _, _, payload @ .., _]) => Ok(payload),
            _ => Err(CrsfError::BufferError),
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
    pub fn dst_src(&self) -> Result<(PacketAddress, PacketAddress), CrsfError> {
        if self.is_extended() {
            if let [_, _, _, dst, src, ..] = self.as_slice() {
                match (PacketAddress::try_from(*dst), PacketAddress::try_from(*src)) {
                    (Ok(dst), Ok(src)) => Ok((dst, src)),
                    _ => Err(CrsfError::InvalidPayload),
                }
            } else {
                Err(CrsfError::BufferError)
            }
        } else {
            // NOTE Not sure what the error here should be
            Err(CrsfError::UnknownType { typ: 0 })
        }
    }

    /// Convert the raw packet into a parsed packet
    pub fn into_packet(&self) -> Result<Packet, CrsfError> {
        let payload = self.payload()?;
        match PacketType::try_from(self.buf[2]) {
            Ok(PacketType::RcChannelsPacked) => {
                RcChannelsPacked::decode(payload).map(Packet::RcChannelsPacked)
            }
            Ok(PacketType::LinkStatistics) => {
                LinkStatistics::decode(payload).map(Packet::LinkStatistics)
            }
            _ => Err(CrsfError::UnknownType { typ: self.buf[2] }),
        }
    }
}
