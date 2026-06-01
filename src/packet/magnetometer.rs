use crate::{PacketType, Payload, PayloadDump};

/// `Magnetometer` payload type
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Magnetometer {
    /// Magnetic field X component (milligauss * 3)
    pub field_x: i16,
    /// Magnetic field Y component (milligauss * 3)
    pub field_y: i16,
    /// Magnetic field Z component (milligauss * 3)
    pub field_z: i16,
}

const LEN: usize = 6;

impl Magnetometer {
    /// Parses a `Magnetometer` payload.
    pub(crate) fn parse(data: &[u8]) -> Option<Self> {
        let data: &[u8; LEN] = crate::util::ref_array_start(data)?;

        Some(Magnetometer {
            field_x: i16::from_be_bytes([data[0], data[1]]),
            field_y: i16::from_be_bytes([data[2], data[3]]),
            field_z: i16::from_be_bytes([data[4], data[5]]),
        })
    }
}

impl Payload for Magnetometer {
    fn len(&self) -> usize {
        LEN
    }

    fn typ(&self) -> PacketType {
        PacketType::Magnetometer
    }

    fn encode(&self, data: &mut [u8]) {
        let data: &mut [u8; LEN] =
            crate::util::mut_array_start(data).expect("buffer length mismatch");

        data[0..2].copy_from_slice(&self.field_x.to_be_bytes());
        data[2..4].copy_from_slice(&self.field_y.to_be_bytes());
        data[4..6].copy_from_slice(&self.field_z.to_be_bytes());
    }
}

impl PayloadDump for Magnetometer {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magnetometer_parse() {
        let mut data = [0u8; 6];

        let field_x = 1000i16;
        data[0..2].copy_from_slice(&field_x.to_be_bytes());

        let field_y = -500i16;
        data[2..4].copy_from_slice(&field_y.to_be_bytes());

        let field_z = 1500i16;
        data[4..6].copy_from_slice(&field_z.to_be_bytes());

        let mag = Magnetometer::parse(&data).expect("parse failed");

        assert_eq!(mag.field_x, field_x);
        assert_eq!(mag.field_y, field_y);
        assert_eq!(mag.field_z, field_z);
    }

    #[test]
    fn test_magnetometer_encode() {
        let mag = Magnetometer {
            field_x: 1000,
            field_y: -500,
            field_z: 1500,
        };

        let mut buf = [0u8; 6];
        mag.encode(&mut buf);

        assert_eq!(&buf[0..2], &1000i16.to_be_bytes());
        assert_eq!(&buf[2..4], &(-500i16).to_be_bytes());
        assert_eq!(&buf[4..6], &1500i16.to_be_bytes());
    }

    #[test]
    fn test_magnetometer_roundtrip() {
        let original = Magnetometer {
            field_x: 1000,
            field_y: -500,
            field_z: 1500,
        };

        let mut buf = [0u8; 6];
        original.encode(&mut buf);
        let parsed = Magnetometer::parse(&buf).expect("parse failed");

        assert_eq!(original, parsed);
    }
}
