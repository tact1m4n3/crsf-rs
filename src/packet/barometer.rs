use crate::{PacketType, Payload, PayloadDump};

/// `Barometer` payload type
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Barometer {
    /// Atmospheric pressure in Pascals
    pub pressure_pa: i32,
    /// Temperature in centidegrees Celsius
    pub baro_temp: i32,
}

const LEN: usize = 8;

impl Barometer {
    /// Parses a `Barometer` payload.
    pub(crate) fn parse(data: &[u8]) -> Option<Self> {
        let data: &[u8; LEN] = crate::util::ref_array_start(data)?;

        Some(Barometer {
            pressure_pa: i32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            baro_temp: i32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        })
    }
}

impl Payload for Barometer {
    fn len(&self) -> usize {
        LEN
    }

    fn typ(&self) -> PacketType {
        PacketType::Barometer
    }

    fn encode(&self, data: &mut [u8]) {
        let data: &mut [u8; LEN] =
            crate::util::mut_array_start(data).expect("buffer length mismatch");

        data[0..4].copy_from_slice(&self.pressure_pa.to_be_bytes());
        data[4..8].copy_from_slice(&self.baro_temp.to_be_bytes());
    }
}

impl PayloadDump for Barometer {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_barometer_parse() {
        let mut data = [0u8; 8];

        // Pressure: 101325 Pa (sea level)
        let pressure = 101325i32;
        data[0..4].copy_from_slice(&pressure.to_be_bytes());

        // Temperature: 25.00°C = 2500 centidegrees
        let temp = 2500i32;
        data[4..8].copy_from_slice(&temp.to_be_bytes());

        let baro = Barometer::parse(&data).expect("parse failed");

        assert_eq!(baro.pressure_pa, pressure);
        assert_eq!(baro.baro_temp, temp);
    }

    #[test]
    fn test_barometer_encode() {
        let baro = Barometer {
            pressure_pa: 101325,
            baro_temp: 2500,
        };

        let mut buf = [0u8; 8];
        baro.encode(&mut buf);

        assert_eq!(&buf[0..4], &101325i32.to_be_bytes());
        assert_eq!(&buf[4..8], &2500i32.to_be_bytes());
    }

    #[test]
    fn test_barometer_roundtrip() {
        let original = Barometer {
            pressure_pa: 101325,
            baro_temp: 2500,
        };

        let mut buf = [0u8; 8];
        original.encode(&mut buf);
        let parsed = Barometer::parse(&buf).expect("parse failed");

        assert_eq!(original, parsed);
    }
}
