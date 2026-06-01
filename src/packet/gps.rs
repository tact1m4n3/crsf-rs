use crate::{PacketType, Payload, PayloadDump};

/// `Gps` payload type
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Gps {
    /// Latitude (degrees * 1e7)
    pub latitude: i32,
    /// Longitude (degrees * 1e7)
    pub longitude: i32,
    /// Ground speed (km/h * 100)
    pub groundspeed: u16,
    /// Heading (degrees * 100)
    pub heading: u16,
    /// Altitude above sea level (meters - 1000m offset)
    pub altitude: u16,
    /// Number of satellites in view
    pub satellites: u8,
}

const LEN: usize = 15;

impl Gps {
    /// Parses a `Gps` payload.
    pub(crate) fn parse(data: &[u8]) -> Option<Self> {
        let data: &[u8; LEN] = crate::util::ref_array_start(data)?;

        Some(Gps {
            latitude: i32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            longitude: i32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            groundspeed: u16::from_be_bytes([data[8], data[9]]),
            heading: u16::from_be_bytes([data[10], data[11]]),
            altitude: u16::from_be_bytes([data[12], data[13]]),
            satellites: data[14],
        })
    }
}

impl Payload for Gps {
    fn len(&self) -> usize {
        LEN
    }

    fn typ(&self) -> PacketType {
        PacketType::Gps
    }

    fn encode(&self, data: &mut [u8]) {
        let data: &mut [u8; LEN] =
            crate::util::mut_array_start(data).expect("buffer length mismatch");

        data[0..4].copy_from_slice(&self.latitude.to_be_bytes());
        data[4..8].copy_from_slice(&self.longitude.to_be_bytes());
        data[8..10].copy_from_slice(&self.groundspeed.to_be_bytes());
        data[10..12].copy_from_slice(&self.heading.to_be_bytes());
        data[12..14].copy_from_slice(&self.altitude.to_be_bytes());
        data[14] = self.satellites;
    }
}

impl PayloadDump for Gps {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gps_parse() {
        // Sample data with known values
        let mut data = [0u8; 15];

        // Latitude: 47.1234567 degrees = 471234567 * 1e-7
        let lat = 471234567i32;
        data[0..4].copy_from_slice(&lat.to_be_bytes());

        // Longitude: 8.9876543 degrees = 88876543 * 1e-7
        let lon = 88876543i32;
        data[4..8].copy_from_slice(&lon.to_be_bytes());

        // Groundspeed: 50.5 km/h = 5050 * 0.01
        let speed = 5050u16;
        data[8..10].copy_from_slice(&speed.to_be_bytes());

        // Heading: 123.45 degrees = 12345 * 0.01
        let hdg = 12345u16;
        data[10..12].copy_from_slice(&hdg.to_be_bytes());

        // Altitude: 500 meters (with 1000m offset) = 1500 raw
        let alt = 1500u16;
        data[12..14].copy_from_slice(&alt.to_be_bytes());

        // Satellites: 12
        data[14] = 12;

        let gps = Gps::parse(&data).expect("parse failed");

        assert_eq!(gps.latitude, lat);
        assert_eq!(gps.longitude, lon);
        assert_eq!(gps.groundspeed, speed);
        assert_eq!(gps.heading, hdg);
        assert_eq!(gps.altitude, alt);
        assert_eq!(gps.satellites, 12);
    }

    #[test]
    fn test_gps_encode() {
        let gps = Gps {
            latitude: 471234567,
            longitude: 88876543,
            groundspeed: 5050,
            heading: 12345,
            altitude: 1500,
            satellites: 12,
        };

        let mut buf = [0u8; 15];
        gps.encode(&mut buf);

        assert_eq!(&buf[0..4], &471234567i32.to_be_bytes());
        assert_eq!(&buf[4..8], &88876543i32.to_be_bytes());
        assert_eq!(&buf[8..10], &5050u16.to_be_bytes());
        assert_eq!(&buf[10..12], &12345u16.to_be_bytes());
        assert_eq!(&buf[12..14], &1500u16.to_be_bytes());
        assert_eq!(buf[14], 12);
    }

    #[test]
    fn test_gps_roundtrip() {
        let original = Gps {
            latitude: 471234567,
            longitude: 88876543,
            groundspeed: 5050,
            heading: 12345,
            altitude: 1500,
            satellites: 12,
        };

        let mut buf = [0u8; 15];
        original.encode(&mut buf);
        let parsed = Gps::parse(&buf).expect("parse failed");

        assert_eq!(original, parsed);
    }
}
