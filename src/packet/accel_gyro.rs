use crate::{PacketType, Payload, PayloadDump};

/// `AccelGyro` payload type - IMU data with timestamp
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AccelGyro {
    /// Sample timestamp in microseconds
    pub sample_time: u32,
    /// Gyro X rotation (LSB = INT16_MAX/2000 DPS)
    pub gyro_x: i16,
    /// Gyro Y rotation (LSB = INT16_MAX/2000 DPS)
    pub gyro_y: i16,
    /// Gyro Z rotation (LSB = INT16_MAX/2000 DPS)
    pub gyro_z: i16,
    /// Accel X (LSB = INT16_MAX/16 G)
    pub acc_x: i16,
    /// Accel Y (LSB = INT16_MAX/16 G)
    pub acc_y: i16,
    /// Accel Z (LSB = INT16_MAX/16 G)
    pub acc_z: i16,
    /// Gyro temperature in centidegrees Celsius
    pub gyro_temp: i16,
}

const LEN: usize = 18;

impl AccelGyro {
    /// Parses an `AccelGyro` payload (assumes it to be valid).
    pub(crate) fn parse(data: &[u8]) -> Option<Self> {
        let data: &[u8; LEN] = crate::util::ref_array_start(data)?;

        Some(AccelGyro {
            sample_time: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            gyro_x: i16::from_be_bytes([data[4], data[5]]),
            gyro_y: i16::from_be_bytes([data[6], data[7]]),
            gyro_z: i16::from_be_bytes([data[8], data[9]]),
            acc_x: i16::from_be_bytes([data[10], data[11]]),
            acc_y: i16::from_be_bytes([data[12], data[13]]),
            acc_z: i16::from_be_bytes([data[14], data[15]]),
            gyro_temp: i16::from_be_bytes([data[16], data[17]]),
        })
    }
}

impl Payload for AccelGyro {
    fn len(&self) -> usize {
        LEN
    }

    fn typ(&self) -> PacketType {
        PacketType::AccelGyro
    }

    fn encode(&self, data: &mut [u8]) {
        let data: &mut [u8; LEN] =
            crate::util::mut_array_start(data).expect("buffer length mismatch");

        data[0..4].copy_from_slice(&self.sample_time.to_be_bytes());
        data[4..6].copy_from_slice(&self.gyro_x.to_be_bytes());
        data[6..8].copy_from_slice(&self.gyro_y.to_be_bytes());
        data[8..10].copy_from_slice(&self.gyro_z.to_be_bytes());
        data[10..12].copy_from_slice(&self.acc_x.to_be_bytes());
        data[12..14].copy_from_slice(&self.acc_y.to_be_bytes());
        data[14..16].copy_from_slice(&self.acc_z.to_be_bytes());
        data[16..18].copy_from_slice(&self.gyro_temp.to_be_bytes());
    }
}

impl PayloadDump for AccelGyro {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accel_gyro_parse() {
        let mut data = [0u8; 18];

        let timestamp = 1234567u32;
        data[0..4].copy_from_slice(&timestamp.to_be_bytes());

        let gyro_x = 1000i16;
        data[4..6].copy_from_slice(&gyro_x.to_be_bytes());

        let gyro_y = -500i16;
        data[6..8].copy_from_slice(&gyro_y.to_be_bytes());

        let gyro_z = 2000i16;
        data[8..10].copy_from_slice(&gyro_z.to_be_bytes());

        let acc_x = 5000i16;
        data[10..12].copy_from_slice(&acc_x.to_be_bytes());

        let acc_y = -3000i16;
        data[12..14].copy_from_slice(&acc_y.to_be_bytes());

        let acc_z = 8000i16;
        data[14..16].copy_from_slice(&acc_z.to_be_bytes());

        let gyro_temp = 2500i16;
        data[16..18].copy_from_slice(&gyro_temp.to_be_bytes());

        let ag = AccelGyro::parse(&data).unwrap();

        assert_eq!(ag.sample_time, timestamp);
        assert_eq!(ag.gyro_x, gyro_x);
        assert_eq!(ag.gyro_y, gyro_y);
        assert_eq!(ag.gyro_z, gyro_z);
        assert_eq!(ag.acc_x, acc_x);
        assert_eq!(ag.acc_y, acc_y);
        assert_eq!(ag.acc_z, acc_z);
        assert_eq!(ag.gyro_temp, gyro_temp);
    }

    #[test]
    fn test_accel_gyro_encode() {
        let ag = AccelGyro {
            sample_time: 1234567,
            gyro_x: 1000,
            gyro_y: -500,
            gyro_z: 2000,
            acc_x: 5000,
            acc_y: -3000,
            acc_z: 8000,
            gyro_temp: 2500,
        };

        let mut buf = [0u8; 18];
        ag.encode(&mut buf);

        assert_eq!(&buf[0..4], &1234567u32.to_be_bytes());
        assert_eq!(&buf[4..6], &1000i16.to_be_bytes());
        assert_eq!(&buf[6..8], &(-500i16).to_be_bytes());
        assert_eq!(&buf[8..10], &2000i16.to_be_bytes());
        assert_eq!(&buf[10..12], &5000i16.to_be_bytes());
        assert_eq!(&buf[12..14], &(-3000i16).to_be_bytes());
        assert_eq!(&buf[14..16], &8000i16.to_be_bytes());
        assert_eq!(&buf[16..18], &2500i16.to_be_bytes());
    }

    #[test]
    fn test_accel_gyro_roundtrip() {
        let original = AccelGyro {
            sample_time: 1234567,
            gyro_x: 1000,
            gyro_y: -500,
            gyro_z: 2000,
            acc_x: 5000,
            acc_y: -3000,
            acc_z: 8000,
            gyro_temp: 2500,
        };

        let mut buf = [0u8; 18];
        original.encode(&mut buf);
        let parsed = AccelGyro::parse(&buf).unwrap();

        assert_eq!(original, parsed);
    }
}
