use crate::{
    crc8::Crc8, Error, Packet, PacketType, RawPacket, CRSF_HEADER_LEN, CRSF_MAX_LEN, CRSF_SYNC_BYTE,
};

/// Represents a state machine for reading a CRSF packet
///
/// +--------------+   +-------------+   +---------+
/// | AwaitingSync |-->| AwaitingLen |-->| Reading |
/// +--------------+   +-------------+   +---------+
///         ^                   |                |
///         |                   |                |
///         +-------------------+                |
///         +------------------------------------+
///
enum ReadState {
    AwaitingSync,
    AwaitingLen,
    Reading,
}

#[non_exhaustive]
pub struct Config {
    /// Sync byte to use for finding the start of a frame. Default is `0xC8`
    sync: &'static [u8],

    /// Whether to ensure the type byte is a valid PacketType enum value. Default is `true`.
    type_check: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sync: &[CRSF_SYNC_BYTE],
            type_check: true,
        }
    }
}

/// Represents a packet reader
pub struct PacketReader {
    state: ReadState,
    raw: RawPacket,
    digest: Crc8,
    config: Config,
}

impl PacketReader {
    // Minimum data length, must include type and crc bytes
    const MIN_LEN_BYTE: u8 = 2;
    // Maximum data length, includes type, payload and crc bytes
    const MAX_LEN_BYTE: u8 = CRSF_MAX_LEN as u8 - Self::MIN_LEN_BYTE;

    /// Creates a new PacketReader struct
    pub const fn new(config: Config) -> Self {
        Self {
            state: ReadState::AwaitingSync,
            raw: RawPacket::empty(),
            digest: Crc8::new(),
            config,
        }
    }

    /// Resets reader's state
    ///
    /// Useful in situations when timeout is triggered but a packet is not parsed
    pub fn reset(&mut self) {
        self.state = ReadState::AwaitingSync;
        self.raw.len = 0; // Soft-reset the buffer
        self.digest.reset();
    }

    /// Reads the first packet from the buffer
    pub fn push_bytes<'r, 'b>(
        &'r mut self,
        bytes: &'b [u8],
    ) -> (Option<Result<&'r RawPacket, Error>>, &'b [u8]) {
        let mut reader = crate::buffer::BytesReader::new(bytes);
        let packet = 'state_machine: loop {
            match self.state {
                ReadState::AwaitingSync => {
                    while let Some(sync_byte) = reader.next() {
                        if self.config.sync.contains(&sync_byte) {
                            self.raw.buf[0] = sync_byte;
                            self.state = ReadState::AwaitingLen;
                            continue 'state_machine;
                        }
                    }

                    if reader.is_empty() {
                        break Some(Err(Error::NoSyncByte));
                    }
                }
                ReadState::AwaitingLen => {
                    let Some(len_byte) = reader.next() else {
                        break None;
                    };
                    match len_byte {
                        Self::MIN_LEN_BYTE..=Self::MAX_LEN_BYTE => {
                            self.raw.buf[1] = len_byte;
                            self.raw.len = CRSF_HEADER_LEN;
                            self.state = ReadState::Reading;
                        }
                        _ => {
                            self.reset();
                            break Some(Err(Error::InvalidLength { len: len_byte }));
                        }
                    }
                }
                ReadState::Reading => {
                    if reader.is_empty() {
                        break None;
                    }

                    let final_len = self.raw.buf[1] as usize + CRSF_HEADER_LEN;
                    let data = reader.next_n(final_len - self.raw.len);
                    self.raw.buf[self.raw.len..self.raw.len + data.len()].copy_from_slice(data);
                    self.raw.len += data.len();

                    // Validate that type is in PacketType enum
                    if let Some(type_byte) = self.raw.buf.get(2).copied() {
                        if self.config.type_check && PacketType::try_from(type_byte).is_err() {
                            self.reset();
                            break Some(Err(Error::UnknownType { typ: type_byte }));
                        }
                    }

                    // If we have received the CRC byte, do not use it in the digest
                    if self.raw.len == final_len {
                        self.digest.compute(&data[..data.len() - 1]);
                        let act_crc = self.digest.get_checksum();
                        let exp_crc = self.raw.buf[self.raw.len - 1];
                        if act_crc != exp_crc {
                            self.reset();
                            break Some(Err(Error::CrcMismatch {
                                exp: exp_crc,
                                act: act_crc,
                            }));
                        }
                    } else {
                        self.digest.compute(data);
                    }

                    if self.raw.len >= final_len {
                        self.digest.reset();
                        self.state = ReadState::AwaitingSync;
                        break Some(Ok(&self.raw));
                    }
                }
            }
        };

        (packet, reader.remaining())
    }

    /// Returns an interator over the given buffer. If the buffer contains packet of a valid format,
    /// the iterator will return `Ok(RawPacket)`. If the buffer contains invalid packets, the iterator
    /// will return `Err(Error)`. If the buffer is too small to parse, the iterator will yield.
    /// Once the iterator yields, all bytes in the buffer have been consumed.
    ///
    /// To get an iterator that returns `Packet`, use `iter_packets`.
    pub fn iter_raw_packets<'a, 'b>(&'a mut self, buf: &'b [u8]) -> IterRawPackets<'a, 'b> {
        IterRawPackets { parser: self, buf }
    }

    /// Returns an iterator over the given buffer. If the buffer contains packets of a valid format,
    /// the iterator will return `Ok(Packet)`. If the buffer contains invalid packets, the iterator
    /// will return `Err(Error)`. If the buffer is too small to parse, the iterator will yield.
    /// Once the iterator yields, all bytes in the buffer have been consumed.
    ///
    /// To get an iterator that returns `RawPacket`, use `iter_raw_packets`.
    pub fn iter_packets<'a, 'b>(&'a mut self, buf: &'b [u8]) -> IterPackets<'a, 'b> {
        IterPackets { parser: self, buf }
    }
}

/// An iterator over a buffer that yield `RawPacket` instances, or `Error` in case of currupt data.
/// This iterator will consume the and process the entire buffer. For an iterator that also parses the
/// packets into `Packet` instances, use `IterPackets` instead.
pub struct IterRawPackets<'a, 'b> {
    parser: &'a mut PacketReader,
    buf: &'b [u8],
}

impl<'a, 'b> Iterator for IterRawPackets<'a, 'b> {
    type Item = Result<RawPacket, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        let result;
        (result, self.buf) = self.parser.push_bytes(self.buf);
        result.map(|raw| raw.cloned())
    }
}

/// An iterator over a buffer that return parsed `Packet` instances, or `Error` in case of currupt data.
/// This iterator will consume the and process the entire buffer.
pub struct IterPackets<'a, 'b> {
    parser: &'a mut PacketReader,
    buf: &'b [u8],
}

impl<'a, 'b> Iterator for IterPackets<'a, 'b> {
    type Item = Result<Packet, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        let result;
        (result, self.buf) = self.parser.push_bytes(self.buf);
        result.map(|res| match res {
            Ok(raw) => raw.to_packet(),
            Err(err) => Err(err),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::Error;
    use crate::Packet;
    use crate::PacketReader;
    use crate::PacketType;
    use crate::Payload;
    use crate::RcChannelsPacked;
    use crate::Config;
    use crate::CRSF_SYNC_BYTE;

    #[test]
    fn test_packet_reader_waiting_for_sync_byte() {
        let mut reader = PacketReader::new(Config::default());

        let typ = PacketType::RcChannelsPacked as u8;

        for _ in 0..2 {
            // Garbage
            assert!(matches!(
                reader.push_bytes(&[1, 2, 3]).0,
                Some(Err(Error::NoSyncByte))
            ));
            // More garbage
            assert!(matches!(
                reader.push_bytes(&[254, 255]).0,
                Some(Err(Error::NoSyncByte))
            ));
            // Sync
            assert!(reader.push_bytes(&[CRSF_SYNC_BYTE]).0.is_none());
            // Len
            assert!(reader.push_bytes(&[24]).0.is_none());
            // Type
            assert!(reader.push_bytes(&[typ]).0.is_none());
            // Payload
            assert!(reader.push_bytes(&[0; 22]).0.is_none());

            // Checksum
            let result = reader.push_bytes(&[239]).0.expect("result expected");

            let raw_packet = result.expect("raw packet expected");
            let packet = raw_packet.to_packet().expect("packet expected");

            match packet {
                Packet::RcChannelsPacked(ch) => {
                    ch.0.iter().all(|&x| x == 0);
                }
                _ => panic!("unexpected packet type"),
            }
        }
    }

    #[test]
    fn test_parse_next_packet() {
        let mut reader = PacketReader::new(Config::default());

        let typ = PacketType::RcChannelsPacked;

        // Sync
        assert!(reader.push_bytes(&[CRSF_SYNC_BYTE]).0.is_none());
        // Len
        assert!(reader.push_bytes(&[24]).0.is_none());
        // Type
        assert!(reader.push_bytes(&[typ as u8]).0.is_none());
        // Payload
        assert!(reader.push_bytes(&[0; 22]).0.is_none());
        // Checksum
        let result = reader.push_bytes(&[239]).0.expect("result expected");

        let raw_packet = result.expect("raw packet expected");
        let packet = raw_packet.to_packet().expect("packet expected");

        match packet {
            Packet::RcChannelsPacked(ch) => {
                ch.0.iter().all(|&x| x == 0);
            }
            _ => panic!("unexpected packet type"),
        }
    }

    #[test]
    fn test_push_segments() {
        // similar to the doc-test at the top
        let mut reader = PacketReader::new(Config::default());
        let data: &[&[u8]] = &[&[0xc8, 24, 0x16], &[0; 22], &[239]];
        for (i, input_buf) in data.iter().enumerate() {
            for (j, result) in reader.iter_packets(input_buf).enumerate() {
                match result {
                    Ok(Packet::RcChannelsPacked(rc_channels)) => {
                        assert_eq!(rc_channels, RcChannelsPacked([0u16; 16]))
                    }
                    e => panic!("This data should parse succesfully: {e:?}, {i}, {j}"),
                }
            }
        }
    }

    #[test]
    fn test_multiple_sync() {
        let mut reader = PacketReader::new(Config {
            sync: &[0xC8, 0x00],
            ..Default::default()
        });

        let rc_channels1 = RcChannelsPacked([1000; 16]);
        let raw_packet1 = rc_channels1
            .to_raw_packet_with_sync(0xC8)
            .unwrap();

        let rc_channels2 = RcChannelsPacked([1500; 16]);
        let raw_packet2 = rc_channels2
            .to_raw_packet_with_sync(0x00)
            .unwrap();

        let rc_channels3 = RcChannelsPacked([2000; 16]); // Some other address here ---v
        let raw_packet3 = rc_channels3
            .to_raw_packet_with_sync(0x8A)
            .unwrap();

        let result1 = reader
            .push_bytes(raw_packet1.as_slice())
            .0
            .expect("result expected")
            .expect("raw packet expected");
        assert_eq!(
            result1.to_packet().expect("packet expected"),
            Packet::RcChannelsPacked(rc_channels1)
        );

        let result2 = reader
            .push_bytes(raw_packet2.as_slice())
            .0
            .expect("result expected")
            .expect("raw packet expected");
        assert_eq!(
            result2.to_packet().expect("packet expected"),
            Packet::RcChannelsPacked(rc_channels2)
        );

        let result3 = reader
            .push_bytes(raw_packet3.as_slice())
            .0
            .expect("result expected")
            .expect_err("Error expected");
        assert!(matches!(result3, Error::NoSyncByte));
    }

    #[test]
    fn test_parse_full_packet() {
        let mut reader = PacketReader::new(Config::default());

        let typ = PacketType::RcChannelsPacked;

        #[rustfmt::skip]
        let data = [
            // Sync
            CRSF_SYNC_BYTE,
            // Len
            24,
            // Type
            typ as u8,
            // Payload
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // Checksum
            239,
        ];

        let result = reader
            .push_bytes(data.as_slice())
            .0
            .expect("result expected");

        let raw_packet = result.expect("raw packet expected");
        let packet = raw_packet.to_packet().expect("packet expected");

        match packet {
            Packet::RcChannelsPacked(ch) => {
                ch.0.iter().all(|&x| x == 0);
            }
            _ => panic!("unexpected packet type"),
        }
    }

    #[test]
    fn test_parse_next_packet_with_validation_error() {
        let mut reader = PacketReader::new(Config::default());

        // Sync
        assert!(reader.push_bytes(&[CRSF_SYNC_BYTE]).0.is_none());
        // Len
        assert!(reader.push_bytes(&[24]).0.is_none());
        // Type
        assert!(reader
            .push_bytes(&[PacketType::RcChannelsPacked as u8])
            .0
            .is_none());
        // Payload
        assert!(reader.push_bytes(&[0; 22]).0.is_none());
        // Checksum
        let result = reader.push_bytes(&[42]).0.expect("result expected");

        assert!(matches!(
            result,
            Err(Error::CrcMismatch { act: 239, exp: 42 })
        ));
    }
}
