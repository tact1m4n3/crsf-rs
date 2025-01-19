use crate::{util::BytesReader, Packet, PacketType, CRC8, MAX_PACKET_LEN, SYNC_BYTE, SYNC_RC_BYTE};
use snafu::Snafu;

/// Struct for configuring a `Parser`.
#[non_exhaustive]
pub struct ParserConfig {
    /// Sync byte to use for finding the start of a frame. Default is `0xC8`.
    pub sync: &'static [u8],
}

impl ParserConfig {
    pub const fn default() -> Self {
        Self { sync: &[SYNC_RC_BYTE, SYNC_BYTE] }
    }
}

/// State machine for reading a CRSF packet.
///
/// +--------------+   +-------------+   +---------+
/// | AwaitingSync |-->| AwaitingLen |-->| Reading |
/// +--------------+   +-------------+   +---------+
///         ^                   |                |
///         |                   |                |
///         +-------------------+                |
///         +------------------------------------+
///
enum State {
    AwaitingSync,
    AwaitingLen,
    Reading { index: usize, len: usize },
}

const MIN_LEN_BYTE: u8 = 2;
const MAX_LEN_BYTE: u8 = MAX_PACKET_LEN as u8 - 2;

/// Struct for parsing CRSF packets.
pub struct Parser {
    config: ParserConfig,
    state: State,
    buf: [u8; MAX_PACKET_LEN],
}

impl Parser {
    /// Creates a new `Parser` struct.
    pub const fn new(config: ParserConfig) -> Self {
        Self {
            config,
            state: State::AwaitingSync,
            buf: [0; MAX_PACKET_LEN],
        }
    }

    /// Resets the parser's state.
    ///
    /// Useful in situations when timeout is triggered but a packet is not parsed.
    pub fn reset(&mut self) {
        self.state = State::AwaitingSync;
    }

    /// Consumes a byte and returns a parsed packet if one is available.
    pub fn push_byte(&mut self, byte: u8) -> Option<Result<Packet, ParseError>> {
        self.push_byte_raw(byte)
            .map(|res| res.and_then(|raw_packet| Packet::parse(raw_packet)))
    }

    /// Consumes a byte and returns a raw (not parsed) packet if one is available.
    pub fn push_byte_raw(&mut self, byte: u8) -> Option<Result<&[u8], ParseError>> {
        match self.state {
            State::AwaitingSync => {
                if self.config.sync.contains(&byte) {
                    self.buf[0] = byte;
                    self.state = State::AwaitingLen;
                }
            }
            State::AwaitingLen => {
                if (MIN_LEN_BYTE..=MAX_LEN_BYTE).contains(&byte) {
                    self.state = State::Reading {
                        index: 2,
                        len: 2 + byte as usize,
                    };

                    self.buf[1] = byte;
                } else {
                    self.state = State::AwaitingSync;
                }
            }
            State::Reading { index, len } => {
                self.buf[index] = byte;

                if index == len - 1 {
                    self.state = State::AwaitingSync;

                    let expected_checksum = self.buf[len - 1];

                    let actual_checksum = CRC8.checksum(&self.buf[2..len - 1]);

                    if actual_checksum == expected_checksum {
                        return Some(Ok(&self.buf[..len]));
                    } else {
                        return Some(Err(ParseError::ChecksumMismatch {
                            expected: expected_checksum,
                            actual: actual_checksum,
                        }));
                    }
                } else {
                    self.state = State::Reading {
                        index: index + 1,
                        len,
                    };
                }
            }
        }

        None
    }

    /// Consumes a slice of bytes and returns a parsed packet if one is available. It's optimized
    /// for reading multiple bytes at a time.
    pub fn push_bytes<'b>(
        &mut self,
        data: &'b [u8],
    ) -> Option<(Result<Packet, ParseError>, &'b [u8])> {
        self.push_bytes_raw(data).map(|(res, remaining)| {
            (
                res.and_then(|raw_packet| Packet::parse(raw_packet)),
                remaining,
            )
        })
    }

    /// Consumes a slice of bytes and returns a raw (not parsed) packet if one is available. It's
    /// optimized for reading multiple bytes at a time.
    pub fn push_bytes_raw<'a, 'b>(
        &'a mut self,
        data: &'b [u8],
    ) -> Option<(Result<&'a [u8], ParseError>, &'b [u8])> {
        let mut reader = BytesReader::new(data);

        loop {
            match self.state {
                State::AwaitingSync => {
                    while let Some(byte) = reader.next() {
                        if self.config.sync.contains(&byte) {
                            self.state = State::AwaitingLen;
                            self.buf[0] = byte;
                            break;
                        }
                    }

                    if reader.is_empty() {
                        return None;
                    }
                }
                State::AwaitingLen => {
                    let byte = reader.next()?;

                    if (MIN_LEN_BYTE..=MAX_LEN_BYTE).contains(&byte) {
                        self.state = State::Reading {
                            index: 2,
                            len: 2 + byte as usize,
                        };

                        self.buf[1] = byte;
                    } else {
                        return Some((
                            Err(ParseError::InvalidLength { len: byte }),
                            reader.remaining(),
                        ));
                    }
                }
                State::Reading { index, len } => {
                    if reader.is_empty() {
                        return None;
                    }

                    let available_bytes = reader.next_n(len - index);
                    self.buf[index..index + available_bytes.len()].copy_from_slice(available_bytes);

                    if index + available_bytes.len() == len {
                        self.state = State::AwaitingSync;

                        let expected_checksum = self.buf[len - 1];

                        let actual_checksum = CRC8.checksum(&self.buf[2..len - 1]);

                        if actual_checksum == expected_checksum {
                            break Some((Ok(&self.buf[..len]), reader.remaining()));
                        } else {
                            return Some((
                                Err(ParseError::ChecksumMismatch {
                                    expected: expected_checksum,
                                    actual: actual_checksum,
                                }),
                                reader.remaining(),
                            ));
                        }
                    } else {
                        self.state = State::Reading {
                            index: index + available_bytes.len(),
                            len,
                        };
                    }
                }
            }
        }
    }

    /// Returns an iterator over all the packets in the provided buffer.
    pub fn iter_packets<'a, 'b>(&'a mut self, data: &'b [u8]) -> PacketIterator<'a, 'b> {
        PacketIterator {
            parser: self,
            remaining_data: data,
        }
    }
}

/// Iterator for packets in a given buffer. This struct is created by the `iter_packets` method of
/// a `Parser`
pub struct PacketIterator<'a, 'b> {
    parser: &'a mut Parser,
    remaining_data: &'b [u8],
}

impl Iterator for PacketIterator<'_, '_> {
    type Item = Result<Packet, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((result, remaining_data)) = self.parser.push_bytes(self.remaining_data) {
            self.remaining_data = remaining_data;
            Some(result)
        } else {
            None
        }
    }
}

/// Enum of parsing errors.
#[non_exhaustive]
#[derive(Debug, PartialEq, Snafu)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ParseError {
    #[snafu(display("Invalid length {len}, should be between {MIN_LEN_BYTE} and {MAX_LEN_BYTE}"))]
    InvalidLength { len: u8 },
    #[snafu(display("Crc checksum mismatch: expected {expected:#04x}, got {actual:#04x}"))]
    ChecksumMismatch { expected: u8, actual: u8 },
    #[snafu(display("Invalid type {typ:#04x}, see PacketType enum"))]
    InvalidType { typ: u8 },
    #[snafu(display("Unimplemented type {typ:?}, should be implemented ASAP"))]
    UnimplementedType { typ: PacketType },
    #[snafu(display("Invalid address {addr:#04x}, see PacketAddress enum"))]
    InvalidAddress { addr: u8 },
}

#[cfg(test)]
mod tests {
    use crate::{Packet, PacketAddress, PacketType, Parser, ParserConfig, SYNC_BYTE};

    #[test]
    fn test_parser_push_bytes_raw() {
        let mut parser = Parser::new(ParserConfig::default());

        let typ = PacketType::RcChannelsPacked as u8;

        for _ in 0..2 {
            // Garbage
            assert!(matches!(parser.push_bytes_raw(&[0x39, 0x58, 0x30]), None));

            // Sync
            assert!(matches!(parser.push_bytes_raw(&[SYNC_BYTE]), None));
            // Len
            assert!(matches!(parser.push_bytes_raw(&[24]), None));
            // Type
            assert!(matches!(parser.push_bytes_raw(&[typ]), None));
            // Payload
            assert!(matches!(parser.push_bytes_raw(&[0; 22]), None));

            // Checksum
            let result = parser.push_bytes_raw(&[239]).expect("result expected");

            let raw_packet = result.0.expect("raw packet expected");
            let packet = Packet::parse(raw_packet).expect("packet expected");

            match packet {
                Packet::RcChannelsPacked(ch) => {
                    ch.0.iter().all(|&x| x == 0);
                }
                _ => panic!("unexpected packet type"),
            }
        }
    }

    #[test]
    fn test_parser_push_bytes() {
        let mut parser = Parser::new(ParserConfig::default());

        let typ = PacketType::RcChannelsPacked as u8;

        for _ in 0..2 {
            // Garbage
            assert!(matches!(parser.push_bytes(&[0x39, 0x58, 0x30]), None));

            // Sync
            assert!(matches!(parser.push_bytes(&[SYNC_BYTE]), None));
            // Len
            assert!(matches!(parser.push_bytes(&[24]), None));
            // Type
            assert!(matches!(parser.push_bytes(&[typ]), None));
            // Payload
            assert!(matches!(parser.push_bytes(&[0; 22]), None));

            // Checksum
            let result = parser.push_bytes(&[239]).expect("result expected");

            let packet = result.0.expect("packet expected");

            match packet {
                Packet::RcChannelsPacked(ch) => {
                    ch.0.iter().all(|&x| x == 0);
                }
                _ => panic!("unexpected packet type"),
            }
        }
    }

    #[test]
    fn test_parser_push_byte_raw() {
        let mut parser = Parser::new(ParserConfig::default());

        let typ = PacketType::RcChannelsPacked as u8;

        for _ in 0..2 {
            // Garbage
            assert!(matches!(parser.push_byte_raw(0x39), None));
            assert!(matches!(parser.push_byte_raw(0x21), None));
            assert!(matches!(parser.push_byte_raw(0x89), None));

            // Sync
            assert!(matches!(parser.push_byte_raw(SYNC_BYTE), None));
            // Len
            assert!(matches!(parser.push_byte_raw(24), None));
            // Type
            assert!(matches!(parser.push_byte_raw(typ), None));
            // Payload
            assert!(matches!(parser.push_bytes_raw(&[0; 22]), None)); // they can interoperate

            // Checksum
            let result = parser.push_byte_raw(239).expect("result expected");

            let raw_packet = result.expect("raw packet expected");
            let packet = Packet::parse(raw_packet).expect("packet expected");

            match packet {
                Packet::RcChannelsPacked(ch) => {
                    ch.0.iter().all(|&x| x == 0);
                }
                _ => panic!("unexpected packet type"),
            }
        }
    }

    #[test]
    fn test_parser_push_byte() {
        let mut parser = Parser::new(ParserConfig::default());

        let typ = PacketType::RcChannelsPacked as u8;

        for _ in 0..2 {
            // Garbage
            assert!(matches!(parser.push_byte_raw(0x39), None));
            assert!(matches!(parser.push_byte_raw(0x21), None));
            assert!(matches!(parser.push_byte_raw(0x89), None));

            // Sync
            assert!(matches!(parser.push_byte_raw(SYNC_BYTE), None));
            // Len
            assert!(matches!(parser.push_byte_raw(24), None));
            // Type
            assert!(matches!(parser.push_byte_raw(typ), None));
            // Payload
            assert!(matches!(parser.push_bytes_raw(&[0; 22]), None)); // they can interoperate

            // Checksum
            let result = parser.push_byte_raw(239).expect("result expected");

            let raw_packet = result.expect("raw packet expected");
            let packet = Packet::parse(raw_packet).expect("packet expected");

            match packet {
                Packet::RcChannelsPacked(ch) => {
                    ch.0.iter().all(|&x| x == 0);
                }
                _ => panic!("unexpected packet type"),
            }
        }
    }

    #[test]
    fn test_parser_iter_packets() {
        #[rustfmt::skip]
        let data = [
            SYNC_BYTE, 12, 0x14, 16, 19, 99, 151, 1, 2, 3, 8, 88, 148, 252,

            SYNC_BYTE, 0x04, 0x28, PacketAddress::Broadcast as u8, PacketAddress::Handset as u8,
            0x54,
        ];

        let mut parser = Parser::new(ParserConfig::default());
        let mut iter = parser.iter_packets(data.as_slice());
        assert!(matches!(iter.next(), Some(Ok(Packet::LinkStatistics(_)))));
        assert!(matches!(
            iter.next(),
            Some(Ok(Packet::Extended {
                dst: PacketAddress::Broadcast,
                src: PacketAddress::Handset,
                packet: crate::ExtendedPacket::DevicePing(_)
            }))
        ));
    }
}
