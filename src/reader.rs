use crate::{
    crc8::Crc8, Error, Packet, PacketAddress, PacketAddressFlags, PacketType, RawPacket,
    CRSF_HEADER_LEN, CRSF_MAX_LEN,
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

pub struct ReaderConfig {
    /// Sync byte to use for finding the start of a frame. Default is `0xC8`
    sync: PacketAddressFlags,

    /// Whether to ensure the type byte is a valid PacketType enum value. Default is `true`.
    type_check: bool,
}

impl ReaderConfig {
    // Not using default trait because it is not const
    const fn default() -> Self {
        Self {
            sync: PacketAddressFlags::FLIGHT_CONTROLLER,
            type_check: true,
        }
    }
}

/// Represents a packet reader
pub struct PacketReader {
    state: ReadState,
    raw: RawPacket,
    digest: Crc8,
    config: ReaderConfig,
}

impl Default for PacketReader {
    /// Creates a new PacketReader with the default configuration
    fn default() -> Self {
        Self {
            state: ReadState::AwaitingSync,
            raw: RawPacket::empty(),
            digest: Crc8::new(),
            config: ReaderConfig::default(),
        }
    }
}

impl PacketReader {
    // Minimum data length, must include type and crc bytes
    const MIN_LEN_BYTE: u8 = 2;
    // Maximum data length, includes type, payload and crc bytes
    const MAX_LEN_BYTE: u8 = CRSF_MAX_LEN as u8 - Self::MIN_LEN_BYTE;

    /// Creates a new PacketReader struct
    pub const fn new() -> Self {
        Self {
            state: ReadState::AwaitingSync,
            raw: RawPacket::empty(),
            digest: Crc8::new(),
            config: ReaderConfig::default(),
        }
    }

    pub const fn builder() -> PacketReaderBuilder {
        PacketReaderBuilder {
            config: ReaderConfig {
                sync: PacketAddressFlags::FLIGHT_CONTROLLER,
                type_check: true,
            },
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
                        if self.config.sync.contains_u8(sync_byte) {
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

pub struct PacketReaderBuilder {
    config: ReaderConfig,
}

impl PacketReaderBuilder {
    pub fn sync(mut self, sync: &[PacketAddress]) -> Self {
        let mut sync_byte = PacketAddressFlags::empty();
        for addr in sync {
            sync_byte |= PacketAddressFlags::from_address(*addr);
        }
        self.config.sync = sync_byte;
        self
    }

    pub fn type_check(mut self, type_check: bool) -> Self {
        self.config.type_check = type_check;
        self
    }

    pub fn build(self) -> PacketReader {
        PacketReader {
            state: ReadState::AwaitingSync,
            raw: RawPacket::empty(),
            digest: Crc8::new(),
            config: self.config,
        }
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
