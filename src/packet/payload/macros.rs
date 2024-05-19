macro_rules! impl_any_payload {
    ($name:ident, $len:expr) => {
        impl $crate::packet::payload::AnyPayload for $name {
            const LEN: usize = $len;

            fn packet_type(&self) -> $crate::packet::typ::PacketType {
                $crate::packet::typ::PacketType::$name
            }

            fn decode(buf: &[u8]) -> Result<Self, $crate::Error> {
                let data: &[u8; LEN] = $crate::to_array::ref_array_start(buf).ok_or($crate::Error::BufferError)?;
                Ok(raw_decode(data))
            }

            fn encode<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], $crate::Error> {
                let data: &mut [u8; LEN] = $crate::to_array::mut_array_start(buf).ok_or($crate::Error::BufferError)?;
                raw_encode(self, data);
                Ok(data)
            }
        }
    };
}

macro_rules! impl_payload {
    ($name:ident, $len:expr) => {
        impl_any_payload!($name, $len);
        impl $crate::packet::payload::Payload for $name {}
    };
}

macro_rules! impl_extended_payload {
    ($name:ident, $len:expr) => {
        impl_any_payload!($name, $len);
        impl $crate::packet::payload::ExtendedPayload for $name {}
    };
}
