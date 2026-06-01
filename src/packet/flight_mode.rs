use core::ffi::CStr;

use crate::{PacketType, Payload, PayloadDump};

/// `FlightMode` payload type
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(missing_docs)]
pub struct FlightMode<'a> {
    pub flight_mode: &'a str,
}

impl<'a> FlightMode<'a> {
    /// Parses a `FlightMode` payload.
    pub(crate) fn parse(data: &'a [u8]) -> Option<Self> {
        Some(FlightMode {
            flight_mode: CStr::from_bytes_with_nul(data).ok()?.to_str().ok()?,
        })
    }
}

impl Payload for FlightMode<'_> {
    fn len(&self) -> usize {
        self.flight_mode.len()
    }

    fn typ(&self) -> PacketType {
        PacketType::FlightMode
    }

    fn encode(&self, data: &mut [u8]) {
        data[..self.flight_mode.len()].copy_from_slice(self.flight_mode.as_bytes());
    }
}

impl PayloadDump for FlightMode<'_> {}
