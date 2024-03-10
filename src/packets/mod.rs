pub use link_statistics::*;
pub use rc_channels::*;

use crate::PacketType;

mod link_statistics;
mod rc_channels;

pub(crate) trait Payload {
    fn len(&self) -> u8;

    fn packet_type(&self) -> PacketType;

    fn dump(&self, buf: &mut [u8]);
}
