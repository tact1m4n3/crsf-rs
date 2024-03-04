pub use link_statistics::*;
pub use rc_channels::*;

mod link_statistics;
mod rc_channels;

// TODO: implement an extended packet payload

#[derive(Debug)]
pub enum PacketPayload {
    LinkStatistics(LinkStatistics),
    RcChannels(RcChannels),
}
