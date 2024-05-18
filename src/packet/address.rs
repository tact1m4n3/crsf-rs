use num_enum::TryFromPrimitive;

/// Represents all CRSF packet addresses
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum PacketAddress {
    Broadcast = 0x00,
    Usb = 0x10,
    Bluetooth = 0x12,
    TbsCorePnpPro = 0x80,
    Reserved1 = 0x8A,
    CurrentSensor = 0xC0,
    Gps = 0xC2,
    TbsBlackbox = 0xC4,
    FlightController = 0xC8,
    Reserved2 = 0xCA,
    RaceTag = 0xCC,
    Handset = 0xEA,
    Receiver = 0xEC,
    Transmitter = 0xEE,
}

bitflags::bitflags! {
    pub(crate) struct PacketAddressFlags: u16 {
        const BROADCAST = 1;
        const USB = 1 << 1;
        const BLUETOOTH = 1 << 2;
        const TBS_CORE_PNP_PRO = 1 << 3;
        const RESERVED1 = 1 << 4;
        const CURRENT_SENSOR = 1 << 5;
        const GPS = 1 << 6;
        const TBS_BLACKBOX = 1 << 7;
        const FLIGHT_CONTROLLER = 1 << 8;
        const RESERVED2 = 1 << 9;
        const RACE_TAG = 1 << 10;
        const HANDSET =  1 << 11;
        const RECEIVER = 1 << 12;
        const TRANSMITTER = 1 << 13;
    }
}

impl PacketAddressFlags {
    pub(crate) fn from_address(address: PacketAddress) -> Self {
        use PacketAddress::*;

        match address {
            Broadcast => PacketAddressFlags::BROADCAST,
            Usb => PacketAddressFlags::USB,
            Bluetooth => PacketAddressFlags::BLUETOOTH,
            TbsCorePnpPro => PacketAddressFlags::TBS_CORE_PNP_PRO,
            Reserved1 => PacketAddressFlags::RESERVED1,
            CurrentSensor => PacketAddressFlags::CURRENT_SENSOR,
            Gps => PacketAddressFlags::GPS,
            TbsBlackbox => PacketAddressFlags::TBS_BLACKBOX,
            FlightController => PacketAddressFlags::FLIGHT_CONTROLLER,
            Reserved2 => PacketAddressFlags::RESERVED2,
            RaceTag => PacketAddressFlags::RACE_TAG,
            Handset => PacketAddressFlags::HANDSET,
            Receiver => PacketAddressFlags::RECEIVER,
            Transmitter => PacketAddressFlags::TRANSMITTER,
        }
    }

    pub(crate) fn contains_u8(&self, value: u8) -> bool {
        PacketAddress::try_from(value)
            .map_or(false, |address| self.contains(Self::from_address(address)))
    }
}
