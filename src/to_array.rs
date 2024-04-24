/// Helper function to get a fixed-size array at the start of an immutable slice
pub(crate) fn ref_array_start<const N: usize>(buf: &[u8]) -> Option<&[u8; N]> {
    let len = buf.len();
    (&buf[..N.min(len)]).try_into().ok()
}

/// Helper function to get a fixed-size array at the start of a mutable slice
pub(crate) fn mut_array_start<const N: usize>(buf: &mut [u8]) -> Option<&mut [u8; N]> {
    let len = buf.len();
    (&mut buf[..N.min(len)]).try_into().ok()
}
