pub(crate) struct BytesReader<'a> {
    buf: &'a [u8],
    idx: usize,
}

impl<'a> BytesReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, idx: 0 }
    }

    // Get a slice of the remaining part of the buffer
    pub fn remaining(&self) -> &'a [u8] {
        debug_assert!(self.idx <= self.buf.len());
        self.buf.get(self.idx..).unwrap_or(&[])
    }

    pub fn is_empty(&self) -> bool {
        self.idx == self.buf.len()
    }

    pub fn next(&mut self) -> Option<u8> {
        if self.idx < self.buf.len() {
            let val = self.buf[self.idx];
            self.idx += 1;
            Some(val)
        } else {
            None
        }
    }

    pub fn next_n(&mut self, n: usize) -> &[u8] {
        let end_idx = (self.idx + n).min(self.buf.len());
        let data = &self.buf[self.idx..end_idx];
        self.idx = end_idx;
        data
    }
}

#[cfg(test)]
mod tests {
    use crate::buffer::BytesReader;

    #[test]
    fn test_bytes_reader() {
        let bytes: &[u8] = &[1, 2, 3, 4, 5];
        let mut reader = BytesReader::new(bytes);
        assert_eq!(reader.next(), Some(1));
        assert_eq!(reader.remaining(), &[2, 3, 4, 5]);
        assert_eq!(reader.next_n(2), &[2, 3]);
        assert_eq!(reader.remaining(), &[4, 5]);
        assert_eq!(reader.next(), Some(4));
        assert_eq!(reader.next(), Some(5));
        assert_eq!(reader.remaining(), &[]);
    }
}
