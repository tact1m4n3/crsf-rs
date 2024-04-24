pub(crate) struct Buf<const C: usize> {
    buf: [u8; C],
    len: usize,
}

impl<const C: usize> Buf<C> {
    pub(crate) const fn new() -> Self {
        Self {
            buf: [0; C],
            len: 0,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn push(&mut self, c: u8) -> bool {
        if let Some(v) = self.buf.get_mut(self.len) {
            *v = c;
            self.len += 1;
            true
        } else {
            false
        }
    }

    pub(crate) fn push_bytes(&mut self, data: &[u8]) {
        self.buf[self.len..self.len + data.len()].copy_from_slice(data);
        self.len += data.len();
    }

    pub(crate) fn data(&self) -> &[u8; C] {
        &self.buf
    }

    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }
}
