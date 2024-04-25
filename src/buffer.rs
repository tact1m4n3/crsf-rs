pub(crate) struct BytesReader<'a> {
    buf: &'a [u8],
    idx: usize,
}

impl<'a> BytesReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, idx: 0 }
    }

    pub fn consumed(&self) -> usize {
        self.idx
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

pub(crate) struct Buf<const C: usize> {
    buf: [u8; C],
    len: usize,
}

impl<const C: usize> Buf<C> {
    pub const fn new() -> Self {
        Self {
            buf: [0; C],
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn push(&mut self, c: u8) -> bool {
        if let Some(v) = self.buf.get_mut(self.len) {
            *v = c;
            self.len += 1;
            true
        } else {
            false
        }
    }

    pub fn push_bytes(&mut self, data: &[u8]) {
        self.buf[self.len..self.len + data.len()].copy_from_slice(data);
        self.len += data.len();
    }

    pub fn data(&self) -> &[u8; C] {
        &self.buf
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }
}
