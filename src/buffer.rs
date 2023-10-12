pub struct CircularBuffer<const C: usize> {
    data: [u8; C],
    len: usize,
    head: usize,
    tail: usize,
}

impl<const C: usize> Default for CircularBuffer<C> {
    fn default() -> Self {
        Self {
            data: [0; C],
            len: 0,
            head: 0,
            tail: 0,
        }
    }
}

impl<const C: usize> CircularBuffer<C> {
    pub const fn len(&self) -> usize {
        self.len
    }

    pub fn push_back(&mut self, byte: u8) {
        if self.len >= C {
            return;
        }

        self.data[self.head] = byte;
        self.head = (self.head + 1) % C;
        self.len += 1;
    }

    pub fn pop_front(&mut self) -> Option<u8> {
        if self.len <= 0 {
            return None;
        }

        let val = self.data[self.tail];
        self.tail = (self.tail + 1) % C;
        self.len -= 1;
        Some(val)
    }

    pub const fn peek_front(&self, idx: usize) -> Option<u8> {
        if idx < self.len {
            let idx = (self.tail + idx) % C;
            Some(self.data[idx])
        } else {
            None
        }
    }
}
