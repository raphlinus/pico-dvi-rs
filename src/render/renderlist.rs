use alloc::vec::Vec;

pub struct Renderlist(Vec<u32>);

pub struct RenderlistBuilder {
    v: Vec<u32>,
    stripe_start: usize,
}

impl RenderlistBuilder {
    pub fn new() -> Self {
        RenderlistBuilder {
            v: alloc::vec![],
            stripe_start: 0,
        }
    }

    pub fn begin_stripe(&mut self, height: u32) {
        self.v.extend([height, 0]);
    }

    pub fn end_stripe(&mut self) {
        let len = self.v.len();
        self.v[self.stripe_start + 1] = len as u32;
        self.stripe_start = len;
    }

    pub fn build(self) -> Renderlist {
        Renderlist(self.v)
    }
}

impl Renderlist {
    pub fn get(&self) -> &[u32] {
        &self.0
    }
}
