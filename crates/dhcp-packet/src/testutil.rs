//! A small deterministic generator for the property tests: xorshift64*,
//! seeded per test, so a failure reproduces exactly and the codec keeps
//! zero dependencies, dev ones included.

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Uniform in `0..n`; `n` must be non-zero.
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    pub fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    pub fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }

    /// `seed` with a few bytes overwritten, and its tail sometimes cut
    /// or extended: inputs that get past the header checks.
    pub fn mutate(&mut self, seed: &[u8]) -> Vec<u8> {
        let mut out = seed.to_vec();
        if !out.is_empty() {
            for _ in 0..=self.below(4) {
                let i = self.below(out.len());
                out[i] = self.byte();
            }
        }
        match self.below(3) {
            0 => {
                let keep = self.below(out.len() + 1);
                out.truncate(keep);
            }
            1 => {
                let extra = self.below(16);
                out.extend(self.bytes(extra));
            }
            _ => {}
        }
        out
    }
}
