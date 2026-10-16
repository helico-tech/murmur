//! A small deterministic random generator (SplitMix64). Murmur's choices (which peer to dial,
//! jitter) come from it, so a swarm given the same seed and inputs behaves the same way.

#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number in `0..n` (0 when `n` is 0).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }

    /// `base` ± `spread`/2, never below 1.
    pub fn jitter(&mut self, base: u64, spread: u64) -> u64 {
        (base + self.below(spread + 1)).saturating_sub(spread / 2).max(1)
    }

    /// A probability check.
    #[cfg_attr(not(feature = "sim"), allow(dead_code))]
    pub fn chance(&mut self, p: f64) -> bool {
        ((self.next_u64() >> 11) as f64 / (1u64 << 53) as f64) < p
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        items.get(self.below(items.len() as u64) as usize)
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            items.swap(i, j);
        }
    }
}
