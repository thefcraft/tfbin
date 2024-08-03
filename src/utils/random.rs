use std::time::{SystemTime, UNIX_EPOCH};
pub struct Random {
    state: u64,
    multiplier: u64,
    increment: u64,
    modulus: u64,
}
impl Random {
    pub fn new() -> Self {
        let seed: u128 = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_nanos();
        let multiplier = 1664525_u64;
        let increment = 1013904223_u64;
        let modulus = 2_u64.pow(32);
        Self {
            state: seed as u64,
            multiplier,
            increment,
            modulus,
        }
    }
    pub fn set_seed(&mut self, seed: u64) {
        self.state = seed;
    }
    pub fn randint(&mut self, min: i64, max: i64) -> i64 {
        // Ensure min <= max
        assert!(min <= max, "min must be less than or equal to max");
        self.update();
        // Convert to i64 and return in the range [min, max]
        let range = (max - min + 1) as u64;
        let random_number = self.state % range;
        (random_number as i64) + min
    }
    pub fn random(&mut self) -> f64 {
        self.update();
        // Return a float in range [0, 1)
        // let a = self.state as f64 / self.modulus as f64; // [0, 1)
        // maybe (-1.0, 1.0)
        ((self.state as f64 / self.modulus as f64) - 0.5)*2.0
    }
    fn update(&mut self) {
        // Update the state using a simple linear congruential generator (LCG)
        // self.state = (self.state * 1103515245 as u128 + 12345 as u128) & 0x7fffffff;
        self.state = (self.state.wrapping_mul(self.multiplier).wrapping_add(self.increment)) % self.modulus;
    }
}