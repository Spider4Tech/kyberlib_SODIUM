#![cfg(feature = "90s")]
#[derive(Debug)]
pub struct Naclx {
    pub sk_exp: [u64; 120],
    pub ivw: [u32; 16],
}

impl Naclx {
    pub fn new() -> Self {
        Self {
            sk_exp: [0u64; 120],
            ivw: [0u32; 16],
        }
    }
}

impl Default for Naclx {
    fn default() -> Self {
        Self::new()
    }
}