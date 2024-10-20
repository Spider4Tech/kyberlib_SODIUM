#![cfg(feature = "90s")]
#[derive(Debug)]
pub struct Naclx {
    pub sk_exp: [u8; 32],
    pub nonce: sodiumoxide::crypto::stream::Nonce,
}

impl Naclx {
    pub fn new() -> Self {
        Self {
            sk_exp: [0; 32],
            nonce: sodiumoxide::crypto::stream::Nonce([0u8; 24]),
        }
    }
}

impl Default for Naclx {
    fn default() -> Self {
        Self::new()
    }
}