// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(dead_code)]

#[cfg(feature = "90s")]
use crate::aes256ctr::*;

#[cfg(feature = "90s")]
use sha2::{Digest, Sha256, Sha512};

#[cfg(feature = "90s-fixslice")]
use aes::cipher::{
    generic_array::GenericArray, KeyIvInit, StreamCipher,
};
#[cfg(feature = "90s-fixslice")]
type Aes256Ctr = ctr::Ctr32BE<aes::Aes256>;

/// Block size for AES256CTR in bytes.
#[cfg(feature = "90s")]
pub const AES256CTR_BLOCKBYTES: usize = 64;

/// Block size for XOF (Extendable Output Function) in bytes.
#[cfg(feature = "90s")]
pub const XOF_BLOCKBYTES: usize = AES256CTR_BLOCKBYTES;

/// Type alias for the XOF (Extendable Output Function) state in 90s mode.
#[cfg(feature = "90s")]
pub type XofState = Aes256CtrCtx;

/// Keccak state for absorbing data
#[derive(Copy, Clone, Debug, Default)]
pub struct KeccakState {
    /// State array for Keccak
    pub s: [u64; 25],
    /// Position in the state array
    pub pos: usize,
}

impl KeccakState {
    /// Creates a new KeccakState
    pub fn new() -> Self {
        KeccakState {
            s: [0u64; 25],
            pos: 0usize,
        }
    }

    /// Resets the KeccakState
    pub fn reset(&mut self) {
        self.s = [0u64; 25];
        self.pos = 0;
    }
}

/// Computes SHA2-256 hash in 90s mode
#[cfg(feature = "90s")]
pub fn hash_h(out: &mut [u8], input: &[u8], inlen: usize) {
    let mut hasher = Sha256::new();
    hasher.update(&input[..inlen]);
    let digest = hasher.finalize();
    out[..digest.len()].copy_from_slice(&digest);
}

/// Computes SHA2-512 hash in 90s mode
#[cfg(feature = "90s")]
pub fn hash_g(out: &mut [u8], input: &[u8], inlen: usize) {
    let mut hasher = Sha512::new();
    hasher.update(&input[..inlen]);
    let digest = hasher.finalize();
    out[..digest.len()].copy_from_slice(&digest);
}

/// Absorbs input data into the XOF state in 90s mode
#[cfg(feature = "90s")]
pub fn xof_absorb(state: &mut XofState, input: &[u8], x: u8, y: u8) {
    let mut nonce = [0u8; 12];
    nonce[0] = x;
    nonce[1] = y;
    aes256ctr_init(state, input, nonce);
}

/// Squeezes XOF data into output in 90s mode
#[cfg(feature = "90s")]
pub fn xof_squeezeblocks(
    out: &mut [u8],
    outblocks: usize,
    state: &mut XofState,
) {
    aes256ctr_squeezeblocks(out, outblocks, state);
}

/// Pseudo-random function (PRF) in 90s mode
#[cfg(feature = "90s")]
pub fn prf(out: &mut [u8], _outbytes: usize, key: &[u8], nonce: u8) {
    #[cfg(feature = "90s-fixslice")]
    {
        // RustCrypto fixslice
        let mut expnonce = [0u8; 16];
        expnonce[0] = nonce;
        let key = GenericArray::from_slice(key);
        let iv = GenericArray::from_slice(&expnonce);
        let mut cipher = Aes256Ctr::new(key, iv);
        cipher.apply_keystream(out)
    }
}

/// Key derivation function (KDF) in 90s mode
#[cfg(feature = "90s")]
pub fn kdf(out: &mut [u8], input: &[u8], inlen: usize) {
    let mut hasher = Sha256::new();
    hasher.update(&input[..inlen]);
    let digest = hasher.finalize();
    out[..digest.len()].copy_from_slice(&digest);
}
