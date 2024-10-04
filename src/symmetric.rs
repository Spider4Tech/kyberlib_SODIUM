// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use sodiumoxide::crypto::{secretbox, stream};

#[cfg(feature = "90s-fixslice")]
type _XChaCha20Poly1305 = sodiumoxide::crypto::aead::xchacha20poly1305_ietf::Key;

/// Block size for AES256CTR in bytes.
#[cfg(feature = "90s")]
pub const AES256CTR_BLOCKBYTES: usize = 64;

/// Block size for XOF (Extendable Output Function) in bytes.
#[cfg(feature = "90s")]
pub const XOF_BLOCKBYTES: usize = 64;

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
    let mut hasher = blake3::Hasher::new();
    hasher.update(&input[..inlen]);
    let digest = hasher.finalize();

    let digest_bytes = digest.as_bytes();
    out[..digest_bytes.len()].copy_from_slice(digest_bytes)
}

/// Computes SHA2-512 hash in 90s mode
#[cfg(feature = "90s")]
pub fn hash_g(out: &mut [u8], input: &[u8], inlen: usize) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&input[..inlen]);
    let digest = hasher.finalize();

    let digest_bytes = digest.as_bytes();
    out[..digest_bytes.len()].copy_from_slice(digest_bytes)
}

/// Absorbs input data into the XOF state in 90s mode
#[cfg(feature = "90s")]
pub fn xof_absorb(state: &mut XofState, input: &[u8], x: u8, y: u8) {
    use sodiumoxide::crypto::stream::{Key, Nonce};
    
    sodiumoxide::init().expect("Sodium initialization failed");
    
    let mut nonce = [0u8; 8];
    nonce[0] = x;
    nonce[1] = y;
    
    let key = Key::from_slice(input).expect("Invalid key length");
    
    let nonce = Nonce::from_slice(&nonce).expect("Invalid nonce length");
    
    let mut stream = stream::stream_xor(input, &nonce,&key);
    
    let mut output = vec![0u8; input.len()];

    // Mettre à jour l'état avec les données transformées
    state.update(&output);
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

    let key = secretbox::Key::from_slice(key).expect("Key must be 32 bytes");

    //nonce de 24 octets, en utilisant le nonce fourni
    let mut expnonce = [0u8; secretbox::NONCEBYTES];
    expnonce[0] = nonce; // Utilisez le nonce fourni
    let nonce = secretbox::Nonce::from_slice(&expnonce).expect("Nonce must be 24 bytes");


    let ciphertext = secretbox::seal(out, &nonce, &key);
    let truncated_ciphertext = &ciphertext[..ciphertext.len() - 16];

    out.copy_from_slice(truncated_ciphertext);
}

/// Key derivation function (KDF) in 90s mode
#[cfg(feature = "90s")]
pub fn kdf(out: &mut [u8], input: &[u8], inlen: usize) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&input[..inlen]);
    let digest = hasher.finalize();

    let digest_bytes = digest.as_bytes();
    out[..digest_bytes.len()].copy_from_slice(digest_bytes)
}