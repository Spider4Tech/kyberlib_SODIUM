// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use sodiumoxide::crypto::{secretbox, stream};
// use crate::aes::Aes256CtrCtx;
use sodiumoxide::crypto::stream::Key;

use crate::nacl::Naclx;


type _XChaCha20Poly1305 = sodiumoxide::crypto::aead::xchacha20poly1305_ietf::Key;

/// Block size for AES256CTR in bytes.
#[cfg(feature = "90s")]
pub const AES256CTR_BLOCKBYTES: usize = 64;

/// Block size for XOF (Extendable Output Function) in bytes.
#[cfg(feature = "90s")]
pub const XOF_BLOCKBYTES: usize = 64;

/// Type alias for the XOF (Extendable Output Function) state in 90s mode.
#[cfg(feature = "90s")]
pub type XofState = Naclx;

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
    let hash = blake3::hash(&input[..inlen]);
    let hash_bytes = hash.as_bytes();
    out[..hash_bytes.len()].copy_from_slice(hash_bytes);
}

/// Computes SHA2-512 hash in 90s mode
#[cfg(feature = "90s")]
pub fn hash_g(out: &mut [u8], input: &[u8], inlen: usize) {    
    let mut hasher = blake3::Hasher::new();
    hasher.update(&input[..inlen]);

    let mut output = [0u8; 64];

    hasher.finalize_xof().fill(&mut output);

    out.copy_from_slice(&output[..out.len()]);
}

/// Absorbs input data into the XOF state in 90s mode
#[cfg(feature = "90s")]
pub fn xof_absorb(state: &mut XofState, _input: &[u8], _x: u8, _y: u8) {    
    sodiumoxide::init().expect("Sodium initialization failed");
    
    let _key = Key::from_slice(_input).expect("Invalid key length");

    // Mettre à jour l'état avec les données transformées
    //TODO Implémenter correctement le nonce en cul lait deux ta rasse
    state.nonce = stream::gen_nonce();
}

/// Squeezes XOF data into output in 90s mode
#[cfg(feature = "90s")]
pub fn xof_squeeze(
    out: &mut [u8],
    state: &mut XofState,
) {
    sodiumoxide::init().expect("Sodium initialization failed");

    let key = Key::from_slice(&state.sk_exp).expect("Invalid key length");

    stream::stream_xor_inplace(out, &state.nonce, &key);

    let out_copy= &mut vec![];

    out.clone_into( out_copy);

    out.copy_from_slice(&out_copy[..out_copy.len()]);
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
    let truncated_ciphertext = &ciphertext[..ciphertext.len() - 16]; //TODO à modifier an cul lait

    out.copy_from_slice(truncated_ciphertext);
}

/// Key derivation function (KDF) in 90s mode
#[cfg(feature = "90s")]
pub fn kdf(out: &mut [u8], input: &[u8], inlen: usize) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&input[..inlen]);
    let digest = hasher.finalize();

    let digest_bytes = digest.as_bytes();

    out[..digest_bytes.len()].copy_from_slice(digest_bytes);
}
