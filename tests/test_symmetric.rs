// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    // Import necessary items
    use kyberlib::{
        symmetric::{hash_g, hash_h, kdf, prf},
        KYBER_SHARED_SECRET_BYTES,
    };

    // Test the hash_h function
    #[test]
    fn test_hash_h() {
        let input = b"test input";
        let inlen = input.len();
        let mut out = [0u8; 32];

        // Call the hash_h function
        hash_h(&mut out, input, inlen);

        // Assert that the output is not all zeros
        assert_ne!(out, [0u8; 32]);
    }

    // Test the hash_g function
    #[test]
    fn test_hash_g() {
        let input = b"test input";
        let inlen = input.len();
        let mut out = [0u8; 64];

        // Call the hash_g function
        hash_g(&mut out, input, inlen);

        // Assert that the output is not all zeros
        assert_ne!(out, [0u8; 64]);
    }

    // Test the prf function
    #[test]
    fn test_prf() {
        use kyberlib::params::KYBER_SYM_BYTES;
        let mut key = [0u8; KYBER_SYM_BYTES];
        key[..8].copy_from_slice(b"test key");
        let nonce = 42;
        let mut out = [0u8; 64];
        let outbytes = out.len();

        // Call the prf function
        prf(&mut out, outbytes, &key, nonce);

        // Assert that the output is not all zeros
        assert_ne!(out, [0u8; 64]);
    }

    // Test the kdf function
    #[test]
    fn test_kdf() {
        let input = b"test input";
        let inlen = input.len();
        let mut out = [0u8; KYBER_SHARED_SECRET_BYTES];

        // Call the kdf function
        kdf(&mut out, input, inlen);

        // Assert that the output is not all zeros
        assert_ne!(out, [0u8; KYBER_SHARED_SECRET_BYTES]);
    }
}
