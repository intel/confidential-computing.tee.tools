// Copyright (C) 2025 Intel Corporation
// SPDX-License-Identifier: BSD-3-Clause

use rsa::{traits::PublicKeyParts, RsaPublicKey};
use sha2::{Sha512, Digest};
use base64::prelude::*;

// Extension trait for RsaPublicKey providing additional utility methods.
pub trait RsaPublicKeyExt {
    /// Returns the Base64 encoding of the public key.
    ///
    /// # Returns
    ///
    /// A `String` containing the Base64 encoded public key.
    ///
    /// # Panics
    ///
    /// This method will panic if the public key serialization to DER format fails.
    fn base64_encoded(&self) -> String;

    /// Returns the SHA-512 digest of the public key.
    ///
    /// # Returns
    ///
    /// An array of 64 bytes representing the SHA-512 digest of the public key.
    ///
    /// # Panics
    ///
    /// This method will panic if the public key serialization to DER format fails.
    fn sha512_digest(&self) -> [u8; 64];
}

impl RsaPublicKeyExt for RsaPublicKey {
    fn base64_encoded(&self) -> String {
        let key = serialize_pk_ita(self);

        // Calculate base64 encoding of the key.
        BASE64_STANDARD.encode(&key)
    }

    fn sha512_digest(&self) -> [u8; 64] {
        let key = serialize_pk_ita(self);

        // Calculate sha512 hash of the key.
        let mut hasher = Sha512::new();
        hasher.update(&key);
        let key_hash = hasher.finalize();
        key_hash.into()
    }
}

/// Serializes the given RSA public key to the format expected by ITA KBS.
///
/// # Arguments
///
/// * `public_key` - A reference to the RSA public key to be serialized.
///
/// # Returns
///
/// A `Vec<u8>` containing the serialized public key.
fn serialize_pk_ita(public_key: &RsaPublicKey) -> Vec<u8> {
    // Convert public_key modulus to byte array
    let modulus = public_key.n().to_bytes_be();

    // Copy exponent of public key to a 32 bit array in little endian format
    let mut exponent_le = [0u8; 4];
    let exponent_bytes = public_key.e().to_bytes_le();
    exponent_le[..exponent_bytes.len()].copy_from_slice(&exponent_bytes);

    // Append modulus to exponent_le
    let mut key = vec![0u8; 4 + modulus.len()];
    key[..4].copy_from_slice(&exponent_le);
    key[4..].copy_from_slice(&modulus);

    key
}
