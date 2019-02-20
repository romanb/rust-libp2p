// Copyright 2019 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use ed25519_dalek as ed25519;
use failure::Fail;
use super::error::DecodingError;
use zeroize::Zeroize;

/// An Ed25519 keypair.
pub struct Keypair(ed25519::Keypair);
/// An Ed25519 public key.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct PublicKey(ed25519::PublicKey);

impl Keypair {
    /// Generate a new Ed25519 keypair.
    pub fn generate() -> Keypair {
        Keypair(ed25519::Keypair::generate(&mut rand::thread_rng()))
    }

    /// Create an Ed25519 keypair from a secret key.
    pub fn from_secret(pk: impl AsRef<[u8]>) -> Result<Keypair, DecodingError> {
        let secret = ed25519::SecretKey::from_bytes(pk.as_ref())
            .map_err(|e| DecodingError::new("Ed25519 secret key", e.compat()))?;
        let public = ed25519::PublicKey::from(&secret);
        Ok(Keypair(ed25519::Keypair { secret, public }))
    }

    /// Encode the keypair into a byte array by concatenating the bytes
    /// of the secret scalar and the compressed public point,
    /// an informal standard for encoding Ed25519 keypairs.
    pub fn encode(&self) -> [u8; 64] {
        self.0.to_bytes()
    }

    /// Decode a keypair from the format produced by `encode`.
    pub fn decode(kp: &[u8]) -> Result<Keypair, DecodingError> {
        ed25519::Keypair::from_bytes(kp)
            .map(Keypair)
            .map_err(|e| DecodingError::new("Ed25519 keypair", e.compat()))
    }

    /// Sign a message using the private key of this keypair.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.0.sign(msg).to_bytes().to_vec()
    }

    /// Get the public key of this keypair.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.public)
    }

    /// View the bytes of the secret key (i.e. the scalar).
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.0.secret.as_bytes()
    }
}

impl Clone for Keypair {
    fn clone(&self) -> Keypair {
        let mut sk_bytes = self.0.secret.to_bytes();
        let secret = ed25519::SecretKey::from_bytes(&sk_bytes)
            .expect("ed25519::SecretKey::from_bytes(to_bytes(k)) != k");
        sk_bytes.zeroize();
        let public = ed25519::PublicKey::from_bytes(&self.0.public.to_bytes())
            .expect("ed25519::PublicKey::from_bytes(to_bytes(k)) != k");
        Keypair(ed25519::Keypair { secret, public })
    }
}

impl PublicKey {
    /// Verify the Ed25519 signature on a message using the public key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        ed25519::Signature::from_bytes(sig).map(|s| self.0.verify(msg, &s)).is_ok()
    }

    /// Encode the public key into a byte array in compressed form, i.e.
    /// where one coordinate is represented by a single bit.
    pub fn encode(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Decode a public key from a byte array as produced by `encode`.
    pub fn decode(k: &[u8]) -> Result<PublicKey, DecodingError> {
        ed25519::PublicKey::from_bytes(k)
            .map_err(|e| DecodingError::new("Ed25519 public key", e.compat()))
            .map(PublicKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;

    #[test]
    fn ed25519_keypair_encode_decode() {
        fn prop() -> bool {
            let pk = Keypair::generate();
            Keypair::decode(&pk.encode()).is_ok()
        }
        QuickCheck::new().tests(10).quickcheck(prop as fn() -> _);
    }
}

