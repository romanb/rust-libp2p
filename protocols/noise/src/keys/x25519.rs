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

use crate::error::NoiseError;
use curve25519_dalek::edwards::CompressedEdwardsY;
use libp2p_core::identity::ed25519;
use rand::Rng;
use ring::digest::{SHA512, digest};
use super::DhKeys;
use x25519_dalek as x25519;
use x25519::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::Zeroize;

/// X25519 static keypair.
#[derive(Clone)]
pub struct Keypair {
    secret: SecretKey,
    public: PublicKey
}

/// X25519 secret key (i.e. secret scalar).
#[derive(Clone)]
pub struct SecretKey([u8; 32]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// X25519 public key (i.e. public point).
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl DhKeys for Keypair {
    type PublicKey = PublicKey;

    fn public_from_slice(bytes: &[u8]) -> Result<PublicKey, NoiseError> {
        if bytes.len() != 32 {
            return Err(NoiseError::InvalidKey)
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(bytes);
        Ok(PublicKey(pk))
    }
}

impl snow::types::Dh for Keypair {
    fn name(&self) -> &'static str { "25519" }
    fn pub_len(&self) -> usize { 32 }
    fn priv_len(&self) -> usize { 32 }
    fn pubkey(&self) -> &[u8] { &self.public.0 }
    fn privkey(&self) -> &[u8] { &self.secret.0 }

    fn set(&mut self, sk: &[u8]) {
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&sk[..]);
        self.secret = SecretKey(secret); // Copy
        self.public = PublicKey(x25519(secret, X25519_BASEPOINT_BYTES));
        secret.zeroize();
    }

    fn generate(&mut self, rng: &mut dyn snow::types::Random) {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        self.secret = SecretKey(secret); // Copy
        self.public = PublicKey(x25519(secret, X25519_BASEPOINT_BYTES));
        secret.zeroize();
    }

    fn dh(&self, pk: &[u8], shared_secret: &mut [u8]) -> Result<(), ()> {
        let mut p = [0; 32];
        p.copy_from_slice(&pk[.. 32]);
        let ss = x25519(self.secret.0, p);
        shared_secret[.. 32].copy_from_slice(&ss[..]);
        Ok(())
    }
}

impl Keypair {
    /// An "empty" keypair as a starting state for DH computations in `snow`,
    /// which get manipulated through the `snow::types::Dh` interface.
    pub(crate) fn default() -> Keypair {
        Keypair {
            secret: SecretKey([0u8; 32]),
            public: PublicKey([0u8; 32])
        }
    }

    /// Get a reference to the public key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Create a new X25519 keypair.
    pub fn new() -> Keypair {
        let mut sk_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut sk_bytes);
        let sk = SecretKey(sk_bytes); // Copy
        sk_bytes.zeroize();
        Self::from(sk)
    }

    /// Construct a X25519 keypair from an Ed25519 keypair.
    ///
    /// *Note*: If the Ed25519 keypair is already used in the context
    /// of other cryptographic protocols outside of Noise, e.g. for
    /// signing in the `secio` protocol, it should be preferred to
    /// create a new keypair for use in the Noise protocol.
    ///
    /// See also:
    ///
    /// [Noise: Static Key Reuse](http://www.noiseprotocol.org/noise.html#security-considerations)
    /// [Ed25519 to Curve25519](https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519)
    pub fn from_ed25519(ed: &ed25519::Keypair) -> Keypair {
        // An Ed25519 public key is derived off the left half of the SHA512 of the
        // secret scalar, hence a matching conversion of the secret key must do
        // the same to yield a Curve25519 keypair with the same public key.
        let ed25519_sk = ed.secret_bytes();
        let mut curve25519_sk: [u8; 32] = [0; 32];
        let hash = digest(&SHA512, ed25519_sk);
        curve25519_sk.copy_from_slice(&hash.as_ref()[..32]);
        let sk = SecretKey(curve25519_sk); // Copy
        curve25519_sk.zeroize();
        Self::from(sk)
    }
}

impl From<SecretKey> for Keypair {
    fn from(secret: SecretKey) -> Keypair {
        let public = PublicKey(x25519(secret.0, X25519_BASEPOINT_BYTES));
        Keypair { secret, public }
    }
}

impl PublicKey {
    /// Construct a curve25519 public key from an Ed25519 public key.
    ///
    /// See also [`Keypair::from_ed25519`].
    ///
    /// [`Keypair::from_ed25519`]: struct.StaticKeypair.html#method.from_ed25519
    pub fn from_ed25519(pk: &ed25519::PublicKey) -> PublicKey {
        PublicKey(CompressedEdwardsY(pk.encode())
            .decompress()
            .expect("An Ed25519 public key is a valid point by construction.")
            .to_montgomery().0)
    }
}

#[cfg(test)]
mod tests {
    use libp2p_core::identity::ed25519;
    use quickcheck::*;
    use sodiumoxide::crypto::sign;
    use std::os::raw::c_int;
    use super::*;

    // ed25519 to x25519 keypair conversion must yield the same results as
    // obtained through libsodium.
    #[test]
    fn prop_ed25519_to_x25519_matches_libsodium() {
        fn prop() -> bool {
            let ed25519 = ed25519::Keypair::generate();
            let x25519 = Keypair::from_ed25519(&ed25519);

            let sodium_sec = ed25519_sk_to_curve25519(&sign::SecretKey(ed25519.encode()));
            let sodium_pub = ed25519_pk_to_curve25519(&sign::PublicKey(ed25519.public().encode().clone()));

            let our_pub = x25519.public.0;
            // libsodium does the [clamping] of the scalar upon key construction,
            // just like x25519-dalek, but this module uses the raw byte-oriented x25519
            // function from x25519-dalek, as defined in RFC7748, so "our" secret scalar
            // must be clamped before comparing it to the one computed by libsodium.
            // That happens in `StaticSecret::from`.
            //
            // [clamping]: http://www.lix.polytechnique.fr/~smith/ECC/#scalar-clamping
            let our_sec = x25519::StaticSecret::from(x25519.secret.0).to_bytes();

            sodium_sec.as_ref() == Some(&our_sec) &&
            sodium_pub.as_ref() == Some(&our_pub)
        }

        quickcheck(prop as fn() -> _);
    }

    // The x25519 public key obtained through ed25519 keypair conversion
    // (and thus derived from the converted secret key) must match the x25519
    // public key derived directly from the ed25519 public key.
    #[test]
    fn prop_public_ed25519_to_x25519_matches() {
        fn prop() -> bool {
            let ed25519 = ed25519::Keypair::generate();
            let x25519 = Keypair::from_ed25519(&ed25519);
            let x25519_public = PublicKey::from_ed25519(&ed25519.public());
            x25519.public == x25519_public
        }

        quickcheck(prop as fn() -> _);
    }

    // Bindings to libsodium's ed25519 to curve25519 key conversions, to check that
    // they agree with the conversions performed in this module.

    extern "C" {
        pub fn crypto_sign_ed25519_pk_to_curve25519(c: *mut u8, e: *const u8) -> c_int;
        pub fn crypto_sign_ed25519_sk_to_curve25519(c: *mut u8, e: *const u8) -> c_int;
    }

    pub fn ed25519_pk_to_curve25519(k: &sign::PublicKey) -> Option<[u8; 32]> {
        let mut out = [0u8; 32];
        unsafe {
            if crypto_sign_ed25519_pk_to_curve25519(out.as_mut_ptr(), (&k.0).as_ptr()) == 0 {
                Some(out)
            } else {
                None
            }
        }
    }

    pub fn ed25519_sk_to_curve25519(k: &sign::SecretKey) -> Option<[u8; 32]> {
        let mut out = [0u8; 32];
        unsafe {
            if crypto_sign_ed25519_sk_to_curve25519(out.as_mut_ptr(), (&k.0).as_ptr()) == 0 {
                Some(out)
            } else {
                None
            }
        }
    }
}

