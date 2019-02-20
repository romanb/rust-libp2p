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

use curve25519_dalek::edwards::CompressedEdwardsY;
use libp2p_core::identity::ed25519;
use ring::digest::{SHA512, digest};
use x25519_dalek as x25519;

/// X25519 static keypair.
pub struct StaticKeypair {
    secret: x25519::StaticSecret,
    public: StaticPublicKey
}

impl Clone for StaticKeypair {
    fn clone(&self) -> StaticKeypair {
        StaticKeypair {
            secret: x25519::StaticSecret::from(self.secret.to_bytes()),
            public: self.public.clone()
        }
    }
}

impl StaticKeypair {
    /// Get a reference to the static secret key.
    pub fn secret(&self) -> &x25519::StaticSecret {
        &self.secret
    }

    /// Get a reference to the static public key.
    pub fn public(&self) -> &StaticPublicKey {
        &self.public
    }

    /// Create a new static X25519 keypair.
    pub fn new() -> StaticKeypair {
        Self::from(x25519::StaticSecret::new(&mut rand::thread_rng()))
    }

    /// Construct a static X25519 keypair from an Ed25519 keypair.
    ///
    /// *Note*: If the Ed25519 keypair is already used in the context
    /// of other cryptographic protocols outside of Noise, e.g. for
    /// signing in the `secio` protocol, it should be preferred to
    /// create a new `StaticKeypair` for use in the Noise protocol.
    ///
    /// See also:
    ///
    /// [Noise: Static Key Reuse](http://www.noiseprotocol.org/noise.html#security-considerations)
    /// [Ed25519 to Curve25519](https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519)
    pub fn from_ed25519(ed: &ed25519::Keypair) -> StaticKeypair {
        // An Ed25519 public key is derived off the left half of the SHA512 of the
        // secret scalar, hence a matching conversion of the secret key must do
        // the same to yield a Curve25519 keypair with the same public key.
        let ed25519_sk = ed.secret_bytes();
        let mut curve25519_sk: [u8; 32] = [0; 32];
        let hash = digest(&SHA512, ed25519_sk);
        curve25519_sk.copy_from_slice(&hash.as_ref()[..32]);
        Self::from(x25519::StaticSecret::from(curve25519_sk))
    }
}

impl From<x25519::StaticSecret> for StaticKeypair {
    fn from(secret: x25519::StaticSecret) -> StaticKeypair {
        let public = StaticPublicKey(x25519::PublicKey::from(&secret));
        StaticKeypair { secret, public }
    }
}

/// Static X25519 public key.
pub struct StaticPublicKey(pub x25519::PublicKey);

impl StaticPublicKey {
    /// Construct a static X25519 public key from an Ed25519 public key.
    ///
    /// See also [`StaticKeypair::from_ed25519`].
    ///
    /// [`StaticKeypair::from_ed25519`]: struct.StaticKeypair.html#method.from_ed25519
    pub fn from_ed25519(pk: &ed25519::PublicKey) -> Option<StaticPublicKey> {
        CompressedEdwardsY(pk.encode())
            .decompress()
            .map(|p| StaticPublicKey(p.to_montgomery().0.into()))
    }
}

impl Clone for StaticPublicKey {
    fn clone(&self) -> Self {
        StaticPublicKey(self.0.as_bytes().clone().into())
    }
}

impl PartialEq for StaticPublicKey {
    fn eq(&self, other: &StaticPublicKey) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for StaticPublicKey {}

impl From<[u8; 32]> for StaticPublicKey {
    fn from(k: [u8; 32]) -> StaticPublicKey {
        StaticPublicKey(x25519::PublicKey::from(k))
    }
}

impl std::ops::Deref for StaticPublicKey {
    type Target = x25519::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
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
            let x25519 = StaticKeypair::from_ed25519(&ed25519);

            let sodium_sec = ed25519_sk_to_curve25519(&sign::SecretKey(ed25519.encode()));
            let sodium_pub = ed25519_pk_to_curve25519(&sign::PublicKey(ed25519.public().encode().clone()));

            sodium_sec.as_ref() == Some(&x25519.secret.to_bytes()) &&
            sodium_pub.as_ref() == Some(x25519.public.as_bytes())
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
            let x25519 = StaticKeypair::from_ed25519(&ed25519);
            let x25519_public = StaticPublicKey::from_ed25519(&ed25519.public());
            Some(x25519.public()) == x25519_public.as_ref()
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

