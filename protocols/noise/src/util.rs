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

use crate::NoiseError;
use rand::FromEntropy;
use x25519_dalek as x25519;

pub(crate) fn to_array(bytes: &[u8]) -> Result<[u8; 32], NoiseError> {
    if bytes.len() != 32 {
        return Err(NoiseError::InvalidKey)
    }
    let mut m = [0; 32];
    m.copy_from_slice(bytes);
    Ok(m)
}

/// Custom `snow::CryptoResolver` which delegates to the `RingResolver`
/// for hash functions and symmetric ciphers, while using x25519-dalek
/// for Curve25519 DH. We do not use the default resolver for any of
/// the choices, because it comes with unwanted additional dependencies,
/// notably rust-crypto, and to avoid being affected by changes to
/// the defaults.
pub(crate) struct Resolver;

impl snow::resolvers::CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn snow::types::Random>> {
        Some(Box::new(Rng(rand::rngs::StdRng::from_entropy())))
    }

    fn resolve_dh(&self, choice: &snow::params::DHChoice) -> Option<Box<dyn snow::types::Dh>> {
        if let snow::params::DHChoice::Curve25519 = choice {
            Some(Box::new(Dh25519::default()))
        } else {
            None
        }
    }

    fn resolve_hash(&self, choice: &snow::params::HashChoice) -> Option<Box<dyn snow::types::Hash>> {
        snow::resolvers::RingResolver.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &snow::params::CipherChoice) -> Option<Box<dyn snow::types::Cipher>> {
        snow::resolvers::RingResolver.resolve_cipher(choice)
    }
}

/// Wrapper around a CSPRNG to implement `snow::Random` trait for.
struct Rng(rand::rngs::StdRng);

impl rand::RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl rand::CryptoRng for Rng {}

impl snow::types::Random for Rng {}

/// Short-lived container for a static or ephemeral X25519 keypair
/// used during DH computations by `snow`.
#[derive(Default)]
struct Dh25519 { sk: [u8; 32], pk:  [u8; 32] }

impl snow::types::Dh for Dh25519 {
    fn name(&self) -> &'static str { "25519" }
    fn pub_len(&self) -> usize { 32 }
    fn priv_len(&self) -> usize { 32 }
    fn pubkey(&self) -> &[u8] { &self.pk }
    fn privkey(&self) -> &[u8] { &self.sk }

    fn set(&mut self, sk: &[u8]) {
        self.sk.copy_from_slice(&sk[..]);
        self.pk = x25519::x25519(self.sk, x25519::X25519_BASEPOINT_BYTES);
    }

    fn generate(&mut self, rng: &mut dyn snow::types::Random) {
        rng.fill_bytes(&mut self.sk);
        self.pk = x25519::x25519(self.sk, x25519::X25519_BASEPOINT_BYTES);
    }

    fn dh(&self, pk: &[u8], shared_secret: &mut [u8]) -> Result<(), ()> {
        let mut p = [0; 32];
        p.copy_from_slice(&pk[.. 32]);
        let ss = x25519::x25519(self.sk, p);
        shared_secret[.. 32].copy_from_slice(&ss[..]);
        Ok(())
    }
}
