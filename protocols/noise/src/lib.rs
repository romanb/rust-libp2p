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

//! [Noise protocol framework][noise] support for libp2p.
//!
//! This crate provides `libp2p_core::InboundUpgrade` and `libp2p_core::OutboundUpgrade`
//! implementations for various noise handshake patterns, currently IK, IX, and XX.
//!
//! All upgrades produce as output a pair, consisting of the remote's static public key
//! and a `NoiseOutput` which represents the established cryptographic session with the
//! remote, implementing `tokio_io::AsyncRead` and `tokio_io::AsyncWrite`.
//!
//! # Usage
//!
//! Example:
//!
//! ```
//! use libp2p_core::Transport;
//! use libp2p_tcp::TcpConfig;
//! use libp2p_noise::{x25519, NoiseConfig};
//!
//! # fn main() {
//! let keys = x25519::Keypair::new();
//! let transport = TcpConfig::new().with_upgrade(NoiseConfig::xx(keys));
//! // ...
//! # }
//! ```
//!
//! [noise]: http://noiseprotocol.org/

mod error;
mod io;
mod keys;
mod util;

pub mod rt1;
pub mod rt15;

pub use error::NoiseError;
pub use io::NoiseOutput;
pub use keys::{DhKeys, x25519};

use libp2p_core::{UpgradeInfo, InboundUpgrade, OutboundUpgrade};
use snow;
use tokio_io::{AsyncRead, AsyncWrite};
use util::Resolver;

fn params_ik(dh: &impl snow::types::Dh) -> snow::params::NoiseParams {
    format!("Noise_IK_{}_ChaChaPoly_SHA256", dh.name())
        .parse()
        .expect("valid pattern")
}

fn params_ix(dh: &impl snow::types::Dh) -> snow::params::NoiseParams {
    format!("Noise_IX_{}_ChaChaPoly_SHA256", dh.name())
        .parse()
        .expect("valid pattern")
}

fn params_xx(dh: &impl snow::types::Dh) -> snow::params::NoiseParams {
    format!("Noise_XX_{}_ChaChaPoly_SHA256", dh.name())
        .parse()
        .expect("valid pattern")
}

/// Type tag for the IK handshake pattern.
#[derive(Debug, Clone)]
pub enum IK {}

/// Type tag for the IX handshake pattern.
#[derive(Debug, Clone)]
pub enum IX {}

/// Type tag for the XX handshake pattern.
#[derive(Debug, Clone)]
pub enum XX {}

/// The protocol upgrade configuration.
#[derive(Clone)]
pub struct NoiseConfig<P, K: DhKeys, R = ()> {
    keys: K,
    params: snow::params::NoiseParams,
    remote: R,
    _marker: std::marker::PhantomData<P>
}

impl<K: DhKeys> NoiseConfig<IX, K> {
    /// Create a new `NoiseConfig` for the IX handshake pattern.
    pub fn ix(keys: K) -> Self {
        let params = params_ix(&keys);
        NoiseConfig {
            keys,
            params,
            remote: (),
            _marker: std::marker::PhantomData
        }
    }
}

impl<K: DhKeys> NoiseConfig<XX, K> {
    /// Create a new `NoiseConfig` for the XX handshake pattern.
    pub fn xx(keys: K) -> Self {
        let params = params_xx(&keys);
        NoiseConfig {
            keys,
            params,
            remote: (),
            _marker: std::marker::PhantomData
        }
    }
}

impl<K: DhKeys> NoiseConfig<IK, K> {
    /// Create a new `NoiseConfig` for the IK handshake pattern (recipient side).
    pub fn ik_listener(keys: K) -> Self {
        let params = params_ik(&keys);
        NoiseConfig {
            keys,
            params,
            remote: (),
            _marker: std::marker::PhantomData
        }
    }
}

impl<K: DhKeys> NoiseConfig<IK, K, K::PublicKey> {
    /// Create a new `NoiseConfig` for the IK handshake pattern (initiator side).
    pub fn ik_dialer(keys: K, remote: K::PublicKey) -> Self {
        let params = params_ik(&keys);
        NoiseConfig {
            keys,
            params,
            remote,
            _marker: std::marker::PhantomData
        }
    }
}

// Handshake pattern IX /////////////////////////////////////////////////////

impl UpgradeInfo for NoiseConfig<IX, x25519::Keypair> {
    type Info = &'static [u8];
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once(b"/noise/ix/25519/chachapoly/sha256/0.1.0")
    }
}

impl<T,K: DhKeys> InboundUpgrade<T> for NoiseConfig<IX, K>
where
    T: AsyncRead + AsyncWrite,
    NoiseConfig<IX, K>: UpgradeInfo
{
    type Output = (K::PublicKey, NoiseOutput<T>);
    type Error = NoiseError;
    type Future = rt1::NoiseInboundFuture<T, K>;

    fn upgrade_inbound(self, socket: T, _: Self::Info) -> Self::Future {
        let session = snow::Builder::with_resolver(self.params, Box::new(Resolver))
            .local_private_key(self.keys.privkey())
            .build_responder()
            .map_err(NoiseError::from);
        rt1::NoiseInboundFuture::new(socket, session)
    }
}

impl<T, K: DhKeys> OutboundUpgrade<T> for NoiseConfig<IX, K>
where
    T: AsyncRead + AsyncWrite,
    NoiseConfig<IX, K>: UpgradeInfo
{
    type Output = (K::PublicKey, NoiseOutput<T>);
    type Error = NoiseError;
    type Future = rt1::NoiseOutboundFuture<T, K>;

    fn upgrade_outbound(self, socket: T, _: Self::Info) -> Self::Future {
        let session = snow::Builder::with_resolver(self.params, Box::new(Resolver))
            .local_private_key(self.keys.privkey())
            .build_initiator()
            .map_err(NoiseError::from);
        rt1::NoiseOutboundFuture::new(socket, session)
    }
}

// Handshake pattern XX /////////////////////////////////////////////////////

impl UpgradeInfo for NoiseConfig<XX, x25519::Keypair> {
    type Info = &'static [u8];
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once(b"/noise/xx/25519/chachapoly/sha256/0.1.0")
    }
}

impl<T, K: DhKeys> InboundUpgrade<T> for NoiseConfig<XX, K>
where
    T: AsyncRead + AsyncWrite,
    NoiseConfig<XX, K>: UpgradeInfo
{
    type Output = (K::PublicKey, NoiseOutput<T>);
    type Error = NoiseError;
    type Future = rt15::NoiseInboundFuture<T, K>;

    fn upgrade_inbound(self, socket: T, _: Self::Info) -> Self::Future {
        let session = snow::Builder::with_resolver(self.params, Box::new(Resolver))
            .local_private_key(self.keys.privkey())
            .build_responder()
            .map_err(NoiseError::from);
        rt15::NoiseInboundFuture::new(socket, session)
    }
}

impl<T, K: DhKeys> OutboundUpgrade<T> for NoiseConfig<XX, K>
where
    T: AsyncRead + AsyncWrite,
    NoiseConfig<XX, K>: UpgradeInfo
{
    type Output = (K::PublicKey, NoiseOutput<T>);
    type Error = NoiseError;
    type Future = rt15::NoiseOutboundFuture<T, K>;

    fn upgrade_outbound(self, socket: T, _: Self::Info) -> Self::Future {
        let session = snow::Builder::with_resolver(self.params, Box::new(Resolver))
            .local_private_key(self.keys.privkey())
            .build_initiator()
            .map_err(NoiseError::from);
        rt15::NoiseOutboundFuture::new(socket, session)
    }
}

// Handshake pattern IK /////////////////////////////////////////////////////

impl UpgradeInfo for NoiseConfig<IK, x25519::Keypair> {
    type Info = &'static [u8];
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once(b"/noise/ik/25519/chachapoly/sha256/0.1.0")
    }
}

impl UpgradeInfo for NoiseConfig<IK, x25519::Keypair, x25519::PublicKey> {
    type Info = &'static [u8];
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once(b"/noise/ik/25519/chachapoly/sha256/0.1.0")
    }
}

impl<T, K: DhKeys> InboundUpgrade<T> for NoiseConfig<IK, K>
where
    T: AsyncRead + AsyncWrite,
    NoiseConfig<IK, K>: UpgradeInfo
{
    type Output = (K::PublicKey, NoiseOutput<T>);
    type Error = NoiseError;
    type Future = rt1::NoiseInboundFuture<T, K>;

    fn upgrade_inbound(self, socket: T, _: Self::Info) -> Self::Future {
        let session = snow::Builder::with_resolver(self.params, Box::new(Resolver))
            .local_private_key(self.keys.privkey())
            .build_responder()
            .map_err(NoiseError::from);
        rt1::NoiseInboundFuture::new(socket, session)
    }
}

impl<T, K: DhKeys> OutboundUpgrade<T> for NoiseConfig<IK, K, K::PublicKey>
where
    T: AsyncRead + AsyncWrite,
    NoiseConfig<IK, K, K::PublicKey>: UpgradeInfo
{
    type Output = (K::PublicKey, NoiseOutput<T>);
    type Error = NoiseError;
    type Future = rt1::NoiseOutboundFuture<T, K>;

    fn upgrade_outbound(self, socket: T, _: Self::Info) -> Self::Future {
        let session = snow::Builder::with_resolver(self.params, Box::new(Resolver))
            .local_private_key(self.keys.privkey())
            .remote_public_key(self.remote.as_ref())
            .build_initiator()
            .map_err(NoiseError::from);
        rt1::NoiseOutboundFuture::new(socket, session)
    }
}

