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

pub mod x25519;

use crate::{NoiseError, PublicKey};

#[derive(Clone)]
pub struct ProtocolParams(pub(crate) snow::params::NoiseParams);

/// Type tag for the IK handshake pattern.
#[derive(Debug, Clone)]
pub enum IK {}

/// Type tag for the IX handshake pattern.
#[derive(Debug, Clone)]
pub enum IX {}

/// Type tag for the XX handshake pattern.
#[derive(Debug, Clone)]
pub enum XX {}

/// A Noise protocol over a DH curve `C`.
pub trait Protocol<C> {
    fn params_ik() -> ProtocolParams;
    fn params_ix() -> ProtocolParams;
    fn params_xx() -> ProtocolParams;

    /// Construct a DH public key from a byte slice.
    fn public_from_bytes(s: &[u8]) -> Result<PublicKey<C>, NoiseError>;
}

