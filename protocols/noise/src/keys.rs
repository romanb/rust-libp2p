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

use zeroize::Zeroize;

/// DH keypair.
#[derive(Clone)]
pub struct Keypair<T: Zeroize> {
    pub(crate) secret: SecretKey<T>,
    pub(crate) public: PublicKey<T>
}

impl<T: Zeroize> Keypair<T> {
    pub fn public(&self) -> &PublicKey<T> {
        &self.public
    }

    pub fn secret(&self) -> &SecretKey<T> {
        &self.secret
    }
}

/// DH secret key.
#[derive(Clone)]
pub struct SecretKey<T: Zeroize>(pub(crate) T);

impl<T: Zeroize> Drop for SecretKey<T> {
    fn drop(&mut self) {
        self.0.zeroize()
    }
}

impl<T: AsRef<[u8]> + Zeroize> AsRef<[u8]> for SecretKey<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// DH public key.
#[derive(Clone)]
pub struct PublicKey<T>(pub(crate) T);

impl<T: AsRef<[u8]>> PartialEq for PublicKey<T> {
    fn eq(&self, other: &PublicKey<T>) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl<T: AsRef<[u8]>> Eq for PublicKey<T> {}

impl<T: AsRef<[u8]>> AsRef<[u8]> for PublicKey<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

