// Copyright 2018 Parity Technologies (UK) Ltd.
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

use crate::transport::TransportError;
use std::{error::Error, io};

/// Errors that can occur in the context of a pending or established `Connection`.
#[derive(thiserror::Error, Debug)]
pub enum ConnectionError<THandlerErr, TTransErr>
where
    THandlerErr: Error + 'static,
    TTransErr: Error + 'static,
{
    /// An error occurred while negotiating the transport protocol(s).
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError<TTransErr>),

    /// The peer identity obtained on the connection did not
    /// match the one that was expected or is otherwise invalid.
    #[error("Invalid peer ID.")]
    InvalidPeerId,

    /// An I/O error occurred on the connection.
    // TODO: Eventually this should also be a custom error?
    #[error("I/O error: {0}")]
    IO(#[from] io::Error),

    /// The connection handler produced an error.
    #[error("Handler error: {0}")]
    Handler(#[source] THandlerErr),
}

