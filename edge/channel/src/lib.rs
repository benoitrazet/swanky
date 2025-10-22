//! This crate contains the core types used for communication in Swanky.
//!
//! [`Channel`] is the type that should be used for (most) network communications in Swanky. If you
//! need to perform network communication for testing, see the [`local`] module.

#![deny(missing_docs)]

use std::io::{Read, Write};

use bytemuck::TransparentWrapper;
use generic_array::GenericArray;
use swanky_party::{Party, private::PartyPrivate};
use swanky_party2::GenericParty;
use swanky_serialization::CanonicalSerialize;

pub mod local;

/// Rust doesn't support `(dyn Read + Write)`, so we make this trait, so we can write `dyn
/// ReadWrite`, instead.
trait ReadWrite: Read + Write {}
impl<T: Read + Write + ?Sized> ReadWrite for T {}

/// The sizes of the read and write buffers be for a [`Channel`]
///
/// The struct is only intended to be used as an argument to [`Channel::with_sizes`]
pub struct BufferSizes {
    /// Size (in bytes) of the read buffer
    pub read: usize,
    /// Size (in bytes) of the write buffer
    pub write: usize,
}
impl Default for BufferSizes {
    fn default() -> Self {
        BufferSizes {
            // Upside of a larger value: Fewer system calls
            // Downside of a larger value: More memory consumption
            // The default Linux TCP receive window size (on systems I tested) is 128*1024
            // We set this to 1024*256 to give us some wiggle room (due to the minimal) downside.
            // This is also greater than the maximum TLS record size.
            read: 1024 * 256,
            // Upside of a larger value: Fewer system calls
            // Downsides of a larger value:
            //      (1) More memory consumption. Memory is typically not a bottleneck, so this is
            //          usually a non-issue.
            //      (2) Lower concurrency with the peer. Any time between when a party performs a
            //          write() and when the write buffer gets flushed is time that the peer can't
            //          spend computing on the written data.
            // To that end, the default write value is set so as to fill a single TLS record:
            //   MAX_TLS_RECORD_SIZE - (SIZE_OF_TLS_MAC + SIZE_OF_TLS_13_RECORD_TYPE)
            // = 2^14 - (16+1)
            write: (1 << 14) - (16 + 1),
        }
    }
}

/// A network channel wrapper
///
/// This wrapper provides buffering and automatic flushing of the channel.
///
/// # Flushing
/// `Channel` will automatically flush the write buffer before performing a read. As a result,
/// users of the `Channel` API should almost never need to manually flush.
///
/// A manual flush should only be _required_ when interleaving `Channel` operations with
/// non-`Channel` operations. For example, it would be advisable to `manual_flush()` before reading
/// user input from standard in. `Channel` can't flush for you, because it doesn't know that you're
/// about to read from standard in!
///
/// # Error Handling
/// On error, `Channel` is left in an unknown state. For example, if a `Channel` wraps a
/// `TcpStream`, and a `write_bytes` fails with an
/// [`ETIMEDOUT`](https://man7.org/linux/man-pages/man7/tcp.7.html#ERRORS) error, due to the
/// [Two Generals' Problem](https://en.wikipedia.org/wiki/Two_Generals%27_Problem), it's not
/// possible to know whether or not the peer received the sent data.
///
/// As a result, on channel error, the only safe remediation strategy is to drop (and close) the
/// inner `Read + Write` type.
pub struct Channel<'inner> {
    read_buffer: Vec<u8>,
    read_buffer_pos: usize,
    read_buffer_len: usize,
    write_buffer: Vec<u8>,
    inner: &'inner mut dyn ReadWrite,
}

impl<'inner> Channel<'inner> {
    /// Construct a new `[Channel]` wrapping the full-duplex connection, `inner`.
    ///
    /// This function is equivalent to calling [`Channel::with_sizes`] with the default
    /// [`BufferSizes`]. See that function for more information.
    pub fn with<C, T, F>(inner: C, thunk: F) -> eyre::Result<T>
    where
        for<'a, 'b> F: FnOnce(&'a mut Channel<'b>) -> eyre::Result<T>,
        C: Read + Write,
    {
        Self::with_sizes(inner, BufferSizes::default(), thunk)
    }

    /// Construct a new `[Channel]` wrapping the full-duplex connection, `inner`.
    ///
    /// The fresh channel gets passed to `thunk`, and (barring any errors) the result of `thunk`
    /// gets returned by `with_sizes()`.
    ///
    /// # Buffering
    ///
    /// Because [`Channel`] uses a buffer (of size `sizes`) internally, it's
    /// preferable to pass an _unbuffered_ `inner` stream (such as a `TcpStream`).
    ///
    /// `with_sizes()` will flush any outgoing buffered data before returning.
    ///
    /// The channel should be _moved_ into `inner`, to avoid dropping a partial read buffer. See
    /// [`std::io::BufReader::into_inner`] for more info.
    ///
    /// # Example
    ///
    /// ```rust
    /// fn do_crypto_with_a_tcp_connection(conn: std::net::TcpStream) -> eyre::Result<()> {
    ///     swanky_channel::Channel::with_sizes(conn, Default::default(), |channel| {
    ///         channel.write_bytes(b"hello!")?;
    ///         Ok(())
    ///     })
    /// }
    /// ```
    pub fn with_sizes<C, T, F>(mut inner: C, sizes: BufferSizes, thunk: F) -> eyre::Result<T>
    where
        for<'a, 'b> F: FnOnce(&'a mut Channel<'b>) -> eyre::Result<T>,
        C: Read + Write,
    {
        let mut channel = Channel {
            read_buffer: vec![0; sizes.read.max(1)],
            read_buffer_pos: 0,
            read_buffer_len: 0,
            write_buffer: {
                let mut buf = Vec::new();
                buf.reserve_exact(sizes.write.max(1));
                buf
            },
            inner: &mut inner,
        };
        let t = thunk(&mut channel)?;
        channel.force_flush()?;
        Ok(t)
    }

    #[inline(never)]
    fn force_flush_slow(&mut self) -> std::io::Result<()> {
        self.inner.write_all(&self.write_buffer)?;
        self.write_buffer.clear();
        self.inner.flush()?;
        Ok(())
    }

    /// Flush the channel
    ///
    /// Write buffers and [`Write::flush()`] the underlying channel.
    ///
    /// You shouldn't need to call this function in normal operation (since the channel will
    /// automatically insert flushes as needed).
    ///
    /// See the "Flushes" section in [`Channel`] for more information.
    #[inline]
    pub fn force_flush(&mut self) -> std::io::Result<()> {
        if !self.write_buffer.is_empty() {
            self.force_flush_slow()?;
        }
        Ok(())
    }
    #[inline(never)]
    fn write_bytes_slow(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let available = self.write_buffer.capacity() - self.write_buffer.len();
        debug_assert!(bytes.len() > available);
        self.force_flush()?;
        debug_assert!(self.write_buffer.is_empty());
        if bytes.len() > self.write_buffer.capacity() {
            self.inner.write_all(bytes)?;
            // We flush here because we use the length of the write_buffer to indicate whether
            // there are outstanding writes to flush. If we didn't flush here, then a long write
            // followed by a read would deadlock.
            self.inner.flush()?;
        } else {
            self.write_buffer.extend_from_slice(bytes);
        }
        Ok(())
    }
    /// Write all of `bytes` to the peer.
    ///
    /// If this function succeeds, all bytes have been written to the peer.
    ///
    /// # Example
    /// ```
    /// use swanky_channel::Channel;
    /// let mut dst = [0; 5];
    /// swanky_channel::local::local_channel_pair(
    ///     |c| Ok(c.read_bytes(&mut dst)?),
    ///     |c| Ok(c.write_bytes(b"hello")?),
    /// )
    /// .unwrap();
    /// assert_eq!(dst.as_slice(), b"hello");
    /// ```
    #[inline]
    pub fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let available = self.write_buffer.capacity() - self.write_buffer.len();
        if available >= bytes.len() {
            self.write_buffer.extend_from_slice(bytes);
            Ok(())
        } else {
            self.write_bytes_slow(bytes)
        }
    }
    fn fill_read_buffer(&mut self) -> std::io::Result<()> {
        self.read_buffer_pos = 0;
        loop {
            match self.inner.read(&mut self.read_buffer) {
                Ok(n) => {
                    self.read_buffer_len = n;
                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
    #[inline(never)]
    fn read_bytes_slow(&mut self, mut dst: &mut [u8]) -> std::io::Result<()> {
        while !dst.is_empty() {
            if self.read_buffer_len > 0 {
                let to_take = self.read_buffer_len.min(dst.len());
                let (filled, remaining) = dst.split_at_mut(to_take);
                dst = remaining;
                filled.copy_from_slice(
                    &self.read_buffer[self.read_buffer_pos..self.read_buffer_pos + to_take],
                );
                self.read_buffer_pos += to_take;
                self.read_buffer_len -= to_take;
            } else if dst.len() > self.read_buffer.len() {
                // Fill big reads from inner, directly.
                self.inner.read_exact(dst)?;
                return Ok(());
            } else {
                self.fill_read_buffer()?;
                if self.read_buffer_len == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Hit unexpected EOF",
                    ));
                }
            }
        }
        Ok(())
    }
    /// Read exactly `dst.len()` bytes from the peer into `dst`.
    ///
    /// # Example
    /// ```
    /// use swanky_channel::Channel;
    /// let mut dst = [0; 5];
    /// swanky_channel::local::local_channel_pair(
    ///     |c| Ok(c.read_bytes(&mut dst)?),
    ///     |c| Ok(c.write_bytes(b"hello")?),
    /// )
    /// .unwrap();
    /// assert_eq!(dst.as_slice(), b"hello");
    /// ```
    #[inline]
    pub fn read_bytes(&mut self, dst: &mut [u8]) -> std::io::Result<()> {
        self.force_flush()?;
        let read_buffer =
            &self.read_buffer[self.read_buffer_pos..self.read_buffer_pos + self.read_buffer_len];
        if let Some(src) = read_buffer.get(0..dst.len()) {
            dst.copy_from_slice(src);
            self.read_buffer_pos += dst.len();
            self.read_buffer_len -= dst.len();
            Ok(())
        } else {
            self.read_bytes_slow(dst)
        }
    }
    /// Read a `T` and deserialize it.
    ///
    /// # Example
    /// ```
    /// use swanky_channel::Channel;
    /// let (r, _) =
    ///     swanky_channel::local::local_channel_pair(|c| c.read::<i32>(), |c| c.write(&42_i32))
    ///         .unwrap();
    /// assert_eq!(r, 42);
    /// ```
    #[inline]
    pub fn read<T: CanonicalSerialize>(&mut self) -> eyre::Result<T> {
        let mut buf = GenericArray::<u8, T::ByteReprLen>::default();
        self.read_bytes(&mut buf)?;
        Ok(T::from_bytes(&buf)?)
    }
    /// Serialize `t` and [`Self::write_bytes()`] it over the wire.
    ///
    /// # Example
    /// ```
    /// use swanky_channel::Channel;
    /// let (r, _) =
    ///     swanky_channel::local::local_channel_pair(|c| c.read::<i32>(), |c| c.write(&42_i32))
    ///         .unwrap();
    /// assert_eq!(r, 42);
    /// ```
    #[inline]
    pub fn write<T: CanonicalSerialize>(&mut self, t: &T) -> eyre::Result<()> {
        Ok(self.write_bytes(&t.to_bytes())?)
    }

    /// Return an [`IoAdapter`] for this channel which implements [`std::io::Read`] and
    /// [`std::io::Write`].
    ///
    /// # Example
    /// ```
    /// use swanky_channel::Channel;
    /// use std::io::Write;
    /// fn use_write(mut x: impl Write) -> eyre::Result<()> {
    ///     x.write_all(b"x")?;
    ///     Ok(())
    /// }
    /// let (r, _) =
    ///     swanky_channel::local::local_channel_pair(
    ///         |c| c.read::<u8>(),
    ///         |c| use_write(c.as_std_io())
    ///     ).unwrap();
    /// assert_eq!(r, b'x');
    /// ```
    #[inline]
    pub fn as_std_io(&mut self) -> &mut IoAdapter<'inner> {
        IoAdapter::wrap_mut(self)
    }

    /// Turn a `PartyPrivate<P, T>` into a `T` by communicating it.
    ///
    /// If `P` can see its value, then send it over the wire and return it. Otherwise, read the
    /// peer's value from over the wire and return that.
    ///
    /// # Example
    /// ```
    /// use swanky_channel::{Channel, local::local_channel_pair};
    /// use swanky_party::{Party, Prover, Verifier, private::ProverPrivateCopy};
    /// fn do_work<P: Party>(c: &mut Channel) -> eyre::Result<i32> {
    ///     let x: ProverPrivateCopy<P, i32> = ProverPrivateCopy::new(4586);
    ///     // Only the prover knows x.
    ///     let x: i32 = c.communicate(x)?;
    ///     // Now both parties know x.
    ///     Ok(x)
    /// }
    /// let (a, b) = local_channel_pair(
    ///     |c| do_work::<Prover>(c),
    ///     |c| do_work::<Verifier>(c),
    /// ).unwrap();
    /// assert_eq!(a, b);
    /// ```
    #[inline]
    pub fn communicate<P: Party, T: CanonicalSerialize>(
        &mut self,
        p: impl PartyPrivate<P, T>,
    ) -> eyre::Result<T> {
        match p.into_option() {
            Some(t) => {
                self.write(&t)?;
                Ok(t)
            }
            None => self.read(),
        }
    }

    /// Turn a `swanky_party2::PartyPrivate<P, T>` into a `T` by communicating it.
    ///
    /// (The `2` in `communicate2` refers to `swanky_party2`, since `communicate()` refers to
    /// `swanky_party`)
    ///
    /// If `P` can see its value, then send it over the wire and return it. Otherwise, read the
    /// peer's value from over the wire and return that.
    ///
    /// # Example
    /// ```
    /// use swanky_channel::{Channel, local::local_channel_pair};
    /// use swanky_party2::{private::PartyPrivateCopy, party_system};
    ///
    /// party_system! {
    ///     // These names are arbitrary; they're representative of parties for oblivious transfer.
    ///     pub mod ot {
    ///         Sender,
    ///         Receiver,
    ///     }
    /// }
    /// use ot::*;
    /// fn do_work<P: Party>(c: &mut Channel) -> eyre::Result<i32> {
    ///     // Only the sender knows x. We're party P. If P == Sender, then _we_ know x.
    ///     let x: PartyPrivateCopy<Sender, P, i32> = PartyPrivateCopy::new(4586);
    ///     // If we're the sender, send x to the receiver. If P == Receiver, then recieve x.
    ///     let x: i32 = c.communicate2(x)?;
    ///     // Now both parties know x.
    ///     Ok(x)
    /// }
    /// let (a, b) = local_channel_pair(
    ///     |c| do_work::<Sender>(c),
    ///     |c| do_work::<Receiver>(c),
    /// ).unwrap();
    /// assert_eq!(a, b);
    /// ```
    #[inline]
    pub fn communicate2<
        PrivateTo: GenericParty<PartySystem = P::PartySystem>,
        P: GenericParty,
        T: CanonicalSerialize,
    >(
        &mut self,
        p: swanky_party2::private::PartyPrivateCopy<PrivateTo, P, T>,
    ) -> eyre::Result<T> {
        match Option::<T>::from(p) {
            Some(t) => {
                self.write(&t)?;
                Ok(t)
            }
            None => self.read(),
        }
    }
}

/// An adapter for [`Channel`] which implements [`std::io::Read`] and [`std::io::Write`].
///
/// See [`Channel::as_std_io`] for more info.
#[repr(transparent)]
#[derive(TransparentWrapper)]
pub struct IoAdapter<'a> {
    inner: Channel<'a>,
}
impl std::io::Read for IoAdapter<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.force_flush()?;
        if self.inner.read_buffer_len == 0 {
            self.inner.fill_read_buffer()?;
            if self.inner.read_buffer_len == 0 {
                return Ok(0);
            }
        }
        let to_take = buf.len().min(self.inner.read_buffer_len);
        self.inner.read_bytes(&mut buf[0..to_take])?;
        Ok(to_take)
    }
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.inner.read_bytes(buf)
    }
}
impl std::io::Write for IoAdapter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write_bytes(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.force_flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.inner.write_bytes(buf)
    }
}

#[cfg(test)]
mod tests;
