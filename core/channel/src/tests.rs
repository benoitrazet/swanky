use std::io::{Read, Write};

use proptest::collection::vec as pvec;
use proptest::prelude::*;
use swanky_error::{ErrorKind, WrapErr};

use crate::{
    BufferSizes, Channel,
    local::{LocalSocket, local_channel_pair},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sender {
    A,
    B,
}
use Sender::*;

fn runit(mut sock: LocalSocket, whoami: Sender, data: Vec<(Vec<u8>, Sender)>) {
    Channel::with_sizes(&mut sock, BufferSizes { read: 2, write: 2 }, |channel| {
        let mut read_buf = vec![0; 256];
        for (bytes, who_sends) in data.into_iter() {
            if who_sends == whoami {
                channel.write_bytes(&bytes).unwrap();
            } else {
                channel.read_bytes(&mut read_buf[0..bytes.len()]).unwrap();
                assert_eq!(&read_buf[0..bytes.len()], bytes.as_slice());
            }
        }
        Ok(())
    })
    .unwrap();
}

proptest! {
    #[test]
    fn test_channel(
        data in pvec((
            prop_oneof![
                pvec(any::<u8>(), 0..=2),
                pvec(any::<u8>(), 2..=8),
            ],
            // The sender
            prop_oneof![
                Just(A),
                Just(B),
            ]
        ), 0..512),
    ) {
        let (a, b) = LocalSocket::pair().unwrap();
        std::thread::scope(|scope|{
            let data2 = data.clone();
            scope.spawn(move ||runit(b, B, data2));
            runit(a, A, data);
        });
    }
}

#[test]
fn io_adapter_write() {
    type T = u32;
    let (a, b) = local_channel_pair(
        |c| {
            let x = c.read::<T>()?;
            let y = c.read::<T>()?;
            Ok((x, y))
        },
        |c| {
            let x: T = 0x8BADF00D;
            let y: T = 0xDEADBEEF;
            let c = c.as_std_io();
            let _we_use_write_all_under_the_hood = c
                .write(x.to_le_bytes().as_slice())
                .wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to write bytes to channel.".to_string()
                })?;
            c.write_all(y.to_le_bytes().as_slice())
                .wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to write bytes to channel.".to_string()
                })?;
            Ok((x, y))
        },
    )
    .unwrap();
    assert_eq!(a, b);
}

#[test]
fn io_adapter_read_eof() {
    type T = u32;
    let (a, b) = local_channel_pair(
        |c| {
            let x = c.read::<T>()?;
            assert_eq!(
                c.as_std_io()
                    .read(&mut [0])
                    .wrap_err_with(ErrorKind::NetworkError, || {
                        "Failed to read bytes from a channel.".to_string()
                    },)?,
                0
            );
            Ok(x)
        },
        |c| {
            let x: T = 0x8BADF00D;
            c.write(&x)?;
            Ok(x)
        },
    )
    .unwrap();
    assert_eq!(a, b);
}

#[test]
fn io_adapter_read() {
    let msg: Vec<u8> = (0..=u8::MAX).collect();
    let (mut a, mut b) = LocalSocket::pair().unwrap();
    std::thread::scope(|s| {
        s.spawn(|| {
            b.write_all(&msg).unwrap();
            std::mem::drop(b);
        });
        Channel::with_sizes(&mut a, BufferSizes { read: 2, write: 16 }, |a| {
            let mut buf = vec![0_u8; 8];
            let a = a.as_std_io();
            a.read_exact(&mut buf[0..1])
                .wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to read bytes from a channel.".to_string()
                })?;
            a.read_exact(&mut buf[1..3])
                .wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to read bytes from a channel.".to_string()
                })?;
            a.read_exact(&mut buf[3..8])
                .wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to read bytes from a channel.".to_string()
                })?;
            a.read_to_end(&mut buf)
                .wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to read bytes from a channel.".to_string()
                })?;
            assert_eq!(buf, msg);
            Ok(())
        })
        .unwrap();
    });
}

#[test]
fn communicate() {
    use swanky_party::private::PartyPrivateCopy;
    swanky_party::party_system! {
        mod ps {
            A,
            B,
        }
    }
    use ps::{A, B, Party};

    fn do_work<P: Party>(c: &mut Channel) -> swanky_error::Result<i32> {
        let x: PartyPrivateCopy<A, P, i32> = PartyPrivateCopy::new(7117);
        let x = c.communicate(x)?;
        Ok(x)
    }

    let (a, b) = local_channel_pair(do_work::<A>, do_work::<B>).unwrap();
    assert_eq!(a, b);
}
