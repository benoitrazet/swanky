use std::{
    fs::File,
    io::{BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::Arc,
    time::Duration,
};

use bufstream::BufStream;
use mac_n_cheese_vole::party::{Party, WhichParty};
use rand::RngCore;
use rustls::{ClientConnection, ServerConnection, StreamOwned};
use swanky_error::{ErrorKind, WrapErr};
use swanky_party::either::{PartyEither, PartyEitherCopy};
use vectoreyes::SimdBase;

use crate::{MAC_N_CHEESE_RUNNER_VERSION, keys::Keys};

pub struct TlsConnection<P: Party> {
    inner: BufStream<
        PartyEither<
            P,
            StreamOwned<ServerConnection, TcpStream>,
            StreamOwned<ClientConnection, TcpStream>,
        >,
    >,
    needs_flush_on_read: bool,
}
impl<P: Party> Write for TlsConnection<P> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.needs_flush_on_read = true;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()?;
        self.needs_flush_on_read = false;
        Ok(())
    }
}
impl<P: Party> Read for TlsConnection<P> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.needs_flush_on_read {
            self.flush()?;
        }
        self.inner.read(buf)
    }
}

const PURPORTED_TLS_HOST_NAME: &str = "galois.macncheese.example.com";

const BUF_SIZE: usize = 16 * 1024; // Max TLS record size

// note: non standard tls setup
/// On the prover, `address` is the address to listen on. On the verifier, it's the address to
/// connect to.
// root_ca should be a list of files. probably not standard.
// tls_cert should have both public and private keys
// extra connections are in order
// TODO: set TCP keepalive?
pub fn initiate_tls<P: Party>(
    address: SocketAddr,
    root_cas: &Path,
    tls_cert: &Path,
    num_connections: PartyEitherCopy<P, (), usize>,
) -> swanky_error::Result<(Keys<P>, TlsConnection<P>, Vec<TcpStream>)> {
    let tls_root_store = {
        let mut tls_root_store = rustls::RootCertStore::empty();
        let mut f = BufReader::new(
            File::open(root_cas).wrap_err_with(ErrorKind::FilesystemError, || {
                format!("Unable to open root CA file {:?}", root_cas)
            })?,
        );
        for cert in rustls_pemfile::certs(&mut f) {
            let cert = cert.wrap_err_with(ErrorKind::FilesystemError, || {
                format!("Unable to read root CAs from file {:?}", root_cas)
            })?;
            tls_root_store
                .add(cert)
                .wrap_err_with(ErrorKind::OtherError, || {
                    "Failed to add root CA".to_string()
                })?;
        }
        tls_root_store
    };
    let (tls_certs, tls_private_key) = {
        let mut f = BufReader::new(
            File::open(tls_cert).wrap_err_with(ErrorKind::FilesystemError, || {
                format!("Unable to open TLS cert file {:?}", tls_cert)
            })?,
        );
        let mut tls_certs: Vec<_> = Default::default();
        let mut key: Option<rustls::pki_types::PrivateKeyDer> = None;
        for x in rustls_pemfile::read_all(&mut f) {
            let x = x.wrap_err_with(ErrorKind::FilesystemError, || {
                format!("Unable to read TLS cert file {:?}", tls_cert)
            })?;
            match x {
                rustls_pemfile::Item::X509Certificate(c) => tls_certs.push(c),
                rustls_pemfile::Item::Pkcs1Key(k) => {
                    key = Some(k.into());
                }
                rustls_pemfile::Item::Pkcs8Key(k) => {
                    key = Some(k.into());
                }
                _ => {
                    // Ignore unknown entries.
                }
            }
        }
        if let Some(key) = key {
            (tls_certs, key)
        } else {
            swanky_error::bail!(
                ErrorKind::OtherError,
                "No private key found in {:?}",
                tls_cert
            );
        }
    };
    Ok(match P::WHICH {
        WhichParty::Prover(e) => {
            let tls_config =
                rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .with_client_cert_verifier(
                        rustls::server::WebPkiClientVerifier::builder(Arc::new(tls_root_store))
                            .build()
                            .wrap_err_with(ErrorKind::InitializationError, || {
                                "Building client cert validator".to_string()
                            })?,
                    )
                    .with_single_cert(tls_certs, tls_private_key)
                    .wrap_err_with(ErrorKind::OtherError, || {
                        "Failed to build rustls client config".to_string()
                    })?;
            let listener = TcpListener::bind(address)
                .wrap_err_with(ErrorKind::NetworkError, || {
                    format!("Failed tcp binding to {:?}", address)
                })?;
            eprintln!("Waiting for connection on {address:?}");
            let (root_conn, _) = listener
                .accept()
                .wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to accept connection.".to_string()
                })?;
            root_conn
                .set_nodelay(true)
                .wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to set nodelay on root connection.".to_string()
                })?;
            let tls_root_conn = rustls::ServerConnection::new(Arc::new(tls_config))
                .wrap_err_with(ErrorKind::InitializationError, || {
                    "Failed to start new TLS connection.".to_string()
                })?;
            let mut root_conn = BufStream::new(PartyEither::new(
                e,
                rustls::StreamOwned::new(tls_root_conn, root_conn),
            ));
            let runner_version = {
                let mut buf = [0; 8];
                root_conn
                    .read_exact(&mut buf)
                    .wrap_err_with(ErrorKind::NetworkError, || {
                        "Failed to read bytes from root connection.".to_string()
                    })?;
                u64::from_le_bytes(buf)
            };
            swanky_error::ensure!(
                runner_version == MAC_N_CHEESE_RUNNER_VERSION,
                ErrorKind::OtherError,
                "Verifier has version {runner_version}. Expected {MAC_N_CHEESE_RUNNER_VERSION}"
            );
            let num_connections = {
                let mut buf = [0; 8];
                root_conn
                    .read_exact(&mut buf)
                    .wrap_err_with(ErrorKind::NetworkError, || {
                        "Failed to read bytes from root connection.".to_string()
                    })?;
                usize::try_from(u64::from_le_bytes(buf))
                    .wrap_err_with(ErrorKind::OtherError, || {
                        "Failed to represent number of connections as a usize.".to_string()
                    })?
            };
            let keys = {
                let mut base_key = [0; 32];
                root_conn
                    .read_exact(&mut base_key)
                    .wrap_err_with(ErrorKind::NetworkError, || {
                        "Failed to read base key.".to_string()
                    })?;
                Keys::from_base_key(&base_key)
            };
            let mut unsorted_connections = Vec::with_capacity(num_connections);
            for _ in 0..num_connections {
                let c = listener
                    .accept()
                    .wrap_err_with(ErrorKind::NetworkError, || {
                        "Failed to accept connection.".to_string()
                    })?
                    .0;
                c.set_nodelay(true)
                    .wrap_err_with(ErrorKind::NetworkError, || {
                        "Failed to set nodelay.".to_string()
                    })?;
                unsorted_connections.push(c);
            }
            let mut sorted_connections: Vec<Option<TcpStream>> = Vec::new();
            sorted_connections.resize_with(num_connections, || None);
            for mut c in unsorted_connections.into_iter() {
                let mut token = [0; 16];
                c.read_exact(&mut token)
                    .wrap_err_with(ErrorKind::NetworkError, || {
                        "Failed to read token.".to_string()
                    })?;
                let idx = keys.decode_connection_index_token(token.into(), num_connections)?;
                swanky_error::ensure!(
                    sorted_connections[idx].is_none(),
                    ErrorKind::OtherError,
                    "Duplicate connection with index {idx}"
                );
                sorted_connections[idx] = Some(c);
            }
            let mut connections = Vec::with_capacity(num_connections);
            for (i, c) in sorted_connections.into_iter().enumerate() {
                match c {
                    Some(c) => {
                        connections.push(c);
                    }
                    _ => {
                        // We panic here since this situation shouldn't ever occur.
                        // We've put every connection into a slot with no duplicates.
                        panic!("Connection {i} is missing");
                    }
                }
            }
            root_conn
                .flush()
                .wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to flush root connection.".to_string()
                })?;
            (
                keys,
                TlsConnection {
                    inner: root_conn,
                    needs_flush_on_read: false,
                },
                connections,
            )
        }
        WhichParty::Verifier(e) => {
            let tls_config =
                rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .with_root_certificates(tls_root_store)
                    .with_client_auth_cert(tls_certs, tls_private_key)
                    .wrap_err_with(ErrorKind::InitializationError, || {
                        "Failed to build rustls client config.".to_string()
                    })?;
            let tls_root_conn = rustls::ClientConnection::new(
                Arc::new(tls_config),
                PURPORTED_TLS_HOST_NAME.try_into().unwrap(),
            )
            .wrap_err_with(ErrorKind::InitializationError, || {
                "Failed to set up tls client connection.".to_string()
            })?;
            // TODO: configurable tcp connection timeouts
            let root_conn = loop {
                eprintln!("Connecting to {address:?}");
                match TcpStream::connect_timeout(&address, Duration::from_secs(2)) {
                    Ok(c) => break c,
                    Err(e) => {
                        eprintln!(
                            "Failed to connect to {:?} due to {}. Sleeping then trying again.",
                            address, e
                        );
                        std::thread::sleep(Duration::from_millis(500));
                    }
                }
            };
            eprintln!("Connected to prover!");
            root_conn
                .set_nodelay(true)
                .wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to set nodelay on root connection.".to_string()
                })?;
            let mut root_conn = BufStream::with_capacities(
                BUF_SIZE,
                BUF_SIZE,
                PartyEither::new(e, rustls::StreamOwned::new(tls_root_conn, root_conn)),
            );
            root_conn
                .write_all(&MAC_N_CHEESE_RUNNER_VERSION.to_le_bytes())
                .wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to write Mac'n'Cheese runner version bytes.".to_string()
                })?;
            let num_connections = num_connections.into_inner(e);
            root_conn
                .write_all(&(num_connections as u64).to_le_bytes())
                .wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to write number of connections.".to_string()
                })?;
            let mut base_key = [0; 32];
            rand::rngs::OsRng::default().fill_bytes(&mut base_key);
            root_conn
                .write_all(&base_key)
                .wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to write base key.".to_string()
                })?;
            root_conn
                .flush()
                .wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to flush root connection.".to_string()
                })?;
            let keys = Keys::from_base_key(&base_key);
            let mut connections = Vec::with_capacity(num_connections);
            for _ in 0..num_connections {
                let c = TcpStream::connect(address)
                    .wrap_err_with(ErrorKind::NetworkError, || {
                        format!("Failed to connect to {address}.")
                    })?;
                c.set_nodelay(true)
                    .wrap_err_with(ErrorKind::NetworkError, || {
                        "Failed to set nodelay on connection.".to_string()
                    })?;
                connections.push(c);
            }
            for (i, c) in connections.iter_mut().enumerate() {
                c.write_all(&keys.produce_connection_index_token(i).as_array())
                    .wrap_err_with(ErrorKind::NetworkError, || {
                        "Failed to write connection index token.".to_string()
                    })?;
                c.flush().wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to flush connection.".to_string()
                })?;
            }
            root_conn
                .flush()
                .wrap_err_with(ErrorKind::NetworkError, || {
                    "Failed to flush root connection.".to_string()
                })?;
            (
                keys,
                TlsConnection {
                    inner: root_conn,
                    needs_flush_on_read: false,
                },
                connections,
            )
        }
    })
}
