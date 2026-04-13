#![deny(unused_must_use)]

use std::fs::File;
use std::io::{Read, Write};
use std::marker::PhantomData;

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use mac_n_cheese_ir::compilation_format::fb::{self, DataChunkAddress};
use mac_n_cheese_ir::compilation_format::{
    AtomicGraphDegreeCount, Manifest, Type, read_private_manifest,
};
use mac_n_cheese_vole::party::{Party, Prover, Verifier, WhichParty};
use party::either::PartyEitherCopy;
use party::private::{PartyPrivate, PartyPrivateCopy};
use party::ty_eq::Witness;
use rand::SeedableRng;
use swanky_error::{ErrorKind, OptionExt, ResultExt, WrapErr};
use swanky_party as party;
use swanky_rng::SwankyRng;
use types::visit_type;

use crate::runner::RunQueue;

use crate::task_queue::{QUEUE_NAME_RUN_QUEUE, TaskQueue};
use crate::thread_spawner::ThreadSpawner;
use crate::types::TypeVisitor;

pub const MAC_N_CHEESE_RUNNER_VERSION: u64 = 1;

mod alloc;
mod base_vole;
mod bounded_queue;
mod channel_adapter;
mod event_log;
mod flatbuffers_ext;
mod keys;
mod reactor;
mod runner;
mod task_definitions;
mod task_framework;
mod task_queue;
mod thread_spawner;
mod tls;
mod type_map;
mod types;

/// A zero-knowledge proof runner.
#[derive(Parser)]
struct Opt {
    /// This should be a single file
    #[clap(short, long)]
    root_cas: PathBuf,
    /// A single PEM file containing both the private key and the signed certificate
    #[clap(short = 'k', long)]
    tls_cert: PathBuf,
    #[clap(short, long)]
    circuit: PathBuf,
    #[clap(short, long)]
    address: SocketAddr,
    #[clap(long)]
    event_log: Option<PathBuf>,
    /// If this isn't supplied, then use the number of CPUs on the machine.
    #[clap(long)]
    num_threads: Option<usize>,
    /// If specified, write the proof's run time (in nanoseconds) to this path.
    #[clap(long)]
    write_run_time_to: Option<PathBuf>,
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Parser)]
enum Command {
    Prove {
        private_data: PathBuf,
    },
    Verify {
        #[clap(long, default_value = "16")]
        num_connections: usize,
    },
}

fn setup_panic_handler() {
    // a panic on any thread will kill the process.
    let orig = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        orig(info);
        std::process::exit(1);
    }));
}

fn read_atomic_graph_degree_counts(
    manifest: &Manifest,
    addr: &DataChunkAddress,
) -> swanky_error::Result<Vec<AtomicGraphDegreeCount>> {
    let num_bytes = addr.length() as usize;
    swanky_error::ensure!(
        num_bytes.is_multiple_of(std::mem::size_of::<AtomicGraphDegreeCount>()),
        ErrorKind::OtherError,
        "invalid atomic degree count data chunk"
    );
    let len = num_bytes / std::mem::size_of::<AtomicGraphDegreeCount>();
    // TODO: when Box::new_zeroed_slice gets stabilized, use that instead.
    let mut out = Vec::with_capacity(len);
    unsafe {
        // SAFETY: AtomicGraphDegreeCount "has the same in-memory representation as the
        // underlying integer type." And the underlying integer type is zeroable.
        // out was allocated with len capacity.
        std::ptr::write_bytes(out.as_mut_ptr(), 0, len);
        out.set_len(len);
    }
    manifest.read_data_chunk(addr, unsafe {
        // SAFETY: AtomicGraphDegreeCount "has the same in-memory representation as the
        // underlying integer type." And the underlying integer type is POD.
        std::slice::from_raw_parts_mut(out.as_mut_ptr() as *mut u8, num_bytes)
    })?;
    Ok(out)
}

fn party_main<P: Party>(
    opt: &Opt,
    private_data: PartyPrivateCopy<Prover, P, &Path>,
    num_connections: PartyEitherCopy<P, (), usize>,
) -> swanky_error::Result<()> {
    let rng = SwankyRng::from_rng(rand::rngs::OsRng).unwrap();
    let circuit_file = File::open(&opt.circuit)
        .wrap_err_with(ErrorKind::FilesystemError, || {
            format!("Opening circuit {:?}", opt.circuit)
        })?;
    let span = event_log::ReadingCircuit.start();
    let circuit_manifest = Manifest::read(circuit_file)
        .with_context(|| format!("Reading circuit {:?}", opt.circuit))?;
    let manifest = circuit_manifest.manifest();
    span.finish();
    let mut private_file = PartyPrivate::from(private_data)
        .map(|path| {
            File::open(path).wrap_err_with(ErrorKind::FilesystemError, || {
                format!("Opening private data {path:?}")
            })
        })
        .lift_result()?;
    let private_manifest = private_file
        .as_mut()
        .map(|private_file| {
            let span = event_log::ReadingPrivates.start();
            let manifest = read_private_manifest(private_file);
            span.finish();
            manifest
        })
        .lift_result()?;
    let dependent_counts =
        read_atomic_graph_degree_counts(&circuit_manifest, manifest.dependent_counts())
            .context("Reading dependent counts")?;
    swanky_error::ensure!(
        dependent_counts.len() == manifest.tasks().len(),
        ErrorKind::OtherError,
        ""
    );
    let dependency_counts =
        read_atomic_graph_degree_counts(&circuit_manifest, manifest.dependency_counts())
            .context("Reading dependency counts")?;
    alloc::init_alloc_pool(&mut extract_allocation_sizes::<P>(
        manifest.allocation_sizes(),
    )?);
    let (keys, mut root_conn, extra_conns) =
        tls::initiate_tls::<P>(opt.address, &opt.root_cas, &opt.tls_cert, num_connections)
            .context("initiating root tls connection")?;
    let start_time = Instant::now();
    event_log::ProofStart.submit();
    eprintln!("Starting proof!");
    match P::WHICH {
        WhichParty::Prover(_) => {
            root_conn
                .write_all(&circuit_manifest.hash().to_le_bytes())
                .wrap_err(ErrorKind::NetworkError, "Failed to write manifest hash.")?;
            root_conn
                .flush()
                .wrap_err(ErrorKind::NetworkError, "Failed to flush root connection.")?;
        }
        WhichParty::Verifier(_) => {
            let mut buf = [0; 8];
            root_conn
                .read_exact(&mut buf)
                .wrap_err(ErrorKind::NetworkError, "Failed to read circuit hash.")?;
            if u64::from_le_bytes(buf) != circuit_manifest.hash() {
                eprintln!("WARNING: CIRCUIT HASH MISMATCH!");
            }
        }
    }
    let circuit_manifest = Arc::new(circuit_manifest);
    // First, we spin up the reactor.
    let mut ts = ThreadSpawner::new();
    let run_queue: RunQueue<P> = Arc::new(TaskQueue::new(QUEUE_NAME_RUN_QUEUE));
    let reactor = reactor::new_reactor(
        &mut ts,
        circuit_manifest.clone(),
        private_file,
        extra_conns,
        run_queue.clone(),
        keys,
    )?;
    // Finally we can kick things off with the task graph.
    runner::run_proof_background(
        opt.num_threads.unwrap_or_else(num_cpus::get),
        rng,
        &mut ts,
        root_conn,
        run_queue,
        circuit_manifest,
        reactor,
        private_manifest,
        dependent_counts,
        dependency_counts,
    )?;
    ts.wait_on_threads()?;
    let proof_time = start_time.elapsed();
    event_log::ProofFinish.submit();
    eprintln!("Proof finished in {proof_time:?}");
    if let Some(path) = &opt.write_run_time_to {
        std::fs::write(path, proof_time.as_nanos().to_string().as_bytes())
            .wrap_err_with(ErrorKind::FilesystemError, || {
                format!("Failed to write proof time to {path:?}.")
            })?;
    }
    Ok(())
}

fn extract_allocation_sizes<P: Party>(
    allocation_sizes: flatbuffers::Vector<flatbuffers::ForwardsUOffset<fb::AllocationSize>>,
) -> swanky_error::Result<Vec<usize>> {
    let mut out = Vec::with_capacity(allocation_sizes.len());
    for sz in allocation_sizes.iter() {
        out.push(
            usize::try_from(sz.count())
                .wrap_err(
                    ErrorKind::OtherError,
                    "Failed to represent allocation size as a usize.",
                )?
                .checked_mul(if let Some(ty) = sz.type_() {
                    let ty = Type::try_from(ty.encoding())?;
                    struct V<P: Party>(PhantomData<P>);
                    impl<P: Party> TypeVisitor for V<P> {
                        type Output = usize;
                        fn visit<T: 'static + Send + Sync + Copy>(self) -> Self::Output {
                            std::mem::size_of::<T>()
                        }
                    }
                    visit_type::<P, V<P>>(ty, V::<P>(PhantomData))
                } else {
                    1 // the unit is bytes
                })
                .ok_or_swanky_error(ErrorKind::OtherError, "too much memory is requested")?,
        );
    }
    Ok(out)
}

fn main() -> swanky_error::Result<()> {
    setup_panic_handler();
    #[cfg(feature = "dhat")]
    let _profiler = dhat::Profiler::builder().trim_backtraces(None).build();
    let opt = Opt::parse();
    if matches!(
        vectoreyes::VECTOR_BACKEND,
        vectoreyes::VectorBackend::Scalar
    ) {
        eprintln!(
            "WARNING: this version of mac n'cheese will be using the scalar vectoreyes backend!"
        );
    }
    if let Some(log_path) = opt.event_log.as_ref() {
        event_log::open_event_log(log_path)
            .with_context(|| format!("Opening event log at {log_path:?}"))?;
    }
    let party_main_result = match &opt.cmd {
        Command::Prove { private_data } => party_main::<Prover>(
            &opt,
            PartyPrivateCopy::new(private_data),
            PartyEitherCopy::new(Witness::EQUAL_TYPES, ()),
        ),
        Command::Verify { num_connections } => {
            swanky_error::ensure!(
                *num_connections >= 2,
                ErrorKind::OtherError,
                "there must be at least two connections"
            );
            party_main::<Verifier>(
                &opt,
                PartyPrivateCopy::empty(Witness::EQUAL_TYPES),
                PartyEitherCopy::new(Witness::EQUAL_TYPES, *num_connections),
            )
        }
    };
    let close_error_log_result = if opt.event_log.is_some() {
        event_log::close_event_log().context("Closing event log")
    } else {
        Ok(())
    };
    // We want to show _both_ party_main_result and close_error_log_result
    match (party_main_result, close_error_log_result) {
        (Ok(()), x) => x,
        (x, Ok(())) => x,
        (Err(p_err), Err(log_err)) => {
            eprintln!("Closing the event log failed:\n{log_err}");
            Err(p_err)
        }
    }
}
