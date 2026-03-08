use std::marker::PhantomData;

use mac_n_cheese_ir::compilation_format::wire_format::Xor4PrototypeWireFormat;
use mac_n_cheese_vole::{party::Party, specialization::SmallBinaryFieldSpecialization};
use swanky_field::IsSubFieldOf;
use swanky_field_binary::{F2, SmallBinaryField};

use crate::task_framework::{NoContinuation, TaskDefinition};

pub struct Xor4Task<P: Party, TF: SmallBinaryField>(PhantomData<(P, TF)>);

impl<P: Party, TF: SmallBinaryField> TaskDefinition<P> for Xor4Task<P, TF>
where
    F2: IsSubFieldOf<TF>,
{
    const NEEDS_CHALLENGE: bool = false;

    fn global_vole_support_needed() -> crate::task_framework::GlobalVolesNeeded {
        Default::default()
    }

    fn initialize(
        _c: &mut crate::tls::TlsConnection<P>,
        _rng: &mut swanky_aes_rng::AesRng,
        _vc: crate::base_vole::VoleContexts<P>,
        _num_runner_threads: usize,
    ) -> swanky_error::Result<Self> {
        Ok(Self(PhantomData))
    }

    type TaskContinuation = NoContinuation;

    fn finalize(
        self,
        _c: &mut crate::tls::TlsConnection<P>,
        _rng: &mut swanky_aes_rng::AesRng,
    ) -> swanky_error::Result<()> {
        Ok(())
    }

    fn start_task(
        &self,
        ctx: &mut crate::task_framework::TaskContext,
        input: &crate::task_framework::TaskInput<P>,
        _incoming_data: crate::alloc::OwnedAlignedBytes,
        _outgoing_data: crate::alloc::AlignedBytesMut,
    ) -> swanky_error::Result<crate::task_framework::TaskResult<P, Self::TaskContinuation>> {
        input.small_binary_mac_task::<2, 1, (F2, TF, SmallBinaryFieldSpecialization)>(
            ctx,
            Xor4PrototypeWireFormat::default(),
            |[a, b]| Ok([a ^ b]),
        )
    }

    fn continue_task(
        &self,
        _tc: Box<Self::TaskContinuation>,
        _ctx: &mut crate::task_framework::TaskContext,
        _input: &crate::task_framework::TaskInput<P>,
        _incoming_data: crate::alloc::OwnedAlignedBytes,
        _outgoing_data: crate::alloc::AlignedBytesMut,
    ) -> swanky_error::Result<crate::task_framework::TaskResult<P, Self::TaskContinuation>> {
        unreachable!()
    }
}
