use crate::{
    channel_adapter::ChannelAdapter, task_framework::GlobalVolesNeeded, type_map::SmallTypeMap,
    types::RandomMac,
};
use mac_n_cheese_ir::compilation_format::{FieldMacType, FieldTypeMacVisitor};
use mac_n_cheese_vole::{
    mac::{Mac, MacConstantContext, MacTypes},
    party::{Party, WhichParty},
};
use std::{
    any::{Any, TypeId},
    io::{Read, Write},
    marker::PhantomData,
};
use swanky_aes_rng::AesRng;
use swanky_channel_legacy::AbstractChannel;
use swanky_error::{ErrorKind, ResultExt, WrapErr};
use swanky_svole_wykw::base_svole::{Receiver as BaseReceiver, Sender as BaseSender};

pub struct VoleContext<P: Party, T: MacTypes> {
    pub constant_context: MacConstantContext<P, T::TF>,
    pub base_voles: Vec<RandomMac<P, T>>,
}

#[derive(Default)]
pub struct VoleContexts<P: Party> {
    contents: SmallTypeMap<0>,
    phantom: PhantomData<P>,
}
impl<P: Party> VoleContexts<P> {
    pub fn get<T: MacTypes>(&self) -> &VoleContext<P, T> {
        self.contents.get().unwrap()
    }
}

pub fn init_base_vole<P: Party, C: Read + Write>(
    gvn: &[GlobalVolesNeeded],
    rng: &mut AesRng,
    conn: &mut C,
) -> swanky_error::Result<Vec<VoleContexts<P>>> {
    // TODO: we shouldn't service the entirety of these requests with base vole.
    struct V<'a, P: Party, C: Read + Write> {
        rng: &'a mut AesRng,
        conn: &'a mut C,
        outs: &'a mut [SmallTypeMap<0>],
        gvn: &'a [GlobalVolesNeeded],
        count: usize,
        phantom: PhantomData<P>,
    }

    impl<'a, P: Party, C: Read + Write> FieldTypeMacVisitor for V<'a, P, C> {
        type Output = swanky_error::Result<()>;
        fn visit<
            VF: swanky_field::FiniteField + swanky_field::IsSubFieldOf<TF>,
            TF: swanky_field::FiniteField,
            S: mac_n_cheese_vole::specialization::FiniteFieldSpecialization<VF, TF>,
        >(
            self,
        ) -> Self::Output {
            debug_assert_eq!(self.gvn.len(), self.outs.len());
            assert_eq!(
                TypeId::of::<VF>(),
                TypeId::of::<TF::PrimeField>(),
                "TODO support non-subfield base VOLE"
            );
            let mut channel = ChannelAdapter(self.conn);
            let mut total_vole_context: VoleContext<P, (VF, TF, S)> = if self.count == 0 {
                VoleContext {
                    base_voles: Default::default(),
                    constant_context: match P::WHICH {
                        WhichParty::Prover(e) => MacConstantContext::new(e, ()),
                        WhichParty::Verifier(e) => {
                            MacConstantContext::new(e, TF::random_nonzero(self.rng))
                        }
                    },
                }
            } else {
                match P::WHICH {
                    WhichParty::Prover(e) => {
                        let mut base =
                            BaseSender::<TF>::init(&mut channel, Default::default(), self.rng)
                                .wrap_err_with(ErrorKind::InitializationError, || {
                                    "Failed to initialize SVOLE sender.".to_string()
                                })
                                .with_context(|| "base sender init".to_string())?;
                        channel.flush().wrap_err_with(ErrorKind::NetworkError, || {
                            "Failed to flush SVOLE channel.".to_string()
                        })?;
                        let base_voles = base
                            .send(&mut channel, self.count, self.rng)
                            .wrap_err_with(ErrorKind::OtherError, || {
                                "Failed to send base VOLEs.".to_string()
                            })
                            .with_context(|| "base voles".to_string())?;
                        channel.flush().wrap_err_with(ErrorKind::NetworkError, || {
                            "Failed to flush SVOLE channel.".to_string()
                        })?;
                        // We need to convince Rust that (VF == TF::PrimeField). We roundtrip thru
                        // Any in order to do that.
                        let base_voles: &dyn Any = &base_voles;
                        let base_voles: &Vec<(VF, TF)> = base_voles.downcast_ref().unwrap();
                        VoleContext {
                            base_voles: base_voles
                                .iter()
                                .copied()
                                .map(|(x, beta)| RandomMac(Mac::prover_new(e, x, beta)))
                                .collect(),
                            constant_context: MacConstantContext::new(e, ()),
                        }
                    }
                    WhichParty::Verifier(e) => {
                        let mut base =
                            BaseReceiver::<TF>::init(&mut channel, Default::default(), self.rng)
                                .wrap_err_with(ErrorKind::InitializationError, || {
                                    "Failed to initialize base VOLE receiver.".to_string()
                                })
                                .with_context(|| "base receiver init".to_string())?;
                        channel.flush().wrap_err_with(ErrorKind::NetworkError, || {
                            "Failed to flush VOLE channel.".to_string()
                        })?;
                        let base_voles = base
                            .receive(&mut channel, self.count, self.rng)
                            .wrap_err_with(ErrorKind::OtherError, || {
                                "Failed to receive base VOLEs.".to_string()
                            })
                            .with_context(|| "base voles".to_string())?;
                        channel.flush().wrap_err_with(ErrorKind::NetworkError, || {
                            "Failed to flush VOLE channel.".to_string()
                        })?;
                        let alpha = -base.delta();
                        VoleContext {
                            base_voles: base_voles
                                .iter()
                                .copied()
                                .map(|tag| RandomMac(Mac::verifier_new(e, tag)))
                                .collect(),
                            constant_context: MacConstantContext::new(e, alpha),
                        }
                    }
                }
            };
            for (dst, gvn) in self.outs.iter_mut().zip(self.gvn.iter()) {
                let count = if let Some(count) = gvn.get(&FieldMacType::get::<VF, TF>()) {
                    *count
                } else {
                    continue;
                };
                let vc: VoleContext<P, (VF, TF, S)> = VoleContext {
                    base_voles: total_vole_context.base_voles.split_off(
                        total_vole_context
                            .base_voles
                            .len()
                            .checked_sub(count)
                            .unwrap(),
                    ),
                    constant_context: total_vole_context.constant_context,
                };
                let old = dst.insert(vc);
                assert!(old.is_none());
            }
            Ok(())
        }
    }
    let mut total_gvn = GlobalVolesNeeded::default();
    for (ty, count) in gvn.iter().flatten() {
        *total_gvn.entry(*ty).or_default() += count;
    }
    let mut outs = Vec::with_capacity(gvn.len());
    outs.resize_with(gvn.len(), SmallTypeMap::default);
    for (ty, count) in total_gvn.iter() {
        ty.visit(V::<P, C> {
            rng,
            conn,
            count: *count,
            gvn,
            outs: &mut outs,
            phantom: PhantomData,
        })?;
    }
    Ok(outs
        .into_iter()
        .map(|contents| VoleContexts {
            contents,
            phantom: PhantomData,
        })
        .collect())
}
