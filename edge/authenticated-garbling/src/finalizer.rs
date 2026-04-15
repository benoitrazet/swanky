//! A structure which allows two parties to finalize the authenticated garbling computation before
//! the evaluator is able to open the output of the computation
use std::marker::PhantomData;

use fancy_garbling::{Fancy, FancyBinary, HasModulus};
use swanky_channel::Channel;
use swanky_field_binary::F2;
use swanky_party::GenericParty;

/// A structure which contains the verification bits c_γ
#[derive(Clone)]
pub struct Finalizer<P: GenericParty> {
    values: Vec<F2>,
    validation_bits: Vec<F2>,
    current_index: usize,
    phantom: PhantomData<P>,
}

impl<P: GenericParty> Finalizer<P> {
    /// Construct a new finalizer using the existing values
    /// computed during garbling
    pub fn new(values: Vec<F2>) -> Self {
        Finalizer {
            values,
            validation_bits: Vec::new(),
            current_index: 0,
            phantom: PhantomData,
        }
    }

    pub(crate) fn validate(&self) -> swanky_error::Result<bool> {
        for bit in self.validation_bits.iter() {
            if *bit != F2::from(0) {
                return Err(swanky_error::Error::new(
                    swanky_error::ErrorKind::OtherError,
                    "Authenticated validation check failed!",
                    None,
                ));
            }
        }
        Ok(true)
    }
    pub(crate) fn value_at_index(&mut self, index: usize) -> F2 {
        self.values[index]
    }
    /// The evaluator sends a masked value to the garbler in order for them to perform
    /// the final validations in the protocol before opening the results.
    pub fn exchange_masked_values(&mut self, nwires: usize, channel: &mut Channel) {
        match P::GENERIC_WHICH {
            swanky_party::GenericWhichParty::Party0(_witness) => {
                let _ = (0..nwires).map(|_| {
                    let value = channel.read().unwrap();
                    self.values.push(value);
                });
            }
            swanky_party::GenericWhichParty::Party1(_witness) => {
                let _ = self.values.iter().map(|v| channel.write(v));
            }
        }
    }
}

/// A structure which contains the current masked value of a wire
/// A masked value in the paper is referred to as:
/// \hat{z}_w := z_w ⊕ λ_w
#[derive(Clone, Copy)]
pub struct FinalizerItem<P: GenericParty> {
    masked_value: F2,
    phantom: PhantomData<P>,
    index: usize,
}

impl<P: GenericParty> FinalizerItem<P> {
    pub(crate) fn new(masked_value: F2, global_index: &mut usize) -> Self {
        let index = *global_index;
        *global_index += 1;
        FinalizerItem {
            masked_value,
            phantom: PhantomData,
            index,
        }
    }

    pub(crate) fn masked_value(&self) -> F2 {
        self.masked_value
    }
    pub(crate) fn update_masked_value(&mut self, new_masked_value: F2) {
        self.masked_value = new_masked_value;
    }
    pub(crate) fn index(&self) -> usize {
        self.index
    }
}
impl<P: GenericParty> HasModulus for FinalizerItem<P> {
    fn modulus(&self) -> u16 {
        2
    }
}

impl<P: GenericParty> std::fmt::Display for Finalizer<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "The validation bits are {:?}", self.validation_bits)?;
        Ok(())
    }
}

impl<P: GenericParty> FancyBinary for Finalizer<P> {
    fn xor(&mut self, _x: &Self::Item, _y: &Self::Item) -> Self::Item {
        let index = self.current_index;
        FinalizerItem::new(self.value_at_index(index), &mut self.current_index)
    }

    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        _channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let mut res = FinalizerItem::new(x.masked_value * y.masked_value, &mut self.current_index);
        res.update_masked_value(res.masked_value() + self.value_at_index(res.index()));
        Ok(res)
    }
    /// Double check later that negation does not affect the authentication shares
    fn negate(&mut self, _x: &Self::Item) -> Self::Item {
        let index = self.current_index;
        FinalizerItem::new(self.value_at_index(index), &mut self.current_index)
    }
}

impl<P: GenericParty> Fancy for Finalizer<P> {
    type Item = FinalizerItem<P>;

    fn receive_many(
        &mut self,
        moduli: &[u16],
        _channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        let start_index;
        let end_index;
        match P::GENERIC_WHICH {
            swanky_party::GenericWhichParty::Party0(_gb) => {
                // The evaluator's wires go second in the values' vector
                start_index = moduli.len();
                end_index = 2 * moduli.len();
            }
            swanky_party::GenericWhichParty::Party1(_eb) => {
                // The garbler's wires go first in the values' vector
                start_index = 0;
                end_index = moduli.len();
            }
        };
        Ok(self.values[start_index..end_index]
            .iter()
            .map(|v| FinalizerItem::new(*v, &mut self.current_index))
            .collect())
    }

    fn encode_many(
        &mut self,
        _values: &[u16],
        moduli: &[u16],
        _channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        let start_index;
        let end_index;
        match P::GENERIC_WHICH {
            swanky_party::GenericWhichParty::Party0(_gb) => {
                // The garbler's wires go first in the values' vector
                start_index = 0;
                end_index = moduli.len();
            }
            swanky_party::GenericWhichParty::Party1(_eb) => {
                // The evaluator's wires go second in the values' vector
                start_index = moduli.len();
                end_index = 2 * moduli.len();
            }
        };
        Ok(self.values[start_index..end_index]
            .iter()
            .map(|v| FinalizerItem::new(*v, &mut self.current_index))
            .collect())
    }
    fn constant(
        &mut self,
        _val: u16,
        _q: u16,
        _channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let index = self.current_index;
        Ok(FinalizerItem::new(
            self.value_at_index(index),
            &mut self.current_index,
        ))
    }

    fn output(
        &mut self,
        _x: &Self::Item,
        _channel: &mut Channel,
    ) -> swanky_error::Result<Option<u16>> {
        Ok(Some(self.validate()?.into()))
    }
}
