//! Evaluator for Authenticated Garbling
use std::marker::PhantomData;

use fancy_garbling::{AllWire, Fancy, FancyBinary, HasModulus, WireLabel, check_binary};
use swanky_channel::Channel;

/// Streaming evaluator using a callback to receive ciphertexts as needed.
///
/// Evaluates a garbled circuit on the fly, using messages containing ciphertexts and
/// wires. Parallelizable.
pub struct Evaluator<Wire> {
    current_gate: usize,
    current_output: usize,
    _phantom: PhantomData<Wire>,
}

impl<Wire: WireLabel> Evaluator<Wire> {
    /// Create a new `Evaluator`.
    pub fn new() -> Self {
        Evaluator {
            current_gate: 0,
            current_output: 0,
            _phantom: PhantomData,
        }
    }

    /// The current non-free gate index of the garbling computation.
    fn current_gate(&mut self) -> usize {
        let current = self.current_gate;
        self.current_gate += 1;
        current
    }

    /// The current output index of the garbling computation.
    fn current_output(&mut self) -> usize {
        let current = self.current_output;
        self.current_output += 1;
        current
    }

    /// Read a Wire from the reader.
    pub fn read_wire(&mut self, modulus: u16, channel: &mut Channel) -> swanky_error::Result<Wire> {
        let bytes = channel.read()?;
        Ok(Wire::from_repr(bytes, modulus))
    }
}

impl FancyBinary for Evaluator<AllWire> {
    /// Overriding `negate` to be a noop: entirely handled on garbler's end
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        check_binary!(x);
        todo!()
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        check_binary!(x);
        check_binary!(y);

        todo!()
    }

    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        // If we got here, one of the wires isn't binary
        check_binary!(x);
        check_binary!(y);

        todo!()
    }
}

impl<Wire: WireLabel> Fancy for Evaluator<Wire> {
    type Item = Wire;

    fn receive_many(
            &mut self,
            moduli: &[u16],
            channel: &mut Channel,
        ) -> swanky_error::Result<Vec<Self::Item>> {
        todo!()
    }
    fn encode_many(
            &mut self,
            values: &[u16],
            moduli: &[u16],
            channel: &mut Channel,
        ) -> swanky_error::Result<Vec<Self::Item>> {
        todo!()
    }
    fn constant(&mut self, _: u16, q: u16, channel: &mut Channel) -> swanky_error::Result<Wire> {
        self.read_wire(q, channel)
    }

    fn output(&mut self, x: &Wire, channel: &mut Channel) -> swanky_error::Result<Option<u16>> {
        todo!()
    }
}
