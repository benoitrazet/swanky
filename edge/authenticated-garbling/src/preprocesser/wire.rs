//! `Informer` runs a fancy computation and learns information from it.

use fancy_garbling::{Fancy, FancyBinary, HasModulus};
use std::collections::HashMap;
use swanky_authenticated_bits::authshares::AuthShare;
use swanky_channel::Channel;
use swanky_party::GenericParty;

/// A trait which defines a garbled circuit wire which has an index.
pub trait IndexedWire {
    /// Returns the index of the wire
    fn to_index(&self) -> usize;
    /// Sets the index of the wire
    fn set_index(&mut self, index: usize);
}

/// A struct which defines a wire that can be used for pre-processing
/// an authenticated garbling circuit. The main feature of this wire is that
/// it has an index and that it keeps track of the wire's authenticated share. The
/// later part is especially important because one of the assumptions that
/// [KRRW18] makes and does not explicitly state is that once the authenticate shares
/// are generated during pre-processing, the garbler has to construct the authenticated
/// share of XOR and Negation gates during pre-processing in order to correctly produce known and gates.
#[derive(Clone, Copy)]
pub struct PreProcessedWire<P: GenericParty> {
    index: usize,
    auth_share: AuthShare<P>,
    modulus: u16,
}

impl<P: GenericParty> PreProcessedWire<P> {
    /// Construct a new [`PreProcessedWire`] from an index and an authenticated share
    pub fn new(index: usize, auth_share: AuthShare<P>) -> Self {
        PreProcessedWire {
            index,
            auth_share,
            modulus: 2,
        }
    }
    /// Xor two [`PreProcessedWire`].
    pub fn xor(&self, other: &PreProcessedWire<P>, output_index: usize) -> PreProcessedWire<P> {
        PreProcessedWire {
            index: output_index,
            auth_share: self.auth_share ^ other.auth_share,
            modulus: 2,
        }
    }
    /// Return the [`AuthShare`] stored inside the [`PreProcessedWire`]
    pub fn into_auth_share(self) -> AuthShare<P> {
        self.auth_share
    }
}
impl<P: GenericParty> IndexedWire for PreProcessedWire<P> {
    fn to_index(&self) -> usize {
        self.index
    }
    fn set_index(&mut self, index: usize) {
        self.index = index;
    }
}
impl<P: GenericParty> HasModulus for PreProcessedWire<P> {
    fn modulus(&self) -> u16 {
        self.modulus
    }
}
/// A struct which allows us to correctly correlate the indices
/// of the input wires of an AND gate, to the index of the output
/// wire of that gate. This is required in order to figure out how
/// to turn random and triples into known ones since it allows us to
/// figure out which pairs of wires need to be correlated together.
#[derive(Clone)]
pub struct WirePreProcessor<P: GenericParty> {
    auth_shares: Vec<AuthShare<P>>,
    indexed_auth_shares: HashMap<usize, PreProcessedWire<P>>,
    and_triples_corrolation: Vec<(usize, usize, usize)>,
    current_index: usize,
}

impl<P: GenericParty> WirePreProcessor<P> {
    /// Construct a new [`WirePreProcessor`] using a vector of [`AuthShare`]
    pub fn new(auth_shares: Vec<AuthShare<P>>) -> WirePreProcessor<P> {
        WirePreProcessor {
            auth_shares,
            indexed_auth_shares: HashMap::new(),
            and_triples_corrolation: Vec::new(),
            current_index: 0,
        }
    }
    /// Construct an empty [`WirePreProcessor`]
    pub fn empty() -> WirePreProcessor<P> {
        WirePreProcessor {
            auth_shares: Vec::new(),
            indexed_auth_shares: HashMap::new(),
            and_triples_corrolation: Vec::new(),
            current_index: 0,
        }
    }
    /// Returns a reference of the vector holding the indices of input/output
    /// wires of AND gates, where the wires of the same gate belong to the same
    /// triple.
    pub fn into_and_triples_corrolation(&self) -> &[(usize, usize, usize)] {
        &self.and_triples_corrolation
    }
    /// Returns the [`AuthShare`] associated with the input wires of AND gates.
    /// These shares are split according to whether they are the left or right
    /// wires of a gate.
    pub fn and_gate_input_shares(&mut self) -> (Vec<AuthShare<P>>, Vec<AuthShare<P>>, Vec<usize>) {
        let mut lefts = Vec::new();
        let mut rights = Vec::new();
        let mut indices = Vec::new();
        for (left, right, index) in &self.and_triples_corrolation {
            lefts.push(self.retrieve_auth_share(*left));
            rights.push(self.retrieve_auth_share(*right));
            indices.push(*index)
        }
        (lefts, rights, indices)
    }
    /// Returns the hash map of [`AuthShare`] with their wire index
    pub fn into_indexed_auth_shares(self) -> HashMap<usize, PreProcessedWire<P>> {
        self.indexed_auth_shares
    }
    /// Pops an [`AuthShare<P>`] from the vector of authenticated share stores in
    /// [`KnownAndTriplesIndices`].
    pub fn pop_auth_share(&mut self) -> AuthShare<P> {
        let res = self.auth_shares.pop();
        match res {
            Some(r) => r,
            None => {
                panic!("There aren't enough authenticated shares generated during preprocessing!")
            }
        }
    }
    /// Returns the [`AuthShare`] associated with a specific index
    pub fn retrieve_auth_share(&self, index: usize) -> AuthShare<P> {
        self.indexed_auth_shares[&index].into_auth_share()
    }
    /// Returns the [`PreProcessedWire`] associated with a specific index
    pub fn retrieve_preprocessing_wire(&mut self, index: usize) -> PreProcessedWire<P> {
        self.indexed_auth_shares[&index]
    }

    /// Insert a [`PreProcessedWire`] into the [`WirePreProcessor`]'s HashMap of indexed wires.
    pub fn insert_wire(&mut self, wire: PreProcessedWire<P>) {
        self.indexed_auth_shares.insert(wire.to_index(), wire);
    }
    /// Inserts the indices of the left, right and output wire of an AND gate into the
    /// [`WirePreProcessor`]'s HashMap.
    pub fn insert_index_corrolation(&mut self, left: usize, right: usize, and_triple_index: usize) {
        self.and_triples_corrolation
            .push((left, right, and_triple_index));
    }
    /// Returns the current wire's index.
    fn current_index(&mut self) -> usize {
        let current = self.current_index;
        self.current_index += 1;
        current
    }
}

impl<P: GenericParty> std::fmt::Display for WirePreProcessor<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for (left, right, and_triple_index) in &self.and_triples_corrolation {
            writeln!(
                f,
                "Current Known AND Triple has index {}, and is correlated with left input {} and right input {}",
                and_triple_index, left, right
            )?;
        }
        Ok(())
    }
}

impl<P: GenericParty> FancyBinary for WirePreProcessor<P> {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        let index = self.current_index();
        let mut result = x.xor(y, index);
        result.set_index(index);
        self.insert_wire(result);
        result
    }

    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        _channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let index = self.current_index();
        let authshare = self.pop_auth_share();

        let result = PreProcessedWire::new(index, authshare);
        self.insert_index_corrolation(x.to_index(), y.to_index(), index);
        self.insert_wire(result);
        Ok(result)
    }
    /// Double check later that negation does not affect the authentication shares
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        *x
    }
}

impl<P: GenericParty> Fancy for WirePreProcessor<P> {
    type Item = PreProcessedWire<P>;
    fn receive_many(
        &mut self,
        moduli: &[u16],
        _channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        let mut wires: Vec<PreProcessedWire<P>> = Vec::with_capacity(moduli.len());
        for _ in 0..moduli.len() {
            let index = self.current_index();
            let auth_share = self.pop_auth_share();
            let wire = PreProcessedWire::new(index, auth_share);
            self.insert_wire(wire);
            wires.push(wire);
        }
        Ok(wires)
    }

    fn encode_many(
        &mut self,
        values: &[u16],
        _moduli: &[u16],
        _channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        let mut wires: Vec<PreProcessedWire<P>> = Vec::with_capacity(values.len());
        for _ in 0..values.len() {
            let index = self.current_index();
            let auth_share = self.pop_auth_share();
            let wire = PreProcessedWire::new(index, auth_share);
            self.insert_wire(wire);
            wires.push(wire);
        }
        Ok(wires)
    }
    fn constant(
        &mut self,
        _val: u16,
        _q: u16,
        _channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let index = self.current_index();
        let authshare = self.pop_auth_share();
        let mut result = PreProcessedWire::new(index, authshare);
        result.set_index(index);
        self.insert_wire(result);
        Ok(result)
    }

    fn output(
        &mut self,
        _x: &Self::Item,
        _channel: &mut Channel,
    ) -> swanky_error::Result<Option<u16>> {
        Ok(Some(0))
    }
}
