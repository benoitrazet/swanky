//! A module which unifies the different ways a circuit can be pre-processed in
use std::collections::HashMap;

use fancy_garbling::{
    BinaryBundle, BinaryGadgets, Fancy, FancyBinary, HasModulus,
    circuit_analyzer::{AnalyzerItem, CircuitAnalyzer},
};
use rand::{CryptoRng, RngCore};
use swanky_authenticated_bits::authshares::AuthShare;
use swanky_channel::Channel;
use swanky_party::GenericParty;

use crate::{
    garbler::Garbler,
    preprocesser::wire::{PreProcessedWire, WirePreProcessor},
    ps::PartyGarbler,
    wire::AuthenticatedWireMod2,
};

/// A enum which includes all the ways a circuit can be preprocessed
pub enum CircuitExecutor<P: GenericParty, RNG: CryptoRng + RngCore> {
    /// A [`CircuitAnalyzer`] which provides statistics about the circuit
    Analyzer(CircuitAnalyzer),
    /// A [`WirePreProcessor`] which preprocesses wires in a circuit
    WirePreProcessor(WirePreProcessor<P>),
    /// A [`Garbler`] which garbles the circuit
    Garbler(Garbler<RNG>),
}

impl<P: GenericParty, RNG: CryptoRng + RngCore> CircuitExecutor<P, RNG> {
    /// Constructs a new [`CircuitAnalyzer`]
    pub fn new_analyzer() -> Self {
        CircuitExecutor::Analyzer(CircuitAnalyzer::new())
    }
    /// Constructs a new [`WirePreProcessor`] from a vector of [`AuthShare`]
    pub fn new_preprocessing_wires(auth_shares: Vec<AuthShare<P>>) -> Self {
        CircuitExecutor::WirePreProcessor(WirePreProcessor::new(auth_shares))
    }
    /// Returns a reference to the underlying [`WirePreProcessor`]
    pub fn to_wire_preprocessor(&self) -> &WirePreProcessor<P> {
        match &self {
            CircuitExecutor::WirePreProcessor(w) => w,
            _ => panic!("Passed Circuit Executor is not a WirePreProcessor"),
        }
    }
    /// Returns a reference to the underlying [`CircuitAnalyzer`]
    pub fn analyzer(&self) -> &CircuitAnalyzer {
        match &self {
            CircuitExecutor::Analyzer(a) => a,
            _ => panic!("Passed Circuit Executor is not an Analyzer"),
        }
    }
    /// Returns the [`AuthShare`] associated with the input wires of AND gates in the underlying [`WirePreProcessor`].
    pub fn and_gate_input_shares(&self) -> (Vec<AuthShare<P>>, Vec<AuthShare<P>>, Vec<usize>) {
        self.to_wire_preprocessor().clone().and_gate_input_shares()
    }
    /// Returns the hash map of [`AuthShare`] with their wire index present in the underlying [`WirePreProcessor`]
    pub fn into_indexed_auth_shares(&self) -> HashMap<usize, PreProcessedWire<P>> {
        self.to_wire_preprocessor()
            .clone()
            .into_indexed_auth_shares()
    }
    /// Mock running a circuit locally with a "mock" [`Fancy`] object which can analyze or
    /// execute parts of preprocessing a circuit that involves traversing it.
    pub fn mock_circuit(
        &mut self,
        circuit: &impl Fn(
            &mut CircuitExecutor<P, RNG>,
            BinaryBundle<CircuitExecutorItem<P>>,
            BinaryBundle<CircuitExecutorItem<P>>,
            &mut Channel,
        ) -> swanky_error::Result<BinaryBundle<CircuitExecutorItem<P>>>,
        input_size: usize,
        channel: &mut Channel,
    ) -> swanky_error::Result<()> {
        let dummy_wires = self.bin_encode(0, input_size, channel).unwrap();

        circuit(self, dummy_wires.clone(), dummy_wires, channel)?;
        Ok(())
    }
}

/// A [`CircuitExecutor`]'s pre-processing item. This is used
/// when implementing [`Fancy`] and includes optional [`AnalyzerItem`] and [`PreProcessedWire`]
/// depending on the mode the circuit is currently being pre-processed in.
#[derive(Clone)]
pub enum CircuitExecutorItem<P: GenericParty> {
    /// A [`CircuitAnalyzer`]'s [`AnalyzerItem`]
    AnalyzerItem(AnalyzerItem),
    /// A [`WirePreProcessor`]'s [`PreProcessedWire`]
    PreProcessedWire(PreProcessedWire<P>),
    /// A [`Garbler`]'s [`AuthenticatedWireMod2`]
    GbWire(AuthenticatedWireMod2<PartyGarbler>),
}

impl<P: GenericParty> CircuitExecutorItem<P> {
    /// Creates a [`CircuitExecutorItem`] from an [`AnalyzerItem`]
    pub fn from_analyzer_item(analyzer_item: AnalyzerItem) -> Self {
        CircuitExecutorItem::AnalyzerItem(analyzer_item)
    }
    /// Creates a [`CircuitExecutorItem`] from an [`PreProcessedWire`]
    pub fn from_preprocessing_wire(preprocessed_wire: PreProcessedWire<P>) -> Self {
        CircuitExecutorItem::PreProcessedWire(preprocessed_wire)
    }
    /// Creates a [`CircuitExecutorItem`] from an [`AuthenticatedWireMod2`]
    pub fn from_gb_authenticated_wire(wire: AuthenticatedWireMod2<PartyGarbler>) -> Self {
        CircuitExecutorItem::GbWire(wire)
    }
    /// Returns a reference to the underlying [`AnalyzerItem`]
    pub fn analyzer_item(&self) -> &AnalyzerItem {
        match &self {
            CircuitExecutorItem::AnalyzerItem(a) => a,
            _ => panic!("Current CircuitExecutorItem is not an AnalyzerItem"),
        }
    }
    /// Returns a reference to the underlying [`PreProcessedWire`]
    pub fn preprocessed_wire(&self) -> &PreProcessedWire<P> {
        match &self {
            CircuitExecutorItem::PreProcessedWire(p) => p,
            _ => panic!("Current CircuitExecutorItem is not an PreProcessedWire"),
        }
    }
    /// Returns a reference to the underlying [`AuthenticatedWireMod2`]
    pub fn gb_authenticated_wire(&self) -> &AuthenticatedWireMod2<PartyGarbler> {
        match &self {
            CircuitExecutorItem::GbWire(w) => w,
            _ => panic!("Current CircuitExecutorItem is not an Binary Wire!"),
        }
    }
}

impl<P: GenericParty> HasModulus for CircuitExecutorItem<P> {
    fn modulus(&self) -> u16 {
        match &self {
            CircuitExecutorItem::AnalyzerItem(a) => a.modulus(),
            CircuitExecutorItem::PreProcessedWire(p) => p.modulus(),
            CircuitExecutorItem::GbWire(w) => w.modulus(),
        }
    }
}

impl<P: GenericParty, RNG: CryptoRng + RngCore> FancyBinary for CircuitExecutor<P, RNG> {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        match self {
            CircuitExecutor::Analyzer(a) => {
                CircuitExecutorItem::from_analyzer_item(a.xor(x.analyzer_item(), y.analyzer_item()))
            }
            CircuitExecutor::WirePreProcessor(w) => CircuitExecutorItem::from_preprocessing_wire(
                w.xor(x.preprocessed_wire(), y.preprocessed_wire()),
            ),
            CircuitExecutor::Garbler(gb) => CircuitExecutorItem::from_gb_authenticated_wire(
                gb.xor(x.gb_authenticated_wire(), y.gb_authenticated_wire()),
            ),
        }
    }

    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        _channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        match self {
            CircuitExecutor::Analyzer(a) => Ok(CircuitExecutorItem::from_analyzer_item(a.and(
                x.analyzer_item(),
                y.analyzer_item(),
                _channel,
            )?)),
            CircuitExecutor::WirePreProcessor(w) => {
                Ok(CircuitExecutorItem::from_preprocessing_wire(w.and(
                    x.preprocessed_wire(),
                    y.preprocessed_wire(),
                    _channel,
                )?))
            }
            CircuitExecutor::Garbler(gb) => {
                Ok(CircuitExecutorItem::from_gb_authenticated_wire(gb.and(
                    x.gb_authenticated_wire(),
                    y.gb_authenticated_wire(),
                    _channel,
                )?))
            }
        }
    }
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        match self {
            CircuitExecutor::Analyzer(a) => {
                CircuitExecutorItem::from_analyzer_item(a.negate(x.analyzer_item()))
            }
            CircuitExecutor::WirePreProcessor(w) => {
                CircuitExecutorItem::from_preprocessing_wire(w.negate(x.preprocessed_wire()))
            }
            CircuitExecutor::Garbler(gb) => CircuitExecutorItem::from_gb_authenticated_wire(
                gb.negate(x.gb_authenticated_wire()),
            ),
        }
    }
}

impl<P: GenericParty, RNG: CryptoRng + RngCore> Fancy for CircuitExecutor<P, RNG> {
    type Item = CircuitExecutorItem<P>;
    fn receive_many(
        &mut self,
        _moduli: &[u16],
        _channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        match self {
            CircuitExecutor::Analyzer(a) => Ok(a
                .receive_many(_moduli, _channel)?
                .into_iter()
                .map(|w| CircuitExecutorItem::from_analyzer_item(w))
                .collect()),
            CircuitExecutor::WirePreProcessor(w) => Ok(w
                .receive_many(_moduli, _channel)?
                .into_iter()
                .map(|w| CircuitExecutorItem::from_preprocessing_wire(w))
                .collect()),
            CircuitExecutor::Garbler(gb) => Ok(gb
                .receive_many(_moduli, _channel)?
                .into_iter()
                .map(|w| CircuitExecutorItem::from_gb_authenticated_wire(w))
                .collect()),
        }
    }

    fn encode_many(
        &mut self,
        _values: &[u16],
        _moduli: &[u16],
        _channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        match self {
            CircuitExecutor::Analyzer(a) => Ok(a
                .encode_many(_values, _moduli, _channel)?
                .into_iter()
                .map(|w| CircuitExecutorItem::from_analyzer_item(w))
                .collect()),
            CircuitExecutor::WirePreProcessor(w) => Ok(w
                .encode_many(_values, _moduli, _channel)?
                .into_iter()
                .map(|w| CircuitExecutorItem::from_preprocessing_wire(w))
                .collect()),
            CircuitExecutor::Garbler(gb) => Ok(gb
                .encode_many(_values, _moduli, _channel)?
                .into_iter()
                .map(|w| CircuitExecutorItem::from_gb_authenticated_wire(w))
                .collect()),
        }
    }
    fn constant(
        &mut self,
        _val: u16,
        _q: u16,
        _channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        match self {
            CircuitExecutor::Analyzer(a) => Ok(CircuitExecutorItem::from_analyzer_item(
                a.constant(_val, _q, _channel)?,
            )),

            CircuitExecutor::WirePreProcessor(w) => Ok(
                CircuitExecutorItem::from_preprocessing_wire(w.constant(_val, _q, _channel)?),
            ),

            CircuitExecutor::Garbler(gb) => Ok(CircuitExecutorItem::from_gb_authenticated_wire(
                gb.constant(_val, _q, _channel)?,
            )),
        }
    }

    fn output(
        &mut self,
        _x: &Self::Item,
        _channel: &mut Channel,
    ) -> swanky_error::Result<Option<u16>> {
        match self {
            CircuitExecutor::Analyzer(a) => a.output(_x.analyzer_item(), _channel),

            CircuitExecutor::WirePreProcessor(w) => w.output(_x.preprocessed_wire(), _channel),

            CircuitExecutor::Garbler(gb) => gb.output(_x.gb_authenticated_wire(), _channel),
        }
    }
}
