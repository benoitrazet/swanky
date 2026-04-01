//! `Informer` runs a fancy computation and learns information from it.

use crate::{
    FancyArithmetic, FancyBinary,
    fancy::{Fancy, FancyInput, FancyReveal, HasModulus},
};
use std::collections::{HashMap, HashSet};
use swanky_channel::Channel;

/// Implements `Fancy`. Used to learn information about a `Fancy` computation in
/// a lightweight way.
pub struct Informer<F: Fancy> {
    /// The underlying fancy object.
    pub underlying: F,
    stats: InformerStats,
}

/// The statistics revealed by the informer.
#[derive(Clone, Debug)]
pub struct InformerStats {
    input_moduli: Vec<u16>,
    constants: HashSet<(u16, u16)>,
    outputs: Vec<u16>,
    nadds: usize,
    nsubs: usize,
    ncmuls: usize,
    nmuls: usize,
    nprojs: usize,
    nciphertexts: usize,
    moduli: HashMap<u16, usize>,
}

impl InformerStats {
    /// Number of inputs in the fancy computation.
    pub fn num_inputs(&self) -> usize {
        self.input_moduli.len()
    }

    /// Moduli of inputs in the fancy computation.
    pub fn input_moduli(&self) -> Vec<u16> {
        self.input_moduli.clone()
    }

    /// Number of constants in the fancy computation.
    pub fn num_consts(&self) -> usize {
        self.constants.len()
    }

    /// Number of outputs in the fancy computation.
    pub fn num_outputs(&self) -> usize {
        self.outputs.len()
    }

    /// Number of output ciphertexts.
    pub fn num_output_ciphertexts(&self) -> usize {
        self.outputs.iter().map(|&m| m as usize).sum()
    }

    /// Number of additions in the fancy computation.
    pub fn num_adds(&self) -> usize {
        self.nadds
    }

    /// Number of subtractions in the fancy computation.
    pub fn num_subs(&self) -> usize {
        self.nsubs
    }

    /// Number of scalar multiplications in the fancy computation.
    pub fn num_cmuls(&self) -> usize {
        self.ncmuls
    }

    /// Number of multiplications in the fancy computation.
    pub fn num_muls(&self) -> usize {
        self.nmuls
    }

    /// Number of projections in the fancy computation.
    pub fn num_projs(&self) -> usize {
        self.nprojs
    }

    /// Number of ciphertexts in the fancy computation.
    pub fn num_ciphertexts(&self) -> usize {
        self.nciphertexts
    }
}

impl std::fmt::Display for InformerStats {
    /// Print information about the fancy computation.
    ///
    /// For example, below is the output when run on `circuits/AES-non-expanded.txt`:
    /// ```text
    /// computation info:
    ///   inputs:                          256 // comms cost: 32 Kb
    ///   outputs:                         128
    ///   output ciphertexts:              256 // comms cost: 32 Kb
    ///   constants:                         1 // comms cost: 0.125 Kb
    ///   additions:                     25124
    ///   subtractions:                   1692
    ///   cmuls:                             0
    ///   projections:                       0
    ///   multiplications:                6800
    ///   ciphertexts:                   13600 // comms cost: 1.66 Mb (1700.00 Kb)
    ///   total comms cost:            1.75 Mb // 1700.00 Kb
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut total = 0.0;
        writeln!(f, "computation info:")?;
        let comm = self.num_inputs() as f64 * 128.0 / 1000.0;

        writeln!(
            f,
            "  inputs:     {:16} // communication: {:.2} Kb",
            self.num_inputs(),
            comm
        )?;
        total += comm;

        let comm = self.num_output_ciphertexts() as f64 * 128.0 / 1000.0;

        writeln!(f, "  outputs:            {:16}", self.num_outputs())?;
        writeln!(
            f,
            "  output ciphertexts: {:16} // communication: {:.2} Kb",
            self.num_output_ciphertexts(),
            comm
        )?;
        total += comm;
        let comm = self.num_consts() as f64 * 128.0 / 1000.0;

        writeln!(
            f,
            "  constants:          {:16} // communication: {:.2} Kb",
            self.num_consts(),
            comm
        )?;
        total += comm;

        writeln!(f, "  additions:          {:16}", self.num_adds())?;
        writeln!(f, "  subtractions:       {:16}", self.num_subs())?;
        writeln!(f, "  cmuls:              {:16}", self.num_cmuls())?;
        writeln!(f, "  projections:        {:16}", self.num_projs())?;
        writeln!(f, "  multiplications:    {:16}", self.num_muls())?;
        let cs = self.num_ciphertexts();
        let kb = cs as f64 * 128.0 / 1000.0;
        let mb = kb / 1000.0;
        writeln!(
            f,
            "  ciphertexts:        {:16} // communication: {:.2} Mb ({:.2} Kb)",
            cs, mb, kb
        )?;
        total += kb;

        let mb = total / 1000.0;
        writeln!(f, "  total communication:  {:11.2} Mb", mb)?;
        writeln!(f, "  wire moduli: {:#?}", self.moduli)?;
        Ok(())
    }
}

impl<F: Fancy> Informer<F> {
    /// Make a new `Informer`.
    pub fn new(underlying: F) -> Informer<F> {
        Informer {
            underlying,
            stats: InformerStats {
                input_moduli: Vec::new(),
                constants: HashSet::new(),
                outputs: Vec::new(),
                nadds: 0,
                nsubs: 0,
                ncmuls: 0,
                nmuls: 0,
                nprojs: 0,
                nciphertexts: 0,
                moduli: HashMap::new(),
            },
        }
    }

    /// Get the statistics collected by the `Informer`
    pub fn stats(&self) -> InformerStats {
        self.stats.clone()
    }

    fn update_moduli(&mut self, q: u16) {
        let entry = self.stats.moduli.entry(q).or_insert(0);
        *entry += 1;
    }
}

impl<F: Fancy + FancyInput<Item = <F as Fancy>::Item>> FancyInput for Informer<F> {
    type Item = <F as Fancy>::Item;

    fn receive_many(
        &mut self,
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        self.stats.input_moduli.extend(moduli.iter().cloned());
        self.underlying.receive_many(moduli, channel)
    }

    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        self.stats.input_moduli.extend(moduli.iter().cloned());
        self.underlying.encode_many(values, moduli, channel)
    }
}

impl<F: FancyBinary> FancyBinary for Informer<F> {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        let result = self.underlying.xor(x, y);
        self.stats.nadds += 1;
        self.update_moduli(x.modulus());
        result
    }

    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let result = self.underlying.and(x, y, channel)?;
        self.stats.nmuls += 1;
        self.stats.nciphertexts += 2;
        self.update_moduli(x.modulus());
        Ok(result)
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        let result = self.underlying.negate(x);

        // Technically only the garbler adds: noop for the evaluator
        self.stats.nadds += 1;
        self.update_moduli(x.modulus());
        result
    }
}

impl<F: FancyArithmetic> FancyArithmetic for Informer<F> {
    // In general, for the below, we first check to see if the result succeeds before
    // updating the stats. That way we can avoid checking multiple times that, e.g.
    // the moduli are equal.

    fn add(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        let result = self.underlying.add(x, y);
        self.stats.nadds += 1;
        self.update_moduli(x.modulus());
        result
    }

    fn sub(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        let result = self.underlying.sub(x, y);
        self.stats.nsubs += 1;
        self.update_moduli(x.modulus());
        result
    }

    fn cmul(&mut self, x: &Self::Item, y: u16) -> Self::Item {
        let result = self.underlying.cmul(x, y);
        self.stats.ncmuls += 1;
        self.update_moduli(x.modulus());
        result
    }

    fn mul(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        if x.modulus() < y.modulus() {
            return self.mul(y, x, channel);
        }
        let result = self.underlying.mul(x, y, channel)?;
        self.stats.nmuls += 1;
        self.stats.nciphertexts += x.modulus() as usize + y.modulus() as usize - 2;
        if x.modulus() != y.modulus() {
            // there is an extra ciphertext to support nonequal inputs
            self.stats.nciphertexts += 1;
        }
        self.update_moduli(x.modulus());
        Ok(result)
    }

    fn proj(
        &mut self,
        x: &Self::Item,
        q: u16,
        tt: Option<Vec<u16>>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let result = self.underlying.proj(x, q, tt, channel)?;
        self.stats.nprojs += 1;
        self.stats.nciphertexts += x.modulus() as usize - 1;
        self.update_moduli(q);
        Ok(result)
    }
}

impl<F: Fancy> Fancy for Informer<F> {
    type Item = F::Item;

    fn constant(
        &mut self,
        val: u16,
        q: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        self.stats.constants.insert((val, q));
        self.update_moduli(q);
        self.underlying.constant(val, q, channel)
    }

    fn output(
        &mut self,
        x: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<u16>> {
        let result = self.underlying.output(x, channel)?;
        self.stats.outputs.push(x.modulus());
        Ok(result)
    }
}

impl<F: Fancy + FancyReveal> FancyReveal for Informer<F> {
    fn reveal(&mut self, x: &Self::Item, channel: &mut Channel) -> swanky_error::Result<u16> {
        self.underlying.reveal(x, channel)
    }
}
