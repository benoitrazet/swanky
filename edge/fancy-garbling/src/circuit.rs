//! DSL for creating circuits compatible with fancy-garbling in the old-fashioned way,
//! where you create a circuit for a computation then garble it.

use crate::{
    dummy::{Dummy, DummyVal},
    fancy::{BinaryBundle, CrtBundle, Fancy, HasModulus},
    informer::Informer,
};
use std::{collections::HashMap, fmt::Display};
use swanky_channel::Channel;
use swanky_error::Result;

mod binary;
pub use binary::{BinaryCircuit, BinaryGate};
mod arithmetic;
pub use arithmetic::{ArithmeticCircuit, ArithmeticGate};

/// Trait for executing computations directly over a [`Fancy`] object.
///
/// # Example
/// Below is a simple example of computing an add gate over an arbitrary
/// modulus. The computation is defined in `execute` by directly calling
/// operations on the underlying [`Fancy`] backend. We also need to track how
/// many inputs the computation takes, and the moduli of those inputs; these are
/// given in the `ninputs` and `modulus` methods, respectively.
/// ```
/// # use fancy_garbling::{FancyArithmetic, circuit::CircuitExecutor};
/// # use swanky_channel::Channel;
/// # use swanky_error::Result;
/// struct AddCircuit(u16);
/// impl<F: FancyArithmetic> CircuitExecutor<F> for AddCircuit {
///     fn execute(
///         &self,
///         backend: &mut F,
///         inputs: &[F::Item],
///         channel: &mut Channel,
///     ) -> Result<Vec<F::Item>> {
///         let output = backend.add(&inputs[0], &inputs[1]);
///         Ok(vec![output])
///     }
///
///     fn ninputs(&self) -> usize {
///         2
///     }
///
///     fn modulus(&self, _: usize) -> u16 {
///         2
///     }
/// }
/// ```
pub trait CircuitExecutor<F: Fancy> {
    /// Execute a circuit on a given [`Fancy`] backend using the provided inputs.
    fn execute(
        &self,
        backend: &mut F,
        inputs: &[F::Item],
        channel: &mut Channel,
    ) -> Result<Vec<F::Item>>;
    /// The number of inputs to provide to [`CircuitExecutor::execute`].
    fn ninputs(&self) -> usize;
    /// The modulus for input `i`.
    fn modulus(&self, i: usize) -> u16;
}

/// The index and modulus of a gate in a circuit.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CircuitRef {
    pub(crate) ix: usize,
    pub(crate) modulus: u16,
}

impl std::fmt::Display for CircuitRef {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "[{} | {}]", self.ix, self.modulus)
    }
}

impl HasModulus for CircuitRef {
    fn modulus(&self) -> u16 {
        self.modulus
    }
}

/// Trait to display circuit evaluation costs
///
/// Blanket implementation available for all circuits
/// that can be evaluated with an `Informer`
pub trait CircuitInfo {
    /// Print circuit info
    fn print_info(&self) -> swanky_error::Result<()>;
}

impl<C: CircuitExecutor<Informer<Dummy>>> CircuitInfo for C {
    fn print_info(&self) -> swanky_error::Result<()> {
        let mut informer = crate::informer::Informer::new(Dummy::new());

        // encode inputs as InformerVals
        let inputs = Channel::with(std::io::empty(), |channel| {
            (0..self.ninputs())
                .map(|i| informer.encode(0, self.modulus(i), channel))
                .collect::<swanky_error::Result<Vec<DummyVal>>>()
        })?;

        Channel::with(std::io::empty(), |c| {
            self.execute(&mut informer, &inputs, c)
        })?;
        println!("{}", informer.stats());
        Ok(())
    }
}

/// Trait representing circuit gates that can be used in `CircuitType`
pub trait GateType: Display {
    /// Generate constant gate
    fn make_constant(val: u16) -> Self;

    /// Generate input gate
    fn make_input(id: usize) -> Self;
}

impl GateType for ArithmeticGate {
    fn make_constant(val: u16) -> Self {
        Self::Constant { val }
    }

    fn make_input(id: usize) -> Self {
        Self::Input { id }
    }
}

/// Trait representing circuits that can be built by `CircuitBuilder`
pub trait CircuitType {
    /// Gates that the circuit is composed of
    type Gate: GateType;

    /// Increase number of nonfree gates
    fn increment_nonfree_gates(&mut self);

    /// Make a new `Circuit` object.
    fn new(ngates: Option<usize>) -> Self;

    /// Get all output refs
    fn get_output_refs(&self) -> &[CircuitRef];

    /// Get all input refs
    fn get_input_refs(&self) -> &[CircuitRef];

    /// Get number of nonfree gates
    fn get_num_nonfree_gates(&self) -> usize;

    /// Add a gate
    fn push_gates(&mut self, gate: Self::Gate);

    /// Add a constant ref
    fn push_const_ref(&mut self, xref: CircuitRef);

    /// Add an output ref
    fn push_output_ref(&mut self, xref: CircuitRef);

    /// Add an input ref
    fn push_input_ref(&mut self, xref: CircuitRef);

    /// Add wire moulus
    fn push_modulus(&mut self, modulus: u16);

    /// Return the modulus of the input indexed by `i`.
    fn input_mod(&self, i: usize) -> u16;

    /// Return the number of inputs.
    #[inline]
    fn num_inputs(&self) -> usize {
        self.get_input_refs().len()
    }

    /// Return the number of outputs.
    #[inline]
    fn noutputs(&self) -> usize {
        self.get_output_refs().len()
    }
}

/// Evaluate the circuit in plaintext.
///
/// # Panics
/// Panics if `inputs.len()` does not equal the circuit's expected number of
/// inputs.
pub fn eval_plain<C: CircuitExecutor<Dummy>>(
    circuit: &C,
    inputs: &[u16],
) -> swanky_error::Result<Vec<u16>> {
    assert_eq!(inputs.len(), circuit.ninputs());

    let mut dummy = crate::dummy::Dummy::new();

    // encode inputs as DummyVals
    let inputs = inputs
        .iter()
        .enumerate()
        .map(|(i, x)| DummyVal::new(*x, circuit.modulus(i)))
        .collect::<Vec<_>>();

    let outputs = Channel::with(std::io::empty(), |c| {
        circuit.execute(&mut dummy, &inputs, c)
    })?;
    Ok(outputs.iter().map(|x| x.val()).collect())
}

/// CircuitBuilder is used to build circuits.
pub struct CircuitBuilder<Circuit> {
    next_ref_ix: usize,
    next_input_id: usize,
    const_map: HashMap<(u16, u16), CircuitRef>,
    circ: Circuit,
}

impl<Circuit: CircuitType> Fancy for CircuitBuilder<Circuit> {
    type Item = CircuitRef;

    fn constant(
        &mut self,
        val: u16,
        modulus: u16,
        _: &mut Channel,
    ) -> swanky_error::Result<CircuitRef> {
        Ok(self.lookup_constant(val, modulus))
    }

    fn output(&mut self, xref: &CircuitRef, _: &mut Channel) -> swanky_error::Result<Option<u16>> {
        self.circ.push_output_ref(*xref);
        Ok(None)
    }

    fn encode_many(
        &mut self,
        _values: &[u16],
        _moduli: &[u16],
        _channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        unimplemented!("Encoding invalid for `CircuitBuilder`")
    }

    fn receive_many(
        &mut self,
        _moduli: &[u16],
        _channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        unimplemented!("Receiving invalid for `CircuitBuilder`")
    }
}

impl<Circuit: CircuitType> CircuitBuilder<Circuit> {
    /// Make a new `CircuitBuilder`.
    pub fn new() -> Self {
        CircuitBuilder {
            next_ref_ix: 0,
            next_input_id: 0,
            const_map: HashMap::new(),
            circ: Circuit::new(None),
        }
    }

    /// Finish circuit building, outputting the resulting circuit.
    pub fn finish(self) -> Circuit {
        self.circ
    }

    /// Look up a constant in the internal constant map, or add it if no such
    /// constant exists.
    fn lookup_constant(&mut self, val: u16, modulus: u16) -> CircuitRef {
        match self.const_map.get(&(val, modulus)) {
            Some(&r) => r,
            None => {
                let gate = Circuit::Gate::make_constant(val);
                let r = self.gate(gate, modulus);
                self.const_map.insert((val, modulus), r);
                self.circ.push_const_ref(r);
                r
            }
        }
    }

    fn get_next_input_id(&mut self) -> usize {
        let current = self.next_input_id;
        self.next_input_id += 1;
        current
    }

    fn get_next_ciphertext_id(&mut self) -> usize {
        let current = self.circ.get_num_nonfree_gates();
        self.circ.increment_nonfree_gates();
        current
    }

    fn get_next_ref_ix(&mut self) -> usize {
        let current = self.next_ref_ix;
        self.next_ref_ix += 1;
        current
    }

    fn gate(&mut self, gate: Circuit::Gate, modulus: u16) -> CircuitRef {
        self.circ.push_gates(gate);
        self.circ.push_modulus(modulus);
        let ix = self.get_next_ref_ix();
        CircuitRef { ix, modulus }
    }

    /// Get CircuitRef for an input wire.
    pub fn input(&mut self, modulus: u16) -> CircuitRef {
        let id = self.get_next_input_id();
        let r = self.gate(Circuit::Gate::make_input(id), modulus);
        self.circ.push_input_ref(r);
        r
    }

    /// Get a vec of CircuitRefs for inputs.
    pub fn inputs(&mut self, mods: &[u16]) -> Vec<CircuitRef> {
        mods.iter().map(|q| self.input(*q)).collect()
    }

    /// Get a CrtBundle using composite modulus `modulus`
    pub fn crt_input(&mut self, modulus: u128) -> CrtBundle<CircuitRef> {
        CrtBundle::new(self.inputs(&crate::util::factor(modulus)))
    }

    /// Get a BinaryBundle with `nbit` bits.
    pub fn bin_input(&mut self, nbits: usize) -> BinaryBundle<CircuitRef> {
        BinaryBundle::new(self.inputs(&vec![2; nbits]))
    }
}

impl<Circuit: CircuitType> Default for CircuitBuilder<Circuit> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod plaintext {
    use super::*;
    use crate::{FancyArithmetic, FancyBinary, FancyProj, util::RngExt};
    use itertools::Itertools;
    use rand::thread_rng;

    #[test] // {{{ and_gate_fan_n
    fn and_gate_fan_n() {
        let mut rng = thread_rng();
        let n = 2 + (rng.gen_usize() % 200);

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::<BinaryCircuit>::new();
            let inps = b.inputs(&vec![2; n]);
            let z = b.and_many(&inps, channel).unwrap();
            b.output(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        for _ in 0..16 {
            let mut inps: Vec<u16> = Vec::new();
            for _ in 0..n {
                inps.push(rng.gen_bool() as u16);
            }
            let res = inps.iter().fold(1, |acc, &x| x & acc);
            let out = eval_plain(&c, &inps).unwrap()[0];
            if out != res {
                println!("{:?} {} {}", inps, out, res);
                panic!("incorrect output n={}", n);
            }
        }
    }
    //}}}
    #[test] // {{{ or_gate_fan_n
    fn or_gate_fan_n() {
        let mut rng = thread_rng();
        let n = 2 + (rng.gen_usize() % 200);
        let c = Channel::with(std::io::empty(), |channel| {
            let mut b: CircuitBuilder<BinaryCircuit> = CircuitBuilder::new();
            let inps = b.inputs(&vec![2; n]);
            let z = b.or_many(&inps, channel).unwrap();
            b.output(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        for _ in 0..16 {
            let mut inps: Vec<u16> = Vec::new();
            for _ in 0..n {
                inps.push(rng.gen_bool() as u16);
            }
            let res = inps.iter().fold(0, |acc, &x| x | acc);
            let out = eval_plain(&c, &inps).unwrap()[0];
            if out != res {
                println!("{:?} {} {}", inps, out, res);
                panic!();
            }
        }
    }

    #[test] // {{{ or_gate_fan_n_arithmetic
    fn or_gate_fan_n_arithmetic() {
        let mut rng = thread_rng();
        let n = 2 + (rng.gen_usize() % 200);

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b: CircuitBuilder<ArithmeticCircuit> = CircuitBuilder::new();
            let inps = b.inputs(&vec![2; n]);
            let z = b.or_many(&inps, channel).unwrap();
            b.output(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        for _ in 0..16 {
            let mut inps: Vec<u16> = Vec::new();
            for _ in 0..n {
                inps.push(rng.gen_bool() as u16);
            }
            let res = inps.iter().fold(0, |acc, &x| x | acc);
            let out = eval_plain(&c, &inps).unwrap()[0];
            if out != res {
                println!("{:?} {} {}", inps, out, res);
                panic!();
            }
        }
    }
    //}}}
    #[test] // {{{ half_gate
    fn binary_half_gate() {
        let mut rng = thread_rng();
        let q = 2;

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::<BinaryCircuit>::new();
            let x = b.input(q);
            let y = b.input(q);
            let z = b.and(&x, &y, channel).unwrap();
            b.output(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();
        for _ in 0..16 {
            let x = rng.gen_u16() % q;
            let y = rng.gen_u16() % q;
            let out = eval_plain(&c, &[x, y]).unwrap();
            assert_eq!(out[0], x * y % q);
        }
    }
    #[test] // {{{ half_gate
    fn arithmetic_half_gate() {
        let mut rng = thread_rng();
        let q = rng.gen_prime();

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let x = b.input(q);
            let y = b.input(q);
            let z = b.mul(&x, &y, channel).unwrap();
            b.output(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();
        for _ in 0..16 {
            let x = rng.gen_u16() % q;
            let y = rng.gen_u16() % q;
            let out = eval_plain(&c, &[x, y]).unwrap();
            assert_eq!(out[0], x * y % q);
        }
    }
    //}}}
    #[test] // mod_change {{{
    fn mod_change() {
        let mut rng = thread_rng();
        let p = rng.gen_prime();
        let q = rng.gen_prime();

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let x = b.input(p);
            let y = b.mod_change(&x, q, channel).unwrap();
            let z = b.mod_change(&y, p, channel).unwrap();
            b.output(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();
        for _ in 0..16 {
            let x = rng.gen_u16() % p;
            let out = eval_plain(&c, &[x]).unwrap();
            assert_eq!(out[0], x % q);
        }
    }
    //}}}
    #[test] // add_many_mod_change {{{
    fn add_many_mod_change() {
        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let n = 113;
            let args = b.inputs(&vec![2; n]);
            let wires = args
                .iter()
                .map(|x| b.mod_change(x, n as u16 + 1, channel).unwrap())
                .collect_vec();
            let s = b.add_many(&wires);
            b.output(&s, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        let mut rng = thread_rng();
        for _ in 0..64 {
            let inps = (0..c.num_inputs())
                .map(|i| rng.gen_u16() % c.input_mod(i))
                .collect_vec();
            let s: u16 = inps.iter().sum();
            println!("{:?}, sum={}", inps, s);
            let out = eval_plain(&c, &inps).unwrap();
            assert_eq!(out[0], s);
        }
    }
    // }}}
    #[test] // constants {{{
    fn constants() {
        let mut rng = thread_rng();
        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let circ = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();

            let x = b.input(q);
            let y = b.constant(c, q, channel).unwrap();
            let z = b.add(&x, &y);
            b.output(&z, channel).unwrap();

            let circ = b.finish();
            Ok(circ)
        })
        .unwrap();

        for _ in 0..64 {
            let x = rng.gen_u16() % q;
            let z = eval_plain(&circ, &[x]).unwrap();
            assert_eq!(z[0], (x + c) % q);
        }
    }
    //}}}
}

#[cfg(test)]
mod bundle {
    use super::*;
    use crate::{
        ArithmeticProjBundleGadgets, CrtProjGadgets,
        fancy::{ArithmeticBundleGadgets, BinaryGadgets, BundleGadgets, CrtGadgets},
        util::{self, RngExt, crt_factor, crt_inv_factor},
    };
    use itertools::Itertools;
    use rand::thread_rng;

    #[test] // bundle input and output {{{
    fn test_bundle_input_output() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let x = b.crt_input(q);
            println!("{:?} wires", x.wires().len());
            b.output_bundle(&x, channel).unwrap();
            let c: ArithmeticCircuit = b.finish();
            Ok(c)
        })
        .unwrap();

        println!("{:?}", c.output_refs);

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let res = eval_plain(&c, &crt_factor(x, q)).unwrap();
            println!("{:?}", res);
            let z = crt_inv_factor(&res, q);
            assert_eq!(x, z);
        }
    }

    //}}}
    #[test] // bundle addition {{{
    fn test_addition() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let x = b.crt_input(q);
            let y = b.crt_input(q);
            let z = b.crt_add(&x, &y);
            b.output_bundle(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut inputs = crt_factor(x, q);
            inputs.extend(crt_factor(y, q));
            let res = eval_plain(&c, &inputs).unwrap();
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, (x + y) % q);
        }
    }
    //}}}
    #[test] // bundle subtraction {{{
    fn test_subtraction() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let x = b.crt_input(q);
            let y = b.crt_input(q);
            let z = b.sub_bundles(&x, &y);
            b.output_bundle(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut inputs = crt_factor(x, q);
            inputs.extend(crt_factor(y, q));
            let res = eval_plain(&c, &inputs).unwrap();
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, (x + q - y) % q);
        }
    }
    //}}}
    #[test] // bundle cmul {{{
    fn test_cmul() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(16);
        let y = rng.gen_u128() % q;

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let x = b.crt_input(q);
            let z = b.crt_cmul(&x, y);
            b.output_bundle(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        for _ in 0..16 {
            let x = rng.gen_u128() % q;
            let res = eval_plain(&c, &crt_factor(x, q)).unwrap();
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, (x * y) % q);
        }
    }
    //}}}
    #[test] // bundle multiplication {{{
    fn test_multiplication() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let x = b.crt_input(q);
            let y = b.crt_input(q);
            let z = b.mul_bundles(&x, &y, channel).unwrap();
            b.output_bundle(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        for _ in 0..16 {
            let x = rng.gen_u64() as u128 % q;
            let y = rng.gen_u64() as u128 % q;
            let mut inputs = crt_factor(x, q);
            inputs.extend(crt_factor(y, q));

            let res = eval_plain(&c, &inputs).unwrap();
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, (x * y) % q);
        }
    }
    // }}}
    #[test] // bundle cexp {{{
    fn test_cexp() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        let y = rng.gen_u16() % 10;

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let x = b.crt_input(q);
            let z = b.crt_cexp(&x, y, channel).unwrap();
            b.output_bundle(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        for _ in 0..64 {
            let x = rng.gen_u16() as u128 % q;
            let should_be = x.pow(y as u32) % q;
            let res = eval_plain(&c, &crt_factor(x, q)).unwrap();
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, should_be);
        }
    }
    // }}}
    #[test] // bundle remainder {{{
    fn test_remainder() {
        let mut rng = thread_rng();
        let ps = rng.gen_usable_factors();
        let q = ps.iter().fold(1, |acc, &x| (x as u128) * acc);
        let p = ps[rng.gen_u16() as usize % ps.len()];

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let x = b.crt_input(q);
            let z = b.crt_rem(&x, p, channel).unwrap();
            b.output_bundle(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        for _ in 0..64 {
            let x = rng.gen_u128() % q;
            let should_be = x % p as u128;
            let res = eval_plain(&c, &crt_factor(x, q)).unwrap();
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // bundle equality {{{
    fn test_equality() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let x = b.crt_input(q);
            let y = b.crt_input(q);
            let z = b.eq_bundles(&x, &y, channel).unwrap();
            b.output(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        // lets have at least one test where they are surely equal
        let x = rng.gen_u128() % q;
        let mut inputs = crt_factor(x, q);
        inputs.extend(crt_factor(x, q));
        let res = eval_plain(&c, &inputs).unwrap();
        assert_eq!(res, &[(x == x) as u16]);

        for _ in 0..64 {
            let x = rng.gen_u128() % q;
            let y = rng.gen_u128() % q;
            let mut inputs = crt_factor(x, q);
            inputs.extend(crt_factor(y, q));
            let res = eval_plain(&c, &inputs).unwrap();
            assert_eq!(res, &[(x == y) as u16]);
        }
    }
    //}}}
    #[test] // bundle mixed_radix_addition {{{
    fn test_mixed_radix_addition() {
        let mut rng = thread_rng();

        let nargs = 2 + rng.gen_usize() % 100;
        let mods = (0..7).map(|_| rng.gen_modulus()).collect_vec();

        let circ = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let xs = (0..nargs)
                .map(|_| crate::fancy::Bundle::new(b.inputs(&mods)))
                .collect_vec();
            let z = b.mixed_radix_addition(&xs, channel).unwrap();
            b.output_bundle(&z, channel).unwrap();
            let circ = b.finish();
            Ok(circ)
        })
        .unwrap();

        let Q: u128 = mods.iter().map(|&q| q as u128).product();

        // test maximum overflow
        let mut ds = Vec::new();
        for _ in 0..nargs {
            ds.extend(util::as_mixed_radix(Q - 1, &mods).iter());
        }
        let res = eval_plain(&circ, &ds).unwrap();
        assert_eq!(
            util::from_mixed_radix(&res, &mods),
            (Q - 1) * (nargs as u128) % Q
        );

        // test random values
        for _ in 0..4 {
            let mut should_be = 0;
            let mut ds = Vec::new();
            for _ in 0..nargs {
                let x = rng.gen_u128() % Q;
                should_be = (should_be + x) % Q;
                ds.extend(util::as_mixed_radix(x, &mods).iter());
            }
            let res = eval_plain(&circ, &ds).unwrap();
            assert_eq!(util::from_mixed_radix(&res, &mods), should_be);
        }
    }
    //}}}
    #[test] // bundle relu {{{
    fn test_relu() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        println!("q={}", q);

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let x = b.crt_input(q);
            let z = b.crt_relu(&x, "100%", None, channel).unwrap();
            b.output_bundle(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        for _ in 0..128 {
            let pt = rng.gen_u128() % q;
            let should_be = if pt < q / 2 { pt } else { 0 };
            let res = eval_plain(&c, &crt_factor(pt, q)).unwrap();
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // bundle sgn {{{
    fn test_sgn() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        println!("q={}", q);

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let x = b.crt_input(q);
            let z = b.crt_sgn(&x, "100%", None, channel).unwrap();
            b.output_bundle(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        for _ in 0..128 {
            let pt = rng.gen_u128() % q;
            let should_be = if pt < q / 2 { 1 } else { q - 1 };
            let res = eval_plain(&c, &crt_factor(pt, q)).unwrap();
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // bundle leq {{{
    fn test_leq() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let x = b.crt_input(q);
            let y = b.crt_input(q);
            let z = b.crt_lt(&x, &y, "100%", channel).unwrap();
            b.output(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        // lets have at least one test where they are surely equal
        let x = rng.gen_u128() % q / 2;
        let mut inputs = crt_factor(x, q);
        inputs.extend(crt_factor(x, q));
        let res = eval_plain(&c, &inputs).unwrap();
        assert_eq!(res, &[(x < x) as u16], "x={}", x);

        for _ in 0..64 {
            let x = rng.gen_u128() % q / 2;
            let y = rng.gen_u128() % q / 2;
            let mut inputs = crt_factor(x, q);
            inputs.extend(crt_factor(y, q));
            let res = eval_plain(&c, &inputs).unwrap();
            assert_eq!(res, &[(x < y) as u16], "x={} y={}", x, y);
        }
    }
    //}}}
    #[test] // bundle max {{{
    fn test_max() {
        let mut rng = thread_rng();
        let q = util::modulus_with_width(10);
        let n = 10;
        println!("n={} q={}", n, q);

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let xs = (0..n).map(|_| b.crt_input(q)).collect_vec();
            let z = b.crt_max(&xs, "100%", channel).unwrap();
            b.output_bundle(&z, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        for _ in 0..16 {
            let inps = (0..n).map(|_| rng.gen_u128() % (q / 2)).collect_vec();
            println!("{:?}", inps);
            let should_be = *inps.iter().max().unwrap();

            let enc_inps = inps
                .into_iter()
                .flat_map(|x| crt_factor(x, q))
                .collect_vec();
            let res = eval_plain(&c, &enc_inps).unwrap();
            let z = crt_inv_factor(&res, q);
            assert_eq!(z, should_be);
        }
    }
    //}}}
    #[test] // binary addition {{{
    fn test_binary_addition() {
        let mut rng = thread_rng();
        let n = 2 + (rng.gen_usize() % 10);
        let q = 2;
        let Q = util::product(&vec![q; n]);
        println!("n={} q={} Q={}", n, q, Q);

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::<BinaryCircuit>::new();
            let x = b.bin_input(n);
            let y = b.bin_input(n);
            let (zs, carry) = b.bin_addition(&x, &y, channel).unwrap();
            b.output(&carry, channel).unwrap();
            b.output_bundle(&zs, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        for _ in 0..16 {
            let x = rng.gen_u128() % Q;
            let y = rng.gen_u128() % Q;
            println!("x={} y={}", x, y);
            let res_should_be = (x + y) % Q;
            let carry_should_be = (x + y >= Q) as u16;
            let mut inputs = util::u128_to_bits(x, n);
            inputs.extend(util::u128_to_bits(y, n));
            let res = eval_plain(&c, &inputs).unwrap();
            assert_eq!(util::u128_from_bits(&res[1..]), res_should_be);
            assert_eq!(res[0], carry_should_be);
        }
    }
    //}}}
    #[test] // binary demux {{{
    fn test_bin_demux() {
        let mut rng = thread_rng();
        let nbits = 1 + (rng.gen_usize() % 7);
        let Q = 1 << nbits as u128;

        let c = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::<BinaryCircuit>::new();
            let x = b.bin_input(nbits);
            let d = b.bin_demux(&x, channel).unwrap();
            b.outputs(&d, channel).unwrap();
            let c = b.finish();
            Ok(c)
        })
        .unwrap();

        for _ in 0..16 {
            let x = rng.gen_u128() % Q;
            println!("x={}", x);
            let mut should_be = vec![0; Q as usize];
            should_be[x as usize] = 1;

            let res = eval_plain(&c, &util::u128_to_bits(x, nbits)).unwrap();

            for (i, y) in res.into_iter().enumerate() {
                if i as u128 == x {
                    assert_eq!(y, 1);
                } else {
                    assert_eq!(y, 0);
                }
            }
        }
    }
    //}}}
}
