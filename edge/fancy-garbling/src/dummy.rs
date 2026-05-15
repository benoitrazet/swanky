//! Dummy implementation of `Fancy`.
//!
//! Useful for evaluating the circuits produced by `Fancy` without actually
//! creating any circuits.

use swanky_channel::Channel;
use swanky_error::ErrorKind;

use crate::{
    FancyArithmetic, FancyBinary, FancyProj, check_binary,
    circuit::{CircuitExecutor, Flatten},
    fancy::{Fancy, HasModulus},
};

/// Simple struct that performs the fancy computation over `u16`.
pub struct Dummy;

/// Wrapper around `u16`.
#[derive(Clone, Debug)]
pub struct DummyVal {
    val: u16,
    modulus: u16,
}

impl HasModulus for DummyVal {
    fn modulus(&self) -> u16 {
        self.modulus
    }
}

impl DummyVal {
    /// Create a new DummyVal.
    pub fn new(val: u16, modulus: u16) -> Self {
        Self { val, modulus }
    }

    /// Extract the value.
    pub fn val(&self) -> u16 {
        self.val
    }
}

impl Dummy {
    /// Create a new Dummy.
    pub fn new() -> Dummy {
        Dummy {}
    }

    /// Evaluate `circuit` in plaintext.
    ///
    /// # Panics
    /// Panics if `inputs.len()` does not equal the circuit's expected number of
    /// inputs.
    pub fn eval<C: CircuitExecutor<Dummy>>(
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
            circuit.execute(&mut dummy, &circuit.map(&inputs), c)
        })?;
        let outputs = outputs.flatten();
        Ok(outputs.iter().map(|x| x.val()).collect())
    }
}

impl Default for Dummy {
    fn default() -> Self {
        Self::new()
    }
}

impl FancyBinary for Dummy {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        check_binary!(x);
        check_binary!(y);

        self.add(x, y)
    }

    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        check_binary!(x);
        check_binary!(y);

        self.mul(x, y, channel)
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        check_binary!(x);

        self.xor(x, &DummyVal::new(1, 2))
    }
}

impl FancyArithmetic for Dummy {
    fn add(&mut self, x: &DummyVal, y: &DummyVal) -> DummyVal {
        assert_eq!(x.modulus(), y.modulus());
        DummyVal {
            val: (x.val + y.val) % x.modulus,
            modulus: x.modulus,
        }
    }

    fn sub(&mut self, x: &DummyVal, y: &DummyVal) -> DummyVal {
        assert_eq!(x.modulus(), y.modulus());
        DummyVal {
            val: (x.modulus + x.val - y.val) % x.modulus,
            modulus: x.modulus,
        }
    }

    fn cmul(&mut self, x: &DummyVal, c: u16) -> DummyVal {
        DummyVal {
            val: (x.val * c) % x.modulus,
            modulus: x.modulus,
        }
    }

    fn mul(
        &mut self,
        x: &DummyVal,
        y: &DummyVal,
        _channel: &mut Channel,
    ) -> swanky_error::Result<DummyVal> {
        if x.modulus < y.modulus {
            return self.mul(y, x, _channel);
        }
        Ok(DummyVal {
            val: x.val * y.val % x.modulus,
            modulus: x.modulus,
        })
    }
}

impl FancyProj for Dummy {
    fn proj(
        &mut self,
        x: &DummyVal,
        modulus: u16,
        tt: Option<Vec<u16>>,
        _: &mut Channel,
    ) -> swanky_error::Result<DummyVal> {
        assert!(tt.is_some(), "`tt` must not be `None`");
        let tt = tt.unwrap();
        assert!(
            tt.len() >= x.modulus() as usize,
            "`tt` not large enough for `x`s modulus"
        );
        assert!(
            tt.iter().all(|&x| x < modulus),
            "`tt` value larger than `q`"
        );
        let val = tt[x.val as usize];
        Ok(DummyVal { val, modulus })
    }
}

impl Fancy for Dummy {
    type Item = DummyVal;

    /// Encode a single dummy value.
    fn encode(
        &mut self,
        value: u16,
        modulus: u16,
        _: &mut Channel,
    ) -> swanky_error::Result<DummyVal> {
        Ok(DummyVal::new(value, modulus))
    }

    /// Encode a slice of inputs and a slice of moduli as DummyVals.
    fn encode_many(
        &mut self,
        xs: &[u16],
        moduli: &[u16],
        _: &mut Channel,
    ) -> swanky_error::Result<Vec<DummyVal>> {
        assert_eq!(xs.len(), moduli.len());
        Ok(xs
            .iter()
            .zip(moduli.iter())
            .map(|(x, q)| DummyVal::new(*x, *q))
            .collect())
    }

    fn receive_many(
        &mut self,
        _moduli: &[u16],
        _: &mut Channel,
    ) -> swanky_error::Result<Vec<DummyVal>> {
        // Receive is undefined for Dummy which is a single party "protocol"
        swanky_error::bail!(
            ErrorKind::UnsupportedError,
            "`receive_many` is undefined for `Dummy`"
        );
    }

    fn constant(
        &mut self,
        val: u16,
        modulus: u16,
        _: &mut Channel,
    ) -> swanky_error::Result<DummyVal> {
        Ok(DummyVal { val, modulus })
    }

    fn output(&mut self, x: &DummyVal, _: &mut Channel) -> swanky_error::Result<Option<u16>> {
        Ok(Some(x.val))
    }
}
