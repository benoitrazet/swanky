//! Traits for representing specific kinds of garbled circuit computations.
//!
//! The core trait of this module is [`Fancy`], which represents the basic set
//! of operations possible by a garbled circuit. There are also extension
//! traits, in particular [`FancyBinary`] and [`FancyArithmetic`] that further
//! extend the core [`Fancy`] trait to provide binary and arithmetic operations,
//! respectively.

use itertools::Itertools;
use swanky_channel::Channel;

mod binary;
mod bundle;
mod crt;
pub use binary::{BinaryBundle, BinaryGadgets};
pub use bundle::{
    ArithmeticBundleGadgets, ArithmeticProjBundleGadgets, BinaryBundleGadgets, Bundle,
    BundleGadgets,
};
pub use crt::{CrtBundle, CrtGadgets, CrtProjGadgets};

/// An object that has a modulus.
pub trait HasModulus {
    /// The modulus of the wire.
    fn modulus(&self) -> u16;
}

/// The `Fancy` trait provides the basic set of operations possible in a garbled
/// circuit.
///
/// The trait contains an associated type, [`Fancy::Item`], which defines the
/// underlying wirelabel representation. The trait then defines several methods
/// for:
/// 1. Encoding a value into a wirelabel ([`Fancy::encode`] and
///    [`Fancy::encode_many`]).
/// 2. Receiving a wirelabel for an unknown value ([`Fancy::receive`] and
///    [`Fancy::receive_many`]).
/// 3. Creating a wirelabel for a fixed (public) constant value
///    ([`Fancy::constant`]).
/// 4. Outputting a wirelabel as its underlying value ([`Fancy::output`] and
///    [`Fancy::outputs`]).
///
/// This trait can be further extended to support binary, arithmetic, and/or
/// projections by using the [`FancyBinary`], [`FancyArithmetic`], or
/// [`FancyProj`] extension traits, respectively.
pub trait Fancy {
    /// The underlying wirelabel representation of this [`Fancy`] object.
    type Item: Clone + HasModulus;

    /// Encode many wirelabels for known values.
    ///
    /// When writing a garbler, the return value must correspond to the zero
    /// wire label.
    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>>;

    /// Receive many wirelabels for unknown values.
    fn receive_many(
        &mut self,
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>>;

    /// Encode a constant `x` with modulus `q`.
    fn constant(
        &mut self,
        x: u16,
        q: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item>;

    /// Output the value associated with wirelabel `x`.
    ///
    /// Some [`Fancy`] implementers don't actually *return* output, but they
    /// need to be involved in the process, so they can return `None`.
    fn output(
        &mut self,
        x: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<u16>>;

    /// Output the values associated with a slice of wirelabels.
    ///
    /// Some [`Fancy`] implementers don't actually *return* output, but they
    /// need to be involved in the process, so they can return `None`.
    fn outputs(
        &mut self,
        xs: &[Self::Item],
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<Vec<u16>>> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            zs.push(self.output(x, channel)?);
        }
        Ok(zs.into_iter().collect())
    }

    /// Encode a wirelabel for a known value.
    ///
    /// When writing a garbler, the return value must correspond to the zero
    /// wire label.
    fn encode(
        &mut self,
        value: u16,
        modulus: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let mut xs = self.encode_many(&[value], &[modulus], channel)?;
        Ok(xs.remove(0))
    }

    /// Receive a wirelabel for an unknown value.
    fn receive(&mut self, modulus: u16, channel: &mut Channel) -> swanky_error::Result<Self::Item> {
        let mut xs = self.receive_many(&[modulus], channel)?;
        Ok(xs.remove(0))
    }
}

/// Extension trait for [`Fancy`] that provides binary operations.
pub trait FancyBinary: Fancy {
    /// Binary XOR.
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item;

    /// Binary AND.
    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item>;

    /// Binary negation.
    fn negate(&mut self, x: &Self::Item) -> Self::Item;

    /// Binary OR.
    fn or(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let notx = self.negate(x);
        let noty = self.negate(y);
        let z = self.and(&notx, &noty, channel)?;
        Ok(self.negate(&z))
    }

    /// Binary adder. Returns the result and the carry.
    fn adder(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        carry_in: Option<&Self::Item>,
        channel: &mut Channel,
    ) -> swanky_error::Result<(Self::Item, Self::Item)> {
        if let Some(c) = carry_in {
            let z1 = self.xor(x, y);
            let z2 = self.xor(&z1, c);
            let z3 = self.xor(x, c);
            let z4 = self.and(&z1, &z3, channel)?;
            let carry = self.xor(&z4, x);
            Ok((z2, carry))
        } else {
            let z = self.xor(x, y);
            let carry = self.and(x, y, channel)?;
            Ok((z, carry))
        }
    }
    /// Return 1 if all wirelabels equal 1.
    ///
    /// # Panics
    /// Panics if `args` is empty.
    fn and_many(
        &mut self,
        args: &[Self::Item],
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        assert!(!args.is_empty(), "`args` cannot be empty");
        args.iter()
            .skip(1)
            .try_fold(args[0].clone(), |acc, x| self.and(&acc, x, channel))
    }

    /// Return 1 if any wirelabel equals 1.
    ///
    /// # Panics
    /// Panics if `args` is empty.
    fn or_many(
        &mut self,
        args: &[Self::Item],
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        assert!(!args.is_empty(), "`args` cannot be empty");
        args.iter()
            .skip(1)
            .try_fold(args[0].clone(), |acc, x| self.or(&acc, x, channel))
    }

    /// XOR many wirelabels together.
    ///
    /// # Panics
    /// Panics if `args.len() < 2`.
    fn xor_many(&mut self, args: &[Self::Item]) -> Self::Item {
        assert!(args.len() >= 2, "`args.len()` must be two or more");
        args.iter()
            .skip(1)
            .fold(args[0].clone(), |acc, x| self.xor(&acc, x))
    }

    /// If `x = 0` return the constant `b1`, otherwise return `b2`.
    fn mux_constant_bits(
        &mut self,
        x: &Self::Item,
        b1: bool,
        b2: bool,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        match (b1, b2) {
            (false, true) => Ok(x.clone()),
            (true, false) => Ok(self.negate(x)),
            (false, false) => self.constant(0, 2, channel),
            (true, true) => self.constant(1, 2, channel),
        }
    }

    /// If `b = 0` return `x`, otherwise return `y`.
    fn mux(
        &mut self,
        b: &Self::Item,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let xor = self.xor(x, y);
        let and = self.and(b, &xor, channel)?;
        Ok(self.xor(&and, x))
    }
}

/// Extension trait for [`Fancy`] that provides arithmetic operations.
pub trait FancyArithmetic: Fancy {
    /// Add `x` and `y`.
    ///
    /// # Panics
    /// This panics if `x` and `y` do not have equal moduli.
    fn add(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item;

    /// Subtract `x` and `y`.
    ///
    /// # Panics
    /// This panics if `x` and `y` do not have equal moduli.
    fn sub(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item;

    /// Multiply `x` with the constant `c`.
    fn cmul(&mut self, x: &Self::Item, c: u16) -> Self::Item;

    /// Multiply `x` and `y`.
    fn mul(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item>;

    /// Sum up a slice of wires.
    ///
    /// # Panics
    /// Panics if `args.len() < 2`.
    fn add_many(&mut self, args: &[Self::Item]) -> Self::Item {
        assert!(args.len() >= 2, "`args.len()` must be two or more");
        let mut z = args[0].clone();
        for x in args.iter().skip(1) {
            z = self.add(&z, x);
        }
        z
    }
}

/// Extension trait for [`Fancy`] that provides a projection gate, alongside
/// methods that utilize projection gates.
///
/// # Security Warning
/// In its current form, using projection gates in arithmetic garbling is
/// **insecure**.
pub trait FancyProj: Fancy {
    /// Project `x` according to the truth table `tt`. Resulting wire has modulus `q`.
    ///
    /// Optional `tt` is useful for hiding the gate from the evaluator.
    ///
    /// # Panics
    /// This may panic in certain implementations if `tt` is `None` when it
    /// should be `Some`. In addition, it may panic if `tt` is improperly
    /// formed: either the length of `tt` is smaller than `x`s modulus, or the
    /// values in `tt` are larger than `q`.
    fn proj(
        &mut self,
        x: &Self::Item,
        q: u16,
        tt: Option<Vec<u16>>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item>;

    /// Change the modulus of `x` to `to_modulus` using a projection gate.
    fn mod_change(
        &mut self,
        x: &Self::Item,
        to_modulus: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let from_modulus = x.modulus();
        if from_modulus == to_modulus {
            return Ok(x.clone());
        }
        let tab = (0..from_modulus).map(|x| x % to_modulus).collect_vec();
        self.proj(x, to_modulus, Some(tab), channel)
    }
}

macro_rules! check_binary {
    ($x:ident) => {
        assert_eq!($x.modulus(), 2);
    };
}

pub(crate) use check_binary;
