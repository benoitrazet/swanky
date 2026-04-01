//! The `Fancy` trait represents the kinds of computations possible in `fancy-garbling`.
//!
//! An implementer must be able to create inputs, constants, do modular arithmetic, and
//! create projections.

use itertools::Itertools;
use swanky_channel::Channel;

mod binary;
mod bundle;
mod crt;
mod input;
pub use binary::{BinaryBundle, BinaryGadgets};
pub use bundle::{ArithmeticBundleGadgets, BinaryBundleGadgets, Bundle, BundleGadgets};
pub use crt::{CrtBundle, CrtGadgets};
pub use input::FancyInput;

/// An object that has some modulus. Basic object of `Fancy` computations.
pub trait HasModulus {
    /// The modulus of the wire.
    fn modulus(&self) -> u16;
}

/// DSL for the basic computations supported by `fancy-garbling`.
///
/// Primarily used as a supertrait for `FancyBinary` and `FancyArithmetic`,
/// which indicate computation supported by the DSL.
pub trait Fancy {
    /// The underlying wire datatype created by an object implementing `Fancy`.
    type Item: Clone + HasModulus;

    /// Create a constant `x` with modulus `q`.
    fn constant(
        &mut self,
        x: u16,
        q: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item>;

    /// Process this wire as output. Some `Fancy` implementers don't actually *return*
    /// output, but they need to be involved in the process, so they can return `None`.
    fn output(
        &mut self,
        x: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<u16>>;

    /// Output a slice of wires.
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
}

/// Fancy DSL providing binary operations
///
pub trait FancyBinary: Fancy {
    /// Binary Xor
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item;

    /// Binary And
    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item>;

    /// Binary Not
    fn negate(&mut self, x: &Self::Item) -> Self::Item;

    /// Uses Demorgan's Rule implemented with an and gate and negation.
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
    /// Returns 1 if all wires equal 1.
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

    /// Returns 1 if any wire equals 1.
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

    /// XOR many wires together.
    ///
    /// # Panics
    /// Panics if `args.len() < 2`.
    fn xor_many(&mut self, args: &[Self::Item]) -> Self::Item {
        assert!(args.len() >= 2, "`args.len()` must be two or more");
        args.iter()
            .skip(1)
            .fold(args[0].clone(), |acc, x| self.xor(&acc, x))
    }

    /// If `x = 0` returns the constant `b1` else return `b2`. Folds constants if possible.
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

    /// If `b = 0` returns `x` else `y`.
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

/// DSL for arithmetic computation.
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

    /// Multiply `x` times the constant `c`.
    fn cmul(&mut self, x: &Self::Item, c: u16) -> Self::Item;

    /// Multiply `x` and `y`.
    fn mul(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item>;

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

    ////////////////////////////////////////////////////////////////////////////////
    // Functions built on top of arithmetic fancy operations.

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
