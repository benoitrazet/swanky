//! Traits for representing specific kinds of garbled circuit computations.
//!
//! The core trait of this module is [`Fancy`], which represents the basic set
//! of operations possible by a garbled circuit. There are also extension
//! traits, in particular [`FancyBinary`] and [`FancyArithmetic`] that further
//! extend the core [`Fancy`] trait to provide binary and arithmetic operations,
//! respectively.

use swanky_channel::Channel;
use swanky_error::Result;

mod binary;
mod bundle;
mod crt;
pub use binary::{BinaryBundle, BinaryGadgets};
pub use bundle::Bundle;
pub use crt::{CrtBundle, CrtGadgets};

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
///
/// This trait can be further extended to support binary, arithmetic, and/or
/// projections by using the [`FancyBinary`], [`FancyArithmetic`], or
/// [`FancyProj`] extension traits, respectively.
pub trait Fancy {
    /// The underlying wirelabel representation of this [`Fancy`] object.
    type Item: Clone + core::fmt::Debug + HasModulus;

    /// Encode many wirelabels for known values.
    ///
    /// When writing a garbler, the return value must correspond to the zero
    /// wire label.
    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> Result<Vec<Self::Item>>;

    /// Receive many wirelabels for unknown values.
    fn receive_many(&mut self, moduli: &[u16], channel: &mut Channel) -> Result<Vec<Self::Item>>;

    /// Encode a constant `x` with modulus `q`.
    fn constant(&mut self, x: u16, q: u16, channel: &mut Channel) -> Result<Self::Item>;

    /// Output the value associated with wirelabel `x`.
    ///
    /// Some [`Fancy`] implementers don't actually *return* output, but they
    /// need to be involved in the process, so they can return `None`.
    fn output(&mut self, x: &Self::Item, channel: &mut Channel) -> Result<Option<u16>>;

    /// Output the values associated with a slice of wirelabels.
    ///
    /// Some [`Fancy`] implementers don't actually *return* output, but they
    /// need to be involved in the process, so they can return `None`.
    fn outputs(&mut self, xs: &[Self::Item], channel: &mut Channel) -> Result<Option<Vec<u16>>> {
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
    fn encode(&mut self, value: u16, modulus: u16, channel: &mut Channel) -> Result<Self::Item> {
        let mut xs = self.encode_many(&[value], &[modulus], channel)?;
        Ok(xs.remove(0))
    }

    /// Receive a wirelabel for an unknown value.
    fn receive(&mut self, modulus: u16, channel: &mut Channel) -> Result<Self::Item> {
        let mut xs = self.receive_many(&[modulus], channel)?;
        Ok(xs.remove(0))
    }
}

/// Extension trait for [`Fancy`] that provides binary operations.
pub trait FancyBinary: Fancy {
    /// Binary XOR.
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item;

    /// Binary AND.
    fn and(&mut self, x: &Self::Item, y: &Self::Item, channel: &mut Channel) -> Result<Self::Item>;

    /// Binary negation.
    fn negate(&mut self, x: &Self::Item) -> Self::Item;

    /// Binary OR.
    fn or(&mut self, x: &Self::Item, y: &Self::Item, channel: &mut Channel) -> Result<Self::Item> {
        let notx = self.negate(x);
        let noty = self.negate(y);
        let z = self.and(&notx, &noty, channel)?;
        Ok(self.negate(&z))
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
    fn mul(&mut self, x: &Self::Item, y: &Self::Item, channel: &mut Channel) -> Result<Self::Item>;
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
    ) -> Result<Self::Item>;

    /// Change the modulus of `x` to `to_modulus` using a projection gate.
    fn mod_change(
        &mut self,
        x: &Self::Item,
        to_modulus: u16,
        channel: &mut Channel,
    ) -> Result<Self::Item> {
        let from_modulus = x.modulus();
        if from_modulus == to_modulus {
            return Ok(x.clone());
        }
        let tab = (0..from_modulus)
            .map(|x| x % to_modulus)
            .collect::<Vec<_>>();
        self.proj(x, to_modulus, Some(tab), channel)
    }
}

macro_rules! check_binary {
    ($x:ident) => {
        assert_eq!($x.modulus(), 2);
    };
}

pub(crate) use check_binary;
