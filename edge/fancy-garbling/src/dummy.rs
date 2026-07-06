//! Dummy implementation of `Fancy`.
//!
//! Useful for evaluating the circuits produced by `Fancy` without actually
//! creating any circuits.

use rand::{CryptoRng, Rng, RngCore};
use swanky_channel::Channel;
use swanky_error::{ErrorKind, Result};

use crate::{
    BinaryBundle, BinaryGadgets, Bundle, CrtBundle, CrtGadgets,
    util::{as_mixed_radix, crt_inv_factor, u128_from_bits},
};
use fancy_traits::{
    Circuit, Fancy, FancyArithmetic, FancyBinary, FancyEncode, FancyOutput, FancyProj, HasModulus,
    is_binary,
};

/// Simple struct that performs the fancy computation over `u16`.
pub struct Dummy;

/// Wrapper around `u16`.
#[derive(Clone, Copy, Debug, PartialEq)]
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
    /// Create a new [`DummyVal`].
    pub fn new(val: u16, modulus: u16) -> Self {
        Self {
            val: val % modulus,
            modulus,
        }
    }

    /// Create a new boolean [`DummyVal`].
    pub fn new_bool(val: bool) -> Self {
        Self {
            val: val as u16,
            modulus: 2,
        }
    }

    /// Extract the value.
    pub fn val(&self) -> u16 {
        self.val
    }

    /// Generate a random boolean [`DummyVal`].
    pub fn rand_bool<RNG: CryptoRng + RngCore>(rng: &mut RNG) -> Self {
        Self::rand(2, rng)
    }

    /// Generate a random [`DummyVal`].
    pub fn rand<RNG: CryptoRng + RngCore>(modulus: u16, rng: &mut RNG) -> Self {
        Self::new(rng.r#gen::<u16>(), modulus)
    }

    /// Generate a new [`CrtBundle`] of `value % modulus`.
    pub fn to_crt(value: u128, modulus: u128) -> CrtBundle<Self> {
        let mut dummy = Dummy::new();
        Channel::with(std::io::empty(), |channel| {
            dummy.crt_encode(value, modulus, channel)
        })
        .unwrap()
    }

    /// Convert a [`Bundle`] representing a CRT value into its underlying
    /// `u128`.
    pub fn from_crt(crt: &Bundle<Self>, modulus: u128) -> u128 {
        let crt = crt.wires().iter().map(|w| w.val()).collect::<Vec<_>>();
        crt_inv_factor(&crt, modulus)
    }

    /// Generate a new [`BinaryBundle`] of `value`.
    pub fn to_binary(value: u128, nbits: usize) -> BinaryBundle<Self> {
        let mut dummy = Dummy::new();
        Channel::with(std::io::empty(), |channel| {
            dummy.bin_encode(value, nbits, channel)
        })
        .unwrap()
    }

    /// Convert a [`Bundle`] representing a binary value into its underlying
    /// `u128`.
    pub fn from_binary(bin: &Bundle<Self>) -> u128 {
        let bin = bin.wires().iter().map(|w| w.val()).collect::<Vec<_>>();
        u128_from_bits(&bin)
    }

    /// Generate a new mixed radix form [`Bundle`] for `value` using the
    /// provided `radii`.
    pub fn to_mixed_radix(value: u128, radii: &[u16]) -> CrtBundle<Self> {
        let mixed = as_mixed_radix(value, radii);
        let mixed = mixed
            .into_iter()
            .zip(radii)
            .map(|(x, q)| DummyVal::new(x, *q))
            .collect::<Vec<_>>();
        CrtBundle::new(mixed)
    }

    /// Convert a [`Bundle`] representing mixed radix form into its underlying
    /// `u128`.
    pub fn from_mixed_radix(bundle: &CrtBundle<Self>) -> u128 {
        let mut x: u128 = 0;
        for wire in bundle.wires().iter().rev() {
            let (xp, overflow) = x.overflowing_mul(wire.modulus as u128);
            assert!(!overflow);
            x = xp + wire.val as u128;
        }
        x
    }
}

impl Dummy {
    /// Create a new Dummy.
    pub fn new() -> Dummy {
        Dummy {}
    }

    /// Evaluate `circuit` in plaintext.
    pub fn eval<C: Circuit<Dummy>>(circuit: &C, inputs: C::Input) -> Result<C::Output> {
        let mut dummy = Dummy::new();
        Channel::with(std::io::empty(), |c| circuit.execute(&mut dummy, inputs, c))
    }
}

impl Default for Dummy {
    fn default() -> Self {
        Self::new()
    }
}

impl FancyBinary for Dummy {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        is_binary!(x);
        is_binary!(y);

        self.add(x, y)
    }

    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        is_binary!(x);
        is_binary!(y);

        self.mul(x, y, channel)
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        is_binary!(x);

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

    fn constant(
        &mut self,
        val: u16,
        modulus: u16,
        _: &mut Channel,
    ) -> swanky_error::Result<DummyVal> {
        Ok(DummyVal { val, modulus })
    }
}

impl FancyEncode for Dummy {
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
}

impl FancyOutput for Dummy {
    fn output(&mut self, x: &DummyVal, _: &mut Channel) -> swanky_error::Result<Option<u16>> {
        Ok(Some(x.val))
    }
}
