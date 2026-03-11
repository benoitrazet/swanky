//! Wirelabels for use in garbled circuits.
//!
//! This module contains a [`WireLabel`] trait, alongside various instantiations
//! of this trait. The [`WireLabel`] trait is the core underlying primitive used
//! in garbled circuits, and represents an encoding of the value on any given
//! wire of the circuit.

use crate::{fancy::HasModulus, util};
use rand::{CryptoRng, Rng, RngCore};
use swanky_aes_hash::TweakableCircularCorrelationRobustHash;
use swanky_block::Block;
use vectoreyes::array_utils::{ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize};

mod mod2;
pub use mod2::WireMod2;
mod mod3;
pub use mod3::WireMod3;
mod modq;
pub use modq::WireModQ;
mod npaths_tab;

/// Hash a batch of wires, using the same tweak for each wire.
pub fn hash_wires<const Q: usize, W: WireLabel>(wires: [&W; Q], tweak: u128) -> [Block; Q]
where
    ArrayUnrolledOps: UnrollableArraySize<Q>,
{
    let batch = wires.array_map(|x| x.to_block());
    TweakableCircularCorrelationRobustHash::fixed_key().hash_many(batch, tweak)
}

/// A marker trait indicating that the given [`WireLabel`] instantiation
/// supports arithmetic operations.
pub trait ArithmeticWire: Clone {}

/// A trait that defines a wirelabel as used in garbled circuits.
///
/// At its core, a [`WireLabel`] is a way of encoding values, and operating on
/// those encoded values.
pub trait WireLabel:
    Clone
    + HasModulus
    + core::ops::Add<Output = Self>
    + core::ops::AddAssign
    + core::ops::Sub<Output = Self>
    + core::ops::SubAssign
    + core::ops::Neg<Output = Self>
{
    /// The underlying digits encoded by the [`WireLabel`].
    fn digits(&self) -> Vec<u16>;

    /// Converts a [`WireLabel`] into its [`Block`] representation.
    fn to_block(&self) -> Block;

    /// The color digit of the wire.
    fn color(&self) -> u16;

    /// Multiplies the [`WireLabel`] by a constant `c mod q`.
    fn cmul_eq(&mut self, c: u16) -> &mut Self;

    /// Converts a [`Block`] into its [`WireLabel`] representation, based on the
    /// modulus `q`.
    ///
    /// # Panics
    /// This panics if `q` does not align with the modulus supported by the
    /// [`WireLabel`].
    fn from_block(inp: Block, q: u16) -> Self;

    /// The zero [`WireLabel`], based on the modulus `q`.
    ///
    /// # Panics
    /// This panics if `q` does not align with the modulus supported by the
    /// [`WireLabel`].
    // TODO: This is deceiving. It is _not_ a zero wirelabel as it is called in
    // the literature, but rather simply a zero _value_. This could lead to bugs
    // and should be changed!
    fn zero(q: u16) -> Self;

    /// A random [`WireLabel`] `mod q`, with the first digit set to `1`.
    ///
    /// # Panics
    /// This panics if `q` does not align with the modulus supported by the
    /// [`WireLabel`].
    fn rand_delta<R: CryptoRng + Rng>(rng: &mut R, q: u16) -> Self;

    /// A random [`WireLabel`] `mod q`.
    ///
    /// # Panics
    /// This panics if `q` does not align with the modulus supported by the
    /// [`WireLabel`].
    fn rand<R: CryptoRng + RngCore>(rng: &mut R, q: u16) -> Self;

    /// Converts a hashed block into a valid wire of the given modulus `q`.
    ///
    /// This is useful when separately using [`hash_wires`] to hash a set of
    /// wires in one shot for efficiency reasons.
    ///
    /// # Panics
    /// This panics if `q` does not align with the modulus supported by the
    /// [`WireLabel`].
    fn hash_to_mod(hash: Block, q: u16) -> Self;

    /// Computes the hash of this [`WireLabel`], converting the result back into
    /// a [`WireLabel`] based on the modulus `q`.
    ///
    /// This is equivalent to `WireLabel::hash_to_mod(self.hash(tweak), q)`, and
    /// is useful when stringing together a sequence of operations on a
    /// [`WireLabel`].
    ///
    /// # Panics
    /// This panics if `q` does not align with the modulus supported by the
    /// [`WireLabel`].
    fn hashback(&self, tweak: u128, q: u16) -> Self {
        let hash = self.hash(tweak);
        Self::hash_to_mod(hash, q)
    }

    /// Multiplies the [`WireLabel`] by a constant `c mod q`, consuming the
    /// input.
    fn cmul_mov(mut self, c: u16) -> Self {
        self.cmul_eq(c);
        self
    }

    /// Multiplies the [`WireLabel`] by a constant `c mod q`.
    fn cmul(&self, c: u16) -> Self {
        self.clone().cmul_mov(c)
    }

    /// Computes the hash of the [`WireLabel`].
    #[inline(never)]
    fn hash(&self, tweak: u128) -> Block {
        TweakableCircularCorrelationRobustHash::fixed_key().hash(self.to_block(), tweak)
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// A [`WireLabel`] that supports all possible moduli
pub enum AllWire {
    /// A `mod 2` [`WireLabel`].
    Mod2(WireMod2),
    /// A `mod 3` [`WireLabel`].
    Mod3(WireMod3),
    /// A `mod q` [`WireLabel`], where `3 < q < 2^16`.
    ModN(WireModQ),
}

impl HasModulus for AllWire {
    fn modulus(&self) -> u16 {
        match &self {
            AllWire::Mod2(x) => x.modulus(),
            AllWire::Mod3(x) => x.modulus(),
            AllWire::ModN(x) => x.modulus(),
        }
    }
}

impl core::ops::Add for AllWire {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let (p, q) = (self.modulus(), rhs.modulus());
        match (self, rhs) {
            (Self::Mod2(x), Self::Mod2(y)) => Self::Mod2(x + y),
            (Self::Mod3(x), Self::Mod3(y)) => Self::Mod3(x + y),
            (Self::ModN(x), Self::ModN(y)) => Self::ModN(x + y),
            _ => panic!("unequal moduli: {p} != {q}"),
        }
    }
}

impl core::ops::AddAssign for AllWire {
    fn add_assign(&mut self, rhs: Self) {
        let (p, q) = (self.modulus(), rhs.modulus());
        match (self, rhs) {
            (Self::Mod2(x), Self::Mod2(y)) => *x += y,
            (Self::Mod3(x), Self::Mod3(y)) => *x += y,
            (Self::ModN(x), Self::ModN(y)) => *x += y,
            _ => panic!("unequal moduli: {p} != {q}"),
        }
    }
}

impl core::ops::Sub for AllWire {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + -rhs
    }
}

impl core::ops::SubAssign for AllWire {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs;
    }
}

impl core::ops::Neg for AllWire {
    type Output = Self;

    fn neg(self) -> Self::Output {
        match self {
            Self::Mod2(x) => Self::Mod2(-x),
            Self::Mod3(x) => Self::Mod3(-x),
            Self::ModN(x) => Self::ModN(-x),
        }
    }
}

impl WireLabel for AllWire {
    fn rand_delta<R: CryptoRng + Rng>(rng: &mut R, q: u16) -> Self {
        match q {
            2 => AllWire::Mod2(WireMod2::rand_delta(rng, q)),
            3 => AllWire::Mod3(WireMod3::rand_delta(rng, q)),
            _ => AllWire::ModN(WireModQ::rand_delta(rng, q)),
        }
    }

    fn digits(&self) -> Vec<u16> {
        match &self {
            AllWire::Mod2(x) => x.digits(),
            AllWire::Mod3(x) => x.digits(),
            AllWire::ModN(x) => x.digits(),
        }
    }

    fn to_block(&self) -> Block {
        match &self {
            AllWire::Mod2(x) => x.to_block(),
            AllWire::Mod3(x) => x.to_block(),
            AllWire::ModN(x) => x.to_block(),
        }
    }
    fn color(&self) -> u16 {
        match &self {
            AllWire::Mod2(x) => x.color(),
            AllWire::Mod3(x) => x.color(),
            AllWire::ModN(x) => x.color(),
        }
    }
    fn cmul_eq(&mut self, c: u16) -> &mut Self {
        match &mut *self {
            AllWire::Mod2(x) => {
                x.cmul_eq(c);
            }
            AllWire::Mod3(x) => {
                x.cmul_eq(c);
            }
            AllWire::ModN(x) => {
                x.cmul_eq(c);
            }
        };
        self
    }
    fn from_block(inp: Block, q: u16) -> Self {
        match q {
            2 => AllWire::Mod2(WireMod2::from_block(inp, q)),
            3 => AllWire::Mod3(WireMod3::from_block(inp, q)),
            _ => AllWire::ModN(WireModQ::from_block(inp, q)),
        }
    }

    fn zero(q: u16) -> Self {
        match q {
            2 => AllWire::Mod2(WireMod2::zero(q)),
            3 => AllWire::Mod3(WireMod3::zero(q)),
            _ => AllWire::ModN(WireModQ::zero(q)),
        }
    }

    fn rand<R: CryptoRng + RngCore>(rng: &mut R, q: u16) -> Self {
        match q {
            2 => AllWire::Mod2(WireMod2::rand(rng, q)),
            3 => AllWire::Mod3(WireMod3::rand(rng, q)),
            _ => AllWire::ModN(WireModQ::rand(rng, q)),
        }
    }

    fn hash_to_mod(hash: Block, q: u16) -> Self {
        if q == 3 {
            AllWire::Mod3(WireMod3::encode_block_mod3(hash))
        } else {
            Self::from_block(hash, q)
        }
    }
}
fn _unrank(inp: u128, q: u16) -> Vec<u16> {
    let mut x = inp;
    let ndigits = util::digits_per_u128(q);
    let npaths_tab = npaths_tab::lookup(q);
    x %= npaths_tab[ndigits - 1] * q as u128;

    let mut ds = vec![0; ndigits];
    for i in (0..ndigits).rev() {
        let npaths = npaths_tab[i];

        if q <= 23 {
            // linear search
            let mut acc = 0;
            for j in 0..q {
                acc += npaths;
                if acc > x {
                    x -= acc - npaths;
                    ds[i] = j;
                    break;
                }
            }
        } else {
            // naive division
            let d = x / npaths;
            ds[i] = d as u16;
            x -= d * npaths;
        }
        // } else {
        //     // binary search
        //     let mut low = 0;
        //     let mut high = q;
        //     loop {
        //         let cur = (low + high) / 2;
        //         let l = npaths * cur as u128;
        //         let r = npaths * (cur as u128 + 1);
        //         if x >= l && x < r {
        //             x -= l;
        //             ds[i] = cur;
        //             break;
        //         }
        //         if x < l {
        //             high = cur;
        //         } else {
        //             // x >= r
        //             low = cur;
        //         }
        //     }
        // }
    }
    ds
}

impl ArithmeticWire for AllWire {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::RngExt;
    use itertools::Itertools;
    use rand::thread_rng;

    #[test]
    fn packing() {
        let rng = &mut thread_rng();
        for q in 2..256 {
            for _ in 0..1000 {
                let w = AllWire::rand(rng, q);
                assert_eq!(w, AllWire::from_block(w.to_block(), q));
            }
        }
    }

    #[test]
    fn base_conversion_lookup_method() {
        let rng = &mut thread_rng();
        for _ in 0..1000 {
            let q = 5 + (rng.gen_u16() % 110);
            let x = rng.gen_u128();
            let w = AllWire::from_block(Block::from(x), q);
            let should_be = util::as_base_q_u128(x, q);
            assert_eq!(w.digits(), should_be, "x={} q={}", x, q);
        }
    }

    #[test]
    fn hash() {
        let mut rng = thread_rng();
        for _ in 0..100 {
            let q = 2 + (rng.gen_u16() % 110);
            let x = AllWire::rand(&mut rng, q);
            let y = x.hashback(1u128, q);
            assert!(x != y);
            match y {
                AllWire::Mod2(WireMod2 { val }) => assert!(u128::from(val) > 0),
                AllWire::Mod3(WireMod3 { lsb, msb }) => assert!(lsb > 0 && msb > 0),
                AllWire::ModN(WireModQ { ds, .. }) => assert!(!ds.iter().all(|&y| y == 0)),
            }
        }
    }

    #[test]
    fn negation() {
        let rng = &mut thread_rng();
        for _ in 0..1000 {
            let q = rng.gen_modulus();
            let x = AllWire::rand(rng, q);
            let xneg = -x.clone();
            if q != 2 {
                assert!(x != xneg);
            }
            let y = -xneg;
            assert_eq!(x, y);
        }
    }

    #[test]
    fn zero() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let q = 3 + (rng.gen_u16() % 110);
            let z = AllWire::zero(q);
            let ds = z.digits();
            assert_eq!(ds, vec![0; ds.len()], "q={}", q);
        }
    }

    #[test]
    fn subzero() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let q = rng.gen_modulus();
            let x = AllWire::rand(&mut rng, q);
            let z = AllWire::zero(q);
            assert_eq!(x.clone() - x, z);
        }
    }

    #[test]
    fn pluszero() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let q = rng.gen_modulus();
            let x = AllWire::rand(&mut rng, q);
            assert_eq!(x.clone() + AllWire::zero(q), x);
        }
    }

    #[test]
    fn arithmetic() {
        let mut rng = thread_rng();
        for _ in 0..1024 {
            let q = rng.gen_modulus();
            let x = AllWire::rand(&mut rng, q);
            let y = AllWire::rand(&mut rng, q);
            assert_eq!(x.cmul(0), AllWire::zero(q));
            assert_eq!(x.cmul(q), AllWire::zero(q));
            assert_eq!(x.clone() + x.clone(), x.cmul(2));
            assert_eq!(x.clone() + x.clone() + x.clone(), x.cmul(3));
            assert_eq!(-(-x.clone()), x);
            if q == 2 {
                assert_eq!(x.clone() + y.clone(), x.clone() - y.clone());
            } else {
                assert_eq!(x.clone() + -x.clone(), AllWire::zero(q), "q={}", q);
                assert_eq!(x.clone() + -y.clone(), x.clone() - y.clone());
            }
            let mut w = x.clone();
            let z = w.clone() + y.clone();
            w = w + y;
            assert_eq!(w, z);

            w = x.clone();
            w.cmul_eq(2);
            assert_eq!(x.clone() + x.clone(), w);

            w = x.clone();
            w = -w;
            assert_eq!(-x, w);
        }
    }

    #[test]
    fn ndigits_correct() {
        let mut rng = thread_rng();
        for _ in 0..1024 {
            let q = rng.gen_modulus();
            let x = AllWire::rand(&mut rng, q);
            assert_eq!(x.digits().len(), util::digits_per_u128(q));
        }
    }

    #[test]
    fn parallel_hash() {
        let n = 1000;
        let mut rng = thread_rng();
        let q = rng.gen_modulus();
        let ws = (0..n).map(|_| AllWire::rand(&mut rng, q)).collect_vec();

        let mut handles = Vec::new();
        for w in ws.iter() {
            let w_ = w.clone();
            let h = std::thread::spawn(move || w_.hash(0u128));
            handles.push(h);
        }
        let hashes = handles.into_iter().map(|h| h.join().unwrap()).collect_vec();

        let should_be = ws.iter().map(|w| w.hash(0u128)).collect_vec();

        assert_eq!(hashes, should_be);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_allwire() {
        let mut rng = thread_rng();
        for q in 2..16 {
            let w = AllWire::rand(&mut rng, q);
            let serialized = serde_json::to_string(&w).unwrap();

            let deserialized: AllWire = serde_json::from_str(&serialized).unwrap();

            assert_eq!(w, deserialized);
        }
    }
}
