use rand::{CryptoRng, Rng, RngCore};
use swanky_block::Block;

#[cfg(feature = "serde")]
use crate::errors::WireDeserializationError;
use crate::{ArithmeticWire, HasModulus, WireLabel, wire::_unrank};

/// Intermediate struct to deserialize WireMod3 to
///
/// Checks that both lsb and msb are not set before allowing to convert to WireMod3
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct UntrustedWireMod3 {
    /// The least-significant bits of each `mod-3` element.
    lsb: u64,
    /// The most-significant bits of each `mod-3` element.
    msb: u64,
}

#[cfg(feature = "serde")]
impl TryFrom<UntrustedWireMod3> for WireMod3 {
    type Error = WireDeserializationError;

    fn try_from(wire: UntrustedWireMod3) -> Result<Self, Self::Error> {
        if wire.lsb & wire.msb != 0 {
            return Err(Self::Error::InvalidWireMod3);
        }
        Ok(WireMod3 {
            lsb: wire.lsb,
            msb: wire.msb,
        })
    }
}

/// Representation of a `mod-3` wire.
///
/// We represent a `mod-3` wire by 64 `mod-3` elements. These elements are
/// stored as follows: the least-significant bits of each element are stored
/// in `lsb` and the most-significant bits of each element are stored in
/// `msb`. This representation allows for efficient addition and
/// multiplication as described here by the paper "Hardware Implementation
/// of Finite Fields of Characteristic Three." D. Page, N.P. Smart. CHES
/// 2002. Link:
/// <https://link.springer.com/content/pdf/10.1007/3-540-36400-5_38.pdf>.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "UntrustedWireMod3"))]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct WireMod3 {
    /// The least-significant bits of each `mod-3` element.
    pub(crate) lsb: u64,
    /// The most-significant bits of each `mod-3` element.
    pub(crate) msb: u64,
}

impl HasModulus for WireMod3 {
    fn modulus(&self) -> u16 {
        3
    }
}

impl core::ops::Add for WireMod3 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let a1 = self.lsb;
        let a2 = self.msb;
        let b1 = rhs.lsb;
        let b2 = rhs.msb;

        let t = (a1 | b2) ^ (a2 | b1);
        let c1 = (a2 | b2) ^ t;
        let c2 = (a1 | b1) ^ t;
        Self { lsb: c1, msb: c2 }
    }
}

impl core::ops::AddAssign for WireMod3 {
    fn add_assign(&mut self, rhs: Self) {
        let a1 = self.lsb;
        let a2 = self.msb;
        let b1 = rhs.lsb;
        let b2 = rhs.msb;

        let t = (a1 | b2) ^ (a2 | b1);
        self.lsb = (a2 | b2) ^ t;
        self.msb = (a1 | b1) ^ t;
    }
}

impl core::ops::Sub for WireMod3 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + -rhs
    }
}

impl core::ops::SubAssign for WireMod3 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl core::ops::Neg for WireMod3 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        // Negation just involves swapping `lsb` and `msb`.
        let mut output = self;
        std::mem::swap(&mut output.lsb, &mut output.msb);
        output
    }
}

impl WireMod3 {
    /// We have to convert `block` into a valid `Mod3` encoding.
    ///
    /// We do this by computing the `Mod3` digits using `_unrank`,
    /// and then map these to a `Mod3` encoding.
    pub(crate) fn encode_block_mod3(block: Block) -> Self {
        let mut lsb = 0u64;
        let mut msb = 0u64;
        let mut ds = _unrank(u128::from(block), 3);
        for (i, v) in ds.drain(..64).enumerate() {
            lsb |= ((v & 1) as u64) << i;
            msb |= (((v >> 1) & 1u16) as u64) << i;
        }
        debug_assert_eq!(lsb & msb, 0);
        Self { lsb, msb }
    }
}

impl WireLabel for WireMod3 {
    fn rand_delta<R: CryptoRng + RngCore>(rng: &mut R, q: u16) -> Self {
        if q != 3 {
            panic!("[WireMod3::rand_delta] Expected modulo 3. Got {}", q);
        }
        let mut w = Self::rand(rng, 3);
        w.lsb |= 1;
        w.msb &= 0xFFFF_FFFF_FFFF_FFFE;
        w
    }

    fn digits(&self) -> Vec<u16> {
        (0..64)
            .map(|i| (((self.lsb >> i) as u16) & 1) & ((((self.msb >> i) as u16) & 1) << 1))
            .collect()
    }

    fn to_block(&self) -> Block {
        // This function converts a [`WireMod3`] into its [`Block`] representation.
        // The two 64b values stored in [`WireMod3`], i.e. the lsb and msb, and packed
        // into a 128b value as a [`Block`].
        Block::from(((self.msb as u128) << 64) | (self.lsb as u128))
    }

    fn color(&self) -> u16 {
        let color = (((self.msb & 1) as u16) << 1) | ((self.lsb & 1) as u16);
        debug_assert_ne!(color, 3);
        color
    }

    fn cmul_eq(&mut self, c: u16) -> &mut Self {
        match c {
            0 => {
                self.msb = 0;
                self.lsb = 0;
            }
            1 => {}
            2 => {
                std::mem::swap(&mut self.lsb, &mut self.msb);
            }
            c => {
                self.cmul_eq(c % 3);
            }
        }
        self
    }

    fn from_block(inp: Block, q: u16) -> Self {
        if q != 3 {
            panic!("[WireMod3::from_block] Expected mod 3. Got mod {}", q)
        }
        // This function converts a Block into its WireLabel representation
        // by splitting the Block into two u64, its least significant bits and
        // its most significant bits.
        let inp = u128::from(inp);
        let lsb = inp as u64;
        let msb = (inp >> 64) as u64;
        debug_assert_eq!(lsb & msb, 0);
        Self { lsb, msb }
    }

    fn zero(q: u16) -> Self {
        if q != 3 {
            panic!("[WireMod3::zero] Expected modulo 3. Got {}", q);
        }
        Self::default()
    }

    fn rand<R: CryptoRng + RngCore>(rng: &mut R, q: u16) -> Self {
        if q != 3 {
            panic!("[WireMod3::rand] Expected mod 3. Got mod {}", q)
        }
        let mut lsb = 0u64;
        let mut msb = 0u64;
        for (i, v) in (0..64).map(|_| rng.r#gen::<u8>() % 3).enumerate() {
            lsb |= ((v & 1) as u64) << i;
            msb |= (((v >> 1) & 1) as u64) << i;
        }
        debug_assert_eq!(lsb & msb, 0);
        Self { lsb, msb }
    }

    fn hash_to_mod(hash: Block, q: u16) -> Self {
        if q != 3 {
            panic!("[WireMod3::hash_to_mod] Expected mod 3. Got mod {}", q)
        }
        Self::encode_block_mod3(hash)
    }
}

impl ArithmeticWire for WireMod3 {}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_good_mod3() {
        use crate::{WireLabel, WireMod3};
        use rand::thread_rng;

        let mut rng = thread_rng();
        let w = WireMod3::rand(&mut rng, 3);
        let serialized = serde_json::to_string(&w).unwrap();

        let deserialized: WireMod3 = serde_json::from_str(&serialized).unwrap();

        assert_eq!(w, deserialized);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_bad_mod3() {
        use crate::{WireLabel, WireMod3};
        use rand::thread_rng;

        let mut rng = thread_rng();
        let mut w = WireMod3::rand(&mut rng, 3);

        // lsb and msb can't both be set
        w.lsb |= 1;
        w.msb |= 1;
        let serialized = serde_json::to_string(&w).unwrap();

        let deserialized: Result<WireMod3, _> = serde_json::from_str(&serialized);
        assert!(deserialized.is_err());
    }
}
