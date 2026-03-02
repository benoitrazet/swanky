use crate::{HasModulus, WireLabel};
use rand::{CryptoRng, Rng, RngCore};
use subtle::ConditionallySelectable;
use swanky_block::Block;
use vectoreyes::SimdBase;

impl HasModulus for WireMod2 {
    fn modulus(&self) -> u16 {
        2
    }
}

/// Representation of a `mod-2` wire.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct WireMod2 {
    /// A 128-bit value.
    pub(crate) val: Block,
}

impl ConditionallySelectable for WireMod2 {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        WireMod2::from_block(
            Block::conditional_select(&a.to_block(), &b.to_block(), choice),
            2,
        )
    }
}

impl WireLabel for WireMod2 {
    fn rand_delta<R: CryptoRng + RngCore>(rng: &mut R, q: u16) -> Self {
        if q != 2 {
            panic!("[WireMod2::rand_delta] Expected modulo 2. Got {}", q);
        }
        let mut w = Self::rand(rng, q);
        w.val |= Block::set_lo(1);
        w
    }

    fn digits(&self) -> Vec<u16> {
        (0..128)
            .map(|i| ((u128::from(self.val) >> i) as u16) & 1)
            .collect()
    }

    fn to_block(&self) -> Block {
        // This function converts a [`WireMod2`] into its [`Block`] representation.
        // Since the value of a [`WireMod2`] is a 128b value, its directly returned
        // as a [`Block`].
        self.val
    }

    fn color(&self) -> u16 {
        // This extracts the least-significant bit of the U8x16.
        (self.val.extract::<0>() & 1) as u16
    }

    fn plus_eq<'a>(&'a mut self, other: &Self) -> &'a mut Self {
        self.val ^= other.val;
        self
    }

    fn cmul_eq(&mut self, c: u16) -> &mut Self {
        if c & 1 == 0 {
            self.val = Block::default();
        }
        self
    }

    fn negate_eq(&mut self) -> &mut Self {
        // Do nothing. Additive inverse is a no-op for mod 2.
        self
    }

    fn from_block(inp: Block, q: u16) -> Self {
        // This function converts a Block into its WireLabel representation
        // by just setting the value of WireMod2 to the Block (i.e. the
        // wire's 128b value).
        if q != 2 {
            panic!("[WireMod2::from_block] Expected modulo 2. Got {}", q);
        }
        Self { val: inp }
    }

    fn zero(q: u16) -> Self {
        if q != 2 {
            panic!("[WireMod2::zero] Expected modulo 2. Got {}", q);
        }
        Self::default()
    }

    fn rand<R: CryptoRng + RngCore>(rng: &mut R, q: u16) -> Self {
        if q != 2 {
            panic!("[WireMod2::rand] Expected modulo 2. Got {}", q);
        }

        Self { val: rng.r#gen() }
    }

    fn hash_to_mod(hash: Block, q: u16) -> Self {
        if q != 2 {
            panic!("[WireMod2::hash_to_mod] Expected modulo 2. Got {}", q);
        }
        Self::from_block(hash, q)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_mod2() {
        use crate::{WireLabel, WireMod2};
        use rand::thread_rng;

        let mut rng = thread_rng();
        let w = WireMod2::rand(&mut rng, 2);
        let serialized = serde_json::to_string(&w).unwrap();

        let deserialized: WireMod2 = serde_json::from_str(&serialized).unwrap();

        assert_eq!(w, deserialized);
    }
}
