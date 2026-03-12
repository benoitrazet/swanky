use crate::{ArithmeticWire, HasModulus, WireLabel, util, wire::_unrank};
use rand::{CryptoRng, Rng, RngCore};
use swanky_block::Block;

/// Intermediate struct to deserialize WireModQ to
///
/// Checks that modulus is at least 2
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct UntrustedWireModQ {
    /// The modulus of the wire label
    q: u16, // Assuming mod can fit in u16
    /// A list of `mod-q` digits.
    ds: Vec<u16>,
}

#[cfg(feature = "serde")]
impl TryFrom<UntrustedWireModQ> for WireModQ {
    type Error = crate::errors::WireDeserializationError;

    fn try_from(wire: UntrustedWireModQ) -> Result<Self, Self::Error> {
        // Modulus must be at least 2
        if wire.q < 2 {
            return Err(Self::Error::InvalidWireModQ(
                crate::errors::ModQDeserializationError::BadModulus(wire.q),
            ));
        }

        // Check correct length and make sure all values are less than the modulus
        let expected_len = crate::util::digits_per_u128(wire.q);
        let given_len = wire.ds.len();
        if given_len != expected_len {
            return Err(Self::Error::InvalidWireModQ(
                crate::errors::ModQDeserializationError::InvalidDigitsLength {
                    got: given_len,
                    needed: expected_len,
                },
            ));
        }
        if let Some(i) = wire.ds.iter().position(|&x| x >= wire.q) {
            return Err(Self::Error::InvalidWireModQ(
                crate::errors::ModQDeserializationError::DigitTooLarge {
                    digit: wire.ds[i],
                    modulus: wire.q,
                },
            ));
        }
        Ok(WireModQ {
            q: wire.q,
            ds: wire.ds,
        })
    }
}

// Assuming mod can fit in u16
/// Representation of a `mod-q` wire.
///
/// We represent a `mod-q` wire for `q > 3` by the modulus`q` alongside a
/// list of `mod-q` digits.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "UntrustedWireModQ"))]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct WireModQ {
    /// The modulus of the wire label
    q: u16,
    /// A list of `mod-q` digits.
    pub(crate) ds: Vec<u16>,
}

impl HasModulus for WireModQ {
    fn modulus(&self) -> u16 {
        self.q
    }
}

impl WireLabel for WireModQ {
    fn rand_delta<R: CryptoRng + RngCore>(rng: &mut R, q: u16) -> Self {
        if q < 2 {
            panic!(
                "[WireModQ::rand_delta] Modulus must be at least 2. Got {}",
                q
            );
        }
        let mut w = Self::rand(rng, q);
        w.ds[0] = 1;
        w
    }

    fn digits(&self) -> Vec<u16> {
        self.ds.clone()
    }

    fn to_block(&self) -> Block {
        // This function converts a [`WireMod3`] into its [`Block`] representation.
        // The values stored in [`WireModQ`] are repacked depending on q
        // into a 128b value as a [`Block`].
        Block::from(util::from_base_q(&self.ds, self.q))
    }

    fn color(&self) -> u16 {
        let color = self.ds[0];
        debug_assert!(color < self.q);
        color
    }

    fn plus_eq<'a>(&'a mut self, other: &Self) -> &'a mut Self {
        let xs = &mut self.ds;
        let ys = &other.ds;
        let q = self.q;

        // Assuming modulus has to be the same here
        // Will enforce by type system
        //debug_assert_eq!(, ymod);
        debug_assert_eq!(xs.len(), ys.len());
        xs.iter_mut().zip(ys.iter()).for_each(|(x, &y)| {
            let (zp, overflow) = (*x + y).overflowing_sub(q);
            *x = if overflow { *x + y } else { zp }
        });

        self
    }

    fn cmul_eq(&mut self, c: u16) -> &mut Self {
        let q = self.q;
        self.ds
            .iter_mut()
            .for_each(|d| *d = (*d as u32 * c as u32 % q as u32) as u16);
        self
    }

    fn negate_eq(&mut self) -> &mut Self {
        let q = self.q;
        self.ds.iter_mut().for_each(|d| {
            if *d > 0 {
                *d = q - *d;
            } else {
                *d = 0;
            }
        });
        self
    }

    fn from_block(inp: Block, q: u16) -> Self {
        if q < 2 {
            panic!(
                "[WireModQ::from_block] Modulus must be at least 2. Got {}",
                q
            );
        }
        // This function converts a Block into its WireLabel representation
        // by splitting the Block into several digits mod q that can each fit
        // into 128b.
        let ds = if util::is_power_of_2(q) {
            // It's a power of 2, just split the digits.
            let ndigits = util::digits_per_u128(q);
            let width = 128 / ndigits;
            let mask = (1 << width) - 1;
            let x = u128::from(inp);
            (0..ndigits)
                .map(|i| ((x >> (width * i)) & mask) as u16)
                .collect::<Vec<u16>>()
        } else if q <= 23 {
            _unrank(u128::from(inp), q)
        } else {
            // If all else fails, do unrank using naive division.
            _unrank(u128::from(inp), q)
        };
        Self { q, ds }
    }
    /// Unpack the wire represented by a `Block` with modulus `q`. Assumes that
    /// the block was constructed through the `AllWire` API.
    fn zero(q: u16) -> Self {
        if q < 2 {
            panic!("[WireModQ::zero] Modulus must be at least 2. Got {}", q);
        }
        Self {
            q,
            ds: vec![0; util::digits_per_u128(q)],
        }
    }
    fn rand<R: CryptoRng + RngCore>(rng: &mut R, q: u16) -> Self {
        if q < 2 {
            panic!("[WireModQ::rand] Modulus must be at least 2. Got {}", q);
        }
        let ds = (0..util::digits_per_u128(q))
            .map(|_| rng.r#gen::<u16>() % q)
            .collect();
        Self { q, ds }
    }

    fn hash_to_mod(hash: Block, q: u16) -> Self {
        if q < 2 {
            panic!(
                "[WireModQ::hash_to_mod] Modulus must be at least 2. Got {}",
                q
            );
        }
        Self::from_block(hash, q)
    }
}

impl ArithmeticWire for WireModQ {}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serde")]
    use super::WireModQ;
    #[cfg(feature = "serde")]
    use crate::WireLabel;
    #[cfg(feature = "serde")]
    use rand::Rng;
    #[cfg(feature = "serde")]
    use rand::thread_rng;

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_good_modQ() {
        let mut rng = thread_rng();

        for _ in 0..16 {
            let mut q: u16 = rng.r#gen();
            while q < 2 {
                q = rng.r#gen();
            }
            let w = WireModQ::rand(&mut rng, q);
            let serialized = serde_json::to_string(&w).unwrap();

            let deserialized: WireModQ = serde_json::from_str(&serialized).unwrap();

            assert_eq!(w, deserialized);
        }
    }
    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_bad_modQ_mod() {
        let mut rng = thread_rng();
        let mut q: u16 = rng.r#gen();
        while q < 2 {
            q = rng.r#gen();
        }

        let mut w = WireModQ::rand(&mut rng, q);

        // Manually mess with the modulus
        w.q = 1;
        let serialized = serde_json::to_string(&w).unwrap();

        let deserialized: Result<WireModQ, _> = serde_json::from_str(&serialized);
        assert!(deserialized.is_err());
    }
    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_bad_modQ_ds_mod() {
        let serialized: String = "{\"q\":2,\"ds\":[1,1,0,1,0,5,1,0,0,0,1,1,1,0,0,1,1,0,1,1,1,0,0,0,1,1,0,0,1,1,0,0,0,1,0,1,1,0,1,1,0,0,0,0,0,0,0,0,1,0,1,1,0,0,1,1,0,1,0,1,0,0,1,1,1,1,1,0,1,0,0,0,0,1,1,1,1,1,1,1,1,0,1,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,1,0,1,0,1,0,0,1,1,0,0,0,0,0,0,1,1,1,0,1,1,1,1,1,1,0,0,0,0,0]}".to_string();

        let deserialized: Result<WireModQ, _> = serde_json::from_str(&serialized);
        assert!(deserialized.is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_bad_modQ_ds_count() {
        let serialized: String = "{\"q\":2,\"ds\":[1,1,0,1,0,1,0,0,0,1,1,1,0,0,1,1,0,1,1,1,0,0,0,1,1,0,0,1,1,0,0,0,1,0,1,1,0,1,1,0,0,0,0,0,0,0,0,1,0,1,1,0,0,1,1,0,1,0,1,0,0,1,1,1,1,1,0,1,0,0,0,0,1,1,1,1,1,1,1,1,0,1,0,1,1,0,0,1,1,0,0,1,1,0,0,1,1,1,0,1,0,1,0,0,1,1,0,0,0,0,0,0,1,1,1,0,1,1,1,1,1,1,0,0,0,0,0]}".to_string();

        let deserialized: Result<WireModQ, _> = serde_json::from_str(&serialized);
        assert!(deserialized.is_err());
    }
}
