//! 256-bit blocks of data.

use rand::RngExt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Block;

/// A 256-bit block of data.
#[derive(
    Clone,
    Copy,
    Default,
    Debug,
    PartialEq,
    Eq,
    Hash,
    bytemuck::Pod,
    bytemuck::Zeroable,
    bytemuck::TransparentWrapper,
)]
#[repr(transparent)]
pub struct Block256([Block; 2]);

impl Block256 {
    /// Return the first `n` bytes, where `n` must be `<= 32`.
    #[inline]
    pub fn prefix(&self, n: usize) -> &[u8] {
        debug_assert!(n <= 32);
        &self.as_ref()[0..n]
    }

    /// Return the first `n` bytes as mutable, where `n` must be `<= 32`.
    #[inline]
    pub fn prefix_mut(&mut self, n: usize) -> &mut [u8] {
        &mut self.as_mut()[0..n]
    }
}

impl AsMut<[u8]> for Block256 {
    fn as_mut(&mut self) -> &mut [u8] {
        bytemuck::bytes_of_mut(self)
    }
}

impl AsRef<[u8]> for Block256 {
    fn as_ref(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }
}

impl std::ops::BitXor for Block256 {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        let b0 = self.0[0] ^ rhs.0[0];
        let b1 = self.0[1] ^ rhs.0[1];
        Self([b0, b1])
    }
}

impl std::ops::BitXorAssign for Block256 {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a ^= *b;
        }
    }
}

impl std::fmt::Display for Block256 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#?}", self.0)
    }
}

impl rand::distr::Distribution<Block256> for rand::distr::StandardUniform {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Block256 {
        let b0 = rng.random::<Block>();
        let b1 = rng.random::<Block>();
        Block256([b0, b1])
    }
}

impl From<Block256> for [u32; 8] {
    #[inline]
    fn from(m: Block256) -> [u32; 8] {
        bytemuck::cast(m)
    }
}

impl From<Block256> for [Block; 2] {
    #[inline]
    fn from(m: Block256) -> [Block; 2] {
        m.0
    }
}

impl<'a> From<&'a Block256> for &'a [Block; 2] {
    #[inline]
    fn from(m: &Block256) -> &[Block; 2] {
        &m.0
    }
}

impl<'a> From<&'a mut Block256> for &'a mut [Block; 2] {
    #[inline]
    fn from(m: &mut Block256) -> &mut [Block; 2] {
        &mut m.0
    }
}

impl<'a> From<&'a mut Block256> for &'a mut [u8; 32] {
    #[inline]
    fn from(m: &'a mut Block256) -> Self {
        bytemuck::cast_mut(m)
    }
}

impl From<[Block; 2]> for Block256 {
    #[inline]
    fn from(m: [Block; 2]) -> Block256 {
        Block256(m)
    }
}

impl From<[u8; 32]> for Block256 {
    #[inline]
    fn from(m: [u8; 32]) -> Block256 {
        bytemuck::cast(m)
    }
}

impl TryFrom<&[u8]> for Block256 {
    type Error = core::array::TryFromSliceError;
    #[inline]
    fn try_from(u: &[u8]) -> Result<Self, Self::Error> {
        let bytes = <[u8; 256 / 8]>::try_from(u)?;
        Ok(bytemuck::cast(bytes))
    }
}

#[derive(Serialize, Deserialize)]
struct Helper {
    pub blocks: [Block; 2],
}

impl Serialize for Block256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let helper = Helper { blocks: self.0 };
        helper.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Block256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = Helper::deserialize(deserializer)?;
        Ok(Block256::from(helper.blocks))
    }
}
