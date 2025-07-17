#![deny(missing_docs)]
#![allow(unsafe_op_in_unsafe_fn)]
//! VectorEyes is a (almost entirely) safe and cross-platform wrapper library around vectorized
//! operations.
//!
//! While a normal `add` CPU instruction will add two numbers together, a
//! [SIMD/Vectorized](https://en.wikipedia.org/wiki/Single_instruction,_multiple_data) `add`
//! instruction will perform multiple additions from the same instruction. This will amortize the
//! per-instruction cost (e.g. of the CPU decoding the instruction) across all the additions of the
//! single instruction. This can provide large speed boosts on many platforms.
//!
//! Unfortunately, using these operations require using per-platform unsafe intrinsics. To make
//! this easier, VectorEyes provide safe functions which will function identically on all
//! platforms.
//!
//! The core of this crate is vector types like [U64x2]. This the vector equivalent of `[u64; 2]`.
//! It is a 128-bit vector containing 2 lanes each with a `u64`.
//!
//! # Example
//! These two functions perform the same operation, but the simd variant takes may take better
//! advantage of the CPU hardware.
//! ```
//! # use vectoreyes::*;
//! fn double_without_simd(arr: [u64; 2]) -> [u64; 2] {
//!     [arr[0] + arr[0], arr[1] + arr[1]]
//! }
//! fn double_with_simd(arr: U64x2) -> U64x2 {
//!     arr + arr
//! }
//! assert_eq!(
//!     U64x2::from(double_without_simd([1, 2])),
//!     double_with_simd(U64x2::from([1, 2])),
//! );
//! ```
//!
//! # Backends
//! VectorEyes chooses what backend to execute vector operations with at compile-time.
//!
//! ## AVX2
//! x86-64 CPUs that support the `AVX`, `AVX2`, `SSE4.1`, `AES`, `SSE4.2`, and
//! `PCLMULQDQ` features will use the `AVX2` backend.
//!
//! ## Neon
//! This is available on aarch64/arm64 machines with `neon` and `aes` features.
//!
//! ## Scalar
//! This is a fallback implementation that works on all CPUs. It's not
//! particularly performant.
//!
//! # Cargo Configuration
//! ## Native CPU Setup
//! Compile on the machine that you'll be running your code on, and add the
//! following to your `.cargo/config` file:
//! ```toml
//! [build]
//! rustflags = ["-C", "target-cpu=native", "--cfg=vectoreyes-target-cpu-native"]
//! rustdocflags = ["-C", "target-cpu=native", "--cfg=vectoreyes-target-cpu-native"]
//! ```
//! ## Specific CPU Selection
//! If you want to compile for some specific CPU, add the following to your
//! `.cargo/config` file:
//! ```toml
//! [build]
//! rustflags = ["-C", "target-cpu=TARGET", "--cfg=vectoreyes-target-cpu=\"TARGET\""]
//! rustdocflags = ["-C", "target-cpu=TARGET", "--cfg=vectoreyes-target-cpu=\"TARGET\""]
//! ```
//! ## Maximal Compatibility
//! If you do not put any of the above in your `.cargo/config` file,
//! `vectoreyes` will always use its `scalar` backend, which does not use vector
//! instructions.
//!
//! # Limitations
//! VectorEyes was designed around the AVX2 backend. For example, shuffle operations tend to be
//! constrained to 128-bit lanes because that's how the Intel intrinsics are constrained. As a
//! result, while code that uses VectorEyes might be optimal for an Intel platform, it might not be
//! optimal for an ARM platform with different intrinsics. (This is a limitation, generally, with
//! cross-platform SIMD libraries like VectorEyes.)
//!
//! In addition, many SIMD intrinsics are currently not wrapped in VectorEyes.

use std::ops::*;

/// What backend will be used when targeting the current CPU?
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VectorBackend {
    /// The fallback scalar backend (doesn't use vector instructions).
    Scalar,
    /// A vector backend targeting [AVX2](https://en.wikipedia.org/wiki/Advanced_Vector_Extensions#Advanced_Vector_Extensions_2).
    Avx2,
    /// A vector backend targeting [ARM Neon](https://developer.arm.com/Architectures/Neon).
    Neon,
}

/// The vector backend that this process is using.
pub const VECTOR_BACKEND: VectorBackend = current_vector_backend();

/// Panic if the current binary uses features unsupported by the current CPU.
///
/// `vectoreyes` uses compile-time flags to select which backend to use and which CPU features to
/// require. If this backend is used on an unsupported CPU, it will result in an "Illegal
/// instruction" error (technically, _all_ Rust code--not even just `vectoreyes` code--may result in
/// undefined behavior if run on a CPU that doesn't support the compile-time selected feature
/// flags).
///
/// It would be advisable to call this in the `main()` function of executables to try to catch
/// these errors early.
pub fn assert_cpu_features() {
    vector_backend_check_cpu()
}

/// A scalar that can live in the lane of a vector.
pub trait Scalar:
    'static
    + std::fmt::Debug
    + num_traits::PrimInt
    + num_traits::WrappingAdd
    + num_traits::WrappingSub
    + num_traits::WrappingMul
    + subtle::ConstantTimeEq
    + subtle::ConditionallySelectable
{
    /// A scalar of the same width as this scalar, but signed.
    type Signed: Scalar;
    /// A scalar of the same width as this scalar, but unsigned.
    type Unsigned: Scalar;

    /// A scalar of the same sign as this scalar, but with width 8.
    type SameSign8: Scalar<Signed = i8, Unsigned = u8>;
    /// A scalar of the same sign as this scalar, but with width 16.
    type SameSign16: Scalar<Signed = i16, Unsigned = u16>;
    /// A scalar of the same sign as this scalar, but with width 32.
    type SameSign32: Scalar<Signed = i32, Unsigned = u32>;
    /// A scalar of the same sign as this scalar, but with width 64.
    type SameSign64: Scalar<Signed = i64, Unsigned = u64>;
}
macro_rules! scalar_impls {
    ($(($s:ty, $u:ty)),*) => {$(
        impl Scalar for $s {
            type Signed = $s;
            type Unsigned = $u;

            type SameSign8 = i8;
            type SameSign16 = i16;
            type SameSign32 = i32;
            type SameSign64 = i64;
        }
        impl Scalar for $u {
            type Signed = $s;
            type Unsigned = $u;

            type SameSign8 = u8;
            type SameSign16 = u16;
            type SameSign32 = u32;
            type SameSign64 = u64;
        }
    )*};
}
scalar_impls!((i64, u64), (i32, u32), (i16, u16), (i8, u8));
/// A vector equivalent to `[T; Self::Lanes]`.
///
/// Note that each implemented method shows an equivalent scalar implementation.
///
/// # Representation
/// This type should have the same size as `[T; Self::Lanes]`, though it may have increased
/// alignment requirements.
///
/// # Effects of signedness on shift operations
/// When `Scalar` is _signed_, this will shift in sign bits, as opposed to zeroes.
pub trait SimdBase:
    'static
    + Sized
    + Clone
    + Copy
    + Sync
    + Send
    + std::fmt::Debug
    + PartialEq
    + Eq
    + Default
    + bytemuck::Pod
    + bytemuck::Zeroable
    + BitXor
    + BitXorAssign
    + BitOr
    + BitOrAssign
    + BitAnd
    + BitAndAssign
    + AddAssign
    + Add<Output = Self>
    + SubAssign
    + Sub<Output = Self>
    + ShlAssign<u64>
    + Shl<u64, Output = Self>
    + ShrAssign<u64>
    + Shr<u64, Output = Self>
    + ShlAssign<Self>
    + Shl<Self, Output = Self>
    + ShrAssign<Self>
    + Shr<Self, Output = Self>
    + subtle::ConstantTimeEq
    + subtle::ConditionallySelectable
    + AsRef<[Self::Scalar]>
    + AsMut<[Self::Scalar]>
{
    /// The number of elements of this vector.
    ///
    /// **Note:** this number is _not_ the number of 128-bit lanes in this vector.
    const LANES: usize;

    /// The equivalent array type of this vector.
    type Array: 'static
        + Sized
        + Clone
        + Copy
        + Sync
        + Send
        + std::fmt::Debug
        + bytemuck::Pod
        + bytemuck::Zeroable
        + PartialEq
        + Eq
        + Default
        + std::hash::Hash
        + AsRef<[Self::Scalar]>
        + From<Self>
        + Into<Self>;

    /// The scalar that this value holds.
    type Scalar: Scalar;
    /// The signed version of this vector.
    type Signed: SimdBase<Scalar = <<Self as SimdBase>::Scalar as Scalar>::Signed>
        + From<Self>
        + Into<Self>;
    /// The unsigned version of this vector.
    type Unsigned: SimdBase<Scalar = <<Self as SimdBase>::Scalar as Scalar>::Unsigned>
        + From<Self>
        + Into<Self>;

    /// A vector where every element is zero.
    const ZERO: Self;
    /// Is `self == Self::ZERO`?
    fn is_zero(&self) -> bool;

    /// Create a new vector by setting element 0 to `value`, and the rest of the elements to `0`.
    fn set_lo(value: Self::Scalar) -> Self;

    /// Create a new vector by setting every element to `value`.
    fn broadcast(value: Self::Scalar) -> Self;

    /// A vector of `[Self::Scalar; 128 / (8 * std::mem::size_of::<Self::Scalar>())]`
    type BroadcastLoInput: SimdBase<Scalar = Self::Scalar>;
    /// Create a vector by setting every element to element 0 of `of`.
    fn broadcast_lo(of: Self::BroadcastLoInput) -> Self;

    /// Get the `I`-th element of this vector.
    fn extract<const I: usize>(&self) -> Self::Scalar;

    /// Convert the vector to an array.
    #[inline(always)]
    fn as_array(&self) -> Self::Array {
        (*self).into()
    }

    /// Shift each element left by `BITS`.
    fn shift_left<const BITS: usize>(&self) -> Self;
    /// Shift each element right by `BITS`.
    /// # Effects of Signedness
    /// When `T` is _signed_, this will shift in sign bits, as opposed to zeroes.
    fn shift_right<const BITS: usize>(&self) -> Self;

    /// Compute `self & (! other)`.
    fn and_not(&self, other: Self) -> Self;

    /// Create a vector where each element is all 1's if the elements are equal, and all 0's otherwise.
    fn cmp_eq(&self, other: Self) -> Self;
    /// Create a vector where each element is all 1's if the element of `self` is greater than the
    /// corresponding element of `other`, and all 0's otherwise.
    fn cmp_gt(&self, other: Self) -> Self;

    /// Interleave the elements of the low half of `self` and `other`.
    fn unpack_lo(&self, other: Self) -> Self;
    /// Interleave the elements of the high half of `self` and `other`.
    fn unpack_hi(&self, other: Self) -> Self;

    /// Make a vector consisting of the maximum elements of `self` and other.
    fn max(&self, other: Self) -> Self;
    /// Make a vector consisting of the minimum elements of `self` and other.
    fn min(&self, other: Self) -> Self;
}

/// A vector supporting the gather operation.
pub trait SimdBaseGatherable<IV: SimdBase>: SimdBase {
    /// Construct a vector by accessing values at `base + indices[i]`.
    ///
    /// # Safety
    /// This operation is safe if `std::ptr::read(base.add(indices[i]))` is safe for all `i`.
    unsafe fn gather(base: *const Self::Scalar, indices: IV) -> Self;
    /// Construct a vector by accessing values at `base + indices[i]`, only if the mask is set.
    ///
    /// # Safety
    /// This operation is safe if `std::ptr::read(base.add(indices[i]))` is safe for all `i`.
    unsafe fn gather_masked(base: *const Self::Scalar, indices: IV, mask: Self, src: Self) -> Self;
}

/// A vector containing 4 lanes.
pub trait SimdBase4x: SimdBase {
    /// If `Bi` is true, then that lane will be filled by `if_true`. Otherwise the lane
    /// will be filled from `self`.
    fn blend<const B3: bool, const B2: bool, const B1: bool, const B0: bool>(
        &self,
        if_true: Self,
    ) -> Self;
}

/// A vector containing 8 lanes.
pub trait SimdBase8x: SimdBase {
    /// If `Bi` is true, then that lane will be filled by `if_true`. Otherwise the lane
    /// will be filled from `self`.
    fn blend<
        const B7: bool,
        const B6: bool,
        const B5: bool,
        const B4: bool,
        const B3: bool,
        const B2: bool,
        const B1: bool,
        const B0: bool,
    >(
        &self,
        if_true: Self,
    ) -> Self;
}

/// A vector supporting saturating arithmetic on each entry.
pub trait SimdSaturatingArithmetic: SimdBase {
    /// Pairwise add vectors. On overflow, the entry's value goes to the maximum scalar value.
    fn saturating_add(&self, other: Self) -> Self;
    /// Pairwise add vectors. On overflow, the entry's value goes to the minimum scalar value.
    fn saturating_sub(&self, other: Self) -> Self;
}

/// A vector containing 8-bit values.
pub trait SimdBase8: SimdBase + SimdSaturatingArithmetic
where
    Self::Scalar: Scalar<Unsigned = u8, Signed = i8>,
{
    /// Shift within 128-bit lanes.
    fn shift_bytes_left<const AMOUNT: usize>(&self) -> Self;
    /// Shift within 128-bit lanes.
    fn shift_bytes_right<const AMOUNT: usize>(&self) -> Self;
    /// Get the sign/most significant bits of the elements of the vector.
    fn most_significant_bits(&self) -> u32;
}

/// A vector containing 16-bit values.
pub trait SimdBase16: SimdBase + SimdSaturatingArithmetic
where
    Self::Scalar: Scalar<Unsigned = u16, Signed = i16>,
{
    /// Shuffle within the lower 64-bits of each 128-bit lane.
    fn shuffle_lo<const I3: usize, const I2: usize, const I1: usize, const I0: usize>(
        &self,
    ) -> Self;
    /// Shuffle within the upper 64-bits of each 128-bit lane.
    fn shuffle_hi<const I3: usize, const I2: usize, const I1: usize, const I0: usize>(
        &self,
    ) -> Self;
}

/// A vector containing 32-bit values.
pub trait SimdBase32: SimdBase
where
    Self::Scalar: Scalar<Unsigned = u32, Signed = i32>,
{
    /// Shuffle within 128-bit lanes.
    fn shuffle<const I3: usize, const I2: usize, const I1: usize, const I0: usize>(&self) -> Self;
}

/// A vector containing 64-bit values.
pub trait SimdBase64: SimdBase
where
    Self::Scalar: Scalar<Unsigned = u64, Signed = i64>,
{
    /// Zero out the upper-32 bits of each word, and then perform pairwise multiplication.
    fn mul_lo(&self, other: Self) -> Self;
}

/// A vector containing 4 64-bit values.
pub trait SimdBase4x64: SimdBase64 + SimdBase4x
where
    Self::Scalar: Scalar<Unsigned = u64, Signed = i64>,
{
    /// Shuffle across 128-bit lanes.
    fn shuffle<const I3: usize, const I2: usize, const I1: usize, const I0: usize>(&self) -> Self;
}

// TODO: deprecate the uses of from() everywhere and use traits/functions that make it obvious which
// casts are free and which aren't.

/// Lossily cast a vector by {zero,sign}-extending its values.
pub trait ExtendingCast<T: SimdBase>: SimdBase {
    /// Cast from one vector to another by sign or zero extending the values from the source until it
    /// fills the destination.
    ///
    /// This operation is neccessarily lossy. The lowest-index values in `t` are kept. Other values
    /// are discarded.
    fn extending_cast_from(t: T) -> Self;
}

/// A [[Scalar]] type which has a vector type of length `N`.
///
/// See [[Simd]] for how this trait is used.
pub trait HasVector<const N: usize>: Scalar {
    /// The vector of `[Self; N]`.
    type Vector: SimdBase<Scalar = Self>;
}

/// An alternative way of naming SIMD types.
///
/// This allows for functions to be written which are generic in the type or length of a vector.
///
/// # Example
/// ```
/// # use vectoreyes::*;
/// type MyVector = Simd<u8, 16>; // The same as U8x16.
///
/// fn my_length_generic_code<const N: usize>(x: Simd<u32, N>, y: Simd<u32, N>) -> Simd<u32, N>
///     where u32: HasVector<N>
/// {
///     x + x + y
/// }
/// ```
pub type Simd<T, const N: usize> = <T as HasVector<N>>::Vector;

/// An AES block cipher, suitable for encryption.
///
/// This cipher can be used for encryption. Decryption operations are handled in the subtrait
/// [`AesBlockCipherDecrypt`].
pub trait AesBlockCipher: 'static + Clone + Sync + Send {
    /// The type of the AES key.
    type Key: 'static + Clone + Sync + Send;

    /// Running `encrypt_many` with this many blocks will typically result in good
    /// performance.
    const BLOCK_COUNT_HINT: usize;

    /// Run the AES key schedule operation with a given key.
    fn new_with_key(key: Self::Key) -> Self;

    /// Encrypt a single 128-bit AES block.
    #[inline(always)]
    fn encrypt(&self, block: U8x16) -> U8x16 {
        self.encrypt_many([block])[0]
    }
    /// Encrypt an array of `N` 128-bit AES blocks using ECB mode.
    fn encrypt_many<const N: usize>(&self, blocks: [U8x16; N]) -> [U8x16; N]
    where
        array_utils::ArrayUnrolledOps: array_utils::UnrollableArraySize<N>;
}

/// An AES block cipher, suitable for encryption and decryption.
pub trait AesBlockCipherDecrypt: AesBlockCipher {
    /// Decrypt a single 128-bit AES block.
    #[inline(always)]
    fn decrypt(&self, block: U8x16) -> U8x16 {
        self.decrypt_many([block])[0]
    }
    /// Decrypt an array of `N` 128-bit AES blocks using ECB mode.
    fn decrypt_many<const N: usize>(&self, blocks: [U8x16; N]) -> [U8x16; N]
    where
        array_utils::ArrayUnrolledOps: array_utils::UnrollableArraySize<N>;
}

pub mod array_utils;
pub(crate) mod utils;

// We want to allow `which_lane * 0 + 0` expressions.
// These also allow for simpler generated code. For example, sometimes we have code which looks
// like:
//    let x: {{ty}};
//    x as u8
// When {{ty}} _is_ u8, this cast isn't neccessary. But it's simpler to always insert it in the
// generated code.
#[allow(
    clippy::identity_op,
    clippy::erasing_op,
    clippy::unnecessary_cast,
    clippy::useless_conversion
)]
// intel intrinsics have many arguments
#[allow(clippy::too_many_arguments)]
// our compressed code doesn't have newlines
#[allow(clippy::suspicious_else_formatting)]
// You can't put inline(always) without a closure
#[allow(clippy::redundant_closure)]
// These two lints let us have extra parentheses in the generated source (which makes generation
// easier).
#[allow(unused_parens)]
#[allow(clippy::needless_borrow)]
// </the two lints>
mod generated;
pub use generated::implementation::*;
