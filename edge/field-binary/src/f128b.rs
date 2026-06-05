use crate::F2;
use generic_array::GenericArray;
use rand::Rng;
use std::iter::FromIterator;
use std::ops::{AddAssign, Mul, MulAssign, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf, IsSubRingOf};
use swanky_serialization::{
    ByteElementDeserializer, ByteElementSerializer, BytesDeserializationCannotFail,
    CanonicalSerialize,
};
use vectoreyes::{SimdBase, U8x16};

/// An element of the finite field $\textsf{GF}(2^{128})$ reduced over $x^{128} + x^7 + x^2 + x + 1$
#[derive(Debug, Clone, Copy, Hash, Eq)]
// We use a u128 since Rust will pass it in registers, unlike a __m128i
pub struct F128b(pub(crate) u128);

impl F128b {
    /// Extract the least-significant bit from a `F128b` value.
    pub fn lsb(self) -> F2 {
        F2::from((U8x16::from(self).extract::<0>() & 1) != 0)
    }
}
#[cfg(test)]
use swanky_polynomial::Polynomial;

/// Return the reduction polynomial for the field `F128b`.
#[cfg(test)]
#[allow(clippy::eq_op)]
fn polynomial_modulus_f128b() -> Polynomial<<F128b as FiniteField>::PrimeField> {
    let mut coefficients = vec![F2::ZERO; 128];
    coefficients[128 - 1] = F2::ONE;
    coefficients[7 - 1] = F2::ONE;
    coefficients[2 - 1] = F2::ONE;
    coefficients[1 - 1] = F2::ONE;
    Polynomial {
        constant: F2::ONE,
        coefficients,
    }
}

impl ConstantTimeEq for F128b {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
impl ConditionallySelectable for F128b {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        F128b(u128::conditional_select(&a.0, &b.0, choice))
    }
}

impl<'a> AddAssign<&'a F128b> for F128b {
    #[inline]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn add_assign(&mut self, rhs: &'a F128b) {
        self.0 ^= rhs.0;
    }
}
impl<'a> SubAssign<&'a F128b> for F128b {
    #[inline]
    #[allow(clippy::suspicious_op_assign_impl)]
    fn sub_assign(&mut self, rhs: &'a F128b) {
        // The additive inverse of GF(2^128) is the identity
        *self += rhs;
    }
}

//mod multiply {
//    // TODO: this implements a simple algorithm that works. There are faster algorithms.
//    // Maybe we'll implement one, one day...
//
//    // See https://is.gd/tOd246 pages 12-16. Note, their notation [x_1:x_0] means that x_1 is
//    // the most-significant half of the resulting number.
//    // This function is based on https://git.io/JUUQt
//    // The original code is MIT/Apache 2.0 dual-licensed.
//    // See: https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf
//    // See: https://blog.quarkslab.com/reversing-a-finite-field-multiplication-optimization.html
//    // See: https://tools.ietf.org/html/rfc8452
//
//    #[inline(always)]
//    pub(crate) fn reduce(upper: u128, lower: u128) -> u128 {
//        // Page 15 of https://is.gd/tOd246
//        // Reduce the polynomial represented in bits over x^128 + x^7 + x^2 + x + 1
//        // TODO: we should probably do this in vector operations...
//        fn sep(x: u128) -> (u64, u64) {
//            // (high, low)
//            ((x >> 64) as u64, x as u64)
//        }
//        fn join(u: u64, l: u64) -> u128 {
//            ((u as u128) << 64) | (l as u128)
//        }
//
//        let (x3, x2) = sep(upper);
//        let (x1, x0) = sep(lower);
//        let a = x3 >> 63;
//        let b = x3 >> 62;
//        let c = x3 >> 57;
//        let d = x2 ^ a ^ b ^ c;
//        let (e1, e0) = sep(join(x3, d) << 1);
//        let (f1, f0) = sep(join(x3, d) << 2);
//        let (g1, g0) = sep(join(x3, d) << 7);
//        let h1 = x3 ^ e1 ^ f1 ^ g1;
//        let h0 = d ^ e0 ^ f0 ^ g0;
//        join(x1 ^ h1, x0 ^ h0)
//    }
//
//    #[cfg(test)]
//    mod test {
//        use super::super::polynomial_modulus_f128b;
//        use crate::{F2, F128b};
//        use proptest::prelude::*;
//        use swanky_field::FiniteField;
//        use swanky_polynomial::Polynomial;
//        use vectoreyes::U8x16;
//
//        fn poly_from_upper_and_lower_128(upper: u128, lower: u128) -> Polynomial<F2> {
//            let mut out = Polynomial {
//                constant: F2::try_from((lower & 1) as u8).unwrap(),
//                coefficients: Default::default(),
//            };
//            for shift in 1..128 {
//                out.coefficients
//                    .push(F2::try_from(((lower >> shift) & 1) as u8).unwrap());
//            }
//            for shift in 0..128 {
//                out.coefficients
//                    .push(F2::try_from(((upper >> shift) & 1) as u8).unwrap());
//            }
//            out
//        }
//
//        fn poly_from_128(x: u128) -> Polynomial<F2> {
//            let x = F128b(x).decompose();
//            Polynomial {
//                constant: x[0],
//                coefficients: x[1..].to_vec(),
//            }
//        }
//
//        proptest! {
//            #[test]
//            fn unreduced_multiply(a in any::<u128>(), b in any::<u128>()) {
//                let a_poly = poly_from_128(a);
//                let b_poly = poly_from_128(b);
//                let [lower, upper] = U8x16::from(a).carryless_mul_wide(U8x16::from(b));
//                let lower: u128 = bytemuck::cast(lower);
//                let upper: u128 = bytemuck::cast(upper);
//                let mut product = a_poly;
//                product *= &b_poly;
//                assert_eq!(
//                    poly_from_upper_and_lower_128(upper, lower),
//                    product
//                );
//            }
//        }
//
//        fn assert_div_mod(
//            poly: &Polynomial<F2>,
//            quotient: &Polynomial<F2>,
//            remainder: &Polynomial<F2>,
//        ) {
//            let mut tmp = quotient.clone();
//            tmp *= &polynomial_modulus_f128b();
//            tmp += remainder;
//            assert_eq!(poly, &tmp);
//        }
//
//        proptest! {
//            #![proptest_config(ProptestConfig::with_cases(
//                std::env::var("PROPTEST_CASES")
//                    .map(|x| x.parse().expect("PROPTEST_CASES is a number"))
//                    .unwrap_or(15)
//            ))]
//            #[test]
//            fn reduction(upper in any::<u128>(), lower in any::<u128>()) {
//                let poly = poly_from_upper_and_lower_128(upper, lower);
//                let reduced = super::reduce(upper, lower);
//                let (poly_quotient, poly_reduced) = poly.divmod(&polynomial_modulus_f128b());
//                assert_div_mod(&poly, &poly_quotient, &poly_reduced);
//                assert_eq!(poly_from_128(reduced), poly_reduced);
//            }
//        }
//    }
//}

mod multiplication {
    use vectoreyes::{SimdBase, U64x2, U8x16};
    #[cfg(target_arch = "x86_64")]
    use vectoreyes::SimdBase8;

    #[allow(dead_code)]
    mod unused {
        #[inline(always)]
        fn carryless_mul(x: u64, y: u64) -> u128 {
            #[inline(always)]
            fn bmul64(x: u64, y: u64) -> u64 {
                use std::num::Wrapping;
                let x0 = Wrapping(x & 0x1111_1111_1111_1111);
                let x1 = Wrapping(x & 0x2222_2222_2222_2222);
                let x2 = Wrapping(x & 0x4444_4444_4444_4444);
                let x3 = Wrapping(x & 0x8888_8888_8888_8888);
                let y0 = Wrapping(y & 0x1111_1111_1111_1111);
                let y1 = Wrapping(y & 0x2222_2222_2222_2222);
                let y2 = Wrapping(y & 0x4444_4444_4444_4444);
                let y3 = Wrapping(y & 0x8888_8888_8888_8888);
                let mut z0 = ((x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)).0;
                let mut z1 = ((x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)).0;
                let mut z2 = ((x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)).0;
                let mut z3 = ((x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)).0;
                z0 &= 0x1111_1111_1111_1111;
                z1 &= 0x2222_2222_2222_2222;
                z2 &= 0x4444_4444_4444_4444;
                z3 &= 0x8888_8888_8888_8888;
                z0 | z1 | z2 | z3
            }
            #[inline(always)]
            const fn rev64(mut x: u64) -> u64 {
                x = ((x & 0x5555_5555_5555_5555) << 1) | ((x >> 1) & 0x5555_5555_5555_5555);
                x = ((x & 0x3333_3333_3333_3333) << 2) | ((x >> 2) & 0x3333_3333_3333_3333);
                x = ((x & 0x0f0f_0f0f_0f0f_0f0f) << 4) | ((x >> 4) & 0x0f0f_0f0f_0f0f_0f0f);
                x = ((x & 0x00ff_00ff_00ff_00ff) << 8) | ((x >> 8) & 0x00ff_00ff_00ff_00ff);
                x = ((x & 0xffff_0000_ffff) << 16) | ((x >> 16) & 0xffff_0000_ffff);
                x.rotate_right(32)
            }
            let lo = bmul64(x, y);
            let hi = rev64(bmul64(rev64(x), rev64(y))) >> 1;
            (hi as u128) << 64 | lo as u128
        }

        #[cfg(target_arch = "aarch64")]
        #[target_feature(enable = "neon,aes")]
        #[inline]
        unsafe fn wide_mul_u128_aarch64(a: u128, b: u128) ->(u128, u128) {
            use core::arch::aarch64::vmull_p64;

            let a_lo = a as u64;
            let a_hi = (a >> 64) as u64;
            let a_comb = a_lo ^ a_hi;
            let b_lo = b as u64;
            let b_hi = (b >> 64) as u64;
            let b_comb = b_lo ^ b_hi;

            let p_lo: u128 = vmull_p64(a_lo, b_lo);
            let p_hi: u128 = vmull_p64(a_hi, b_hi);
            let p_mid: u128 = vmull_p64(a_comb, b_comb) ^ p_lo ^ p_hi;


            let lo = p_lo ^ (p_mid << 64);
            let hi = p_hi ^ (p_mid >> 64);

            (hi, lo)
        }
    }

    /// Multiply either the high or low lanes of lhs and rhs, interpreted as degree-127 Boolean
    /// polynomials. The result has degree 255, so it is returned in the form of 2 u128s containing
    /// the upper and lower bits, in that order: (hi, lo) = lhs * rhs
    //
    // This function wraps either F64x2::carryless_mul function from vectoreyes or its aarch64
    // equivalent, defined in this module. If the latter is incorporated into vectoreyes
    //
    // This function is the equivalent of F64x2::carryless_mul instantiated for a platform with
    // aarch64 neon extentions. It could (and probably could) be moved to vectoreyes.
    #[inline(always)]
    fn carryless_mul_64bit<
        const HI_RHS: bool,
        const HI_LHS: bool,
    >(lhs: U64x2, rhs: U64x2) -> U64x2 {
        #[cfg(target_arch = "aarch64")]
        if std::cfg!(all(target_feature = "neon", target_feature = "aes")) {
            let x = if HI_LHS { lhs.as_array()[1] } else { lhs.as_array()[0] };
            let y = if HI_RHS { rhs.as_array()[1] } else { rhs.as_array()[0] };
            let z = unsafe { core::arch::aarch64::vmull_p64(x, y) };
            return U64x2::from_array([z as u64, (z >> 64) as u64]);
        }
        lhs.carryless_mul::<HI_RHS, HI_LHS>(rhs)
    }

    macro_rules! shl {
        ($x:expr, lt64 $n:literal) => {
            {
                debug_assert!(0 <= $n && $n < 64);
                let x: U64x2 = $x; // Barf if x isn't U64x2
                #[cfg(target_arch = "x86_64")]
                {
                    let lo = x.shift_left::<$n>();              // Shift each lane by n
                    let carry = x.shift_right::<{64 - $n}>();   // Bits that should cross lanes
                    // Move carry into high lane
                    let hi_carry = U64x2::from(U8x16::from(carry).shift_bytes_left::<8>());
                    lo ^ hi_carry
                }
                #[cfg(not(target_arch = "x86_64"))]
                bytemuck::cast::<_, U64x2>(bytemuck::cast::<_, u128>(x) << $n)
            }
        };
        ($x:expr, 64) => {
            {
                let x: U64x2 = $x; // Barf if x isn't U64x2
                #[cfg(target_arch = "x86_64")]
                {
                    U64x2::from(U8x16::from(x).shift_bytes_left::<8>())
                }
                #[cfg(not(target_arch = "x86_64"))]
                bytemuck::cast::<_, U64x2>(bytemuck::cast::<_, u128>(x) << 64)
            }
        };
        ($x:expr, gt64 $n:literal) => {
            {
                debug_assert!($n > 64);
                let x: U64x2 = $x; // Barf if x isn't U64x2
                #[cfg(target_arch = "x86_64")]
                {
                    // Move low bits into high lane
                    let lo = U64x2::from(U8x16::from(x).shift_bytes_left::<8>());
                    lo.shift_left::<{$n - 64}>() // Shift high bits the rest of the way
                }
                #[cfg(not(target_arch = "x86_64"))]
                bytemuck::cast::<_, U64x2>(bytemuck::cast::<_, u128>(x) << $n)
            }
        }
    }

    macro_rules! srl {
        ($x:expr, lt64 $n:literal) => {
            {
                let x: U64x2 = $x; // Barf if x isn't U64x2
                #[cfg(target_arch = "x86_64")]
                {
                    let hi = x.shift_right::<$n>();             // Shift each lane by n
                    let carry = x.shift_left::<{64 - $n}>();    // Bits that should cross lanes
                    // Move carry into low lane
                    let lo_carry = U64x2::from(U8x16::from(carry).shift_bytes_right::<8>());
                    hi ^ lo_carry
                }
                #[cfg(not(target_arch = "x86_64"))]
                bytemuck::cast::<_, U64x2>(bytemuck::cast::<_, u128>(x) >> $n)
            }
        };
        ($x:expr, 64) => {
            {
                let x: U64x2 = $x; // Barf if x isn't U64x2
                #[cfg(target_arch = "x86_64")]
                {
                    U64x2::from(U8x16::from(x).shift_bytes_right::<8>())
                }
                #[cfg(not(target_arch = "x86_64"))]
                bytemuck::cast::<_, U64x2>(bytemuck::cast::<_, u128>(x) >> 64)
            }
        };
        ($x:expr, gt64 $n:literal) => {
            {
                let x: U64x2 = $x; // Barf if x isn't U64x2
                #[cfg(target_arch = "x86_64")]
                {
                    // Move high bits into low lane
                    let hi = U64x2::from(U8x16::from(x).shift_bytes_right::<8>());
                    hi.shift_right::<{$n - 64}>() // Shift low bits the rest of the way
                }
                #[cfg(not(target_arch = "x86_64"))]
                bytemuck::cast::<_, U64x2>(bytemuck::cast::<_, u128>(x) >> $n)
            }
        }
    }

    // Algorithm 2 from page 12 of https://is.gd/tOd246
    //
    // The paper describes this as, "one iteration carry-less schoolbook" multiplication.
    #[inline(always)]
    pub(crate) fn clmul(a: u128, b: u128) -> (u128, u128) {
        let a: U64x2 = bytemuck::cast(a);
        let b: U64x2 = bytemuck::cast(b);

        let c = carryless_mul_64bit::<false, false>(a, b);
        let d = carryless_mul_64bit::<true, true>(a, b);
        let e = carryless_mul_64bit::<true, false>(a, b);
        let f = carryless_mul_64bit::<false, true>(a, b);

        let e_f = e ^ f;
        let lo = c ^ shl!(e_f, 64);
        let hi = d ^ srl!(e_f, 64);

        (bytemuck::cast(hi), bytemuck::cast(lo))
    }

    // Same algorithm as carryless_mul_wide from vectoreyes, but using our 64-bit carryless mul.
    // Should be identical to vectoreyes on x86_64, but better on ARM, since it uses intrinsics.
    //
    // Algorithm 1 from page 12 of https://is.gd/tOd246
    //
    // This is a variation of Karatsuba multiplication.
    #[inline(always)]
    pub(crate) fn clmul2(a: u128, b: u128) -> (u128, u128) {
        let a: U64x2 = bytemuck::cast(a);
        let b: U64x2 = bytemuck::cast(b);
        let c = carryless_mul_64bit::<true, true>(a, b);
        let d = carryless_mul_64bit::<false, false>(a, b);
        let e = carryless_mul_64bit::<false, false>(a ^ srl!(a, 64), b ^ srl!(b, 64));
        let product_upper_half =
            c ^ srl!(c, 64) ^ srl!(d, 64) ^ srl!(e, 64);
        let product_lower_half =
            d ^ shl!(d, 64) ^ shl!(c, 64) ^ shl!(e, 64);
        (
            bytemuck::cast(product_upper_half),
            bytemuck::cast(product_lower_half),
        )
    }

    #[inline(always)]
    pub(crate) fn clmul_orig(a: u128, b: u128) -> (u128, u128) {
        let [lo, hi] = U8x16::from(a).carryless_mul_wide(U8x16::from(b));
        let lo: u128 = bytemuck::cast(lo);
        let hi: u128 = bytemuck::cast(hi);
        (hi, lo)
    }

    // Reduction using clmul folding
    #[inline(always)]
    pub(crate) fn reduce(hi: u128, lo: u128) -> u128 {
        let modulus: U64x2 = bytemuck::cast(0x87_u128);
        let hi: U64x2 = bytemuck::cast(hi);
        let lo: U64x2 = bytemuck::cast(lo);

        let r0 = carryless_mul_64bit::<false, false>(hi, modulus);
        let r1 = carryless_mul_64bit::<false, true>(hi, modulus);

        let t = r0 ^ shl!(r1, 64);
        let over = srl!(r1, 64); // ≤ 7 bits
        let over_r = over ^ shl!(over, lt64 1) ^ shl!(over, lt64 2) ^ shl!(over, lt64 7);

        bytemuck::cast(lo ^ t ^ over_r)
    }

    // Our original reduce operation, but vectorized
    #[inline(always)]
    pub(crate) fn reduce2(hi: u128, lo: u128) -> u128 {
        // Page 15 of https://is.gd/tOd246
        // Reduce the polynomial represented in bits over x^128 + x^7 + x^2 + x + 1
        let hi: U64x2 = bytemuck::cast(hi);
        let lo: U64x2 = bytemuck::cast(lo);

        let x3 = srl!(hi, 64);

        let a = srl!(x3, lt64 63);
        let b = srl!(x3, lt64 62);
        let c = srl!(x3, lt64 57);

        let x3_d = hi ^ a ^ b ^ c;
        let e = shl!(x3_d, lt64 1);
        let f = shl!(x3_d, lt64 2);
        let g = shl!(x3_d, lt64 7);

        let h = x3_d ^ e ^ f ^ g;
        bytemuck::cast(lo ^ h)
    }

    #[inline(always)]
    pub(crate) fn reduce_orig(upper: u128, lower: u128) -> u128 {
        // Page 15 of https://is.gd/tOd246
        // Reduce the polynomial represented in bits over x^128 + x^7 + x^2 + x + 1
        // TODO: we should probably do this in vector operations...
        fn sep(x: u128) -> (u64, u64) {
            // (high, low)
            ((x >> 64) as u64, x as u64)
        }
        fn join(u: u64, l: u64) -> u128 {
            ((u as u128) << 64) | (l as u128)
        }

        let (x3, x2) = sep(upper);
        let (x1, x0) = sep(lower);
        let a = x3 >> 63;
        let b = x3 >> 62;
        let c = x3 >> 57;
        let d = x2 ^ a ^ b ^ c;
        let (e1, e0) = sep(join(x3, d) << 1);
        let (f1, f0) = sep(join(x3, d) << 2);
        let (g1, g0) = sep(join(x3, d) << 7);
        let h1 = x3 ^ e1 ^ f1 ^ g1;
        let h0 = d ^ e0 ^ f0 ^ g0;
        join(x1 ^ h1, x0 ^ h0)
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use proptest::prelude::*;
        use swanky_polynomial::Polynomial;
        use swanky_field::FiniteField;
        use crate::{F2, F128b};


        fn poly_from_128(x: u128) -> Polynomial<F2> {
            let x = F128b(x).decompose();
            Polynomial {
                constant: x[0],
                coefficients: x[1..].to_vec(),
            }
        }

        fn clmul_ref(a: u128, b: u128) -> (u128, u128) {
            let [lo, hi] = U8x16::from(a).carryless_mul_wide(U8x16::from(b));
            let lo: u128 = bytemuck::cast(lo);
            let hi: u128 = bytemuck::cast(hi);
            (hi, lo)
        }

        fn reduce_ref(hi: u128, lo: u128) -> Polynomial<F2> {
            fn poly_from_upper_and_lower_128(upper: u128, lower: u128) -> Polynomial<F2> {
                let mut out = Polynomial {
                    constant: F2::try_from((lower & 1) as u8).unwrap(),
                    coefficients: Default::default(),
                };
                for shift in 1..128 {
                    out.coefficients
                        .push(F2::try_from(((lower >> shift) & 1) as u8).unwrap());
                }
                for shift in 0..128 {
                    out.coefficients
                        .push(F2::try_from(((upper >> shift) & 1) as u8).unwrap());
                }
                out
            }

            let poly = poly_from_upper_and_lower_128(hi, lo);
            let (_poly_quotient, poly_reduced) = poly.divmod(&poly_from_128(0x87_u128));

            poly_reduced
        }

        proptest! {
            #[test]
            fn test_carryless_mul_128bit(a: u128, b: u128) {
                prop_assert_eq!(clmul(a, b), clmul_ref(a, b));
            }

            #[test]
            fn test_carryless_mul_128bit2(a: u128, b: u128) {
                prop_assert_eq!(clmul2(a, b), clmul_ref(a, b));
            }

            //#[test]
            //fn test_reduce(upper in any::<u128>(), lower in any::<u128>()) {
            //    let poly_reduced = reduce_ref(upper, lower);
            //    assert_eq!(poly_from_128(reduce(upper, lower)), poly_reduced);
            //}

            //#[test]
            //fn test_reduce2(upper in any::<u128>(), lower in any::<u128>()) {
            //    let poly_reduced = reduce_ref(upper, lower);
            //    assert_eq!(poly_from_128(reduce2(upper, lower)), poly_reduced);
            //}

            #[test]
            fn test_reduce_equiv(a: u128, b: u128) {
                prop_assert_eq!(reduce(a, b), reduce_orig(a, b));
            }

            #[test]
            fn test_reduce2_equiv(a: u128, b: u128) {
                prop_assert_eq!(reduce2(a, b), reduce_orig(a, b));
            }

            #[test]
            fn test_shl(x: u128) {
                let x_v: U64x2 = bytemuck::cast(x);
                let x_1: u128 = bytemuck::cast(shl!(x_v, lt64 1));
                let x_5: u128 = bytemuck::cast(shl!(x_v, lt64 5));
                let x_63: u128 = bytemuck::cast(shl!(x_v, lt64 63));
                let x_64: u128 = bytemuck::cast(shl!(x_v, 64));
                let x_65: u128 = bytemuck::cast(shl!(x_v, gt64 65));
                let x_122: u128 = bytemuck::cast(shl!(x_v, gt64 122));
                let x_127: u128 = bytemuck::cast(shl!(x_v, gt64 127));
                prop_assert_eq!(x_1, x << 1);
                prop_assert_eq!(x_5, x << 5);
                prop_assert_eq!(x_63, x << 63);
                prop_assert_eq!(x_64, x << 64);
                prop_assert_eq!(x_65, x << 65);
                prop_assert_eq!(x_122, x << 122);
                prop_assert_eq!(x_127, x << 127);
            }

            #[test]
            fn test_srl(x: u128) {
                let x_v: U64x2 = bytemuck::cast(x);
                let x_1: u128 = bytemuck::cast(srl!(x_v, lt64 1));
                let x_5: u128 = bytemuck::cast(srl!(x_v, lt64 5));
                let x_63: u128 = bytemuck::cast(srl!(x_v, lt64 63));
                let x_64: u128 = bytemuck::cast(srl!(x_v, 64));
                let x_65: u128 = bytemuck::cast(srl!(x_v, gt64 65));
                let x_122: u128 = bytemuck::cast(srl!(x_v, gt64 122));
                let x_127: u128 = bytemuck::cast(srl!(x_v, gt64 127));
                prop_assert_eq!(x_1, x >> 1);
                prop_assert_eq!(x_5, x >> 5);
                prop_assert_eq!(x_63, x >> 63);
                prop_assert_eq!(x_64, x >> 64);
                prop_assert_eq!(x_65, x >> 65);
                prop_assert_eq!(x_122, x >> 122);
                prop_assert_eq!(x_127, x >> 127);
            }
        }
    }
}

impl F128b {
    /// ???
    #[inline]
    pub fn clmul(a: u128, b: u128) -> (u128, u128) {
        multiplication::clmul(a, b)
    }

    /// ???
    #[inline]
    pub fn clmul2(a: u128, b: u128) -> (u128, u128) {
        multiplication::clmul2(a, b)
    }

    /// ???
    #[inline]
    pub fn clmul_orig(a: u128, b: u128) -> (u128, u128) {
        multiplication::clmul_orig(a, b)
    }

    /// ???
    #[inline]
    pub fn reduce(a: u128, b: u128) -> u128 {
        multiplication::reduce(a, b)
    }

    /// ???
    #[inline]
    pub fn reduce2(a: u128, b: u128) -> u128 {
        multiplication::reduce2(a, b)
    }

    /// ???
    #[inline]
    pub fn reduce_orig(a: u128, b: u128) -> u128 {
        multiplication::reduce_orig(a, b)
    }
}


impl<'a> MulAssign<&'a F128b> for F128b {
    #[inline]
    fn mul_assign(&mut self, rhs: &'a F128b) {
        use multiplication::*;
        let (hi, lo) = clmul(self.0, rhs.0);
        self.0 = reduce(hi, lo);
    }
}

impl FiniteRing for F128b {
    fn from_uniform_bytes(x: &[u8; 16]) -> Self {
        F128b(u128::from_le_bytes(*x))
    }

    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0; 16];
        rng.fill_bytes(&mut bytes[..]);
        F128b(u128::from_le_bytes(bytes))
    }

    const ZERO: Self = F128b(0);
    const ONE: Self = F128b(1);
}

impl CanonicalSerialize for F128b {
    type Serializer = ByteElementSerializer<Self>;
    type Deserializer = ByteElementDeserializer<Self>;
    type ByteReprLen = generic_array::typenum::U16;
    type FromBytesError = BytesDeserializationCannotFail;

    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        Ok(F128b(u128::from_le_bytes(*bytes.as_ref())))
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        self.0.to_le_bytes().into()
    }
}

impl FiniteField for F128b {
    type PrimeField = F2;

    const GENERATOR: Self = F128b(2);

    type NumberOfBitsInBitDecomposition = generic_array::typenum::U128;

    fn bit_decomposition(&self) -> GenericArray<bool, Self::NumberOfBitsInBitDecomposition> {
        swanky_field::standard_bit_decomposition(self.0)
    }

    fn inverse(&self) -> Self {
        if *self == Self::ZERO {
            panic!("Zero cannot be inverted");
        }
        self.pow_var_time(u128::MAX - 1)
    }
}

impl From<F2> for F128b {
    #[inline]
    fn from(x: F2) -> Self {
        Self(x.0 as u128)
    }
}
impl Mul<F128b> for F2 {
    type Output = F128b;
    #[inline]
    fn mul(self, x: F128b) -> F128b {
        F128b::conditional_select(&F128b::ZERO, &x, self.ct_eq(&F2::ONE))
    }
}

impl From<U8x16> for F128b {
    fn from(value: U8x16) -> Self {
        Self(bytemuck::cast(value))
    }
}
impl From<F128b> for U8x16 {
    fn from(value: F128b) -> Self {
        U8x16::from(value.0)
    }
}

impl IsSubRingOf<F128b> for F2 {}
impl IsSubFieldOf<F128b> for F2 {
    type DegreeModulo = generic_array::typenum::U128;
    fn decompose_superfield(fe: &F128b) -> GenericArray<Self, Self::DegreeModulo> {
        GenericArray::from_iter(
            (0..128).map(|shift| F2::try_from(((fe.0 >> shift) & 1) as u8).unwrap()),
        )
    }

    fn form_superfield(components: &GenericArray<Self, Self::DegreeModulo>) -> F128b {
        let mut out = 0;
        for x in components.iter().rev() {
            out <<= 1;
            out |= u128::from(u8::from(*x));
        }
        F128b(out)
    }
}

swanky_field::field_ops!(F128b);

#[cfg(test)]
mod tests {
    use crate::F2;

    use super::F128b;
    use proptest::prelude::*;
    use vectoreyes::U8x16;
    swanky_field_test::test_field!(test_field, F128b, crate::f128b::polynomial_modulus_f128b);
    proptest! {
        #[test]
        fn lsb_works(input in any::<u128>()) {
            prop_assert_eq!(F128b::from(U8x16::from(input)).lsb(), F2::from((input & 1) != 0));
        }
    }
}

#[test]
fn test_generator() {
    let n = u128::MAX;
    let prime_factors: Vec<u128> = vec![67280421310721, 274177, 6700417, 641, 65537, 257, 17, 5, 3];
    let x = F128b::GENERATOR;
    for p in prime_factors.iter() {
        let p = *p;
        assert_ne!(F128b::ONE, x.pow(n / p));
    }
}
