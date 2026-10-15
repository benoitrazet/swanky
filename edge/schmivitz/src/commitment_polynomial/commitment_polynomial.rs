//! Polynomial commitment type for VOLE-based zero-knowledge protocols.
//!
//! A [`CommitmentPolynomial`] represents
//! $\rho_x(t)=\rho_0+\rho_1t+\cdots+\rho_{d-1}t^{d-1}+xt^d$, where $x$ is the
//! committed value (in the base field `F`) and
//! $\rho_0,\ldots,\rho_{d-1}$ are random masking coefficients in the extension field `FE`.
//!
//! Gate operations allow building commitment polynomials bottom-up through a circuit:
//! - [`CommitmentPolynomial::addc`]: add a constant
//! - [`CommitmentPolynomial::add`]: add two commitments (aligning degrees)
//! - [`CommitmentPolynomial::mulc`]: multiply by a constant
//! - [`CommitmentPolynomial::mul`]: multiply two commitments

use swanky_field::{FiniteField, IsSubFieldOf};

/// A polynomial commitment with leading coefficient in the base field `F`
/// and lower coefficients in the extension field `FE`.
///
/// Stores $\rho(t)=\rho_0+\rho_1t+\cdots+\rho_{d-1}t^{d-1}+xt^d$, where:
/// - `lower_coefficients` = $[\rho_0,\rho_1,\ldots,\rho_{d-1}]$ (each in `FE`);
/// - `highest_degree` = $x$ (the committed value, in `F`).
#[derive(Clone, Debug)]
pub struct CommitmentPolynomial<F: FiniteField, FE: FiniteField>
where
    F: IsSubFieldOf<FE>,
{
    lower_coefficients: Vec<FE>,
    highest_degree: F,
}

impl<F: FiniteField, FE: FiniteField> CommitmentPolynomial<F, FE>
where
    F: IsSubFieldOf<FE>,
{
    /// Create a commitment polynomial from a base VOLE.
    pub fn from_base_vole(value: F, mask: FE) -> Self {
        Self {
            lower_coefficients: vec![mask],
            highest_degree: value,
        }
    }

    /// Create a commitment polynomial directly from its lower coefficients
    /// and the highest-degree coefficient.
    #[cfg(test)]
    pub fn from_parts(lower_coefficients: Vec<FE>, highest_degree: F) -> Self {
        Self {
            lower_coefficients,
            highest_degree,
        }
    }

    /// Return the degree of the polynomial.
    pub fn degree(&self) -> usize {
        self.lower_coefficients.len()
    }

    /// Return the lower coefficients.
    pub fn lower_coefficients(&self) -> &[FE] {
        &self.lower_coefficients
    }

    /// Return the highest-degree coefficient $x$ (the committed value).
    pub fn highest_degree(&self) -> F {
        self.highest_degree
    }

    /// Evaluate the polynomial at a given point using Horner's method.
    pub fn evaluate_at_point(&self, point: FE) -> FE {
        let mut result: FE = self.highest_degree.into();
        for c in self.lower_coefficients.iter().rev() {
            result = result * point + *c;
        }
        result
    }

    /// Add a constant.
    pub fn addc(&self, c: F) -> Self {
        Self {
            lower_coefficients: self.lower_coefficients.clone(),
            highest_degree: self.highest_degree + c,
        }
    }

    /// Add two commitment polynomials, aligning to the maximum degree.
    pub fn add(&self, other: &Self) -> Self {
        let d1 = self.degree();
        let d2 = other.degree();
        let d = d1.max(d2);

        let mut lower = vec![FE::ZERO; d];

        let shift1 = d - d1;
        for (i, c) in self.lower_coefficients.iter().enumerate() {
            lower[i + shift1] = lower[i + shift1] + *c;
        }
        let shift2 = d - d2;
        for (i, c) in other.lower_coefficients.iter().enumerate() {
            lower[i + shift2] = lower[i + shift2] + *c;
        }

        Self {
            lower_coefficients: lower,
            highest_degree: self.highest_degree + other.highest_degree,
        }
    }

    /// Multiply by a constant.
    pub fn mulc(&self, c: F) -> Self {
        let lower = self.lower_coefficients.iter().map(|x| c * *x).collect();
        Self {
            lower_coefficients: lower,
            highest_degree: self.highest_degree * c,
        }
    }

    /// Multiply two commitment polynomials.
    pub fn mul(&self, other: &Self) -> Self {
        let d1 = self.degree();
        let d2 = other.degree();
        let new_degree = d1 + d2;
        let mut lower = vec![FE::ZERO; new_degree];

        // lower × lower (FE × FE)
        for (i, a) in self.lower_coefficients.iter().enumerate() {
            for (j, b) in other.lower_coefficients.iter().enumerate() {
                lower[i + j] = lower[i + j] + *a * *b;
            }
        }
        // self.highest × other.lower (F × FE)
        for (j, b) in other.lower_coefficients.iter().enumerate() {
            lower[d1 + j] = lower[d1 + j] + self.highest_degree * *b;
        }
        // self.lower × other.highest (F × FE)
        for (i, a) in self.lower_coefficients.iter().enumerate() {
            lower[i + d2] = lower[i + d2] + other.highest_degree * *a;
        }

        Self {
            lower_coefficients: lower,
            highest_degree: self.highest_degree * other.highest_degree,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::TestCaseResult;
    use rand::SeedableRng;
    use rand::rng;
    use swanky_field::FiniteRing;
    use swanky_field::{FiniteField, IsSubFieldOf};
    use swanky_field_binary::{F2, F8b, F128b};
    use swanky_rng::SwankyRng;

    fn pow_fe<FE: FiniteField>(base: FE, exp: usize) -> FE {
        let mut result = FE::ONE;
        for _ in 0..exp {
            result = result * base;
        }
        result
    }

    /// Reference polynomial evaluation independent of `evaluate_at_point`'s Horner
    /// implementation: cross-checks correctness by recomputing the sum directly.
    fn eval_reference<F: FiniteField, FE: FiniteField>(
        poly: &CommitmentPolynomial<F, FE>,
        point: FE,
    ) -> FE
    where
        F: IsSubFieldOf<FE>,
    {
        let mut acc = FE::ZERO;
        let mut p = FE::ONE;
        for c in poly.lower_coefficients() {
            acc = acc + *c * p;
            p = p * point;
        }
        acc + Into::<FE>::into(poly.highest_degree()) * p
    }

    #[test]
    fn from_base_vole_creates_degree_one() {
        let mut rng = rng();
        let value = F2::random(&mut rng);
        let mask = F128b::random(&mut rng);
        let poly = CommitmentPolynomial::<F2, F128b>::from_base_vole(value, mask);
        assert_eq!(poly.degree(), 1);
        assert_eq!(poly.lower_coefficients(), &[mask]);
        assert_eq!(poly.highest_degree(), value);
    }

    #[test]
    fn from_parts_round_trip() {
        let mut rng = rng();
        let lower = vec![F128b::random(&mut rng), F128b::random(&mut rng)];
        let highest = F2::random(&mut rng);
        let poly = CommitmentPolynomial::<F2, F128b>::from_parts(lower.clone(), highest);
        assert_eq!(poly.lower_coefficients(), &lower[..]);
        assert_eq!(poly.highest_degree(), highest);
        assert_eq!(poly.degree(), 2);
    }

    fn evaluate_at_point_horner<F: FiniteField, FE: FiniteField>(seed: [u8; 16]) -> TestCaseResult
    where
        F: IsSubFieldOf<FE>,
    {
        let mut rng = SwankyRng::from_seed(seed.into());
        let value = F::random(&mut rng);
        let mask = FE::random(&mut rng);
        let point = FE::random(&mut rng);
        let poly = CommitmentPolynomial::<F, FE>::from_base_vole(value, mask);
        // ρ(t) = mask + value·t
        prop_assert_eq!(poly.evaluate_at_point(point), mask + value * point);
        Ok(())
    }

    proptest! {
        #[test]
        fn evaluate_at_point_horner_f128b(seed in any::<[u8; 16]>()) {
            evaluate_at_point_horner::<F2, F128b>(seed)?;
            evaluate_at_point_horner::<F8b, F128b>(seed)?;
            evaluate_at_point_horner::<F128b, F128b>(seed)?;
        }
    }

    fn evaluate_at_point_matches_reference<F: FiniteField, FE: FiniteField>(
        seed: [u8; 16],
        degree: usize,
    ) -> TestCaseResult
    where
        F: IsSubFieldOf<FE>,
    {
        let mut rng = SwankyRng::from_seed(seed.into());
        let lower = (0..degree).map(|_| FE::random(&mut rng)).collect();
        let highest = F::random(&mut rng);
        let poly = CommitmentPolynomial::<F, FE>::from_parts(lower, highest);

        for point in [FE::ZERO, FE::ONE, FE::random(&mut rng)] {
            prop_assert_eq!(
                poly.evaluate_at_point(point),
                eval_reference(&poly, point),
                "degree = {}, point = {:?}",
                degree,
                point,
            );
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn evaluate_at_point_matches_reference_f128b(
            seed in any::<[u8; 16]>(),
            degree in 0usize..=128,
        ) {
            evaluate_at_point_matches_reference::<F2, F128b>(seed, degree)?;
            evaluate_at_point_matches_reference::<F8b, F128b>(seed, degree)?;
            evaluate_at_point_matches_reference::<F128b, F128b>(seed, degree)?;
        }
    }

    fn addc_correctness<F: FiniteField, FE: FiniteField>(
        seed: [u8; 16],
        degree: usize,
    ) -> TestCaseResult
    where
        F: IsSubFieldOf<FE>,
    {
        let mut rng = SwankyRng::from_seed(seed.into());
        let lower = (0..degree).map(|_| FE::random(&mut rng)).collect();
        let highest = F::random(&mut rng);
        let c = F::random(&mut rng);
        let point = FE::random(&mut rng);
        let poly = CommitmentPolynomial::<F, FE>::from_parts(lower, highest);
        let result = poly.addc(c);
        prop_assert_eq!(result.highest_degree(), poly.highest_degree() + c);
        prop_assert_eq!(result.lower_coefficients(), poly.lower_coefficients());
        prop_assert_eq!(result.degree(), degree);
        prop_assert_eq!(
            result.evaluate_at_point(point),
            poly.evaluate_at_point(point) + c * pow_fe(point, degree),
        );
        Ok(())
    }

    proptest! {
        #[test]
        fn addc_increments_highest_degree_f128b(
            seed in any::<[u8; 16]>(),
            degree in 0usize..=128,
        ) {
            addc_correctness::<F2, F128b>(seed, degree)?;
            addc_correctness::<F8b, F128b>(seed, degree)?;
            addc_correctness::<F128b, F128b>(seed, degree)?;
        }
    }

    #[test]
    fn add_same_degree() {
        let mut rng = rng();
        let val_x = F128b::random(&mut rng);
        let val_y = F128b::random(&mut rng);
        let w_x = F128b::random(&mut rng);
        let w_y = F128b::random(&mut rng);
        let point = F128b::random(&mut rng);

        let poly_x = CommitmentPolynomial::<F128b, F128b>::from_base_vole(val_x, w_x);
        let poly_y = CommitmentPolynomial::<F128b, F128b>::from_base_vole(val_y, w_y);

        let sum = poly_x.add(&poly_y);
        assert_eq!(sum.degree(), 1);
        assert_eq!(sum.highest_degree(), val_x + val_y);
        assert_eq!(
            sum.evaluate_at_point(point),
            poly_x.evaluate_at_point(point) + poly_y.evaluate_at_point(point),
        );
    }

    fn add_correctness<F: FiniteField, FE: FiniteField>(
        seed: [u8; 16],
        degree_a: usize,
        degree_b: usize,
    ) -> TestCaseResult
    where
        F: IsSubFieldOf<FE>,
    {
        prop_assume!(degree_a != degree_b);
        let mut rng = SwankyRng::from_seed(seed.into());
        let lower_a = (0..degree_a).map(|_| FE::random(&mut rng)).collect();
        let highest_a = F::random(&mut rng);
        let poly_a = CommitmentPolynomial::<F, FE>::from_parts(lower_a, highest_a);
        let lower_b = (0..degree_b).map(|_| FE::random(&mut rng)).collect();
        let highest_b = F::random(&mut rng);
        let poly_b = CommitmentPolynomial::<F, FE>::from_parts(lower_b, highest_b);
        let degree = degree_a.max(degree_b);

        let points = [FE::ZERO, FE::ONE, FE::random(&mut rng)];
        let sum = poly_a.add(&poly_b);

        for point in points {
            // ρ_sum(t) = t^(d-d_a) ρ_a(t) + t^(d-d_b) ρ_b(t).
            prop_assert_eq!(
                poly_a.evaluate_at_point(point) * pow_fe(point, degree - poly_a.degree())
                    + poly_b.evaluate_at_point(point) * pow_fe(point, degree - poly_b.degree()),
                sum.evaluate_at_point(point),
                "degrees = ({}, {}), point = {:?}",
                poly_a.degree(),
                poly_b.degree(),
                point,
            );
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn add_different_degrees_f128b(
            seed in any::<[u8; 16]>(),
            degree_a in 0usize..=128,
            degree_b in 0usize..=128,
        ) {
            add_correctness::<F2, F128b>(seed, degree_a, degree_b)?;
            add_correctness::<F8b, F128b>(seed, degree_a, degree_b)?;
            add_correctness::<F128b, F128b>(seed, degree_a, degree_b)?;
        }
    }

    fn mulc_correctness<F: FiniteField, FE: FiniteField>(
        seed: [u8; 16],
        degree: usize,
    ) -> TestCaseResult
    where
        F: IsSubFieldOf<FE>,
    {
        let mut rng = SwankyRng::from_seed(seed.into());
        let lower = (0..degree).map(|_| FE::random(&mut rng)).collect();
        let highest = F::random(&mut rng);
        let c = F::random(&mut rng);
        let poly = CommitmentPolynomial::<F, FE>::from_parts(lower, highest);
        let result = poly.mulc(c);

        for point in [FE::ZERO, FE::ONE, FE::random(&mut rng)] {
            prop_assert_eq!(
                c * poly.evaluate_at_point(point),
                result.evaluate_at_point(point),
                "degree = {}, constant = {:?}, point = {:?}",
                degree,
                c,
                point,
            );
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn mulc_correctness_f128b(
            seed in any::<[u8; 16]>(),
            degree in 0usize..=128,
        ) {
            mulc_correctness::<F2, F128b>(seed, degree)?;
            mulc_correctness::<F8b, F128b>(seed, degree)?;
            mulc_correctness::<F128b, F128b>(seed, degree)?;
        }
    }

    fn mul_correctness<F: FiniteField, FE: FiniteField>(
        seed: [u8; 16],
        degree_a: usize,
        degree_b: usize,
    ) -> TestCaseResult
    where
        F: IsSubFieldOf<FE>,
    {
        let mut rng = SwankyRng::from_seed(seed.into());
        let lower_a = (0..degree_a).map(|_| FE::random(&mut rng)).collect();
        let highest_a = F::random(&mut rng);
        let poly_a = CommitmentPolynomial::<F, FE>::from_parts(lower_a, highest_a);
        let lower_b = (0..degree_b).map(|_| FE::random(&mut rng)).collect();
        let highest_b = F::random(&mut rng);
        let poly_b = CommitmentPolynomial::<F, FE>::from_parts(lower_b, highest_b);
        let product = poly_a.mul(&poly_b);

        for point in [FE::ZERO, FE::ONE, FE::random(&mut rng)] {
            prop_assert_eq!(
                poly_a.evaluate_at_point(point) * poly_b.evaluate_at_point(point),
                product.evaluate_at_point(point),
                "degrees = ({}, {}), point = {:?}",
                degree_a,
                degree_b,
                point,
            );
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn mul_correctness_f128b(
            seed in any::<[u8; 16]>(),
            degree_a in 0usize..=128,
            degree_b in 0usize..=128,
        ) {
            mul_correctness::<F2, F128b>(seed, degree_a, degree_b)?;
            mul_correctness::<F8b, F128b>(seed, degree_a, degree_b)?;
            mul_correctness::<F128b, F128b>(seed, degree_a, degree_b)?;
        }
    }
}
