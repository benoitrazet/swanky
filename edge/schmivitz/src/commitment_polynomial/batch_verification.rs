//! Batch verification protocol for polynomial commitments in a VOLE-based zero-knowledge
//! proof system.
//!
//! The protocol operates on commitment polynomials of varying degrees and verifies
//! them as a batch using random challenges and VOLE masking.
//!
//! It is exposed as a streamed "fold one constraint at a time" interface —
//! [`BatchProverAccumulator`] / [`BatchVerifierAccumulator`] — matching the live prover/verifier,
//! whose circuit traversal sees constraints one at a time rather than as a collection.
//! [`crate::proof`] and the traversers push each constraint as it is traversed and then call
//! `finish` to form or check the masked polynomial $\pi(t)$.

use std::marker::PhantomData;

use swanky_error::{ErrorKind, Result, bail};
use swanky_field::{FiniteField, IsSubFieldOf};

use crate::vole::ExtensionFieldLifter;

use super::CommitmentPolynomial;

/// Compute base^exp in a finite field using repeated squaring.
pub(crate) fn power<FE: FiniteField>(base: FE, exp: usize) -> FE {
    if exp == 0 {
        return FE::ONE;
    }
    let mut result = FE::ONE;
    let mut b = base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result *= b;
        }
        b = b * b;
        e >>= 1;
    }
    result
}

/// Evaluate the polynomial with the given `coefficients` (in increasing degree order,
/// `coefficients[k]` the coefficient of $t^k$) at `point`, via Horner's method.
///
/// Shared by the prover ([`BatchProverAccumulator::evaluate_at`], over its own aggregate
/// coefficients) and the verifier ([`BatchVerifierAccumulator::finish`], over the prover's
/// committed $\pi(t)$ coefficients).
fn evaluate_poly<FE: FiniteField>(coefficients: &[FE], point: FE) -> FE {
    coefficients
        .iter()
        .rev()
        .fold(FE::ZERO, |acc, c| acc * point + *c)
}

/// Coefficients of the prover polynomial whose highest-degree coefficient is implicitly zero.
///
/// Stores $[\pi_0,\ldots,\pi_{d-1}]$ in increasing degree order. The coefficient of $t^d$ is
/// known to be zero and is omitted, so [`Self::max_degree`] returns $d$, the protocol's maximum
/// constraint degree, rather than the actual degree of the stored polynomial.
#[derive(Clone, Debug)]
pub struct ZeroPolynomialCoefficients<FE: FiniteField> {
    coefficients: Vec<FE>,
}

impl<FE: FiniteField> ZeroPolynomialCoefficients<FE> {
    /// Return the protocol's maximum constraint degree.
    pub fn max_degree(&self) -> usize {
        self.coefficients.len()
    }

    /// Return the transmitted coefficients in increasing degree order.
    pub fn coefficients(&self) -> &[FE] {
        &self.coefficients
    }
}

/// Prover-side accumulator for the batch verification protocol.
///
/// Used by the live prover ([`crate::proof`]), whose circuit traversal produces one commitment
/// polynomial per higher degree constraint rather than a collection. Constraints are pushed with
/// [`Self::push_constraint`] as they are traversed; masking VOLEs are added by [`Self::finish`] to
/// form the coefficients of $\pi(t)$.
///
/// [`Self::push_constraint`] accumulates
/// $`A(t)=\sum_i\chi_i t^{d-d_i}\rho_i(t)`$ (aligning each constraint's coefficients to the
/// maximum degree), and [`Self::finish`] adds the masks
/// $\sum_{j=1}^{d-1}t^{j-1}\sigma_j(t)$. The maximum degree $d$ is fixed up front (the caller
/// knows it before traversal), so alignment shifts are relative to that fixed size.
pub struct BatchProverAccumulator<F, FE, L>
where
    F: FiniteField + IsSubFieldOf<FE>,
    FE: FiniteField,
    L: ExtensionFieldLifter<F, FE>,
{
    /// Coefficients of $A(t)=\sum_i\chi_i t^{d-d_i}\rho_i(t)$ in increasing degree
    /// order; length $d+1$, or empty if the maximum degree is 0 (no higher degree
    /// constraints).
    aggregate: Vec<FE>,
    phantom: PhantomData<(F, L)>,
}

impl<F, FE, L> BatchProverAccumulator<F, FE, L>
where
    F: FiniteField + IsSubFieldOf<FE>,
    FE: FiniteField,
    L: ExtensionFieldLifter<F, FE>,
{
    /// Create an accumulator for constraints whose maximum degree is `max_degree`.
    ///
    /// A degree-$d$ polynomial has $d+1$ coefficients; the accumulator stays empty if
    /// `max_degree` is 0 (i.e. there are no higher degree constraints).
    pub fn new(max_degree: usize) -> Self {
        Self {
            aggregate: if max_degree == 0 {
                Vec::new()
            } else {
                vec![FE::ZERO; max_degree + 1]
            },
            phantom: PhantomData,
        }
    }

    /// Number of base VOLE correlations that compose into one full-field mask VOLE.
    ///
    /// The flat mask streams passed to [`Self::finish`] are chunked into blocks of this size.
    pub fn mask_vole_size() -> usize {
        L::BASIS_SIZE
    }

    /// Number of base VOLE correlations the batch masking needs for constraints whose maximum
    /// degree is `max_degree`.
    ///
    /// Batching degree-$d$ constraints requires $d-1$ full-field mask VOLEs, each composed from
    /// [`Self::mask_vole_size`] base correlations — so
    /// $(d-1)\mathtt{mask\_vole\_size()}$ in total, or 0
    /// when `max_degree` is 0 or 1 (no masks needed). This is the amount [`crate::proof`] must
    /// provision after the witness VOLEs and later draw as the two flat streams for [`Self::finish`].
    pub fn mask_vole_count(max_degree: usize) -> usize {
        max_degree.saturating_sub(1) * Self::mask_vole_size()
    }

    /// Fold one challenge-scaled, degree-aligned commitment polynomial into the aggregate.
    ///
    /// Accumulates $\chi_i t^{d-d_i}\rho_i(t)$, where $d$ is the maximum degree fixed at
    /// construction and $d_i$ is `constraint.degree()`. Summing constraints one at a time builds
    /// exactly $A(t)=\sum_i\chi_i t^{d-d_i}\rho_i(t)$.
    ///
    /// Returns an error if the constraint exceeds the configured maximum degree or its committed
    /// value is nonzero.
    pub fn push_constraint(
        &mut self,
        constraint: &CommitmentPolynomial<F, FE>,
        challenge: FE,
    ) -> Result<()> {
        // Sum the challenge-scaled constraint into the aggregate, aligning the highest-degree
        // coefficients: the constraint is shifted up by a power of t, so summing constraints one
        // at a time builds exactly $A(t)=\sum_i\chi_i t^{d-d_i}\rho_i(t)$.
        let max_degree = self.max_degree();
        if max_degree == 0 || constraint.degree() > max_degree {
            bail!(
                ErrorKind::OtherError,
                "Higher degree constraint has degree {}, but the accumulator is configured for maximum degree {}",
                constraint.degree(),
                max_degree
            );
        }
        if constraint.highest_degree() != F::ZERO {
            bail!(
                ErrorKind::OtherError,
                "Higher degree constraint does not evaluate to zero"
            );
        }
        let shift = max_degree - constraint.degree();
        for (i, coefficient) in constraint.lower_coefficients().iter().enumerate() {
            self.aggregate[i + shift] += challenge * *coefficient;
        }
        // The committed (highest-degree) coefficient is scaled by the challenge too.
        // TODO: check that shift + constraint.degree() == max_degree and replace
        // TODO: the constraint.highest_degree is zero, so we should drop that altogether.
        self.aggregate[shift + constraint.degree()] += constraint.highest_degree() * challenge;
        Ok(())
    }

    /// The maximum constraint degree fixed at construction.
    ///
    /// This is the `d` used throughout the batch masking arithmetic, e.g. to size the mask VOLE
    /// stream via [`Self::mask_vole_count`].
    pub fn max_degree(&self) -> usize {
        self.aggregate.len().saturating_sub(1)
    }

    /// The aggregate's degree-$d$ coefficient
    /// $A_d=\sum_i\chi_i x_i$, where $x_i$ is the value committed by $\rho_i$.
    /// An honest prover always commits zero here because every constraint evaluates to zero on
    /// the witness. Returns `FE::ZERO` if the accumulator has no higher-degree constraints.
    pub fn top_coefficient(&self) -> FE {
        // TODO: revisit the default value once the proof path activates selectively the higher-degree polynomial only when needed.
        self.aggregate.last().copied().unwrap_or(FE::ZERO)
    }

    /// Evaluate the pre-masking aggregate
    /// $A(t)=\sum_i\chi_i t^{d-d_i}\rho_i(t)$ at `point`.
    /// Used to check consistency with the verifier's homomorphic evaluation.
    pub fn evaluate_at(&self, point: FE) -> FE {
        evaluate_poly(&self.aggregate, point)
    }

    /// Add the masking VOLEs to form the coefficients of $\pi(t)$.
    ///
    /// The mask VOLEs are supplied as two flat streams of base-VOLE correlations — `mask_values`
    /// (the $s_j$ material) and `mask_masks` (the $w_j$ material) — each a concatenation of
    /// $d-1$ blocks of [`Self::mask_vole_size`] elements. This organizes them into the per-mask
    /// blocks, composes each into the full-field $\sigma_j(t)=w_j+s_jt$, then computes
    /// $\pi(t)=A(t)+\sum_{j=1}^{d-1}t^{j-1}\sigma_j(t)$.
    /// The aggregate's degree-$d$ coefficient commits to zero for an honest
    /// prover and is omitted, so $\pi(t)$ has degree at most $d-1$ and is returned as the $d$
    /// coefficients $[\pi_0,\ldots,\pi_{d-1}]$. The result is empty if there were no higher degree
    /// constraints.
    ///
    /// Both streams must have length $(d-1)\mathtt{mask\_vole\_size()}$.
    /// The caller (which owns the VOLE layout) is responsible
    /// for drawing the correct contiguous base-VOLE correlations.
    pub fn finish(
        self,
        mask_values: &[F],
        mask_masks: &[FE],
    ) -> Result<ZeroPolynomialCoefficients<FE>> {
        debug_assert_eq!(self.top_coefficient(), FE::ZERO);
        let degree = self.max_degree();
        let expected_mask_count = Self::mask_vole_count(degree);
        let mask_vole_size = Self::mask_vole_size();
        if mask_vole_size == 0 {
            bail!(
                ErrorKind::OtherError,
                "Extension field lifter must have a nonempty basis"
            );
        }
        if mask_values.len() != expected_mask_count || mask_masks.len() != expected_mask_count {
            bail!(
                ErrorKind::OtherError,
                "Wrong number of higher degree mask VOLEs: Expected {}, got {} values and {} masks",
                expected_mask_count,
                mask_values.len(),
                mask_masks.len()
            );
        }
        let mut pi = self.aggregate[..degree].to_vec();

        // Organize the flat streams into per-mask blocks and compose each into a full-field mask.
        let values_blocks = mask_values.chunks_exact(mask_vole_size);
        let masks_blocks = mask_masks.chunks_exact(mask_vole_size);
        for (j, (values, masks)) in values_blocks.zip(masks_blocks).enumerate() {
            // Compose the base-VOLE blocks into $\sigma_j(t)=w_j+s_jt$, then add
            // $t^{j-1}\sigma_j(t)$; `j` here is 0-based, corresponding to $j+1$ in the document.
            let s_j = L::combine_base(values);
            let w_j = L::combine_extension(masks);
            pi[j] += w_j;
            pi[j + 1] += s_j;
        }

        Ok(ZeroPolynomialCoefficients { coefficients: pi })
    }
}

/// Verifier-side accumulator for the batch verification protocol.
///
/// Used by the live verifier ([`crate::proof`]), whose circuit traversal produces one evaluation
/// per higher degree constraint. Constraints are pushed with [`Self::push_constraint`] during
/// traversal (grouped by degree, with the $\Delta$-alignment deferred). As on the prover side, the
/// maximum degree $d$ is fixed at construction. [`Self::finish`] applies the alignment, adds the
/// mask tags, and checks the prover's $\pi(\Delta)$ against
/// $q=\sum_i\chi_i\Delta^{d-d_i}\gamma_i+\sum_{j=1}^{d-1}\Delta^{j-1}\nu_j$.
pub struct BatchVerifierAccumulator<F, FE, L>
where
    F: FiniteField + IsSubFieldOf<FE>,
    FE: FiniteField,
    L: ExtensionFieldLifter<F, FE>,
{
    /// Challenge-weighted evaluations grouped by constraint degree: index $k$ holds
    /// $\sum_{i:d_i=k}\chi_i\gamma_i$. The $\Delta^{d-k}$ alignment is
    /// applied in [`Self::finish`]. Length $d+1$, or empty if the maximum degree is 0.
    aggregates: Vec<FE>,
    phantom: PhantomData<(F, L)>,
}

impl<F, FE, L> BatchVerifierAccumulator<F, FE, L>
where
    F: FiniteField + IsSubFieldOf<FE>,
    FE: FiniteField,
    L: ExtensionFieldLifter<F, FE>,
{
    /// Create a verifier accumulator for constraints whose maximum degree is `max_degree`.
    pub fn new(max_degree: usize) -> Self {
        Self {
            aggregates: if max_degree == 0 {
                Vec::new()
            } else {
                vec![FE::ZERO; max_degree + 1]
            },
            phantom: PhantomData,
        }
    }

    /// Number of base VOLE correlations that compose into one full-field mask VOLE.
    ///
    /// The flat mask-tag stream passed to [`Self::finish`] is chunked into blocks of this size.
    pub fn mask_vole_size() -> usize {
        L::BASIS_SIZE
    }

    /// Number of base VOLE correlations the batch masking needs for constraints whose maximum
    /// degree is `max_degree` (the verifier-side mirror of
    /// [`BatchProverAccumulator::mask_vole_count`]).
    ///
    /// Batching degree-$d$ constraints requires $d-1$ full-field mask VOLEs, each composed from
    /// [`Self::mask_vole_size`] base correlations — so
    /// $(d-1)\mathtt{mask\_vole\_size()}$ in total, or 0
    /// when `max_degree` is 0 or 1 (no masks needed).
    pub fn mask_vole_count(max_degree: usize) -> usize {
        max_degree.saturating_sub(1) * Self::mask_vole_size()
    }

    /// Fold one challenge-scaled constraint evaluation into the by-degree aggregate.
    ///
    /// `gamma` is the verifier's homomorphic evaluation
    /// $\gamma_i=\rho_i(\Delta)$ of the constraint, and `degree` is $d_i$.
    /// The $\Delta^{d-d_i}$ alignment is deferred to [`Self::finish`].
    ///
    /// Returns an error if `degree` exceeds the configured maximum degree.
    pub fn push_constraint(&mut self, gamma: FE, degree: usize, challenge: FE) -> Result<()> {
        // Group the challenge-weighted evaluations by degree; the $\Delta^{d-d_i}$ alignment is
        // applied after traversal using the maximum degree fixed at construction.
        let max_degree = self.max_degree();
        if max_degree == 0 || degree > max_degree {
            bail!(
                ErrorKind::OtherError,
                "Higher degree constraint has degree {}, but the accumulator is configured for maximum degree {}",
                degree,
                max_degree
            );
        }

        self.aggregates[degree] += challenge * gamma;
        Ok(())
    }

    /// The maximum constraint degree fixed at construction.
    ///
    /// This is the `d` used throughout the batch verification arithmetic, e.g. to size the mask
    /// VOLE stream via [`Self::mask_vole_count`].
    pub fn max_degree(&self) -> usize {
        self.aggregates.len().saturating_sub(1)
    }

    /// Check the prover's committed $\pi(t)$ against the verifier's expected value at $\Delta$.
    ///
    /// First enforces the degree bound: the prover must send exactly `d` coefficients (`d` the
    /// maximum constraint degree), since the degree-$d$ coefficient of $\pi(t)$ is zero and
    /// omitted. Then computes the expected value
    /// $q=\sum_i\chi_i\Delta^{d-d_i}\gamma_i+
    /// \sum_{j=1}^{d-1}\Delta^{j-1}\nu_j$
    /// (each $\nu_j=\sigma_j(\Delta)$ composed from a [`Self::mask_vole_size`]-element block of
    /// the flat `mask_tags` stream), evaluates the prover's $\pi(\Delta)$ from
    /// `prover_coefficients`, and checks they match.
    ///
    /// `mask_tags` must be a flat stream of $(d-1)\mathtt{mask\_vole\_size()}$ tags.
    /// The caller (which owns the VOLE layout) is responsible for drawing the correct contiguous
    /// base-VOLE tags; once the degree bound holds, `prover_coefficients.max_degree()` equals `d`,
    /// so the caller may size that draw from [`ZeroPolynomialCoefficients::max_degree`].
    ///
    /// Returns `Ok(())` if the check passes (including trivially when no higher degree constraint
    /// was pushed), or an error if the degree bound is violated or $\pi(\Delta)$ does not match the
    /// expected value.
    pub fn finish(
        &self,
        delta: FE,
        mask_tags: &[FE],
        prover_coefficients: &ZeroPolynomialCoefficients<FE>,
    ) -> Result<()> {
        // The degree-$d$ coefficient of $\pi(t)$ is zero and omitted, so the prover sends exactly
        // $d$ coefficients. This also enforces the degree bound on $\pi$.
        let max_higher_degree = self.max_degree();
        if prover_coefficients.max_degree() != max_higher_degree {
            bail!(
                ErrorKind::OtherError,
                "Verification failed: expected {} higher degree commitment coefficients, got {}",
                max_higher_degree,
                prover_coefficients.max_degree()
            );
        }
        let mask_vole_size = Self::mask_vole_size();
        if mask_vole_size == 0 {
            bail!(
                ErrorKind::OtherError,
                "Extension field lifter must have a nonempty basis"
            );
        }
        let expected_mask_count = Self::mask_vole_count(max_higher_degree);
        if mask_tags.len() != expected_mask_count {
            bail!(
                ErrorKind::OtherError,
                "Wrong number of higher degree mask VOLEs: Expected {}, got {}",
                expected_mask_count,
                mask_tags.len()
            );
        }
        if max_higher_degree == 0 {
            return Ok(());
        }

        // Constraint contributions: $\sum_i\chi_i\Delta^{d-d_i}\gamma_i$.
        let mut expected = FE::ZERO;
        for (degree, aggregate) in self.aggregates.iter().enumerate() {
            expected += power(delta, max_higher_degree - degree) * *aggregate;
        }

        // Mask contributions: $\sum_j\Delta^{j-1}\nu_j$, organizing the flat stream into per-mask
        // blocks and composing each into nu_j.
        let mut delta_power = FE::ONE;
        for block in mask_tags.chunks_exact(mask_vole_size) {
            expected += delta_power * L::combine_extension(block);
            delta_power *= delta;
        }

        // Evaluate the prover's $\pi(\Delta)$ and compare.
        let pi_at_delta = evaluate_poly(prover_coefficients.coefficients(), delta);

        if pi_at_delta != expected {
            bail!(
                ErrorKind::OtherError,
                "Verification failed: Higher degree constraint check failed"
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vole::{ExtensionFieldLifterF2F128b, combine};
    use proptest::{collection::vec, prelude::*, test_runner::TestCaseResult};
    use rand::{RngExt, SeedableRng};
    use swanky_field_binary::{F2, F8b, F64b, F128b};
    use swanky_rng::SwankyRng;

    struct ExtensionFieldLifterF2F64b;

    impl ExtensionFieldLifter<F2, F64b> for ExtensionFieldLifterF2F64b {
        const BASIS_SIZE: usize = 64;

        fn combine_base(values: &[F2]) -> F64b {
            combine::<F2, F64b>(values)
        }

        fn combine_extension(values: &[F64b]) -> F64b {
            combine::<F64b, F64b>(values)
        }
    }

    struct ExtensionFieldLifterF8bF128b;
    impl ExtensionFieldLifter<F8b, F128b> for ExtensionFieldLifterF8bF128b {
        const BASIS_SIZE: usize = 16;

        fn combine_base(values: &[F8b]) -> F128b {
            combine::<F8b, F128b>(values)
        }

        fn combine_extension(values: &[F128b]) -> F128b {
            combine::<F128b, F128b>(values)
        }
    }

    fn vole_streams<F, FE>(
        rng: &mut SwankyRng,
        delta: FE,
        count: usize,
    ) -> (Vec<F>, Vec<FE>, Vec<FE>)
    where
        F: FiniteField + IsSubFieldOf<FE>,
        FE: FiniteField,
    {
        let values: Vec<F> = (0..count).map(|_| F::random(rng)).collect();
        let masks: Vec<FE> = (0..count).map(|_| FE::random(rng)).collect();
        let tags = (0..count).map(|k| values[k] * delta + masks[k]).collect();
        (values, masks, tags)
    }

    struct IdentityLifter;
    impl ExtensionFieldLifter<F128b, F128b> for IdentityLifter {
        const BASIS_SIZE: usize = 1;
        fn combine_base(values: &[F128b]) -> F128b {
            values[0]
        }
        fn combine_extension(values: &[F128b]) -> F128b {
            values[0]
        }
    }

    // Strategy to generate pairs `(d, degrees)` where `d` is a maximum degree
    // and `degrees` is a vector of polynomial degrees less than or equal to `d`.
    fn strategy_degrees(min_degree: usize) -> impl Strategy<Value = (usize, Vec<usize>)> {
        (min_degree..=20).prop_flat_map(|d| (Just(d), vec(0..=d, 0..=if d == 0 { 0 } else { 20 })))
    }

    fn random_polynomial_constraint<F: FiniteField + IsSubFieldOf<FE>, FE: FiniteField>(
        rng: &mut SwankyRng,
        degree: usize,
    ) -> CommitmentPolynomial<F, FE> {
        CommitmentPolynomial::from_parts((0..degree).map(|_| FE::random(rng)).collect(), F::ZERO)
    }

    fn spec_power<FE: FiniteField>(point: FE, degree: usize) -> FE {
        (0..degree).fold(FE::ONE, |acc, _| acc * point)
    }

    fn spec_polynomial_evaluation<FE: FiniteField>(coefficients: &[FE], point: FE) -> FE {
        coefficients
            .iter()
            .enumerate()
            .map(|(k, c)| *c * spec_power(point, k))
            .sum()
    }

    // test1: Degree bounds and coefficient count.
    // Both accumulators accept constraints within the configured maximum degree and reject larger ones.
    // The prover sends exactly max_degree coefficients, and the verifier accepts the resulting proof.
    fn degree_bounds_and_coefficient_count<F, FE, L>(
        seed: [u8; 16],
        d: usize,
        num_polynomials: usize,
        excess: usize,
    ) -> TestCaseResult
    where
        F: FiniteField + IsSubFieldOf<FE>,
        FE: FiniteField,
        L: ExtensionFieldLifter<F, FE>,
    {
        let rng = &mut SwankyRng::from_seed(seed.into());
        let delta = FE::random(rng);
        let mut prover = BatchProverAccumulator::<F, FE, L>::new(d);
        let mut verifier = BatchVerifierAccumulator::<F, FE, L>::new(d);
        for _ in 0..num_polynomials {
            let degree = rng.random_range(0..=d);
            let poly = random_polynomial_constraint::<F, FE>(rng, degree);
            let chi = FE::random(rng);
            let gamma = poly.evaluate_at_point(delta);
            prop_assert!(prover.push_constraint(&poly, chi).is_ok());
            prop_assert!(verifier.push_constraint(gamma, degree, chi).is_ok());
        }
        let bad = random_polynomial_constraint::<F, FE>(rng, d + excess);
        let chi = FE::random(rng);
        let err_prover = prover.push_constraint(&bad, chi).unwrap_err();
        let err_verifier = verifier
            .push_constraint(bad.evaluate_at_point(delta), bad.degree(), chi)
            .unwrap_err();
        prop_assert!(
            err_prover
                .to_string()
                .contains("but the accumulator is configured for maximum degree")
        );
        prop_assert!(
            err_verifier
                .to_string()
                .contains("but the accumulator is configured for maximum degree")
        );
        let (values, masks, tags) =
            vole_streams::<F, FE>(rng, delta, d.saturating_sub(1) * L::BASIS_SIZE);
        let pi = prover.finish(&values, &masks).unwrap();
        prop_assert_eq!(pi.coefficients().len(), d);
        prop_assert_eq!(pi.max_degree(), d);
        prop_assert!(verifier.finish(delta, &tags, &pi).is_ok());
        Ok(())
    }

    proptest! {
        #[test]
        fn test1_degree_bounds_and_coefficient_count(
            seed in any::<[u8; 16]>(),
            d in 1usize..=20,
            num_polynomials in 0usize..=20,
            excess in 1usize..=4,
        ) {
            degree_bounds_and_coefficient_count::<F2, F128b, ExtensionFieldLifterF2F128b>(
                seed, d, num_polynomials, excess,
            )?;
            degree_bounds_and_coefficient_count::<F2, F64b, ExtensionFieldLifterF2F64b>(
                seed, d, num_polynomials, excess,
            )?;
            degree_bounds_and_coefficient_count::<F8b, F128b, ExtensionFieldLifterF8bF128b>(
                seed, d, num_polynomials, excess,
            )?;
            degree_bounds_and_coefficient_count::<F128b, F128b, IdentityLifter>(
                seed, d, num_polynomials, excess,
            )?;
        }
    }

    // test2: Incremental aggregation.
    // After each constraint is pushed, the prover’s aggregate evaluation matches an independent reference
    // sum with challenge scaling and degree alignment.
    // The verifier is checked against that reference too, using delta = 0, 1, and a random value.
    fn incremental_aggregation_matches_reference<F, FE, L>(
        seed: [u8; 16],
        d: usize,
        degrees: &[usize],
    ) -> TestCaseResult
    where
        F: FiniteField + IsSubFieldOf<FE>,
        FE: FiniteField,
        L: ExtensionFieldLifter<F, FE>,
    {
        let rng = &mut SwankyRng::from_seed(seed.into());
        for delta in [FE::ZERO, FE::ONE, FE::random(rng)] {
            let mut prover = BatchProverAccumulator::<F, FE, L>::new(d);
            let mut verifier = BatchVerifierAccumulator::<F, FE, L>::new(d);
            let (_, _, tags) =
                vole_streams::<F, FE>(rng, delta, d.saturating_sub(1) * L::BASIS_SIZE);
            let mask: FE = tags
                .chunks_exact(L::BASIS_SIZE)
                .enumerate()
                .map(|(j, block)| spec_power(delta, j) * L::combine_extension(block))
                .sum();
            let mut oracle = ZeroPolynomialCoefficients {
                coefficients: vec![FE::ZERO; d],
            };
            if d > 0 {
                oracle.coefficients[0] = mask;
            }
            let mut expected = FE::ZERO;
            prop_assert_eq!(prover.evaluate_at(delta), expected);
            prop_assert!(verifier.finish(delta, &tags, &oracle).is_ok());
            for (i, &degree) in degrees.iter().enumerate() {
                let rho = random_polynomial_constraint::<F, FE>(rng, degree);
                let chi = [FE::ONE, FE::ZERO, FE::random(rng)][i % 3];
                expected += chi
                    * spec_power(delta, d - degree)
                    * spec_polynomial_evaluation(rho.lower_coefficients(), delta);
                prover.push_constraint(&rho, chi).unwrap();
                verifier
                    .push_constraint(rho.evaluate_at_point(delta), degree, chi)
                    .unwrap();
                prop_assert_eq!(prover.evaluate_at(delta), expected);
                // A constant proof checks the verifier against the independent scalar reference.
                oracle.coefficients[0] = expected + mask;
                prop_assert!(verifier.finish(delta, &tags, &oracle).is_ok());
            }
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn test2_incremental_aggregation_matches_reference(
            seed in any::<[u8; 16]>(),
            (d, degrees) in strategy_degrees(0),
        ) {
            incremental_aggregation_matches_reference::<F2, F128b, ExtensionFieldLifterF2F128b>(
                seed, d, &degrees,
            )?;
            incremental_aggregation_matches_reference::<F2, F64b, ExtensionFieldLifterF2F64b>(
                seed, d, &degrees,
            )?;
            incremental_aggregation_matches_reference::<F8b, F128b, ExtensionFieldLifterF8bF128b>(
                seed, d, &degrees,
            )?;
            incremental_aggregation_matches_reference::<F128b, F128b, IdentityLifter>(
                seed, d, &degrees,
            )?;
        }
    }

    // test3: Coefficient tampering.
    // An honest proof passes. Changing one transmitted coefficient by a nonzero amount causes rejection.
    // A nonzero delta ensures the change affects the evaluation.
    fn tampering_coefficient<F, FE, L>(
        seed: [u8; 16],
        d: usize,
        degrees: &[usize],
        coefficient: usize,
    ) -> TestCaseResult
    where
        F: FiniteField + IsSubFieldOf<FE>,
        FE: FiniteField,
        L: ExtensionFieldLifter<F, FE>,
    {
        let rng = &mut SwankyRng::from_seed(seed.into());
        let delta = FE::random_nonzero(rng);
        let mut prover = BatchProverAccumulator::<F, FE, L>::new(d);
        let mut verifier = BatchVerifierAccumulator::<F, FE, L>::new(d);
        for &degree in degrees {
            let rho = random_polynomial_constraint::<F, FE>(rng, degree);
            let chi = FE::random(rng);
            prover.push_constraint(&rho, chi).unwrap();
            verifier
                .push_constraint(rho.evaluate_at_point(delta), degree, chi)
                .unwrap();
        }
        let (values, masks, tags) =
            vole_streams::<F, FE>(rng, delta, d.saturating_sub(1) * L::BASIS_SIZE);
        let mut pi = prover.finish(&values, &masks).unwrap();
        prop_assert!(verifier.finish(delta, &tags, &pi).is_ok());
        pi.coefficients[coefficient % d] += FE::random_nonzero(rng);
        let err = verifier.finish(delta, &tags, &pi).unwrap_err();

        prop_assert!(
            err.to_string()
                .contains("Verification failed: Higher degree constraint check failed")
        );
        Ok(())
    }

    proptest! {
        #[test]
        fn test3_tampering_coefficient(
            seed in any::<[u8; 16]>(),
            (d, degrees) in strategy_degrees(1),
            coefficient in 0usize..20,
        ) {
            tampering_coefficient::<F2, F128b, ExtensionFieldLifterF2F128b>(
                seed, d, &degrees, coefficient,
            )?;
            tampering_coefficient::<F2, F64b, ExtensionFieldLifterF2F64b>(
                seed, d, &degrees, coefficient,
            )?;
            tampering_coefficient::<F8b, F128b, ExtensionFieldLifterF8bF128b>(
                seed, d, &degrees, coefficient,
            )?;
            tampering_coefficient::<F128b, F128b, IdentityLifter>(
                seed, d, &degrees, coefficient,
            )?;
        }
    }

    // test4: Nonzero committed values.
    // The prover rejects a constraint whose highest coefficient is non-zero (the committed value),
    // including when its challenge is zero.
    fn nonzero_committed_value_is_rejected<F, FE, L>(
        seed: [u8; 16],
        d: usize,
        degree: usize,
    ) -> TestCaseResult
    where
        F: FiniteField + IsSubFieldOf<FE>,
        FE: FiniteField,
        L: ExtensionFieldLifter<F, FE>,
    {
        let rng = &mut SwankyRng::from_seed(seed.into());
        let rho = random_polynomial_constraint::<F, FE>(rng, degree % (d + 1))
            .addc(F::random_nonzero(rng));
        for chi in [FE::ZERO, FE::ONE, FE::random(rng)] {
            let mut prover = BatchProverAccumulator::<F, FE, L>::new(d);

            let err = prover.push_constraint(&rho, chi).unwrap_err();
            prop_assert!(
                err.to_string()
                    .contains("Higher degree constraint does not evaluate to zero")
            );
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn test4_nonzero_committed_value_is_rejected(
            seed in any::<[u8; 16]>(),
            d in 1usize..=20,
            degree in 0usize..=20,
        ) {
            nonzero_committed_value_is_rejected::<F2, F128b, ExtensionFieldLifterF2F128b>(
                seed, d, degree,
            )?;
            nonzero_committed_value_is_rejected::<F2, F64b, ExtensionFieldLifterF2F64b>(
                seed, d, degree,
            )?;
            nonzero_committed_value_is_rejected::<F8b, F128b, ExtensionFieldLifterF8bF128b>(
                seed, d, degree,
            )?;
            nonzero_committed_value_is_rejected::<F128b, F128b, IdentityLifter>(seed, d, degree)?;
        }
    }

    // test5: Mask stream lengths.
    // Both sides accept correctly sized mask streams and reject streams that are too short or too long.
    // This includes degrees zero and one, which require no masks.
    fn malformed_mask_streams_are_rejected<F, FE, L>(d: usize) -> TestCaseResult
    where
        F: FiniteField + IsSubFieldOf<FE>,
        FE: FiniteField,
        L: ExtensionFieldLifter<F, FE>,
    {
        for d in [0, 1, d] {
            let n = d.saturating_sub(1) * L::BASIS_SIZE;
            let values = vec![F::ZERO; n + 1];
            let masks = vec![FE::ZERO; n + 1];
            let pi = ZeroPolynomialCoefficients {
                coefficients: vec![FE::ZERO; d],
            };
            let prover = || BatchProverAccumulator::<F, FE, L>::new(d);
            let verifier = || BatchVerifierAccumulator::<F, FE, L>::new(d);
            prop_assert!(prover().finish(&values[..n], &masks[..n]).is_ok());
            prop_assert!(verifier().finish(FE::ONE, &masks[..n], &pi).is_ok());
            for length in [n.saturating_sub(1), n + 1] {
                if length == n {
                    continue;
                }
                let prover_err1 = prover().finish(&values[..length], &masks[..n]).unwrap_err();
                prop_assert!(
                    prover_err1
                        .to_string()
                        .contains("Wrong number of higher degree mask VOLEs")
                );
                let prover_err2 = prover().finish(&values[..n], &masks[..length]).unwrap_err();
                prop_assert!(
                    prover_err2
                        .to_string()
                        .contains("Wrong number of higher degree mask VOLEs")
                );
                let verifier_err = verifier()
                    .finish(FE::ONE, &masks[..length], &pi)
                    .unwrap_err();
                prop_assert!(
                    verifier_err
                        .to_string()
                        .contains("Wrong number of higher degree mask VOLEs")
                );
            }
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn test5_malformed_mask_streams_are_rejected(d in 0usize..=20) {
            malformed_mask_streams_are_rejected::<F2, F128b, ExtensionFieldLifterF2F128b>(d)?;
            malformed_mask_streams_are_rejected::<F2, F64b, ExtensionFieldLifterF2F64b>(d)?;
            malformed_mask_streams_are_rejected::<F8b, F128b, ExtensionFieldLifterF8bF128b>(d)?;
            malformed_mask_streams_are_rejected::<F128b, F128b, IdentityLifter>(d)?;
        }
    }

    // 6. test6: Masking arithmetic.
    // The finished polynomial’s evaluation matches an independent reference combining aligned constraints
    // and shifted VOLE masks.
    // It checks a random evaluation point, checks delta = 0, 1, and a random value, verifies
    // the lifted VOLE correlation, and confirms verifier acceptance.
    fn masking_arithmetic_matches_reference<F, FE, L>(
        seed: [u8; 16],
        d: usize,
        degrees: &[usize],
    ) -> TestCaseResult
    where
        F: FiniteField + IsSubFieldOf<FE>,
        FE: FiniteField,
        L: ExtensionFieldLifter<F, FE>,
    {
        let rng = &mut SwankyRng::from_seed(seed.into());
        for delta in [FE::ZERO, FE::ONE, FE::random(rng)] {
            let point = FE::random(rng);
            let mut prover = BatchProverAccumulator::<F, FE, L>::new(d);
            let mut verifier = BatchVerifierAccumulator::<F, FE, L>::new(d);
            let (mut expected, mut expected_delta) = (FE::ZERO, FE::ZERO);
            for &degree in degrees {
                let rho = random_polynomial_constraint::<F, FE>(rng, degree);
                let chi = FE::random(rng);
                prover.push_constraint(&rho, chi).unwrap();
                verifier
                    .push_constraint(rho.evaluate_at_point(delta), degree, chi)
                    .unwrap();
                expected += chi
                    * spec_power(point, d - degree)
                    * spec_polynomial_evaluation(rho.lower_coefficients(), point);
                expected_delta += chi
                    * spec_power(delta, d - degree)
                    * spec_polynomial_evaluation(rho.lower_coefficients(), delta);
            }
            let (values, masks, tags) =
                vole_streams::<F, FE>(rng, delta, d.saturating_sub(1) * L::BASIS_SIZE);
            for j in 0..d.saturating_sub(1) {
                let block = j * L::BASIS_SIZE..(j + 1) * L::BASIS_SIZE;
                let s = L::combine_base(&values[block.clone()]);
                let w = L::combine_extension(&masks[block.clone()]);
                prop_assert_eq!(L::combine_extension(&tags[block]), w + s * delta);
                expected += spec_power(point, j) * (w + s * point);
                expected_delta += spec_power(delta, j) * (w + s * delta);
            }
            let pi = prover.finish(&values, &masks).unwrap();
            prop_assert_eq!(
                spec_polynomial_evaluation(pi.coefficients(), point),
                expected
            );
            prop_assert_eq!(
                spec_polynomial_evaluation(pi.coefficients(), delta),
                expected_delta
            );
            prop_assert!(verifier.finish(delta, &tags, &pi).is_ok());
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn test6_masked_polynomial_matches_reference(
            seed in any::<[u8; 16]>(),
            (d, degrees) in strategy_degrees(0),
        ) {
            masking_arithmetic_matches_reference::<F2, F128b, ExtensionFieldLifterF2F128b>(
                seed, d, &degrees,
            )?;
            masking_arithmetic_matches_reference::<F2, F64b, ExtensionFieldLifterF2F64b>(
                seed, d, &degrees,
            )?;
            masking_arithmetic_matches_reference::<F8b, F128b, ExtensionFieldLifterF8bF128b>(
                seed, d, &degrees,
            )?;
            masking_arithmetic_matches_reference::<F128b, F128b, IdentityLifter>(seed, d, &degrees)?;
        }
    }
}

#[cfg(test)]
mod alt_tests;
