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
//! `finish` to form / check the masked polynomial $`\pi(t)`$.

use crate::parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM};
use crate::vole::combine;
use swanky_error::{ErrorKind, Result, bail};
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F128b};

use super::CommitmentPolynomial;

/// Number of base VOLE correlations that compose into one full-field mask VOLE (the block size the
/// flat mask streams passed to the `finish` methods are chunked into).
const MASK_VOLE_SIZE: usize = REPETITION_PARAM * VOLE_SIZE_PARAM;

/// Compute base^exp in a finite field using repeated squaring.
pub(crate) fn power(base: F128b, exp: usize) -> F128b {
    if exp == 0 {
        return F128b::ONE;
    }
    let mut result = F128b::ONE;
    let mut b = base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = result * b;
        }
        b = b * b;
        e >>= 1;
    }
    result
}

/// Evaluate the polynomial with the given `coefficients` (in increasing degree order,
/// `coefficients[k]` the coefficient of $`t^k`$) at `point`, via Horner's method.
///
/// Shared by the prover ([`BatchProverAccumulator::evaluate_at`], over its own aggregate
/// coefficients) and the verifier ([`BatchVerifierAccumulator::finish`], over the prover's
/// committed $`\pi(t)`$ coefficients).
fn evaluate_poly(coefficients: &[F128b], point: F128b) -> F128b {
    coefficients
        .iter()
        .rev()
        .fold(F128b::ZERO, |acc, c| acc * point + *c)
}

/// Prover-side accumulator for the batch verification protocol.
///
/// Used by the live prover ([`crate::proof`]), whose circuit traversal produces one commitment
/// polynomial per higher degree constraint rather than a collection. Constraints are pushed with
/// [`Self::push_constraint`] as they are traversed; masking VOLEs are added by [`Self::finish`] to
/// form the coefficients of $`\pi(t)`$.
///
/// [`Self::push_constraint`] accumulates $`\sum_i \chi_i \cdot t^{d - d_i} \cdot \rho_i(t)`$
/// (aligning each constraint's coefficients to the maximum degree), and [`Self::finish`] adds the
/// masks $`\sum_j t^{j-1} \sigma_j(t)`$. The maximum degree $`d`$ is fixed up front (the caller
/// knows it before traversal), so alignment shifts are relative to that fixed size.
pub struct BatchProverAccumulator {
    /// Coefficients of $`\sum_i \chi_i \cdot t^{d - d_i} \cdot \rho_i(t)`$ in increasing degree
    /// order; length $`d + 1`$, or empty if the maximum degree is 0 (no higher degree
    /// constraints).
    aggregate: Vec<F128b>,
}

impl BatchProverAccumulator {
    /// Create an accumulator for constraints whose maximum degree is `max_degree`.
    ///
    /// A degree-`d` polynomial has `d + 1` coefficients; the accumulator stays empty if
    /// `max_degree` is 0 (i.e. there are no higher degree constraints).
    pub fn new(max_degree: usize) -> Self {
        Self {
            aggregate: if max_degree == 0 {
                Vec::new()
            } else {
                vec![F128b::ZERO; max_degree + 1]
            },
        }
    }

    /// Number of base VOLE correlations that compose into one full-field mask VOLE.
    ///
    /// The flat mask streams passed to [`Self::finish`] are chunked into blocks of this size.
    pub fn mask_vole_size() -> usize {
        MASK_VOLE_SIZE
    }

    /// Number of base VOLE correlations the batch masking needs for constraints whose maximum
    /// degree is `max_degree`.
    ///
    /// Batching degree-`d` constraints requires `d - 1` full-field mask VOLEs, each composed from
    /// [`Self::mask_vole_size`] base correlations — so `(d - 1) * mask_vole_size()` in total, or 0
    /// when `max_degree` is 0 or 1 (no masks needed). This is the amount [`crate::proof`] must
    /// provision after the witness VOLEs and later draw as the two flat streams for [`Self::finish`].
    pub fn mask_vole_count(max_degree: usize) -> usize {
        max_degree.saturating_sub(1) * MASK_VOLE_SIZE
    }

    /// Fold one challenge-scaled, degree-aligned commitment polynomial into the aggregate.
    ///
    /// Accumulates `challenge * t^(d - constraint.degree()) * constraint(t)`, where `d` is the
    /// maximum degree fixed at construction. Summing constraints one at a time this way builds
    /// exactly `sum_i chi_i * t^(d - d_i) * rho_i(t)`.
    pub fn push_constraint(
        &mut self,
        constraint: &CommitmentPolynomial<F2, F128b>,
        challenge: F128b,
    ) {
        // Sum the challenge-scaled constraint into the aggregate, aligning the highest-degree
        // coefficients: the constraint is shifted up by a power of t, so summing constraints one
        // at a time builds exactly sum_i chi_i * t^(d - d_i) * rho_i(t).
        debug_assert!(
            constraint.degree() < self.aggregate.len(),
            "Internal invariant failed: higher degree constraint of degree {} exceeds the maximum degree {} computed during preparation",
            constraint.degree(),
            self.aggregate.len().saturating_sub(1),
        );
        let shift = self.aggregate.len() - (constraint.degree() + 1);
        for (i, coefficient) in constraint.lower_coefficients().iter().enumerate() {
            self.aggregate[i + shift] += challenge * *coefficient;
        }
        // The committed (highest-degree) coefficient is scaled by the challenge too.
        self.aggregate[shift + constraint.degree()] += constraint.highest_degree() * challenge;
    }

    /// The maximum degree among the constraints pushed so far (0 if none were pushed).
    ///
    /// This is the `d` used throughout the batch masking arithmetic, e.g. to size the mask VOLE
    /// stream via [`Self::mask_vole_count`].
    pub fn max_degree(&self) -> usize {
        self.aggregate.len().saturating_sub(1)
    }

    /// The aggregate's degree-`d` (highest) coefficient, i.e. the challenge-weighted sum of the
    /// committed constraint values. An honest prover always commits zero here (every constraint
    /// evaluates to zero on the witness). Returns [`F128b::ZERO`] if no constraint was pushed.
    pub fn top_coefficient(&self) -> F128b {
        self.aggregate.last().copied().unwrap_or(F128b::ZERO)
    }

    /// Evaluate the (pre-masking) aggregate polynomial $`\sum_i \chi_i t^{d - d_i} \rho_i(t)`$ at
    /// `point`. Used to check consistency with the verifier's homomorphic evaluation.
    pub fn evaluate_at(&self, point: F128b) -> F128b {
        evaluate_poly(&self.aggregate, point)
    }

    /// Add the masking VOLEs to form the coefficients of $`\pi(t)`$.
    ///
    /// The mask VOLEs are supplied as two flat streams of base-VOLE correlations — `mask_values`
    /// (the $`s_j`$ material) and `mask_masks` (the $`w_j`$ material) — each a concatenation of
    /// $`d - 1`$ blocks of `MASK_VOLE_SIZE` elements. This organizes them into the per-mask
    /// blocks, composes each into the full-field $`\sigma_j(t) = w_j + s_j \cdot t`$ via
    /// `combine`, then computes `pi(t) = aggregate(t) + sum_{j=1}^{d-1} t^(j-1) * sigma_j(t)` for
    /// the maximum degree `d`. The aggregate's degree-`d` coefficient commits to zero for an honest
    /// prover and is omitted, so `pi(t)` has degree at most `d - 1` and is returned as the `d`
    /// coefficients `[pi_0, ..., pi_{d-1}]`. The result is empty if there were no higher degree
    /// constraints.
    ///
    /// Both streams must have length `(d - 1) * ``MASK_VOLE_SIZE`. The caller (which owns the
    /// VOLE layout) is responsible for drawing the correct contiguous base-VOLE correlations.
    pub fn finish(self, mask_values: &[F128b], mask_masks: &[F128b]) -> Vec<F128b> {
        debug_assert_eq!(self.top_coefficient(), F128b::ZERO);
        let degree = self.max_degree();
        let mut pi = self.aggregate[..degree].to_vec();

        // Organize the flat streams into per-mask blocks and compose each into a full-field mask.
        let values_blocks = mask_values.chunks_exact(MASK_VOLE_SIZE);
        let masks_blocks = mask_masks.chunks_exact(MASK_VOLE_SIZE);
        for (j, (values, masks)) in values_blocks.zip(masks_blocks).enumerate() {
            // Compose the base-VOLE blocks into the full-field mask sigma_j(t) = w_j + s_j * t,
            // then add t^(j-1) * sigma_j(t); `j` here is 0-based while the paper's is 1-based.
            let s_j = combine(values);
            let w_j = combine(masks);
            pi[j] += w_j;
            pi[j + 1] += s_j;
        }

        pi
    }
}

/// Verifier-side accumulator for the batch verification protocol.
///
/// Used by the live verifier ([`crate::proof`]), whose circuit traversal produces one evaluation
/// per higher degree constraint. Constraints are pushed with [`Self::push_constraint`] during
/// traversal (grouped by degree, with the $`\Delta`$-alignment deferred), and [`Self::finish`]
/// applies the alignment, adds the mask tags, and checks the prover's $`\pi(\Delta)`$ against the
/// verifier's expected value $`\sum_i \chi_i \Delta^{d - d_i} \gamma_i + \sum_j \Delta^{j-1}
/// \nu_j`$.
pub struct BatchVerifierAccumulator {
    /// Challenge-weighted evaluations grouped by constraint degree: index `d_i` holds
    /// $`\sum_{i : \deg = d_i} \chi_i \cdot \gamma_i`$. The $`\Delta^{d - d_i}`$ alignment is
    /// applied in [`Self::finish`], once the maximum degree is known.
    aggregates: Vec<F128b>,
}

impl BatchVerifierAccumulator {
    /// Create an empty verifier accumulator.
    pub fn new() -> Self {
        Self {
            aggregates: Vec::new(),
        }
    }

    /// Number of base VOLE correlations that compose into one full-field mask VOLE.
    ///
    /// The flat mask-tag stream passed to [`Self::finish`] is chunked into blocks of this size.
    pub fn mask_vole_size() -> usize {
        MASK_VOLE_SIZE
    }

    /// Number of base VOLE correlations the batch masking needs for constraints whose maximum
    /// degree is `max_degree` (the verifier-side mirror of
    /// [`BatchProverAccumulator::mask_vole_count`]).
    ///
    /// Batching degree-`d` constraints requires `d - 1` full-field mask VOLEs, each composed from
    /// [`Self::mask_vole_size`] base correlations — so `(d - 1) * mask_vole_size()` in total, or 0
    /// when `max_degree` is 0 or 1 (no masks needed).
    pub fn mask_vole_count(max_degree: usize) -> usize {
        max_degree.saturating_sub(1) * MASK_VOLE_SIZE
    }

    /// Fold one challenge-scaled constraint evaluation into the by-degree aggregate.
    ///
    /// `gamma` is the verifier's homomorphic evaluation $`\rho_i(\Delta)`$ of the constraint and
    /// `degree` its degree. The `Delta^(d - degree)` alignment is deferred to [`Self::finish`].
    pub fn push_constraint(&mut self, gamma: F128b, degree: usize, challenge: F128b) {
        // Group the challenge-weighted evaluations by degree; the Delta^(d - d_i) alignment is
        // applied once the maximum degree d is known, after traversal.
        if degree >= self.aggregates.len() {
            self.aggregates.resize(degree + 1, F128b::ZERO);
        }
        self.aggregates[degree] += challenge * gamma;
    }

    /// The maximum degree among the constraints pushed so far (0 if none were pushed).
    ///
    /// This is the `d` used throughout the batch verification arithmetic, e.g. to size the mask
    /// VOLE stream via [`Self::mask_vole_count`].
    pub fn max_degree(&self) -> usize {
        self.aggregates.len().saturating_sub(1)
    }

    /// Check the prover's committed $`\pi(t)`$ against the verifier's expected value at $`\Delta`$.
    ///
    /// First enforces the degree bound: the prover must send exactly `d` coefficients (`d` the
    /// maximum constraint degree), since the degree-`d` coefficient of $`\pi(t)`$ is zero and
    /// omitted. Then computes the expected value
    /// `q = sum_i chi_i * Delta^(d - d_i) * gamma_i + sum_{j=1}^{d-1} Delta^(j-1) * nu_j`
    /// (each `nu_j = sigma_j(Delta)` composed via `combine` from a `MASK_VOLE_SIZE`-element
    /// block of the flat `mask_tags` stream), evaluates the prover's `pi(Delta)` from
    /// `prover_coefficients`, and checks they match.
    ///
    /// `mask_tags` must be a flat stream of `(d - 1) * ``MASK_VOLE_SIZE` tags. The caller (which
    /// owns the VOLE layout) is responsible for drawing the correct contiguous base-VOLE tags;
    /// once the degree bound holds, `prover_coefficients.len()` equals `d`, so the caller may size
    /// that draw from `prover_coefficients.len()`.
    ///
    /// Returns `Ok(())` if the check passes (including trivially when no higher degree constraint
    /// was pushed), or an error if the degree bound is violated or `pi(Delta)` does not match the
    /// expected value.
    pub fn finish(
        &self,
        delta: F128b,
        mask_tags: &[F128b],
        prover_coefficients: &[F128b],
    ) -> Result<()> {
        // The degree-d coefficient of pi(t) is zero and omitted, so the prover sends exactly d
        // coefficients. This also enforces the degree bound on pi.
        let max_higher_degree = self.max_degree();
        if prover_coefficients.len() != max_higher_degree {
            bail!(
                ErrorKind::OtherError,
                "Verification failed: expected {} higher degree commitment coefficients, got {}",
                max_higher_degree,
                prover_coefficients.len()
            );
        }
        if max_higher_degree == 0 {
            return Ok(());
        }

        // Constraint contributions: sum_i chi_i * Delta^(d - d_i) * gamma_i.
        let mut expected = F128b::ZERO;
        for (degree, aggregate) in self.aggregates.iter().enumerate() {
            expected += power(delta, max_higher_degree - degree) * *aggregate;
        }

        // Mask contributions: sum_j Delta^(j-1) * nu_j, organizing the flat stream into per-mask
        // blocks and composing each into nu_j.
        let mut delta_power = F128b::ONE;
        for block in mask_tags.chunks_exact(MASK_VOLE_SIZE) {
            expected += delta_power * combine(block);
            delta_power *= delta;
        }

        // Evaluate the prover's pi(Delta) and compare.
        let pi_at_delta = evaluate_poly(prover_coefficients, delta);

        if pi_at_delta != expected {
            bail!(
                ErrorKind::OtherError,
                "Verification failed: Higher degree constraint check failed"
            );
        }

        Ok(())
    }
}

impl Default for BatchVerifierAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, thread_rng};
    use swanky_field::FiniteRing;

    fn random_f128b(rng: &mut impl Rng) -> F128b {
        F128b::random(rng)
    }

    /// Powers `[xi^0, xi^1, ..., xi^(n-1)]`, the per-constraint challenges used by the batch.
    fn challenge_powers(xi: F128b, n: usize) -> Vec<F128b> {
        let mut out = Vec::with_capacity(n);
        let mut p = F128b::ONE;
        for _ in 0..n {
            out.push(p);
            p *= xi;
        }
        out
    }

    /// A degree-1 `F2` commitment for `value`, plus its evaluation γ = ρ(Δ).
    ///
    /// This is the shape the accumulators consume (constraints are built over the base field
    /// `F2`, with masking coefficients in `F128b`).
    fn make_commitment_f2(
        rng: &mut impl Rng,
        delta: F128b,
        value: F2,
    ) -> (CommitmentPolynomial<F2, F128b>, F128b) {
        let w = random_f128b(rng);
        let poly = CommitmentPolynomial::<F2, F128b>::from_base_vole(value, w);
        let gamma = poly.evaluate_at_point(delta);
        (poly, gamma)
    }

    /// Build `num_masks` full-field mask VOLEs as the flat base-VOLE streams the accumulators'
    /// `finish` methods consume.
    ///
    /// Returns `(values, masks, tags)`, each `num_masks * MASK_VOLE_SIZE` long, with
    /// `tags[k] = values[k] * delta + masks[k]`. Because `combine` is linear, this makes each
    /// block satisfy `combine(tags) = delta * combine(values) + combine(masks) = sigma_j(Delta)`,
    /// i.e. the verifier's tag composes to the prover's mask polynomial evaluated at Δ.
    fn make_mask_blocks(
        rng: &mut impl Rng,
        delta: F128b,
        num_masks: usize,
    ) -> (Vec<F128b>, Vec<F128b>, Vec<F128b>) {
        let n = num_masks * MASK_VOLE_SIZE;
        let mut values = Vec::with_capacity(n);
        let mut masks = Vec::with_capacity(n);
        let mut tags = Vec::with_capacity(n);
        for _ in 0..n {
            let u = random_f128b(rng);
            let w = random_f128b(rng);
            values.push(u);
            masks.push(w);
            tags.push(u * delta + w);
        }
        (values, masks, tags)
    }

    /// Create a commitment polynomial from a base VOLE for a value x.
    /// Prover: ρ(t) = w + x·t
    /// Verifier: γ = ρ(Δ) = w + x·Δ
    fn make_commitment(
        rng: &mut impl Rng,
        delta: F128b,
        value: F128b,
    ) -> (CommitmentPolynomial<F128b, F128b>, F128b) {
        let w = random_f128b(rng);
        let poly = CommitmentPolynomial::<F128b, F128b>::from_base_vole(value, w);
        let gamma = poly.evaluate_at_point(delta);
        (poly, gamma)
    }

    #[test]
    fn test_commitment_polynomial_basic() {
        let rng = &mut thread_rng();
        let delta = random_f128b(rng);
        let x = random_f128b(rng);
        let w = random_f128b(rng);

        let poly = CommitmentPolynomial::<F128b, F128b>::from_base_vole(x, w);
        assert_eq!(poly.degree(), 1);
        assert_eq!(poly.lower_coefficients(), &[w]);
        assert_eq!(poly.highest_degree(), x);
        assert_eq!(poly.evaluate_at_point(delta), w + x * delta);
    }

    #[test]
    fn test_addc() {
        let rng = &mut thread_rng();
        let delta = random_f128b(rng);
        let x = random_f128b(rng);
        let c = random_f128b(rng);
        let w = random_f128b(rng);

        let poly_x = CommitmentPolynomial::<F128b, F128b>::from_base_vole(x, w);
        let gamma_x = poly_x.evaluate_at_point(delta);

        let poly_sum = poly_x.addc(c);
        let gamma_sum = poly_sum.evaluate_at_point(delta);

        // Verifier: γ = γ_x + c·Δ^d
        let d = poly_x.degree();
        let expected_gamma = gamma_x + c * power(delta, d);
        assert_eq!(gamma_sum, expected_gamma);
    }

    #[test]
    fn test_add_same_degree() {
        let rng = &mut thread_rng();
        let delta = random_f128b(rng);

        let val_x = random_f128b(rng);
        let val_y = random_f128b(rng);
        let (poly_x, gamma_x) = make_commitment(rng, delta, val_x);
        let (poly_y, gamma_y) = make_commitment(rng, delta, val_y);

        let poly_sum = poly_x.add(&poly_y);
        let gamma_sum = poly_sum.evaluate_at_point(delta);

        // Both degree 1, d = 1, shifts are 0
        assert_eq!(gamma_sum, gamma_x + gamma_y);
    }

    #[test]
    fn test_add_different_degree() {
        let rng = &mut thread_rng();
        let delta = random_f128b(rng);

        // Create a degree-1 polynomial
        let val_x = random_f128b(rng);
        let (poly_x, gamma_x) = make_commitment(rng, delta, val_x);
        // Create a degree-2 polynomial by multiplying two degree-1 polynomials
        let val_a = random_f128b(rng);
        let val_b = random_f128b(rng);
        let (poly_a, gamma_a) = make_commitment(rng, delta, val_a);
        let (poly_b, gamma_b) = make_commitment(rng, delta, val_b);
        let poly_y = poly_a.mul(&poly_b);
        let gamma_y = gamma_a * gamma_b;

        assert_eq!(poly_x.degree(), 1);
        assert_eq!(poly_y.degree(), 2);

        let poly_sum = poly_x.add(&poly_y);
        let gamma_sum = poly_sum.evaluate_at_point(delta);

        // d = max(1, 2) = 2, shift1 = 1, shift2 = 0
        // Verifier: γ = Δ^1·γ_x + Δ^0·γ_y
        let expected = delta * gamma_x + gamma_y;
        assert_eq!(gamma_sum, expected);
    }

    #[test]
    fn test_mulc() {
        let rng = &mut thread_rng();
        let delta = random_f128b(rng);
        let c = random_f128b(rng);

        let val_x = random_f128b(rng);
        let (poly_x, gamma_x) = make_commitment(rng, delta, val_x);

        let poly_prod = poly_x.mulc(c);
        let gamma_prod = poly_prod.evaluate_at_point(delta);

        // Verifier: γ = c·γ_x
        assert_eq!(gamma_prod, c * gamma_x);
    }

    #[test]
    fn test_mul() {
        let rng = &mut thread_rng();
        let delta = random_f128b(rng);

        let val_x = random_f128b(rng);
        let val_y = random_f128b(rng);
        let (poly_x, gamma_x) = make_commitment(rng, delta, val_x);
        let (poly_y, gamma_y) = make_commitment(rng, delta, val_y);

        let poly_prod = poly_x.mul(&poly_y);
        let gamma_prod = poly_prod.evaluate_at_point(delta);

        // Verifier: γ = γ_x·γ_y
        assert_eq!(gamma_prod, gamma_x * gamma_y);
        assert_eq!(poly_prod.degree(), 2);
    }

    #[test]
    fn test_batch_verification_single_degree1() {
        let rng = &mut thread_rng();
        let delta = random_f128b(rng);
        let xi = random_f128b(rng);

        // A single degree-1 constraint. In the assert-zero regime its committed (top) value must
        // be zero, so the aggregate's top coefficient is zero and pi has degree at most 0.
        let (poly, gamma) = make_commitment_f2(rng, delta, F2::ZERO);
        let chi = challenge_powers(xi, 1);

        // Prover: fold the constraint, then finish (max_degree = 1 needs 0 mask VOLEs).
        let mut prover = BatchProverAccumulator::new(1);
        prover.push_constraint(&poly, chi[0]);
        let pi = prover.finish(&[], &[]);

        // 1 coefficient below the top (the constant term).
        assert_eq!(pi.len(), 1);

        // Verifier: fold the evaluation, then check.
        let mut verifier = BatchVerifierAccumulator::new();
        verifier.push_constraint(gamma, 1, chi[0]);
        verifier.finish(delta, &[], &pi).unwrap();
    }

    #[test]
    fn test_batch_verification_degree2() {
        let rng = &mut thread_rng();
        let delta = random_f128b(rng);
        let xi = random_f128b(rng);

        // A degree-1 constraint (committing zero) and a degree-2 constraint (a product that
        // commits zero because one factor does): [poly_a(deg 1, =0), poly_c = a*b(deg 2, =0)].
        // Both have a zero top coefficient, as the assert-zero regime requires.
        let (poly_a, gamma_a) = make_commitment_f2(rng, delta, F2::ZERO);
        let (poly_b, gamma_b) = make_commitment_f2(rng, delta, F2::ONE);
        let poly_c = poly_a.mul(&poly_b); // committed value a*b = 0
        let gamma_c = gamma_a * gamma_b;
        let chi = challenge_powers(xi, 2);

        // max_degree = 2, need 1 mask VOLE.
        let (values, masks, tags) = make_mask_blocks(rng, delta, 1);

        let mut prover = BatchProverAccumulator::new(2);
        prover.push_constraint(&poly_a, chi[0]);
        prover.push_constraint(&poly_c, chi[1]);
        let pi = prover.finish(&values, &masks);

        let mut verifier = BatchVerifierAccumulator::new();
        verifier.push_constraint(gamma_a, 1, chi[0]);
        verifier.push_constraint(gamma_c, 2, chi[1]);
        verifier.finish(delta, &tags, &pi).unwrap();
    }

    #[test]
    fn test_batch_verification_mixed_degrees() {
        let rng = &mut thread_rng();
        let delta = random_f128b(rng);
        let xi = random_f128b(rng);

        // Constraints of degrees 1, 2, 3. Committing val1 = 0 makes every product below commit
        // zero too, so all three constraints have a zero top coefficient (assert-zero regime)
        // while still exercising the degree-1/2/3 alignment.
        let (poly1, gamma1) = make_commitment_f2(rng, delta, F2::ZERO);
        let (poly2, gamma2) = make_commitment_f2(rng, delta, F2::ONE);
        let poly3 = poly1.mul(&poly2); // deg 2, committed value 0
        let gamma3 = gamma1 * gamma2;
        let (poly4, gamma4) = make_commitment_f2(rng, delta, F2::ONE);
        let poly5 = poly3.mul(&poly4); // deg 3, committed value 0
        let gamma5 = gamma3 * gamma4;
        let chi = challenge_powers(xi, 3);

        // max_degree = 3, need 2 mask VOLEs.
        let (values, masks, tags) = make_mask_blocks(rng, delta, 2);

        let mut prover = BatchProverAccumulator::new(3);
        prover.push_constraint(&poly1, chi[0]);
        prover.push_constraint(&poly3, chi[1]);
        prover.push_constraint(&poly5, chi[2]);
        let pi = prover.finish(&values, &masks);

        let mut verifier = BatchVerifierAccumulator::new();
        verifier.push_constraint(gamma1, 1, chi[0]);
        verifier.push_constraint(gamma3, 2, chi[1]);
        verifier.push_constraint(gamma5, 3, chi[2]);
        verifier.finish(delta, &tags, &pi).unwrap();
    }

    #[test]
    fn test_batch_verification_fails_with_wrong_coefficients() {
        let rng = &mut thread_rng();
        let delta = random_f128b(rng);
        let xi = random_f128b(rng);

        // Same degree-1 + degree-2 batch as `test_batch_verification_degree2`.
        let (poly_a, gamma_a) = make_commitment_f2(rng, delta, F2::ZERO);
        let (poly_b, gamma_b) = make_commitment_f2(rng, delta, F2::ONE);
        let poly_c = poly_a.mul(&poly_b);
        let gamma_c = gamma_a * gamma_b;
        let chi = challenge_powers(xi, 2);

        let (values, masks, tags) = make_mask_blocks(rng, delta, 1);

        let mut prover = BatchProverAccumulator::new(2);
        prover.push_constraint(&poly_a, chi[0]);
        prover.push_constraint(&poly_c, chi[1]);
        let mut pi = prover.finish(&values, &masks);

        // Tamper with a coefficient: verification must reject.
        pi[0] += F128b::ONE;

        let mut verifier = BatchVerifierAccumulator::new();
        verifier.push_constraint(gamma_a, 1, chi[0]);
        verifier.push_constraint(gamma_c, 2, chi[1]);
        assert!(verifier.finish(delta, &tags, &pi).is_err());
    }

    #[test]
    fn test_batch_verification_fails_with_wrong_gamma() {
        let rng = &mut thread_rng();
        let delta = random_f128b(rng);
        let xi = random_f128b(rng);

        let (poly_a, gamma_a) = make_commitment_f2(rng, delta, F2::ZERO);
        let (poly_b, _gamma_b) = make_commitment_f2(rng, delta, F2::ONE);
        let poly_c = poly_a.mul(&poly_b);
        let chi = challenge_powers(xi, 2);

        let (values, masks, tags) = make_mask_blocks(rng, delta, 1);

        let mut prover = BatchProverAccumulator::new(2);
        prover.push_constraint(&poly_a, chi[0]);
        prover.push_constraint(&poly_c, chi[1]);
        let pi = prover.finish(&values, &masks);

        // The verifier folds a wrong evaluation for the degree-2 constraint: check must reject.
        let wrong_gamma = random_f128b(rng);
        let mut verifier = BatchVerifierAccumulator::new();
        verifier.push_constraint(gamma_a, 1, chi[0]);
        verifier.push_constraint(wrong_gamma, 2, chi[1]);
        assert!(verifier.finish(delta, &tags, &pi).is_err());
    }

    #[test]
    fn test_circuit_like_polynomial_tracking() {
        // Simulate a simple circuit: x0, x1 private inputs, x2 = x0 * x1, x3 = x2 + x0
        let rng = &mut thread_rng();
        let delta = random_f128b(rng);

        let x0 = random_f128b(rng);
        let x1 = random_f128b(rng);

        // Input gates: degree-1 commitments from base VOLEs
        let (poly_x0, gamma_x0) = make_commitment(rng, delta, x0);
        let (poly_x1, gamma_x1) = make_commitment(rng, delta, x1);

        // Mul gate: x2 = x0 * x1
        let poly_x2 = poly_x0.mul(&poly_x1);
        let gamma_x2 = gamma_x0 * gamma_x1;

        // Add gate: x3 = x2 + x0 (degree alignment)
        let poly_x3 = poly_x2.add(&poly_x0);
        let gamma_x3 = gamma_x2 + delta * gamma_x0; // shift x0 by Δ^(2-1)

        // Verify the polynomial evaluation matches
        assert_eq!(poly_x3.evaluate_at_point(delta), gamma_x3);
    }
}
