# Higher-Degree Polynomial Commitments

This document describes the VOLE-based polynomial commitments and batched constraint check used for higher-degree gates in Schmivitz, following [2026-Agarwal-Baum-Braun-Scholl].

## Protocol setting

Let $\mathbb{F}_p$ be a finite base field, and let $\mathbb{F}_{p^r}$ be an extension field.
The protocol has two parties: a prover $\mathcal{P}$ and a verifier $\mathcal{V}$.
They agree on a computation, while $\mathcal{P}$ holds secret inputs and proves that evaluating the computation on those inputs gives the claimed result.

The construction has two main components:

1. commitment polynomials that support the circuit's gate operations; and
2. a batch protocol that checks many commitment polynomials of different degrees at once.

## Base VOLE

A call to $\operatorname{VOLE}(n)$ produces $n$ correlated triples.
For each $i \in \{1,\ldots,n\}$, the prover receives a random value $u_i$ and a mask $w_i$, and the verifier receives a global key $\delta$ and a tag $v_i$, such that

$$
v_i = u_i\delta + w_i.
$$

The higher-degree construction uses the same correlation with extension-field values and writes the verifier's global key as $\Delta$.

## Commitment polynomials

Definition 2 ("VOLE Commitment") of [2026-Agarwal-Baum-Braun-Scholl] defines the commitment polynomial used here. To commit to a value $x \in \mathbb{F}_p$, the prover holds a degree-$d$ polynomial

$$
\rho_x(t)
  = \rho_0 + \rho_1t + \cdots + \rho_{d-1}t^{d-1} + x t^d,
\qquad
\rho_0,\ldots,\rho_{d-1} \in \mathbb{F}_{p^r}.
$$

Thus, the committed value $x$ is the highest-degree coefficient, while the lower coefficients mask it.
The verifier holds a global key $\Delta \in \mathbb{F}_{p^r}$ that is unknown to the prover, together with the evaluation

$$
\gamma_x = \rho_x(\Delta).
$$

Degree one recovers the base VOLE relation: $\rho_x(t)=w+xt$ and $\gamma_x=w+x\Delta$.
Write $\llbracket x \rrbracket_d$ for a degree-$d$ commitment represented by $\rho_x$ on the prover side and $\gamma_x$ on the verifier side.

## Gate-by-gate commitment propagation

The gate-by-gate evaluation below is the computation performed by `VOLE-ZK.Eval` in Figure 3 of [2026-Agarwal-Baum-Braun-Scholl], using the homomorphic operations defined after Definition 2. Commitment polynomials are constructed bottom-up through circuits containing addition, addition by a constant, multiplication, and multiplication by a constant.
Every rule preserves two invariants: the output polynomial's leading coefficient is the output wire value, and the verifier's value is the output polynomial evaluated at $\Delta$.

- **Addition.**

  Given $\llbracket x \rrbracket_{d_1}$ and $\llbracket y \rrbracket_{d_2}$, let $d=\max(d_1,d_2)$.
  Align both leading coefficients at degree $d$ before adding:

  $$
  \llbracket x+y \rrbracket_d:
  \qquad
  \rho_{x+y}(t)
    = t^{d-d_1}\rho_x(t)+t^{d-d_2}\rho_y(t),
  $$

  $$
  \gamma_{x+y}
    = \Delta^{d-d_1}\gamma_x+\Delta^{d-d_2}\gamma_y.
  $$

  The powers of $t$ and $\Delta$ perform the same degree alignment on the prover and verifier sides.

- **Addition by a constant.**

  For $\llbracket x \rrbracket_d$ and $c \in \mathbb{F}_p$, define

  $$
  \llbracket x+c \rrbracket_d:
  \qquad
  \rho_{x+c}(t)=\rho_x(t)+c\,t^d,
  \qquad
  \gamma_{x+c}=\gamma_x+c\,\Delta^d.
  $$

  Only the leading coefficient changes, so the commitment remains degree $d$.

- **Multiplication by a constant.**

  For $\llbracket x \rrbracket_d$ and $c \in \mathbb{F}_p$, define

  $$
  \llbracket cx \rrbracket_d:
  \qquad
  \rho_{cx}(t)=c\,\rho_x(t),
  \qquad
  \gamma_{cx}=c\,\gamma_x.
  $$

  Scalar multiplication does not change the degree.

- **Multiplication.**

  Given $\llbracket x \rrbracket_{d_1}$ and $\llbracket y \rrbracket_{d_2}$, define

  $$
  \llbracket xy \rrbracket_{d_1+d_2}:
  \qquad
  \rho_{xy}(t)=\rho_x(t)\rho_y(t),
  \qquad
  \gamma_{xy}=\gamma_x\gamma_y.
  $$

  Polynomial multiplication makes the output degree $d_1+d_2$, and evaluation at $\Delta$ remains multiplicative.

## Batched verification

This section follows `VOLE-ZK.BatchVer` in Figure 3 of [2026-Agarwal-Baum-Braun-Scholl], with the Schmivitz adaptations identified below.

1. **Fix the batch degree.** For commitment degrees $d_1,\ldots,d_m$, let

   $$
   d=\max\{d_1,\ldots,d_m\}.
   $$

2. **Generate masking commitments.** For every $j\in\{1,\ldots,d-1\}$, the paper invokes sVOLE to obtain degree-one commitments to base-field coordinates $s_{j,0},\ldots,s_{j,r-1}\in\mathbb{F}_p$.
   Schmivitz obtains the equivalent masking material from its VOLE backend; the construction does not assume a fixed value of $r$.

3. **Compose full-field masks.** For any chosen $\mathbb{F}_p$-basis $(b_0,\ldots,b_{r-1})$ of $\mathbb{F}_{p^r}$, combine the coordinate commitments linearly to obtain

   $$
   \llbracket s_j\rrbracket_1
     =\sum_{k=0}^{r-1}b_k\llbracket s_{j,k}\rrbracket_1,
   \qquad
   s_j=\sum_{k=0}^{r-1}b_k s_{j,k}.
   $$

4. **Identify the constraint polynomials.** Let $\rho_i(t)=\rho_{z_i}(t)$ be the degree-at-most-$d_i$ polynomial for constraint value $z_i$, and let $\gamma_i=\rho_i(\Delta)$.
   The constraint $z_i=0$ holds exactly when $\rho_i$ has degree at most $d_i-1$.

5. **Name the mask polynomials.** Let

   $$
   \sigma_j(t)=w_j+s_jt,
   \qquad
   \nu_j=\sigma_j(\Delta).
   $$

   For $d\le 1$, there are no masking commitments and the corresponding sums below are empty.

6. **Choose challenge weights.** The paper samples $(\chi_1,\ldots,\chi_m)\in\mathbb{F}_{p^r}^m$.
   Schmivitz instead derives $\xi$ by Fiat–Shamir and consumes the global stream $\xi,\xi^2,\ldots$ shared with the other constraint gates; $\chi_i$ denotes the next weight assigned to constraint $i$.

7. **Compute and send the prover polynomial.** First align and aggregate the constraints:

   $$
   A(t)=\sum_{i=1}^{m}\chi_i\,t^{d-d_i}\rho_i(t),
   $$
   Its degree-$d$ coefficient is $\sum_i\chi_i z_i$ and therefore vanishes when all constraints hold.
   Then form and send

   $$
   \pi(t)=A(t)+\sum_{j=1}^{d-1}t^{j-1}\sigma_j(t).
   $$

   The paper sends this polynomial with degree at most $d-1$.
   Its degree-$d$ coefficient must therefore vanish.
   Schmivitz omits that known-zero coefficient and sends $\pi_0,\ldots,\pi_{d-1}$.

8. **Compute and verify the verifier value.** Using the $d-1$ mask tags defined above, compute

   $$
   q
     =\sum_{i=1}^{m}\chi_i\Delta^{d-d_i}\gamma_i
      +\sum_{j=1}^{d-1}\Delta^{j-1}\nu_j.
   $$
   Figure 3 prints $d$ as the upper limit of the second sum, but its preceding steps define and use only $d-1$ masks; Schmivitz uses the consistent upper limit $d-1$ shown here.
   Accept exactly when

   $$
   \pi(\Delta)=\sum_{k=0}^{d-1}\pi_k\Delta^k=q
   $$

   and the transmitted polynomial has degree at most $d-1$.
   The equality checks the prover's aligned and masked polynomial at the verifier's secret point; Schmivitz enforces the degree bound through the transmitted coefficient count.

## Schmivitz integration

The polynomial-gate API belongs in `edge/sieve-ir-api`, and the protocol implementation belongs in `edge/schmivitz`.
Schmivitz instantiates the construction with `F2` as the base field and `F128b` as the extension field.

The `CommitmentPolynomial` interface must support all four gate rules, expose the coefficients of $\rho$ for serialization, reconstruct a polynomial from received coefficients when needed, and evaluate a polynomial at a supplied point such as $\Delta$.
The batch-verification interface must accept commitment polynomials of different degrees, or stream them into an equivalent accumulator, and verify their single combined check.

Implementation should proceed in small stages: define the API, implement each operation, and add focused unit tests as functionality is filled in.
Tests should independently cover polynomial construction and evaluation, each gate rule, mixed-degree alignment, mask composition, successful batch verification, and rejection after tampering.

## Reference

- [2026-Agarwal-Baum-Braun-Scholl]. Amit Agarwal, Carsten Baum, Lennart Braun, and Peter Scholl. *Low-Bandwidth Mixed Arithmetic in VOLE-Based ZK from Low-Degree PRGs*. EUROCRYPT 2025.

[2026-Agarwal-Baum-Braun-Scholl]: https://artifacts.iacr.org/eurocrypt/2025/a8/
