/*!
Implement high-level functionality for VOLE protocol.
*/
#![allow(clippy::needless_range_loop)]
use crate::parameters::{REPETITION_PARAM, SECURITY_PARAM};
use crate::vole::all_but_one_vc::Pdecom;
use crate::vole::commit_reconstruct::{
    apply_corrections_to_q, l_hat, vole_commit, vole_open, vole_reconstruct, Commit, Corrections,
};
use crate::vole::commit_reconstruct::{recompose_d, B};
use crate::vole::consistency_check::{vole_hash, vole_hash_lockstep};
use crate::vole::crypto_primitives::{Chall1, Chall2, Chall3, Com, Seed, H1, H3, IV};
use sha3::{digest::Update, Shake128};
use swanky_field::FiniteRing;
use swanky_field_binary::F128b;
use swanky_field_binary::F2;

use super::all_but_one_vc::Decom;
use super::commit_reconstruct::compute_secret_key;
use super::consistency_check::HashConsistency;
use super::crypto_primitives::{h2_chall1, h2_chall3};
use super::AsSecretBytes;

/// Compute a seed and initialization vection from secret key and hash of
/// statement to prove.
///
/// NOTE: `mu` is coming from the FAEST spec but expected to change when doing
/// more general circuits/polynomials. It's supposed to be a representation
/// of the public components of the computation.
pub(crate) fn compute_seed_iv<Secret: AsSecretBytes>(secret: &Secret, mu: &H1) -> (Seed, IV) {
    let mut hasher = Shake128::default();

    hasher.update(secret.as_bytes().as_ref());
    hasher.update(mu.as_ref());
    let r_iv: H3 = H3::from_xof(hasher);

    // Split hash digest into `r` and `iv`. These unwraps are safe because the
    // lengths are fixed.
    let (r_slice, iv_slice) = r_iv.as_ref().split_at(SECURITY_PARAM / 8);
    let r = r_slice.try_into().unwrap();
    let iv = iv_slice.try_into().unwrap();
    (r, iv)
}

/// Compute first challenge as seen in FAEST spec Fig 8.2 and Fig 8.3.
pub(crate) fn compute_chall_1(mu: &H1, h_com: &Com, corrections: &Corrections, iv: &IV) -> Chall1 {
    h2_chall1(mu, h_com, corrections, iv)
}

/// Compute third challenge as seen in FAEST spec Fig 8.2 and Fig 8.3.
pub(crate) fn compute_chall_3(chall2: &Chall2, a_tilda: F128b, b_tilda: F128b) -> Chall3 {
    h2_chall3(chall2, &a_tilda, &b_tilda)
}

fn bits_to_u8_many(bits: &[F2]) -> Vec<u8> {
    let mut idx = 0;
    let mut b = 0u8;
    let mut out = vec![];

    for bit in bits.iter() {
        b |= (if *bit == F2::ZERO { 0 } else { 1 }) << idx;
        if idx == 7 {
            idx = 0;
            out.push(b);
            b = 0u8; // reset
        } else {
            idx += 1;
        }
    }
    if idx != 0 {
        out.push(b);
    }
    out
}

/// Structure of vole created by the functionality on the prover side.
#[derive(Clone)]
#[allow(unused)]
pub(crate) struct VoleProver {
    /// initial vector
    pub(crate) iv: IV,
    /// Decommitment
    pub(crate) decom: [Decom; REPETITION_PARAM],
    /// Corrections
    pub(crate) corrections: Corrections,
    /// u
    pub(crate) u: Vec<F2>,
    /// v
    pub(crate) v: Vec<F128b>,
    /// First challenge
    pub(crate) chall1: Chall1,
    /// consistency hash of u
    pub(crate) u_tilda: HashConsistency,
    /// hash of the consistency hash of V
    pub(crate) h_v: H1,
    /// Size of the extended witness.
    l: usize,
}

/// Create VOLEs given a statement signature on the prover side.
///
/// Adapted from parts of FAEST.sign from Fig. 8.2
#[inline(never)]
#[allow(unused)]
pub(crate) fn create_vole_prover<Secret: AsSecretBytes>(
    statement_sig: &[u8],
    secret: &Secret,
    l: usize,
) -> VoleProver {
    // line 2
    let mu: H1 = H1::from_bytes(statement_sig); // Hash the signature of the circuit+instance the prover/verifier agree to execute.

    // line 3
    let (r, iv) = compute_seed_iv(secret, &mu);

    // lines 4-5
    let t = std::time::Instant::now();
    let Commit {
        h_com,
        decom,
        corrections,
        u,
        v,
    } = vole_commit(r, iv, l_hat(l));
    log::info!("vole_commit running time: {:?}", t.elapsed());

    // lines 6
    let chall1 = compute_chall_1(&mu, &h_com, &corrections, &iv);

    // line 7-8
    // hash u
    let t = std::time::Instant::now();
    let u_tilda = vole_hash(
        &chall1,
        u[0..l + SECURITY_PARAM].iter().copied(),
        l + SECURITY_PARAM,
        u[l + SECURITY_PARAM..l + 2 * SECURITY_PARAM + B]
            .iter()
            .copied(),
        SECURITY_PARAM + B,
    );
    log::info!("vole_hash(u) running time: {:?}", t.elapsed());

    // line 9
    // hash v column-wise
    let t = std::time::Instant::now();
    let mut v_tilda: Vec<F2> = Vec::with_capacity((SECURITY_PARAM + B) * SECURITY_PARAM);
    let tmp = vole_hash_lockstep(
        &chall1,
        &v[0..l + SECURITY_PARAM],
        &v[l + SECURITY_PARAM..l_hat(l)],
    );
    for newt in tmp {
        v_tilda.extend(newt.0);
    }
    assert_eq!(v_tilda.len(), (SECURITY_PARAM + B) * SECURITY_PARAM);
    log::info!("vole_hash(V) running time: {:?}", t.elapsed());

    // line 10
    let h_v = H1::from_bytes(&bits_to_u8_many(&v_tilda));

    VoleProver {
        iv,
        decom,
        corrections,
        u,
        v,
        chall1,
        u_tilda,
        h_v,
        l,
    }
}

/// Partial decommitment produced by the prover.
pub(crate) struct PartialDecommitment {
    pdecom: Vec<Pdecom>,
    corrections: Corrections,
    iv: IV,
    u_tilda: HashConsistency,
    /// Size of extended witness. `ell` in the paper.
    l: usize,
}

/// Implements get for the functionality on the prover side
#[allow(unused)]
pub(crate) fn decommit(vole: VoleProver, chall3: &Chall3) -> PartialDecommitment {
    let t = std::time::Instant::now();
    let pdecom = vole_open(chall3, &vole.decom);
    log::info!("vole_open running time: {:?}", t.elapsed());

    PartialDecommitment {
        pdecom,
        corrections: vole.corrections,
        iv: vole.iv,
        u_tilda: vole.u_tilda,
        l: vole.l,
    }
}

/// Structure of VOLE created by the functionality on the verifier side.
#[derive(Clone)]
pub(crate) struct VoleVerifier {
    /// correlations on verifier side
    pub(crate) q: Vec<F128b>,
    /// Consistency check. TODO: update challenge appropriately!!
    #[allow(unused)]
    u_tilda: HashConsistency,
    /// Consistency check. TODO: update challenge appropriately!!
    #[allow(unused)]
    h_v: H1,
    /// secret key
    pub(crate) delta: F128b,
    /// Size of extended witness. `ell` in the paper.
    pub(crate) l: usize,
}

/// Create VOLEs given a statement signature and a proof, on the verifier side.
///
/// Adapted from parts of FAEST.verify from Fig. 8.2
#[inline(never)]
#[allow(unused)]
pub(crate) fn create_vole_verifier(
    statement_sig: &[u8],
    decommitment_prover: &PartialDecommitment,
    chall3: &Chall3,
) -> VoleVerifier {
    // line 1
    let PartialDecommitment {
        corrections,
        u_tilda,
        pdecom,
        iv,
        l,
    } = decommitment_prover;

    // line 2
    let mu: H1 = H1::from_bytes(statement_sig);

    // lines 3-4
    let t = std::time::Instant::now();
    let (h, q) = vole_reconstruct(chall3, pdecom, *iv, l_hat(*l));
    log::info!("vole_reconstruct running time: {:?}", t.elapsed());

    // line 5
    let chall1 = compute_chall_1(&mu, &h, corrections, iv);

    // lines 6-14
    let t = std::time::Instant::now();
    let q_f128b = apply_corrections_to_q(
        q,
        chall3,
        corrections,
        l_hat(*l), /* TODO: unsure about this value*/
    );
    log::info!("apply_corrections_to_q running time: {:?}", t.elapsed());

    // line 15
    // hash column-wise Q\tilda + D\tilda
    let t = std::time::Instant::now();
    let mut q_tilda: Vec<F2> = Vec::with_capacity((SECURITY_PARAM + B) * SECURITY_PARAM);
    let tmp = vole_hash_lockstep(
        &chall1,
        &q_f128b[0..l + SECURITY_PARAM],
        &q_f128b[l + SECURITY_PARAM..l_hat(*l)],
    );
    for newt in tmp {
        q_tilda.extend(newt.0);
    }
    assert_eq!(q_tilda.len(), (SECURITY_PARAM + B) * SECURITY_PARAM);

    log::info!("vole_hash(Q) running time: {:?}", t.elapsed());

    // line 11
    let t = std::time::Instant::now();
    let big_d = recompose_d(chall3, u_tilda);
    log::info!("recompose_d running time: {:?}", t.elapsed());

    // line 16
    let t = std::time::Instant::now();
    let q_xor_d: Vec<F2> = q_tilda
        .iter()
        .zip(big_d.iter())
        .map(|(a, b)| *a + *b)
        .collect();
    log::info!("Q + D running time: {:?}", t.elapsed());

    let h_v = H1::from_bytes(&bits_to_u8_many(&q_xor_d));

    // compute the secret key
    let delta = compute_secret_key(chall3);

    VoleVerifier {
        q: q_f128b,
        u_tilda: *u_tilda,
        h_v,
        delta,
        l: *l,
    }
}

/// Adpation of FAEST Verify function Fig. 8.3
#[allow(unused)]
pub(crate) fn verify(chall3: &Chall3, chall2: Chall2, a_tilda: F128b, b_tilda: F128b) -> bool {
    // Line 20
    let chall3_prime = compute_chall_3(&chall2, a_tilda, b_tilda);

    chall3_prime == *chall3
}

#[cfg(test)]
mod test {
    use std::iter::repeat_with;

    use super::{create_vole_prover, create_vole_verifier, decommit, verify};
    use super::{Chall1, Chall2, HashConsistency, H1};
    use crate::vole::crypto_primitives::CHALL2_LENGTH;
    use crate::vole::functionality::compute_chall_3;
    use rand::thread_rng;
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake128;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;
    use swanky_field_binary::{F128b, F8b};
    use swanky_serialization::CanonicalSerialize;

    /// Compute second challenge as seen in FAEST spec Fig 8.2 and Fig 8.3.
    pub(crate) fn compute_chall_2(
        chall1: &Chall1,
        u_tilda: HashConsistency,
        h_v: H1,
        masked_witnesses: &[F2],
    ) -> Chall2 {
        let mut out: Chall2 = [0u8; CHALL2_LENGTH];

        let mut hasher = Shake128::default();
        hasher.update(chall1);
        hasher.update(u_tilda.pack_to_bytes().as_slice());
        hasher.update(h_v.as_ref());

        // pack the binary field values into bytes
        for chunk in masked_witnesses.chunks(8) {
            let mut byte = 0u8;
            for (i, &b) in chunk.iter().enumerate() {
                if b == F2::ONE {
                    byte |= 1 << i;
                }
            }
            // TODO: for performance, accumulate the bytes in say 64 and hash that.
            hasher.update(&[byte]);
        }

        hasher.update(&[2u8]);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut out);
        out
    }

    fn test_vole_prover_and_verifier(how_many: usize) {
        let rng = &mut thread_rng();

        let statement_sig = vec![1u8];
        let secret = repeat_with(|| F2::random(rng))
            .take(1000)
            .collect::<Vec<F2>>();

        let vole_prover = create_vole_prover(&statement_sig, &secret, how_many);

        // Let's clone u and v so that we can test the VOLE fundamental equality at the end.
        let u = vole_prover.u.clone();
        let v = vole_prover.v.clone();

        let dummy_masked = vec![];
        let chall2 = compute_chall_2(
            &vole_prover.chall1,
            vole_prover.u_tilda,
            vole_prover.h_v,
            &dummy_masked,
        );
        let dummy_a_tilda = F128b::ZERO;
        let dummy_b_tilda = F128b::ZERO;
        let chall3 = compute_chall_3(&chall2, dummy_a_tilda, dummy_b_tilda);
        let decommitment_prover = decommit(vole_prover, &chall3);

        let vole_v = create_vole_verifier(&statement_sig, &decommitment_prover, &chall3);

        let b = verify(&chall3, chall2, dummy_a_tilda, dummy_b_tilda);

        for pos in 0..how_many {
            assert_eq!(v[pos] + u[pos] * vole_v.delta, vole_v.q[pos]);
        }

        assert!(b);
    }

    #[test]
    fn test_vole_prover_verifier() {
        let perf = false; // toggle to true for using this test for performance testing the generation of VOLEs
        if !perf {
            test_vole_prover_and_verifier(100);
        } else {
            // Same test but more voles drawn and printing the logs to monitor the timing of the different components
            use std::env;

            // if log-level `RUST_LOG` not already set, then set to info
            match env::var("RUST_LOG") {
                Ok(val) => println!("loglvl: {}", val),
                Err(_) => env::set_var("RUST_LOG", "info"),
            };

            pretty_env_logger::init_timed();
            let t = std::time::Instant::now();
            test_vole_prover_and_verifier(10_000_000);
            log::info!("VOLE-it-Head completed in: {:?}", t.elapsed());
        }
    }

    #[test]
    fn test_form() {
        let v = [27u8; 16];
        let t: F128b = F128b::from_bytes(&v.into()).unwrap();
        assert_eq!(t.to_bytes()[0], 27u8);
        assert_eq!(t.to_bytes()[1], 27u8);

        let v = 43u8;
        let v_f8b: F8b = F8b::from_bytes(&[v].into()).unwrap();
        let v_back: u8 = v_f8b.to_bytes()[0];
        assert_eq!(v_back, 43u8);
    }
}
