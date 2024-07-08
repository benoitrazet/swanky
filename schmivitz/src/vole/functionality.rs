/*!
Implement high-level functionality for VOLE protocol.
*/
#![allow(clippy::needless_range_loop)]
use crate::parameters::{REPETITION_PARAM, SECURITY_PARAM};
use crate::vole::all_but_one_vc::Pdecom;
use crate::vole::commit_reconstruct::{
    apply_corrections_to_q, corrections_to_bytes, l_hat, vole_commit, vole_open, vole_reconstruct,
    Commit, Corrections,
};
use crate::vole::commit_reconstruct::{recompose_d, B};
use crate::vole::consistency_check::{vole_hash, vole_hash_lockstep};
use crate::vole::crypto_primitives::{
    h1, h3, h_chall1, h_chall3, Chall1, Chall2, Chall3, Com, Seed, H1, H3, IV,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use swanky_field::FiniteRing;
use swanky_field_binary::F128b;
use swanky_field_binary::F2;
use swanky_serialization::CanonicalSerialize;

use super::all_but_one_vc::Decom;
use super::commit_reconstruct::compute_secret_key;
use super::consistency_check::HashConsistency;
use super::crypto_primitives::CHALL2_LENGTH;

/// Compute a seed and initialization vection from secret key and hash of statement to prove.
///
/// NOTE: `mu` is coming from the FAEST spec but expected to change when doing
/// more general circuits/polynomials.
pub(crate) fn compute_seed_iv(sk: &[u8], mu: &H1) -> (Seed, IV) {
    let mut h3_inp = vec![];
    h3_inp.extend(sk);
    h3_inp.extend(mu);
    let r_iv: H3 = h3(&h3_inp);

    // splitting r_iv into r and iv
    let mut r: [u8; 16] = [0u8; SECURITY_PARAM / 8];
    r.copy_from_slice(&r_iv[0..SECURITY_PARAM / 8]);
    let mut iv: [u8; 16] = [0u8; 128 / 8];
    iv.copy_from_slice(&r_iv[SECURITY_PARAM / 8..(SECURITY_PARAM + 128) / 8]);
    (r, iv)
}

/// Compute first challenge as seen in FAEST spec Fig 8.2 and Fig 8.3.
pub(crate) fn compute_chall_1(mu: &H1, h_com: &Com, corrections: &Corrections, iv: &IV) -> Chall1 {
    let mut inp = vec![];
    inp.extend(mu);
    inp.extend(h_com);
    inp.extend(corrections_to_bytes(corrections));
    inp.extend(iv);
    h_chall1(&inp)
}

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
    hasher.update(&u_tilda.to_bytes().as_slice());
    hasher.update(&h_v);

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

/// Compute third challenge as seen in FAEST spec Fig 8.2 and Fig 8.3.
pub(crate) fn compute_chall_3(chall2: &Chall2, a_tilda: F128b, b_tilda: F128b) -> Chall3 {
    let mut inp: Vec<u8> = vec![];
    inp.extend(chall2);
    inp.extend(a_tilda.to_bytes().as_slice());
    inp.extend(b_tilda.to_bytes().as_slice());

    h_chall3(&inp)
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

/// Structure of voleith created by the functionality on the prover side.
#[derive(Clone)]
pub struct VoleithProver {
    /// initial vector
    pub iv: IV,
    /// Decommitment
    pub decom: [Decom; REPETITION_PARAM],
    /// Corrections
    pub corrections: Corrections,
    /// u
    pub u: Vec<F2>,
    /// v
    pub v: Vec<F128b>,
    /// First challenge
    pub chall1: Chall1,
    /// consistency hash of u
    pub u_tilda: HashConsistency,
    /// hash of the consistency hash of V        
    pub h_v: H1,
}

/// Create VOLEith given a statement signature on the prover side.
///
/// Adapted from parts of FAEST.sign from Fig. 8.2
#[inline(never)]
pub fn create_voleith_prover(statement_sig: &[u8], secret: &[u8], l: usize) -> VoleithProver {
    // line 2
    let mu: H1 = h1(statement_sig); // Hash the signature of the circuit+instance the prover/verifier agree to execute.

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
    let h_v = h1(&bits_to_u8_many(&v_tilda));

    VoleithProver {
        iv,
        decom,
        corrections,
        u,
        v,
        chall1,
        u_tilda,
        h_v,
    }
}

/// Implements get for the functionality on the prover side
pub fn decommit(decom: &[Decom], chall3: Chall3) -> Vec<Pdecom> {
    let t = std::time::Instant::now();
    let pdecom = vole_open(&chall3, decom);
    log::info!("vole_open running time: {:?}", t.elapsed());

    pdecom
}

/// Structure of VOLEith created by the functionality on the verifier side.
#[derive(Clone)]
pub struct VoleithVerifier {
    /// correlations on verifier side
    pub q: Vec<F128b>,
    /// Second challenge
    pub chall2: Chall2,
    /// secret key
    pub delta: F128b,
}

/// Proof computed by the prover
pub struct VoleVerifierArgs {
    corrections: Corrections,
    u_tilda: HashConsistency,
    d: Vec<F2>, // masked witnesses
    pdecom: Vec<Pdecom>,
    chall3: Chall3,
    iv: IV,
}

/// Create VOLEith given a statement signature and a proof, on the verifier side.
///
/// Adapted from parts of FAEST.verify from Fig. 8.2
#[inline(never)]
pub fn create_voleith_verifier(
    statement_sig: &[u8],
    proof: &VoleVerifierArgs,
    l: usize,
) -> VoleithVerifier {
    // line 1
    let VoleVerifierArgs {
        corrections,
        u_tilda,
        d,
        pdecom,
        chall3,
        iv,
    } = proof;

    // line 2
    let mu: H1 = h1(statement_sig);

    // lines 3-4
    let t = std::time::Instant::now();
    let (h, q) = vole_reconstruct(chall3, pdecom, *iv, l_hat(l));
    log::info!("vole_reconstruct running time: {:?}", t.elapsed());

    // line 5
    let chall1 = compute_chall_1(&mu, &h, corrections, iv);

    // lines 6-14
    let t = std::time::Instant::now();
    let q_f128b = apply_corrections_to_q(
        q,
        chall3,
        corrections,
        l_hat(l), /* TODO: unsure about this value*/
    );
    log::info!("apply_corrections_to_q running time: {:?}", t.elapsed());

    // line 15
    // hash column-wise Q\tilda + D\tilda
    let t = std::time::Instant::now();
    let mut q_tilda: Vec<F2> = Vec::with_capacity((SECURITY_PARAM + B) * SECURITY_PARAM);
    let tmp = vole_hash_lockstep(
        &chall1,
        &q_f128b[0..l + SECURITY_PARAM],
        &q_f128b[l + SECURITY_PARAM..l_hat(l)],
    );
    for newt in tmp {
        q_tilda.extend(newt.0);
    }
    assert_eq!(q_tilda.len(), (SECURITY_PARAM + B) * SECURITY_PARAM);

    log::info!("vole_hash(Q) running time: {:?}", t.elapsed());

    // line 11
    let t = std::time::Instant::now();
    let big_d = recompose_d(chall3, &u_tilda);
    log::info!("recompose_d running time: {:?}", t.elapsed());

    // line 16
    let t = std::time::Instant::now();
    let q_xor_d: Vec<F2> = q_tilda
        .iter()
        .zip(big_d.iter())
        .map(|(a, b)| *a + *b)
        .collect();
    log::info!("Q + D running time: {:?}", t.elapsed());

    let h_v = h1(&bits_to_u8_many(&q_xor_d));

    // line 17
    let chall2 = compute_chall_2(&chall1, u_tilda.clone(), h_v, d);

    // compute the secret key
    let delta = compute_secret_key(chall3);

    VoleithVerifier {
        q: q_f128b,
        chall2,
        delta,
    }
}

/// Adpation of FAEST Verify function Fig. 8.3
pub fn verify(proof: &VoleVerifierArgs, chall2: Chall2, a_tilda: F128b, b_tilda: F128b) -> bool {
    let chall3 = proof.chall3;
    // Line 20
    let chall3_prime = compute_chall_3(&chall2, a_tilda, b_tilda);

    chall3_prime == chall3
}

#[cfg(test)]
mod test {
    use super::{
        create_voleith_prover, create_voleith_verifier, decommit, verify, VoleithProver,
        VoleithVerifier,
    };
    use crate::vole::functionality::compute_chall_2;
    use crate::vole::functionality::compute_chall_3;
    use crate::vole::functionality::VoleVerifierArgs;
    use swanky_field::FiniteRing;
    use swanky_field_binary::{F128b, F8b};
    use swanky_serialization::CanonicalSerialize;

    fn test_vole_prover_and_verifier(how_many: usize) {
        let statement_sig = vec![1u8];
        let secret = vec![42u8];
        let vole_creation = create_voleith_prover(&statement_sig, &secret, how_many);
        let VoleithProver {
            iv,
            decom,
            corrections,
            u,
            v,
            chall1,
            u_tilda,
            h_v,
        } = vole_creation.clone();
        let dummy_masked = vec![];
        let chall2 = compute_chall_2(&chall1, u_tilda.clone(), h_v, &dummy_masked);
        let dummy_a_tilda = F128b::ZERO;
        let dummy_b_tilda = F128b::ZERO;
        let chall3 = compute_chall_3(&chall2, dummy_a_tilda, dummy_b_tilda);
        let pdecom = decommit(&decom, chall3);

        let proof = VoleVerifierArgs {
            corrections,
            u_tilda,
            pdecom,
            d: dummy_masked,
            chall3,
            iv,
        };
        let VoleithVerifier {
            q,
            chall2: chall2_verifier,
            delta,
        } = create_voleith_verifier(&statement_sig, &proof, how_many);
        let b = verify(&proof, chall2_verifier, dummy_a_tilda, dummy_b_tilda);

        for pos in 0..how_many {
            assert_eq!(v[pos] + u[pos] * delta, q[pos]);
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
            println!("VOLE-it-Head completed in: {:?}", t.elapsed());
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
