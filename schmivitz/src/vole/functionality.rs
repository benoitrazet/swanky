/*!
Implement high-level functionality for VOLE protocol.
*/
#![allow(dead_code)]
#![allow(clippy::needless_range_loop)]
use crate::parameters::{REPETITION_PARAM, SECURITY_PARAM};
use crate::vole::all_but_one_vc::Pdecom;
use crate::vole::commit_reconstruct::{
    apply_corrections_to_q, corrections_to_bytes, l_hat, vole_commit, vole_open, vole_reconstruct,
    Corrections,
};
use crate::vole::commit_reconstruct::{recompose_d, B};
use crate::vole::consistency_check::{decompose_bits, simply_vole_hash};
use crate::vole::crypto_primitives::{
    h1, h3, h_chall1, h_chall3, Chall1, Chall2, Chall3, Com, Seed, H1, H3, IV,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use swanky_field::{FiniteField, FiniteRing};
use swanky_field_binary::F128b;
use swanky_field_binary::F8b;
use swanky_field_binary::F2;
use swanky_serialization::CanonicalSerialize;

use super::all_but_one_vc::Decom;
use super::commit_reconstruct::{bitwise_f128b_from_f8b, bools_to_u8, chal_dec};
use super::consistency_check::{hash_consistency_to_bytes, HashConsistency};
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
    // TODO: add `h``
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

    // TODO: add more
    let mut hasher = Shake128::default();
    hasher.update(chall1);
    hasher.update(hash_consistency_to_bytes(&u_tilda).as_slice());
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

// convert a list of [`F128b`] values in column-major vectors of [`F2`].
#[inline(never)]
fn vec_f128b_to_f2(v: &[F128b]) -> Vec<Vec<F2>> {
    let how_many = v.len();
    let mut out: Vec<Vec<F2>> = Vec::with_capacity(SECURITY_PARAM);

    for _ in 0..SECURITY_PARAM {
        out.push(Vec::with_capacity(how_many));
    }

    for k in 0..how_many {
        let f128b = v[k].bit_decomposition();
        for (i, b) in f128b.iter().enumerate() {
            out[i].push(if *b { F2::ONE } else { F2::ZERO });
        }
    }

    assert_eq!(out.len(), SECURITY_PARAM);
    out
}

/// Structure of voleith created by the functionality on the prover side.
#[derive(Clone)]
pub(crate) struct VoleithProver {
    /// initial vector
    pub(crate) iv: IV,
    /// Decommitment
    pub(crate) decom: Vec<Decom>,
    /// Corrections
    pub(crate) corrections: Corrections,
    /// u
    pub(crate) u: Vec<F2>,
    /// v
    pub(crate) v: Vec<Vec<F8b>>,
    /// First challenge
    pub(crate) chall1: Chall1,
    /// consistency hash of u
    pub(crate) u_tilda: HashConsistency,
    /// hash of the consistency hash of V        
    pub(crate) h_v: H1,
}

/// Proof computed by the prover
pub(crate) struct Proof {
    corrections: Corrections,
    u_tilda: HashConsistency,
    d: Vec<F2>,     // masked witnesses
    a_tilda: F128b, // a^\tilda
    pdecom: Vec<Pdecom>,
    chall3: Chall3,
    iv: IV,
}

/// Create VOLEith given a statement signature on the prover side.
///
/// Adapted from parts of FAEST.sign from Fig. 8.2
#[inline(never)]
pub(crate) fn create_voleith_prover(statement_sig: &[u8], l: usize) -> VoleithProver {
    // line 2
    let mu: H1 = h1(statement_sig); // Hash the signature of the circuit+instance the prover/verifier agree to execute.

    // line 3
    let (r, iv) = compute_seed_iv(&[], &mu); // NOTE: there is no secret key here, it was only relevant to FAEST.

    // lines 4-5
    let t = std::time::Instant::now();
    let (h, decom, corrections, u, v) = vole_commit(r, iv, l_hat(l));
    log::info!("vole_commit running time: {:?}", t.elapsed());

    // lines 6
    let chall1 = compute_chall_1(&mu, &h, &corrections, &iv);

    // line 7-8

    println!("P chall1:{:?}", chall1);
    let t = std::time::Instant::now();
    let u_tilda = simply_vole_hash(
        &chall1,
        u[0..l + SECURITY_PARAM].iter().copied(),
        l + SECURITY_PARAM,
        u[l + SECURITY_PARAM..l + 2 * SECURITY_PARAM + B]
            .iter()
            .copied(),
        SECURITY_PARAM + B,
    );
    log::info!("simply_vole_hash(u) running time: {:?}", t.elapsed());

    // line 9
    let t = std::time::Instant::now();
    let mut v_tilda: Vec<F2> = Vec::with_capacity((l + SECURITY_PARAM) * SECURITY_PARAM);
    let v_bits: Vec<F2> = decompose_bits(&v).collect();
    assert_eq!(v_bits.len(), (l_hat(l) * SECURITY_PARAM));
    let split = l + SECURITY_PARAM; // split between x0 and x1
    let step = l_hat(l);
    for i in 0..SECURITY_PARAM {
        let start = step * i;
        let newt = simply_vole_hash(
            &chall1,
            v_bits[start..start + split].iter().copied(),
            l + SECURITY_PARAM,
            v_bits[start + split..start + step].iter().copied(),
            SECURITY_PARAM + B,
        );
        v_tilda.extend(newt);
    }
    log::info!("simply_vole_hash(V) running time: {:?}", t.elapsed());
    // println!("q_tilda {:?}", v_tilda);

    println!("LEN: {}", v_tilda.len());

    // line 10
    let h_v = h1(&bits_to_u8_many(&v_tilda));
    println!("h_v {:?}", h_v);

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
pub(crate) fn prove(
    r: VoleithProver,
    masked_witnesses: Vec<F2>,
    chall2: Chall2,
    a_tilda: F128b,
    b_tilda: F128b,
) -> Proof {
    let VoleithProver {
        iv,
        decom,
        corrections,
        u: _,
        v: _,
        chall1: _,
        u_tilda,
        h_v: _,
    } = r;

    // OBSOLETE:
    // TODO: lines 11-12
    // line 13
    //let chall2 = compute_chall_2(&chall1 /*TODO: add more */);

    // Line 18
    let chall3 = compute_chall_3(&chall2, a_tilda, b_tilda);
    println!("P chall3:{:?}", chall3);
    // lines 20-22

    let t = std::time::Instant::now();
    let pdecom = vole_open(&chall3, decom);
    log::info!("vole_open running time: {:?}", t.elapsed());

    Proof {
        corrections,
        u_tilda,
        d: masked_witnesses,
        a_tilda,
        pdecom,
        chall3,
        iv,
    }
}

/// Compute the secret key delta from a challenge
fn compute_secret_key(chall3: &Chall3) -> F128b {
    // compute the big delta
    let mut big_delta = [F8b::default(); REPETITION_PARAM];
    for tau in 0..REPETITION_PARAM {
        let delta_i = chal_dec(chall3, tau);
        let delta_f8b: F8b = bools_to_u8(&delta_i).into();
        big_delta[tau] = delta_f8b;
    }
    bitwise_f128b_from_f8b(&big_delta)
}

/// Structure of VOLEith created by the functionality on the verifier side.
#[derive(Clone)]
pub(crate) struct VoleithVerifier {
    /// correlations on verifier side
    pub(crate) q: Vec<F128b>,
    /// Second challenge
    pub(crate) chall2: Chall2,
    /// secret key
    pub(crate) delta: F128b,
}

/// Create VOLEith given a statement signature and a proof, on the verifier side.
///
/// Adapted from parts of FAEST.verify from Fig. 8.2
#[inline(never)]
pub(crate) fn create_voleith_verifier(
    statement_sig: &[u8],
    proof: &Proof,
    l: usize,
) -> VoleithVerifier {
    // line 1
    let Proof {
        corrections,
        u_tilda,
        d,
        a_tilda: _,
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
    let chall1 = compute_chall_1(&mu, &h, &corrections, &iv);

    // lines 6-14
    let t = std::time::Instant::now();
    let q_f128b = apply_corrections_to_q(
        q,
        &chall3,
        corrections,
        l_hat(l), /* TODO: unsure about this value*/
    );
    log::info!("recompose_q running time: {:?}", t.elapsed());

    let t = std::time::Instant::now();
    let q_bits = vec_f128b_to_f2(&q_f128b);
    log::info!("vec_f128b_to_f2 running time: {:?}", t.elapsed());
    //println!("q_bits {:?}", t);

    println!("V chall1:{:?}", chall1);
    let t = std::time::Instant::now();
    // TODO: this length seems off with `l`.
    let mut q_tilda: Vec<F2> = Vec::with_capacity((l + SECURITY_PARAM) * SECURITY_PARAM);
    for i in 0..SECURITY_PARAM {
        let newt = simply_vole_hash(
            &chall1,
            q_bits[i][0..l + SECURITY_PARAM].iter().copied(),
            l + SECURITY_PARAM,
            q_bits[i][l + SECURITY_PARAM..l_hat(l)].iter().copied(),
            SECURITY_PARAM + B,
        );
        q_tilda.extend(newt);
    }
    log::info!("simply_vole_hash(Q) running time: {:?}", t.elapsed());
    //println!("q_tilda {:?}", q_tilda);

    let t = std::time::Instant::now();
    let big_d = recompose_d(&chall3, u_tilda);
    log::info!("recompose_d running time: {:?}", t.elapsed());
    //let big_d_bits = f128b_to_f2(&big_d);

    let t = std::time::Instant::now();
    let q_xor_d: Vec<F2> = q_tilda
        .iter()
        .zip(big_d.iter())
        .map(|(a, b)| *a + *b)
        .collect();
    log::info!("Q + D running time: {:?}", t.elapsed());
    println!("LEN: {}", q_xor_d.len());

    let h_v = h1(&bits_to_u8_many(&q_xor_d));
    println!("h_q {:?}", h_v);

    // TODO: line 15
    // TODO: line 16

    // line 17
    let chall2 = compute_chall_2(&chall1, *u_tilda, h_v, &d);

    // compute the secret key
    let delta = compute_secret_key(&chall3);

    VoleithVerifier {
        q: q_f128b,
        chall2,
        delta,
    }
}

/// Adpation of FAEST Verify function Fig. 8.3
pub(crate) fn verify(proof: &Proof, chall2: Chall2, a_tilda: F128b, b_tilda: F128b) -> bool {
    let chall3 = proof.chall3;
    // Line 20
    let chall3_prime = compute_chall_3(&chall2, a_tilda, b_tilda);

    chall3_prime == chall3
}

#[cfg(test)]
mod test {
    use super::{
        create_voleith_prover, create_voleith_verifier, prove, vec_f128b_to_f2, verify,
        VoleithProver, VoleithVerifier,
    };
    use crate::parameters::REPETITION_PARAM;
    use crate::vole::commit_reconstruct::bitwise_f128b_from_f8b;
    use crate::vole::functionality::compute_chall_2;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;
    use swanky_field_binary::{F128b, F8b};
    use swanky_serialization::CanonicalSerialize;

    #[test]
    fn test_sign_verify() {
        let how_many = 100;
        let statement_sig = vec![1u8];
        let vole_creation = create_voleith_prover(&statement_sig, how_many);
        let VoleithProver {
            iv: _,
            decom: __m128i,
            corrections: _,
            u,
            v,
            chall1,
            u_tilda,
            h_v,
        } = vole_creation.clone();
        let dummy_masked = vec![];
        let dummy_chall2 = compute_chall_2(&chall1, u_tilda, h_v, &dummy_masked);
        let dummy_a_tilda = F128b::ZERO;
        let dummy_b_tilda = F128b::ZERO;
        let proof = prove(
            vole_creation,
            dummy_masked,
            dummy_chall2,
            dummy_a_tilda,
            dummy_b_tilda,
        );

        let VoleithVerifier { q, chall2, delta } =
            create_voleith_verifier(&statement_sig, &proof, how_many);
        let b = verify(&proof, chall2, dummy_a_tilda, dummy_b_tilda);

        let mut vs = Vec::with_capacity(how_many);
        for _ in 0..how_many {
            vs.push([F8b::ZERO; REPETITION_PARAM]);
        }

        for pos in 0..how_many {
            for tau in 0..REPETITION_PARAM {
                vs[pos][tau] = v[tau][pos];
            }
        }
        let mut v_f128b: Vec<F128b> = Vec::with_capacity(how_many);
        for pos in 0..how_many {
            let val = bitwise_f128b_from_f8b(&vs[pos]);
            v_f128b.push(val);
        }

        for pos in 0..how_many {
            assert_eq!(v_f128b[pos] + u[pos] * delta, q[pos]);
        }

        assert!(b);
    }

    #[test]
    fn test_form() {
        let v = [27u8; 16];
        let t: F128b = F128b::from_bytes(&v.into()).unwrap();
        assert_eq!(t.to_bytes()[0], 27u8);
        assert_eq!(t.to_bytes()[1], 27u8);

        let v = 43u8;
        let v_f8b: F8b = F8b::from(v);
        let v_back: u8 = v_f8b.to_bytes()[0];
        assert_eq!(v_back, 43u8);
    }

    #[test]
    fn test_f128b_to_f2() {
        let mut part1 = [0u8; 16];
        let mut part2 = [0u8; 16];
        part1[0] = 1;
        part2[0] = 2;
        part2[1] = 4;

        let t = vec_f128b_to_f2(&[
            F128b::from_bytes(&part1.into()).unwrap(),
            F128b::from_bytes(&part2.into()).unwrap(),
        ]);

        assert_eq!(t[0][0], F2::ONE);
        assert_eq!(t[1][1], F2::ONE);
        assert_eq!(t[10][1], F2::ONE);
    }
}
