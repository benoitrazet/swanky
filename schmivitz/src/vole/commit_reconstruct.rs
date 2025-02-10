/*!
Implementation of algorithms to commit, open and reconstruct VOLEs.
 *
 */
#![allow(clippy::needless_range_loop)]
use crate::parameters::{REPETITION_PARAM, SECURITY_PARAM};
use crate::vole::all_but_one_vc::{commit, open, reconstruct, Decom, Pdecom};
use crate::vole::convert_to_vole::{convert_to_vole, convert_to_vole_verifier};
use crate::vole::crypto_primitives::{Chall3, Com, H1, H1_LENGTH, IV, PRG};
use generic_array::{arr, typenum::U16, GenericArray};
use std::{sync::mpsc::channel, thread};
use swanky_field::{FiniteRing, IsSubFieldOf};
use swanky_field_binary::{F128b, F8b, F2};
use swanky_serialization::CanonicalSerialize;

use super::consistency_check::HashConsistency;

/// Parameter used for padding for the security of the consistency check
pub(crate) const B: usize = 16;

/// Function mapping 8 booleans to [`u8`].
pub(crate) fn bools_to_u8(d: &[bool]) -> u8 {
    debug_assert_eq!(d.len(), 8);
    let mut r: u8 = 0;
    for (i, b) in d.iter().enumerate() {
        r |= if *b { 1u8 << i } else { 0u8 };
    }

    r
}

/// Type for corrections applied to voles.
#[derive(Clone, Default)]
pub(crate) struct Corrections([Vec<F2>; REPETITION_PARAM - 1]);

/// hash the commitments coming from the small-domain VOLE
fn hash_commitments(com: &[Com]) -> Com {
    assert_eq!(com.len(), REPETITION_PARAM);
    let mut com_bytes = Vec::with_capacity(H1_LENGTH * REPETITION_PARAM);
    for i in 0..REPETITION_PARAM {
        com_bytes.extend(com[i].as_ref());
    }
    H1::from_bytes(&com_bytes).into_com()
}

/// Vole Commitment
pub(crate) struct Commit {
    /// Hash of the commitments from all the small domain voles
    pub(crate) h_com: Com,
    /// Decommitment from all the small domain voles
    pub(crate) decom: [Decom; REPETITION_PARAM],
    /// Corrections,
    pub(crate) corrections: Corrections,
    /// Random masks associated to VOLEs
    pub(crate) u: Vec<F2>,
    /// Commitments associated to `u`
    pub(crate) v: Vec<F128b>,
}

/// Function generating the voles with associated commitments.
///
/// This corresponds to Figure 5.4 of the FAEST spec.
/// This function relies on multithreading to improve the time performance.
#[inline(never)]
pub(crate) fn vole_commit(r: IV, iv: IV, l: usize) -> Commit {
    let prg_seeds = PRG::new(r, iv).generate_prg_seeds(REPETITION_PARAM);
    let mut u = Vec::with_capacity(REPETITION_PARAM);
    let mut v = Vec::with_capacity(REPETITION_PARAM);
    let mut decom: [Decom; REPETITION_PARAM] = Default::default();
    let mut com = Vec::with_capacity(REPETITION_PARAM);

    // Without multithreading
    /*
    for i in 0..REPETITION_PARAM {
        let (com_i, decom_i, seeds) = commit(prg_seeds[i], iv, 8);
        let (u_i, v_i) = convert_to_vole(&seeds, iv, l, true);
        com.push(com_i);
        decom[i] = decom_i;
        u.push(u_i);
        v.push(v_i)
    }
    */

    // With multithreading
    let t = std::time::Instant::now();
    let mut txs = Vec::with_capacity(REPETITION_PARAM);
    let mut rxs = Vec::with_capacity(REPETITION_PARAM);
    for _ in 0..REPETITION_PARAM {
        let (tx, rx) = channel();
        txs.push(tx);
        rxs.push(rx);
    }
    let mut handles = Vec::new();

    for i in 0..REPETITION_PARAM {
        let tx = txs[i].clone();
        let prg_seeds_i = prg_seeds[i];
        let handle = thread::spawn(move || {
            let (com_i, decom_i, seeds) = commit(prg_seeds_i, iv, 8);
            let (u_i, v_i) = convert_to_vole(&seeds, iv, l, true);

            tx.send((com_i, decom_i, u_i, v_i)).unwrap();
        });
        handles.push(handle);
    }

    for i in 0..REPETITION_PARAM {
        let (com_i, decom_i, u_i, v_i) = rxs[i].recv().unwrap();
        com.push(com_i);
        decom[i] = decom_i;
        u.push(u_i);
        v.push(v_i);
    }
    log::info!(
        "multithreaded convert_to_vole running time: {:?}",
        t.elapsed()
    );
    // End multithreading

    // let's compute the corrections
    let t = std::time::Instant::now();
    let u_0 = u[0].clone(); // TODO: opt transmute here
    let mut corr: [Vec<F2>; REPETITION_PARAM - 1] = Default::default();
    for i in 1..REPETITION_PARAM {
        let mut ci = Vec::with_capacity(l);
        debug_assert_eq!(l, u_0.len());
        let u_i = &u[i];
        for j in 0..l {
            let c = u_0[j] + u_i[j];
            ci.push(c);
        }
        corr[i - 1] = ci;
    }
    log::info!("corrections running time: {:?}", t.elapsed());
    debug_assert_eq!(corr.len(), REPETITION_PARAM - 1);

    // Convert Vec<Vec<F8b>> to Vec<F128b> where the size of the outer vec in Vec<Vec<F8b>> is `REPETITION_PARAM`.
    let t = std::time::Instant::now();
    let mut v_out = Vec::with_capacity(l);
    let mut tmp = [F8b::ZERO; REPETITION_PARAM];
    for i in 0..l {
        for tau in 0..REPETITION_PARAM {
            tmp[tau] = v[tau][i];
        }
        v_out.push(F8b::form_superfield(&tmp.into()));
    }
    log::info!("pack to F128b running time: {:?}", t.elapsed());

    // hash the commitments
    let h_com = hash_commitments(&com);

    Commit {
        h_com,
        decom,
        corrections: Corrections(corr),
        u: u_0,
        v: v_out,
    }
}

/// Function to decompose a challenge into boolean values.
pub(crate) fn chal_dec(chal: &[u8], i: usize) -> Vec<bool> {
    //let mut dec = vec![];

    //assert!(dec.len() == REPETITION_PARAM);
    //let mut r = vec![false; 8];
    //r.copy_from_slice(&FIXED_CHALLENGE);
    //r
    let b = chal[i];
    let mut r = vec![false; 8];
    for i in 0..8 {
        r[i] = ((b >> i) & 1) != 0;
    }
    r
}

/// Function to open voles and return the associated partial decommitment.
///
/// This function implements steps 20-22 of Fig 8.2
pub(crate) fn vole_open(chal: &[u8], decom: &[Decom]) -> Vec<Pdecom> {
    let mut pdecom = Vec::with_capacity(REPETITION_PARAM);
    for i in 0..REPETITION_PARAM {
        let delta_i = chal_dec(chal, i);
        let pdecom_i = open(&decom[i], delta_i);
        pdecom.push(pdecom_i);
    }
    pdecom
}

/// Function to reconstruct voles from a challenge and partial decommitments.
///
/// This implements Figure 5.5 in FAEST spec v1.1
#[inline(never)]
pub(crate) fn vole_reconstruct(
    chal: &[u8], // bytes from fiat-shamir challenge
    pdecom: &[Pdecom],
    iv: IV,
    l: usize,
) -> (Com, Vec<Vec<F8b>>) {
    assert_eq!(pdecom.len(), REPETITION_PARAM);
    assert_eq!(chal.len(), REPETITION_PARAM);
    let mut qs = Vec::with_capacity(REPETITION_PARAM);
    let mut com = Vec::with_capacity(REPETITION_PARAM);

    // Without multithreading:
    /*
    for i in 0..REPETITION_PARAM {
        let delta = chal_dec(chal, i);
        let (com_i, seeds) = reconstruct(pdecom[i].clone(), delta.clone(), iv);
        com.push(com_i);
        let q_i = convert_to_vole_verifier(&seeds, iv, l, bools_to_u8(&delta));
        qs.push(q_i);
    }
    */

    // With multithreading:
    let mut txs = Vec::with_capacity(REPETITION_PARAM);
    let mut rxs = Vec::with_capacity(REPETITION_PARAM);
    for _ in 0..REPETITION_PARAM {
        let (tx, rx) = channel();
        txs.push(tx);
        rxs.push(rx);
    }
    let mut handles = Vec::new();

    for i in 0..REPETITION_PARAM {
        let delta = chal_dec(chal, i);
        let (com_i, seeds) = reconstruct(pdecom[i].clone(), delta.clone(), iv);
        com.push(com_i);
        assert_eq!(seeds.len(), 256);

        let tx = txs[i].clone();
        let handle = thread::spawn(move || {
            let q_i = convert_to_vole_verifier(&seeds, iv, l, bools_to_u8(&delta));
            tx.send(q_i).unwrap();
        });
        handles.push(handle);
    }

    for i in 0..REPETITION_PARAM {
        let q_i = rxs[i].recv().unwrap();
        qs.push(q_i);
    }
    // End multithreading

    // hash the commitments
    let h_com = hash_commitments(&com);

    (h_com, qs)
}

// Compute the secret key delta from a challenge
pub(crate) fn compute_secret_key(chall3: &Chall3) -> GenericArray<F8b, U16> {
    // compute the big delta
    (0..REPETITION_PARAM)
        .map(|tau| {
            let delta_i = chal_dec(chall3, tau);
            F8b::from_bytes(&arr![bools_to_u8(&delta_i)])
        })
        .collect::<Result<GenericArray<F8b, U16>, _>>()
        .unwrap()
}

/// This function applies corrections to the verifier part of voles `q` using a challenge.
///
/// This function implements Lines 7-14 of Figure 8.3 of the FAEST spec.
#[inline(never)]
pub(crate) fn apply_corrections_to_q(
    q: Vec<Vec<F8b>>,
    chall3: &Chall3,
    corrections: &Corrections,
    how_many: usize,
) -> Vec<F128b> {
    // Q_0 is the same
    // Change Q_i with the corrections:
    // loop Q_i xor (\delta_0 c_i ... \delta_7 c_7)
    // Q = (Q_0 ... Q_{tau-1})
    let mut qs = Vec::with_capacity(how_many);
    for _ in 0..how_many {
        qs.push([F8b::default(); REPETITION_PARAM]);
    }
    for pos in 0..how_many {
        qs[pos][0] = q[0][pos];
    }
    for tau in 1..REPETITION_PARAM {
        let delta = chal_dec(chall3, tau);

        for pos in 0..how_many {
            let c_tau = corrections.0[tau - 1][pos];
            let mut delta_times_corr = [F2::default(); 8];
            for (i, d) in delta.iter().enumerate() {
                let corr = F2::from(*d) * c_tau; // TODO: optimize this
                delta_times_corr[i] = corr;
            }
            let delta_times_corr_f8b: F8b = F2::form_superfield(&delta_times_corr.into());
            qs[pos][tau] = q[tau][pos] + delta_times_corr_f8b;
        }
    }

    let mut q_128b: Vec<F128b> = Vec::with_capacity(how_many);
    for pos in 0..how_many {
        let val = F8b::form_superfield(&qs[pos].into());
        q_128b.push(val);
    }
    q_128b
}

/// This function combines a challenge with the hash of `u` to be used for the consistency check by the verifier.
///
/// This function implements lines 8-11 in Fig 8.3 in the FAEST spec.
#[inline(never)]
pub(crate) fn recompose_d(chall3: &Chall3, u_tilda: &HashConsistency) -> Vec<F2> {
    assert_eq!(u_tilda.0.len(), SECURITY_PARAM + B);
    let how_many = u_tilda.0.len();
    let mut qs = Vec::with_capacity(how_many * REPETITION_PARAM * 8);

    for tau in 0..REPETITION_PARAM {
        let delta = chal_dec(chall3, tau);
        let delta_f2: Vec<_> = delta
            .iter()
            .map(|b| if *b { F2::ONE } else { F2::ZERO })
            .collect();
        for b in delta_f2 {
            for u in u_tilda.0.iter() {
                qs.push(b * *u);
            }
        }
    }
    assert_eq!(qs.len(), how_many * REPETITION_PARAM * 8);

    qs
}

/// This function takes the size of the extended witness as input and returns
/// that many more elements necessary based on the parameters of the protocol.
pub(crate) fn l_hat(l: usize) -> usize {
    l + B + 2 * SECURITY_PARAM
}

/// Convert corrections to associated bytes.
#[inline(never)]
pub(crate) fn corrections_to_bytes(corrections: &Corrections) -> Vec<u8> {
    // Corrections are a vector containing tau vectors of long size
    let how_many = corrections.0[0].len();
    let tau = corrections.0.len();
    let mut out = Vec::with_capacity((how_many * tau) / 8);

    let mut b = 0u8;
    let mut i = 0;
    for c in corrections.0.iter() {
        for bit in c.iter() {
            b |= if *bit == F2::ZERO { 0 } else { 1 << i };
            if i == 7 {
                out.push(b);
                b = 0u8;
                i = 0;
            } else {
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod test {
    use std::iter::repeat_with;

    use super::{
        apply_corrections_to_q, compute_secret_key, l_hat, vole_commit, vole_open,
        vole_reconstruct, Commit,
    };
    use crate::vole::crypto_primitives::H1;
    use crate::vole::functionality::compute_seed_iv;
    use rand::thread_rng;
    use swanky_field::{FiniteRing, IsSubFieldOf};
    use swanky_field_binary::{F128b, F8b, F2};

    #[test]
    fn test_vole_commit_reconstruct() {
        let rng = &mut thread_rng();
        let secret = repeat_with(|| F2::random(rng))
            .take(100)
            .collect::<Vec<F2>>();
        let pk = vec![1u8];

        let how_many = l_hat(1_000);

        let mu: H1 = H1::from_bytes(&pk);
        let (r, iv) = compute_seed_iv(&secret, &mu);

        let Commit {
            h_com: _,
            decom,
            corrections,
            u,
            v,
        } = vole_commit(r, iv, how_many);

        let chall3 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let pdecom = vole_open(&chall3, &decom);

        let (_h_ver, q) = vole_reconstruct(&chall3, &pdecom, iv, how_many);

        // Change Q_i with the corrections:
        // loop Q_i xor (\delta_0 c_i ... \delta_7 c_7)
        // Q = (Q_0 ... Q_{tau-1})
        let q_f128b = apply_corrections_to_q(q, &chall3, &corrections, how_many);

        // compute the big delta
        let big_delta = compute_secret_key(&chall3);
        let big_delta_f128b: F128b = F8b::form_superfield(&big_delta);

        for pos in 0..how_many {
            //assert_eq!(v_f128b[pos], q_f128b[pos]);
            assert_eq!(v[pos] + u[pos] * big_delta_f128b, q_f128b[pos]);
        }
    }
}
