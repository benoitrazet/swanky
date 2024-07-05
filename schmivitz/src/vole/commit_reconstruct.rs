/*!
Implementation of algorithms to commit, open and reconstruct VOLEs.
 *
 */
#![allow(clippy::needless_range_loop)]
use crate::parameters::{REPETITION_PARAM, SECURITY_PARAM};
use crate::vole::all_but_one_vc::{commit, open, reconstruct, Decom, Pdecom};
use crate::vole::convert_to_vole::{convert_to_vole, convert_to_vole_verifier};
use crate::vole::crypto_primitives::{Chall3, Com, IV, PRG};
use std::sync::mpsc::channel;
use std::thread;
use swanky_field::FiniteRing;
use swanky_field::IsSubFieldOf;
use swanky_field_binary::F128b;
use swanky_field_binary::F8b;
use swanky_field_binary::F2;
use swanky_serialization::CanonicalSerialize;

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
pub(crate) type Corrections = Vec<Vec<F2>>;

/// Function generating the voles with associated commitments.
///
/// This corresponds to Figure 5.4 of the FAEST spec.
/// This function relies on multithreading to improve the time performance.
#[inline(never)]
pub(crate) fn vole_commit(
    r: IV,
    iv: IV,
    l: usize,
) -> (Com, Vec<Decom>, Corrections, Vec<F2>, Vec<F128b>) {
    let prg_seeds = PRG::new(r, iv).generate_prg_seeds(REPETITION_PARAM);
    let mut u = Vec::with_capacity(REPETITION_PARAM);
    let mut v = Vec::with_capacity(REPETITION_PARAM);
    let mut decom = Vec::with_capacity(REPETITION_PARAM);
    let mut com = Vec::with_capacity(REPETITION_PARAM);

    // Without multithreading
    /*
    for i in 0..REPETITION_PARAM {
        let (com_i, decom_i, seeds) = commit(prg_seeds[i], iv, 8);
        let (u_i, v_i) = convert_to_vole(&seeds, iv, l, true);
        com.push(com_i);
        decom.push(decom_i);
        u.push(u_i);
        v.push(v_i)
    }
    */

    // With multithreading
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
        decom.push(decom_i);
        u.push(u_i);
        v.push(v_i);
    }
    // End multithreading

    // let's compute the corrections
    let u_0 = u[0].clone(); // TODO: opt transmute here
    let mut corr = Vec::with_capacity(REPETITION_PARAM - 1);
    for i in 1..REPETITION_PARAM {
        let mut ci = Vec::with_capacity(l);
        debug_assert_eq!(l, u_0.len());
        let u_i = &u[i];
        for j in 0..l {
            let c = u_0[j] + u_i[j];
            ci.push(c);
        }
        corr.push(ci);
    }
    debug_assert_eq!(corr.len(), REPETITION_PARAM - 1);

    // Convert Vec<Vec<F8b>> to Vec<F128b> where the size of the outer vec in Vec<Vec<F8b>> is `REPETITION_PARAM`.
    let t = std::time::Instant::now();
    let mut v_out = Vec::with_capacity(l);
    let mut tmp = [0u8; REPETITION_PARAM];
    for i in 0..l {
        for tau in 0..REPETITION_PARAM {
            tmp[tau] = v[tau][i].to_bytes()[0];
        }
        v_out.push(F128b::from_bytes((&tmp).into()).unwrap());
    }
    log::info!("pack to F128b: {:?}", t.elapsed());

    (
        com[0], // TODO H1 all of them
        decom, corr, u_0, v_out, // TODO: not exactly same as V in the FAEST spec
    )
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

    (
        com[0], // TODO H1 all of them
        qs,
    )
}

/// Function converting a slice of [`F8b`] values into a [`F128b`] value using the underlying bits.
pub(crate) fn bitwise_f128b_from_f8b(v: &[F8b; REPETITION_PARAM]) -> F128b {
    let mut tmp: [u8; REPETITION_PARAM] = [0; REPETITION_PARAM];
    for (i, b) in v.iter().enumerate() {
        tmp[i] = b.to_bytes()[0];
    }
    F128b::from_bytes(&tmp.into()).unwrap()
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
            let c_tau = corrections[tau - 1][pos];
            let mut delta_times_corr = [F2::default(); 8];
            for (i, d) in delta.iter().enumerate() {
                let corr = (if *d { F2::ONE } else { F2::ZERO }) * c_tau; // TODO: can optimize that
                                                                          //println!("bit:{:?} corr:{:?}", *d, corr);
                delta_times_corr[i] = corr;
            }
            let delta_times_corr_f8b: F8b = F2::form_superfield(&delta_times_corr.into());
            //println!("delta_times:{:?}", delta_times_corr_f8b);
            qs[pos][tau] = q[tau][pos] + delta_times_corr_f8b;
        }
    }

    let mut q_128b: Vec<F128b> = Vec::with_capacity(how_many);
    for pos in 0..how_many {
        let val = bitwise_f128b_from_f8b(&qs[pos]);
        q_128b.push(val);
    }
    q_128b
}

/// This function combines a challenge with the hash of `u` to be used for the consistency check by the verifier.
///
/// This function implements lines 8-11 in Fig 8.3 in the FAEST spec.
#[inline(never)]
pub(crate) fn recompose_d(chall3: &Chall3, u_tilda: &[F2]) -> Vec<F2> {
    assert_eq!(u_tilda.len(), SECURITY_PARAM + B);
    let how_many = u_tilda.len();
    let mut qs = Vec::with_capacity(how_many * REPETITION_PARAM * 8);

    for tau in 0..REPETITION_PARAM {
        let delta = chal_dec(chall3, tau);
        let delta_f2: Vec<_> = delta
            .iter()
            .map(|b| if *b { F2::ONE } else { F2::ZERO })
            .collect();
        for b in delta_f2 {
            for u in u_tilda.iter() {
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
    let how_many = corrections[0].len();
    let tau = corrections.len();
    let mut out = Vec::with_capacity((how_many * tau) / 8);

    let mut b = 0u8;
    let mut i = 0;
    for c in corrections.iter() {
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
    use super::{
        apply_corrections_to_q, bitwise_f128b_from_f8b, bools_to_u8, chal_dec, l_hat, vole_commit,
        vole_open, vole_reconstruct,
    };
    use crate::parameters::REPETITION_PARAM;
    use crate::vole::bitwise_utils::u8_to_f8b;
    use crate::vole::crypto_primitives::{h1, H1};
    use crate::vole::functionality::compute_seed_iv;
    use swanky_field_binary::F8b;

    #[test]
    fn test_vole_commit_reconstruct() {
        let sk = vec![1u8];
        let pk = vec![1u8];

        let how_many = l_hat(1_000);

        let mu: H1 = h1(&pk);
        let (r, iv) = compute_seed_iv(&sk, &mu);

        let (_h, decom, corrections, u, v) = vole_commit(r, iv, how_many);

        let chall3 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let pdecom = vole_open(&chall3, &decom);

        let (_h_ver, q) = vole_reconstruct(&chall3, &pdecom, iv, how_many);

        // Change Q_i with the corrections:
        // loop Q_i xor (\delta_0 c_i ... \delta_7 c_7)
        // Q = (Q_0 ... Q_{tau-1})
        let q_f128b = apply_corrections_to_q(q, &chall3, &corrections, how_many);

        // compute the big delta
        let mut big_delta = [F8b::default(); REPETITION_PARAM];
        for tau in 0..REPETITION_PARAM {
            let delta_i = chal_dec(&chall3, tau);
            let delta_f8b: F8b = u8_to_f8b(bools_to_u8(&delta_i));
            big_delta[tau] = delta_f8b;
        }
        let big_delta_f128b = bitwise_f128b_from_f8b(&big_delta);

        for pos in 0..how_many {
            //assert_eq!(v_f128b[pos], q_f128b[pos]);
            assert_eq!(v[pos] + u[pos] * big_delta_f128b, q_f128b[pos]);
        }
    }
}
