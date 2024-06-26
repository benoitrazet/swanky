/*! */
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
pub const B: usize = 16;

/// TODO
pub fn bools_to_u8(d: &[bool]) -> u8 {
    debug_assert_eq!(d.len(), 8);
    let mut r: u8 = 0;
    for (i, b) in d.iter().enumerate() {
        r |= if *b { 1u8 << i } else { 0u8 };
    }

    r
}

/// Type for corrections
pub type Corrections = Vec<Vec<F2>>;

/// Figure 5.4
#[inline(never)]
pub fn vole_commit(
    r: IV,
    iv: IV,
    l: usize,
) -> (Com, Vec<Decom>, Corrections, Vec<F2>, Vec<Vec<F8b>>) {
    let prg_seeds = PRG::new(r, iv).generate_prg_seeds(REPETITION_PARAM);
    let mut u = Vec::with_capacity(REPETITION_PARAM);
    let mut v = Vec::with_capacity(REPETITION_PARAM);
    let mut decom = Vec::with_capacity(REPETITION_PARAM);
    let mut com = Vec::with_capacity(REPETITION_PARAM);

    // Without multithreading
    /*
    for i in 0..REPETITION_PARAM {
        let (com_i, decom_i, seeds) = commit(prg_seeds[i], iv, 8);
        let (u_i, v_i) = convert_to_vole_xor(&seeds, iv, l, true);
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
        for j in 0..l {
            let c = u_0[j] + u[i][j];
            ci.push(c);
        }
        corr.push(ci);
    }
    debug_assert_eq!(corr.len(), REPETITION_PARAM - 1);

    (
        com[0], // TODO H1 all of them
        decom, corr, u_0, v, // TODO: not exactly same as V in the FAEST spec
    )
}

/// steps 20-22 of Fig 8.2
pub fn vole_open(chal: &[u8], decom: Vec<Decom>) -> Vec<Pdecom> {
    let mut pdecom = Vec::with_capacity(REPETITION_PARAM);
    for i in 0..REPETITION_PARAM {
        let delta_i = chal_dec(chal, i);
        let pdecom_i = open(&decom[i], delta_i);
        pdecom.push(pdecom_i);
    }
    pdecom
}

/// TODO: remove pub
pub fn chal_dec(buf: &[u8], i: usize) -> Vec<bool> {
    //let mut dec = vec![];

    //assert!(dec.len() == REPETITION_PARAM);
    //let mut r = vec![false; 8];
    //r.copy_from_slice(&FIXED_CHALLENGE);
    //r
    let b = buf[i];
    let mut r = vec![false; 8];
    for i in 0..8 {
        r[i] = ((b >> i) & 1) != 0;
    }
    r
}

/// Figure 5.5 in FAEST spec v1.1
#[inline(never)]
pub fn vole_reconstruct(
    chal: &[u8], // bytes from fiat-shamir challenge
    pdecom: Vec<Pdecom>,
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

/// TODO
pub fn bitwise_f128b_from_f8b(v: &[F8b; REPETITION_PARAM]) -> F128b {
    let mut tmp: [u8; REPETITION_PARAM] = [0; REPETITION_PARAM];
    for (i, b) in v.iter().enumerate() {
        tmp[i] = b.to_bytes()[0];
    }
    F128b::from_bytes(&tmp.into()).unwrap()
}

/// Lines 7-14 of Figure 8.3
#[inline(never)]
pub fn vole_recompose_q(
    q: Vec<Vec<F8b>>,
    chall3: &Chall3,
    corr: Corrections,
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
            let c_tau = corr[tau - 1][pos];
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

/// TODO
#[inline(never)]
pub fn recompose_d(chall3: &Chall3, u_tilda: &[F2]) -> Vec<F2> {
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

/// TODO
pub fn l_hat(l: usize) -> usize {
    l + B + 2 * SECURITY_PARAM
}

/// TODO
#[inline(never)]
pub fn corrections_to_bytes(corr: &Corrections) -> Vec<u8> {
    // Corrections are a vector containing tau vectors of long size
    let how_many = corr[0].len();
    let tau = corr.len();
    let mut out = Vec::with_capacity((how_many * tau) / 8);

    let mut b = 0u8;
    let mut i = 0;
    for c in corr.iter() {
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
        bitwise_f128b_from_f8b, bools_to_u8, chal_dec, l_hat, vole_commit, vole_open,
        vole_recompose_q, vole_reconstruct,
    };
    use crate::parameters::REPETITION_PARAM;
    use crate::vole::crypto_primitives::{h1, H1};
    use crate::vole::sign_verify::{
        compute_chall_1, compute_chall_2, compute_chall_3, compute_r_iv,
    };
    use swanky_field::FiniteRing;
    use swanky_field_binary::{F128b, F8b};

    #[test]
    fn test_vole_commit_reconstruct() {
        let sk = vec![1u8];
        let pk = vec![1u8];

        let how_many = l_hat(1_000);

        let mu: H1 = h1(&pk);
        let (r, iv) = compute_r_iv(&sk, &mu);

        let (h, decom, corr, u, v) = vole_commit(r, iv, how_many);

        let chall1 = compute_chall_1(&mu, &h, &corr, &iv);
        let chall2 = compute_chall_2(&chall1 /*TODO: add more */);
        let chall3 = compute_chall_3(&chall2 /*TODO: add more */);

        let pdecom = vole_open(&chall3, decom);

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

        let (h_ver, q) = vole_reconstruct(&chall3, pdecom, iv, how_many);

        // Change Q_i with the corrections:
        // loop Q_i xor (\delta_0 c_i ... \delta_7 c_7)
        // Q = (Q_0 ... Q_{tau-1})
        let q_f128b = vole_recompose_q(q, &chall3, corr, how_many);

        // compute the big delta
        let mut big_delta = [F8b::default(); REPETITION_PARAM];
        for tau in 0..REPETITION_PARAM {
            let delta_i = chal_dec(&chall3, tau);
            let delta_f8b: F8b = bools_to_u8(&delta_i).into();
            big_delta[tau] = delta_f8b;
        }
        let big_delta_f128b = bitwise_f128b_from_f8b(&big_delta);

        for pos in 0..how_many {
            //assert_eq!(v_f128b[pos], q_f128b[pos]);
            assert_eq!(v_f128b[pos] + u[pos] * big_delta_f128b, q_f128b[pos]);
        }
    }
}
