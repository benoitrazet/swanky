/*!
Convert vector commitments to VOLEs.
*/
#![allow(clippy::needless_range_loop)]
use crate::vole::bitwise_utils::u8_to_f8b;
use crate::vole::crypto_primitives::{Seed, IV, PRG};
#[allow(unused_imports)]
// WEIRD: rust-analyzer seems to consider `FiniteRing`, but without it, it is not possible to use ZERO/ONE etc.
use swanky_field::FiniteRing;
use swanky_field_binary::F8b;
use swanky_field_binary::F2;

/// This function converts seeds to voles.
///
/// It can be used as is for the prover, but for the verifier it is a auxiliary function used by [`convert_to_vole_verifier`].
/// This implementation corresponds to ConvertToVOLE as in the FAEST spec.
/// It differs from the naive algorithm by using relying exclusively on xor
/// operations on packed binary field values.
pub(crate) fn convert_to_vole(
    seeds: &[Seed],
    iv: IV,
    l: usize,
    is_prover: bool,
) -> (Vec<F2>, Vec<F8b>) {
    // even if one seed can be bottom, it expects 256 of them.
    assert!(seeds.len() == 256);
    let mut u_res = Vec::with_capacity(l);
    let mut v_res = Vec::with_capacity(l);

    // u64 packs 64 bits/booleans.
    let mut prgs: Vec<Vec<u64>> = vec![];
    for (idx, seed) in seeds.iter().enumerate() {
        if idx == 0 && !is_prover {
            prgs.push(vec![0u64; (l / 64) + 1]);
        } else {
            let prg = PRG::new(*seed, iv);
            let v = prg.prg_compact(l);
            prgs.push(v);
        }
    }

    // `r` is only the last 2 layers of the original structure from the spec.
    // Only 2 layers are used using a swap operation in the loop.
    // Again, u64 to do 64 boolean/bit operations at once.
    let mut r = [[0_u64; 256]; 2];
    let mut remaining = l;
    for pos in 0..(l / 64) + 1 {
        // possibly more but does not matter for performance.

        let mut v = [0_u64; 8];
        for x in 0..256 {
            r[0][x] = prgs[x][pos];
        }
        let mut i_bound = 128;
        for j in 0..8 {
            // 8 = log(256)
            for i in 0..i_bound {
                let i2 = 2 * i;
                let i2_plus_1 = i2 + 1;
                v[j] ^= r[0][i2_plus_1];
                r[1][i] = r[0][i2] ^ r[0][i2_plus_1];
            }

            // swap the top-level to the lower level
            for i in 0..i_bound {
                r[0][i] = r[1][i];
            }
            i_bound /= 2;
        }

        let u = r[0][0];
        // if there are more than 64 then we dont have to check how
        // many are remaining for the next 64 steps.
        if remaining >= 64 {
            for i in 0..64 {
                u_res.push(((u >> i & 1_u64) == 1).into());
                let mut x = 0u8;
                x |= (v[0] >> i & 1) as u8;
                x |= ((v[1] >> i & 1) as u8) << 1;
                x |= ((v[2] >> i & 1) as u8) << 2;
                x |= ((v[3] >> i & 1) as u8) << 3;
                x |= ((v[4] >> i & 1) as u8) << 4;
                x |= ((v[5] >> i & 1) as u8) << 5;
                x |= ((v[6] >> i & 1) as u8) << 6;
                x |= ((v[7] >> i & 1) as u8) << 7;
                v_res.push(u8_to_f8b(x));
            }
            remaining -= 64;
        } else {
            // otherwise let's check one by one
            for i in 0..64 {
                u_res.push(((u >> i & 1_u64) == 1).into());
                let mut x = 0u8;
                x |= (v[0] >> i & 1) as u8;
                x |= ((v[1] >> i & 1) as u8) << 1;
                x |= ((v[2] >> i & 1) as u8) << 2;
                x |= ((v[3] >> i & 1) as u8) << 3;
                x |= ((v[4] >> i & 1) as u8) << 4;
                x |= ((v[5] >> i & 1) as u8) << 5;
                x |= ((v[6] >> i & 1) as u8) << 6;
                x |= ((v[7] >> i & 1) as u8) << 7;
                v_res.push(u8_to_f8b(x));

                remaining -= 1;
                if remaining == 0 {
                    debug_assert_eq!(u_res.len(), l);
                    return (u_res, v_res);
                }
            }
        }
    }
    debug_assert_eq!(u_res.len(), l);
    (u_res, v_res)
}

#[cfg(test)]
/// This function is the naive version of [`convert_to_vole`] that does not
/// operate on packed boolean field values.
fn convert_to_vole_prover_naive(seeds: &[Seed], iv: IV, l: usize) -> (Vec<F2>, Vec<F8b>) {
    assert!(seeds.len() == 256);
    let mut u_res = vec![F2::ZERO; l];
    let mut v_res = vec![F8b::ZERO; l];

    let mut i = 0u8;
    for seed in seeds.iter() {
        let prg = PRG::new(*seed, iv);
        let v = prg.prg(l);
        let i_f8b: F8b = u8_to_f8b(i);
        for (j, r) in v.iter().enumerate() {
            u_res[j] += r;
            v_res[j] += *r * i_f8b;
        }
        i = i.wrapping_add(1);
    }

    (u_res, v_res)
}

/// This function is the verifier version of [`convert_to_vole`].
///
/// It permutes the `seeds` according to `delta` before calling [`convert_to_vole`].
pub(crate) fn convert_to_vole_verifier(seeds: &[Seed], iv: IV, l: usize, delta: u8) -> Vec<F8b> {
    // let's permutate the seeds according to delta, with the permutation
    // i -> i xor delta
    let mut seeds_permuted = vec![Seed::default(); 256];
    let mut i = 0u8;
    for _ in 0u32..256 {
        let idx: u8 = i ^ delta;
        if i != 0 {
            seeds_permuted[i as usize] = seeds[(idx) as usize];
        }
        i = i.wrapping_add(1);
    }

    let (_, v) = convert_to_vole(&seeds_permuted, iv, l, false);
    v
}

// NOTE: the return type is different than ConvertToVOLE in the paper, where is should be a Vec<Vec<F2>>
#[cfg(test)]
fn convert_to_vole_verifier_naive(seeds: &[Seed], iv: IV, l: usize, delta: u8) -> Vec<F8b> {
    assert_eq!(seeds.len(), 256);
    let mut v_res = vec![F8b::ZERO; l];

    let mut i = 0u8;

    //println!("delta_u8 {}", delta);
    for (j, seed) in seeds.iter().enumerate() {
        if j != delta as usize {
            let prg = PRG::new(*seed, iv);
            let v = prg.prg(l);
            let i_f8b: F8b = u8_to_f8b(i);
            let delta_f8b: F8b = u8_to_f8b(delta);
            for (j, r) in v.iter().enumerate() {
                v_res[j] += *r * (delta_f8b - i_f8b);
            }
        } else {
            assert_eq!(*seed, Seed::default());
        }
        i = i.wrapping_add(1);
    }

    v_res
}

#[cfg(test)]
mod test {
    use super::{convert_to_vole, convert_to_vole_prover_naive, convert_to_vole_verifier_naive};
    use crate::vole::{bitwise_utils::u8_to_f8b, crypto_primitives::Seed};
    use rand::{thread_rng, RngCore};
    use swanky_field::FiniteRing;
    use swanky_field_binary::F8b;

    #[test]
    fn test_convert_to_vole() {
        let mut seeds: Vec<Seed> = vec![];
        let rng = &mut thread_rng();

        let mut arr = [0u8; 16];
        for _ in 0..256 {
            rng.try_fill_bytes(&mut arr).unwrap();
            seeds.push(arr);
        }

        rng.try_fill_bytes(&mut arr).unwrap();
        let iv = arr;

        let delta = 3u8;
        let how_many = 1027;
        let (u, vs) = convert_to_vole_prover_naive(seeds.as_slice(), iv, how_many);

        /* This test checks the equivalence between convert_to_vole and its naive version */
        let (u_xor, v_xor) = convert_to_vole(&seeds, iv, how_many, true);
        assert_eq!(u_xor, u);
        assert_eq!(v_xor, vs);

        let mut seeds_verifier = [Seed::default(); 256];
        for i in 0..256 {
            if i != (delta as usize) {
                seeds_verifier[i] = seeds[i];
            }
        }
        let qs = convert_to_vole_verifier_naive(&seeds_verifier, iv, how_many, delta);

        /* This test was to test the correspondance between the two functions */
        let qs_xor = super::convert_to_vole_verifier(&seeds, iv, how_many, delta);
        assert_eq!(qs, qs_xor);

        println!("Minus one {:?}", -(F8b::ONE));
        for ((u, v), q) in u.iter().zip(vs.iter()).zip(qs.iter()) {
            let delta_f8b: F8b = u8_to_f8b(delta);
            assert_eq!(*q, (*u * delta_f8b) - *v);
        }
    }
}
