/*!
Convert vector commitments to VOLEs.
*/
#![allow(clippy::needless_range_loop)]
use crate::vole::crypto_primitives::{IV, Seed};
use rand::Rng;
use swanky_field_binary::F2;
use swanky_field_binary::F8b;
use swanky_rng::SwankyRng;
use swanky_serialization::CanonicalSerialize;

fn u8_to_f8b(x: u8) -> F8b {
    // Safe to unwrap here
    F8b::from_bytes(&[x].into()).unwrap()
}

/// This function converts seeds to voles.
///
/// It can be used as is for the prover, but for the verifier it is a auxiliary
/// function used by [`convert_to_vole_verifier`]. This implementation
/// corresponds to ConvertToVOLE as in the FAEST spec. It differs from the naive
/// algorithm by relying exclusively on xor operations on packed binary
/// field values.
pub(crate) fn convert_to_vole(
    seeds: &[Seed],
    iv: IV,
    l_hat: usize,
    is_prover: bool,
) -> (Vec<F2>, Vec<F8b>) {
    // even if one seed can be bottom, it expects 256 of them.
    assert!(seeds.len() == 256);
    let mut u_res = Vec::with_capacity(l_hat);
    let mut v_res = Vec::with_capacity(l_hat);

    // // u64 packs 64 bits/booleans.
    let mut prgss: [Option<SwankyRng>; 256] = core::array::from_fn(|_| None);
    for (idx, seed) in seeds.iter().enumerate() {
        if idx == 0 && !is_prover {
            // NOTE: the verifier is slightly faster here because it calls a dummy PRG.
            prgss[idx] = None;
        } else {
            prgss[idx] = Some(SwankyRng::from_seed_and_iv(
                (*seed).into(),
                u128::from_le_bytes(iv),
            ));
        }
    }

    // `r` is only the last 2 layers of the original structure from the spec.
    // Only 2 layers are used using a swap operation in the loop.
    // Again, u64 to do 64 boolean/bit operations at once.
    let mut r0 = [0; 256];
    let mut r1 = [0; 256];
    let mut remaining = l_hat;

    // precompute an array of 2*i indices and another array for 2*i+1
    let mut i2_arr = [0usize; 128];
    let mut i2_plus_1_arr = [0usize; 128];
    for i in 0..i2_arr.len() {
        i2_arr[i] = i * 2;
        i2_plus_1_arr[i] = i * 2 + 1;
    }

    for _ in 0..(l_hat / 64) + 1 {
        // possibly more but does not matter for performance.

        let mut v = [0; 8];
        for x in 0..256 {
            if let Some(rng) = &mut prgss[x] {
                r0[x] = rng.r#gen::<u64>();
            }
        }
        let mut i_bound = 128;
        // the bound for the loop is 8 = log(256)
        for j in 0..8 {
            for i in 0..i_bound {
                v[j] ^= r0[i2_plus_1_arr[i]];
                r1[i] = r0[i2_arr[i]] ^ r0[i2_plus_1_arr[i]];
            }

            // swap the top-level to the lower level
            r0[0..i_bound].copy_from_slice(&r1[0..i_bound]);

            i_bound /= 2;
        }

        let u = r0[0];
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
                    debug_assert_eq!(u_res.len(), l_hat);
                    return (u_res, v_res);
                }
            }
        }
    }
    debug_assert_eq!(u_res.len(), l_hat);
    (u_res, v_res)
}

#[cfg(test)]
/// This function is the naive version of [`convert_to_vole`] that does not
/// operate on packed boolean field values.
fn convert_to_vole_prover_naive(seeds: &[Seed], iv: IV, l_hat: usize) -> (Vec<F2>, Vec<F8b>) {
    use swanky_field::FiniteRing;
    assert!(seeds.len() == 256);
    let mut u_res = vec![F2::ZERO; l_hat];
    let mut v_res = vec![F8b::ZERO; l_hat];

    let mut i = 0u8;
    for seed in seeds.iter() {
        let mut prg = SwankyRng::from_seed_and_iv((*seed).into(), u128::from_le_bytes(iv));

        // Generate u64 items to match the use in `convert_to_vole`.
        let randoms = (0..l_hat / 64 + 1)
            .map(|_| prg.r#gen::<u64>())
            .collect::<Vec<_>>();
        let mut v = Vec::with_capacity(l_hat);
        for block in randoms {
            for i in 0..64 {
                let bit = ((block >> i) & 1) == 1;
                v.push(F2::from(bit));
            }
        }
        v.truncate(l_hat);
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
pub(crate) fn convert_to_vole_verifier(
    seeds: &[Seed],
    iv: IV,
    l_hat: usize,
    delta: u8,
) -> Vec<F8b> {
    // let's permutate the seeds according to delta, with the permutation
    // i -> i xor delta
    let mut seeds_permuted = [Seed::default(); 256];
    let mut i = 0u8;
    for _ in 0u32..256 {
        let idx: u8 = i ^ delta;
        if i != 0 {
            seeds_permuted[i as usize] = seeds[(idx) as usize];
        }
        i = i.wrapping_add(1);
    }

    let (_, v) = convert_to_vole(&seeds_permuted, iv, l_hat, false);
    v
}

// NOTE: the return type is different than ConvertToVOLE in the paper, where is should be a Vec<Vec<F2>>
#[cfg(test)]
fn convert_to_vole_verifier_naive(seeds: &[Seed], iv: IV, l_hat: usize, delta: u8) -> Vec<F8b> {
    use swanky_field::FiniteRing;
    assert_eq!(seeds.len(), 256);
    let mut v_res = vec![F8b::ZERO; l_hat];

    let mut i = 0u8;

    for (j, seed) in seeds.iter().enumerate() {
        if j != delta as usize {
            let mut prg = SwankyRng::from_seed_and_iv((*seed).into(), u128::from_le_bytes(iv));

            // Generate u64 items to match the use in `convert_to_vole`.
            let randoms = (0..l_hat / 64 + 1)
                .map(|_| prg.r#gen::<u64>())
                .collect::<Vec<_>>();
            let mut v = Vec::with_capacity(l_hat);
            for block in randoms {
                for i in 0..64 {
                    let bit = ((block >> i) & 1) == 1;
                    v.push(F2::from(bit));
                }
            }
            v.truncate(l_hat);

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
    use super::{
        convert_to_vole, convert_to_vole_prover_naive, convert_to_vole_verifier_naive, u8_to_f8b,
    };
    use crate::vole::crypto_primitives::Seed;
    use rand::{Rng, RngCore, thread_rng};
    use swanky_field_binary::F8b;

    #[test]
    fn test_convert_to_vole_naive() {
        let rng = &mut thread_rng();

        let seeds = (0..256).map(|_| rng.r#gen::<Seed>()).collect::<Vec<_>>();
        let iv = rng.r#gen();

        let delta = 3u8;
        let how_many = 1027;
        let (u, vs) = convert_to_vole_prover_naive(seeds.as_slice(), iv, how_many);

        let mut seeds_verifier = [Seed::default(); 256];
        for i in 0..256 {
            if i != (delta as usize) {
                seeds_verifier[i] = seeds[i];
            }
        }
        let qs = convert_to_vole_verifier_naive(&seeds_verifier, iv, how_many, delta);

        for ((u, v), q) in u.iter().zip(vs.iter()).zip(qs.iter()) {
            let delta_f8b: F8b = u8_to_f8b(delta);
            assert_eq!(*q, (*u * delta_f8b) - *v);
        }
    }

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

        for ((u, v), q) in u.iter().zip(vs.iter()).zip(qs.iter()) {
            let delta_f8b: F8b = u8_to_f8b(delta);
            assert_eq!(*q, (*u * delta_f8b) - *v);
        }
    }
}
