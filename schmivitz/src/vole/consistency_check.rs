/*!
Implementation of algorithms related to consistency checks.
 *
*/
#![allow(clippy::needless_range_loop)]
use crate::parameters::REPETITION_PARAM;
use crate::parameters::SECURITY_PARAM;
use crate::vole::commit_reconstruct::B;
use crate::vole::crypto_primitives::CHALL1_LENGTH;
use rayon::prelude::*;
use swanky_field::{FiniteField, FiniteRing};
use swanky_field_binary::F128b;
use swanky_field_binary::F8b;
use swanky_field_binary::F2;
use swanky_serialization::CanonicalSerialize;

/// Packs bits of the input into `F128b`s. This does not do a field-to-field transformation;
/// it uses `F128b` as a representation of 128 bits, not as a polynomial!
fn pack_f128b(arrs: &[[F8b; REPETITION_PARAM]]) -> Vec<F128b> {
    arrs.into_par_iter()
        .map(|xi| {
            let xi_bytes = xi.map(|xij| xij.to_bytes()[0]);
            F128b::from_bytes(&xi_bytes.into())
        })
        .collect::<Result<_, _>>()
        .unwrap()
}

/// Take a sequence of boolean field values and pack them into `F128b` values. It padds the last values in the sequence if necessary.
///
/// This implements a specialization of ToField Fig 3.1 in FAEST spec
#[inline(never)]
fn to_field_f128_and_pad<I: Iterator<Item = F2>>(x: I, x_len: usize) -> Vec<F128b> {
    let floor = x_len / 128;
    let how_many = floor + if (x_len - (floor) * 128) != 0 { 1 } else { 0 };
    let mut out = Vec::with_capacity(how_many);

    let mut b_128 = [0u8; 128 / 8];
    let mut byte_num = 0;
    let mut bit_num: usize = 0;
    for b in x.into_iter() {
        b_128[byte_num] |= if b == F2::ZERO { 0 } else { 1 << bit_num };
        if bit_num == 7 {
            bit_num = 0; // restart at the beginning of byte
            if byte_num == (128 / 8) - 1 {
                out.push(F128b::from_bytes(&b_128.into()).unwrap());

                // reset
                byte_num = 0;
                // reset
                b_128 = [0u8; 128 / 8];
            } else {
                byte_num += 1;
            }
        } else {
            bit_num += 1;
        }
    }

    // Still have to push a last value if the previous loop terminated before processing `SECURITY_PARAMETER` bits.
    if (bit_num != 0) | (byte_num != 0) {
        out.push(F128b::from_bytes(&b_128.into()).unwrap())
    }

    assert_eq!(out.len(), how_many);
    out
}

/// Take a sequence of [`F128b`] values, interpret every value into its bit decomposition,
/// that becomes a n*128 boolean matrix where n is the length of the sequence.
/// Apply `to_field_f128_and_pad` to every column in lock step and emit a sequence of
/// 128 [`F128b`] values.
#[inline(never)]
#[allow(dead_code)]
fn to_field_f128_and_pad_lockstep(x: &[F128b]) -> Vec<[F128b; SECURITY_PARAM]> {
    let floor = x.len() / 128;
    let how_many = floor + if (x.len() - (floor) * 128) != 0 { 1 } else { 0 };
    let mut out = Vec::with_capacity(how_many);

    let mut b_128 = [[0u8; 128 / 8]; 128];
    let mut b_128_alt = [[0u8; 128]; 128 / 8];
    let mut byte_num = 0;
    let mut bit_num: usize = 0;
    for b in x.iter() {
        let bs = b.bit_decomposition();
        let hot_bit = 1 << bit_num;
        let mut b_vec = [0u8; SECURITY_PARAM];
        for (p, b) in b_vec.iter_mut().zip(bs.iter()) {
            *p = u8::from(*b).wrapping_neg() & hot_bit;
        }

        let t = &mut b_128_alt[byte_num];
        for (e, b_128_alt_byte_num_i) in t.iter_mut().enumerate() {
            *b_128_alt_byte_num_i |= b_vec[e];
        }

        if bit_num == 7 {
            bit_num = 0; // restart at the beginning of byte
            if byte_num == (128 / 8) - 1 {
                // This double loop is optimal that way to maximize the cache hit for reads.
                // The writes will be batched on write-back
                // NOTE: this loop is the bottle-neck
                for i in 0..SECURITY_PARAM / 8 {
                    for k in 0..SECURITY_PARAM {
                        b_128[k][i] = b_128_alt[i][k];
                    }
                }

                let arr: [F128b; SECURITY_PARAM] =
                    b_128.map(|v| F128b::from_bytes(&v.into()).unwrap());
                out.push(arr);

                // reset
                byte_num = 0;
                // reset
                b_128 = [[0u8; 128 / 8]; 128];
                b_128_alt = [[0u8; 128]; 128 / 8];
            } else {
                byte_num += 1;
            }
        } else {
            bit_num += 1;
        }
    }

    // Still have to push a last value if the previous loop terminated before processing `SECURITY_PARAMETER` bits.
    if (bit_num != 0) | (byte_num != 0) {
        // transpose from b_128_alt to b_128
        for i in 0..SECURITY_PARAM / 8 {
            for k in 0..SECURITY_PARAM {
                b_128[k][i] = b_128_alt[i][k];
            }
        }
        let arr: [F128b; SECURITY_PARAM] = b_128.map(|v| F128b::from_bytes(&v.into()).unwrap());
        out.push(arr);
    }

    assert_eq!(out.len(), how_many);
    out
}

#[allow(dead_code)]
struct ColumnEnumState<'a> {
    x: &'a [F128b],
    index: usize,
    length: usize,
}

impl<'a> ColumnEnumState<'a> {
    #[allow(dead_code)]
    pub fn new(x: &'a [F128b]) -> Self {
        Self {
            x,
            index: 0,
            length: x.len(),
        }
    }
}

impl<'a> Iterator for ColumnEnumState<'a> {
    type Item = [F128b; SECURITY_PARAM];

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.length {
            return None;
        }

        let mut b_128 = [[0u8; 128 / 8]; 128];
        let mut b_128_alt = [[0u8; 128]; 128 / 8];
        let mut byte_num = 0;
        let mut bit_num: usize = 0;

        let mut out = [F128b::ZERO; 128];
        for _j in 0..128 {
            let b = self.x[self.index];
            // Advance immediately so the iterator consumes exactly the inputs it processes,
            // even when we early-break on a full 128-block.
            self.index += 1;

            let bs = b.bit_decomposition();
            let hot_bit = 1 << bit_num;
            let mut b_vec = [0u8; SECURITY_PARAM];
            for (p, b) in b_vec.iter_mut().zip(bs.iter()) {
                *p = u8::from(*b).wrapping_neg() & hot_bit;
            }

            let t = &mut b_128_alt[byte_num];
            for (e, b_128_alt_byte_num_i) in t.iter_mut().enumerate() {
                *b_128_alt_byte_num_i |= b_vec[e];
            }

            if bit_num == 7 {
                bit_num = 0; // restart at the beginning of byte
                if byte_num == (128 / 8) - 1 {
                    // This double loop is optimal that way to maximize the cache hit for reads.
                    // The writes will be batched on write-back
                    // NOTE: this loop is the bottle-neck
                    for i in 0..SECURITY_PARAM / 8 {
                        for k in 0..SECURITY_PARAM {
                            b_128[k][i] = b_128_alt[i][k];
                        }
                    }

                    let arr: [F128b; SECURITY_PARAM] =
                        b_128.map(|v| F128b::from_bytes(&v.into()).unwrap());
                    out = arr;
                    break;

                    // reset
                    //byte_num = 0;
                    // reset
                    //b_128 = [[0u8; 128 / 8]; 128];
                    //b_128_alt = [[0u8; 128]; 128 / 8];
                } else {
                    byte_num += 1;
                }
            } else {
                bit_num += 1;
            }

            if self.length == self.index {
                // Still have to push a last value if the previous loop terminated before processing `SECURITY_PARAMETER` bits.
                if (bit_num != 0) | (byte_num != 0) {
                    // transpose from b_128_alt to b_128
                    for i in 0..SECURITY_PARAM / 8 {
                        for k in 0..SECURITY_PARAM {
                            b_128[k][i] = b_128_alt[i][k];
                        }
                    }

                    let arr: [F128b; SECURITY_PARAM] =
                        b_128.map(|v| F128b::from_bytes(&v.into()).unwrap());
                    out = arr;
                    break;
                }
            }
        }

        return Some(out);
    }
}

/// Hash as produced by [`vole_hash`].
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct HashConsistency([F2; SECURITY_PARAM + B]);

impl Default for HashConsistency {
    fn default() -> Self {
        Self([Default::default(); SECURITY_PARAM + B])
    }
}

impl IntoIterator for &HashConsistency {
    type Item = F2;
    type IntoIter = <[F2; SECURITY_PARAM + B] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl HashConsistency {
    pub(crate) fn len(&self) -> usize {
        SECURITY_PARAM + B
    }

    /// Convert a consistency hash to a vector of bytes
    ///
    /// packing the `F2` values in `u8`.
    #[cfg(test)]
    pub(crate) fn pack_to_bytes(&self) -> Vec<u8> {
        let mut out = vec![];
        for chunk in self.0.chunks(8) {
            let mut byte = 0u8;
            for (i, &b) in chunk.iter().enumerate() {
                if b == F2::ONE {
                    byte |= 1 << i;
                }
            }
            out.push(byte);
        }
        out
    }

    /// Convert a [`HashConsistency`] to a list of bytes, without packing.
    pub(crate) fn as_bytes(&self) -> [u8; SECURITY_PARAM + B] {
        self.0.map(|f2| f2.to_bytes()[0])
    }
}

/// Function doing linear hashing of vector of boolean field elements.
#[inline(never)]
pub(crate) fn vole_hash<I1: Iterator<Item = F2>, I2: Iterator<Item = F2>>(
    seed: &[u8],
    x0: I1,
    x0_len: usize,
    x1: I2,
    x1_len: usize,
) -> HashConsistency {
    assert_eq!(seed.len(), CHALL1_LENGTH);
    assert_eq!(x1_len, SECURITY_PARAM + B);

    let byte_len: usize = 128 / 8;
    let mut tmp = [u8::default(); 128 / 8];
    tmp.copy_from_slice(&seed[0..byte_len]);
    let r0 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len..byte_len * 2]);
    let r1 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 2..byte_len * 3]);
    let r2 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 3..byte_len * 4]);
    let r3 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 4..byte_len * 5]);
    let s0 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 5..byte_len * 6]);
    let s1 = F128b::from_bytes(&tmp.into()).unwrap();

    let floor = x0_len / SECURITY_PARAM;
    let how_many = floor
        + if (x0_len - floor * SECURITY_PARAM) != 0 {
            1
        } else {
            0
        };

    let x0_vec = to_field_f128_and_pad(x0, x0_len);
    // NOTE: we dont need to compute how_many, we could directly use `x0_vec.len()`.
    assert_eq!(x0_vec.len(), how_many);

    let mut h0 = F128b::ZERO;
    let mut h1 = F128b::ZERO;
    let mut s0_power = s0;
    let mut s1_power = s1;
    for i in 0..how_many {
        h0 += s0_power * x0_vec[i];
        h1 += s1_power * x0_vec[i];
        // NOTE: difference from FAEST spec where the powers are in
        // reverse order, this is also valid.
        s0_power *= s0;
        s1_power *= s1;
    }
    let h2 = r0 * h0 + r1 * h1;
    let h3 = r2 * h0 + r3 * h1;

    let h2_bits = h2.bit_decomposition();
    let h3_bits = h3.bit_decomposition();

    let mut all_bits = Vec::with_capacity(SECURITY_PARAM + B);
    all_bits.extend_from_slice(h2_bits.as_slice());
    all_bits.extend_from_slice(h3_bits.as_slice());

    all_bits.truncate(x1_len);
    assert_eq!(all_bits.len(), SECURITY_PARAM + B);

    let mut out = [F2::ZERO; SECURITY_PARAM + B];

    out.copy_from_slice(
        all_bits
            .iter()
            .zip(x1)
            .map(|(b1, b2)| (F2::from(*b1) + b2))
            .collect::<Vec<_>>()
            .as_slice(),
    );
    HashConsistency(out)
}

/// Function doing linear hashing of the column of bits in lock-step.
///
/// There are `REPETITION_PARAM` tracks where one group of bits is provided as a [`F128b`] value.
#[inline(never)]
pub(crate) fn vole_hash_lockstep(
    seed: &[u8],
    x0: &[[F8b; REPETITION_PARAM]],
    x1: &[[F8b; REPETITION_PARAM]],
) -> [HashConsistency; SECURITY_PARAM] {
    assert_eq!(seed.len(), CHALL1_LENGTH);
    assert_eq!(x1.len(), SECURITY_PARAM + B);
    let byte_len: usize = 128 / 8;
    let mut tmp = [u8::default(); 128 / 8];

    // `r0`,`r1`, `r2`, `r3`, `s0` and `s1` are the same values of every track.
    tmp.copy_from_slice(&seed[0..byte_len]);
    let r0 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len..byte_len * 2]);
    let r1 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 2..byte_len * 3]);
    let r2 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 3..byte_len * 4]);
    let r3 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 4..byte_len * 5]);
    let s0 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 5..byte_len * 6]);
    let s1 = F128b::from_bytes(&tmp.into()).unwrap();

    let floor = x0.len() / SECURITY_PARAM;
    let how_many = floor
        + if (x0.len() - floor * SECURITY_PARAM) != 0 {
            1
        } else {
            0
        };

    // NOTE (optimize): This packed `f128b` of `x0` is a convenient holder for bits, and should
    // not be treated like a field element.
    let t = std::time::Instant::now();
    //let x0_vec = to_field_f128_and_pad_lockstep(&pack_f128b(x0));

    log::info!(
        "to_field_f128_and_pad_lockstep running time: {:?}",
        t.elapsed()
    );

    // NOTE: we dont need to compute how_many, we could directly use `x0_vec.len()`.
    // assert_eq!(x0_vec.len(), how_many);

    // There are different **options** to hashing the elements. The most runtime effective option is option #2, and the
    // most memory efficient option is option #3 because it is streaming the columns.

    // OPTION #1: naive
    // This option simply create the enumerator for the columns transposed of the field values and hashes with powers the columns sequentially.
    /*
    let packed_x0 = pack_f128b(x0);
    let x0_vec = ColumnEnumState::new(&packed_x0);
    let mut w0 = s0;
    let mut w1 = s1;
    let mut h0 = [F128b::ZERO; SECURITY_PARAM];
    let mut h1 = [F128b::ZERO; SECURITY_PARAM];

    for x0 in x0_vec {
        for (j, x_j) in x0.iter().enumerate() {
            h0[j] += w0 * x_j;
            h1[j] += w1 * x_j;
        }
        w0 *= s0;
        w1 *= s1;
    }
    */
    /* END OPTION #1 */

    // OPTION #2: par_iter()
    // This option transposes the field values into a vector before hashing with powers the columns in parallel using rayon.
    // One downside of this option is that it needs the vector of values to be explicitly and it cannot just use the enumerator.

    /*
    let x0_vec = to_field_f128_and_pad_lockstep(&pack_f128b(x0));
    fn powers(base: F128b, n: usize) -> Vec<F128b> {
        let mut out = Vec::with_capacity(n);
        let mut p = base;
        for _ in 0..n {
            out.push(p);
            p *= base;
        }
        out
    }
    fn accumulate_cols(
        x0_vec: &[[F128b; SECURITY_PARAM]],
        s0: F128b,
        s1: F128b,
    ) -> ([F128b; SECURITY_PARAM], [F128b; SECURITY_PARAM]) {
        let how_many = x0_vec.len();
        let w0 = powers(s0, how_many);
        let w1 = powers(s1, how_many);

        let mut h0 = [F128b::ZERO; SECURITY_PARAM];
        let mut h1 = [F128b::ZERO; SECURITY_PARAM];

        // Parallelize over (h0[j], h1[j]) pairs; each thread owns disjoint &mut slots.
        h0[..]
            .par_iter_mut()
            .zip(h1[..].par_iter_mut())
            .enumerate()
            .for_each(|(j, (h0j, h1j))| {
                let mut acc0 = F128b::ZERO;
                let mut acc1 = F128b::ZERO;
                for i in 0..how_many {
                    let x = x0_vec[i][j]; // strided access across rows
                    acc0 += w0[i] * x;
                    acc1 += w1[i] * x;
                }
                *h0j = acc0;
                *h1j = acc1;
            });

        (h0, h1)
    }

    let (h0, h1) = accumulate_cols(&x0_vec, s0, s1);
    */
    // END OPTION #2

    // OPTION #3: parallel producer/consumer
    // This option creates an enumerator for the column of the transposed field values and then splits the columns in
    // N blocks and spawn threads to do the hashing with powers.

    // use std::sync::mpsc::Sender; // unbounded buffers for messages
    use std::sync::mpsc::{sync_channel, SyncSender}; // SyncChannel uses fixed size buffers, which is useful to control memory.
    use std::{sync::mpsc::channel, thread};

    let packed_x0 = pack_f128b(x0);
    let x0_vec = ColumnEnumState::new(&packed_x0);

    const N: usize = 1; // number of threads
    let mut senders: Vec<SyncSender<[F128b; SECURITY_PARAM / N]>> = Vec::with_capacity(N);
    let mut receivs = Vec::with_capacity(N);
    let (result_sender, result_receiver) = channel();
    for _ in 0..N {
        let (tx, rx) = sync_channel(100);
        senders.push(tx);
        receivs.push(rx);
    }
    let mut handles = Vec::new();

    let mut num = 0;

    for recv in receivs {
        let send_i = result_sender.clone();
        let handle = thread::spawn(move || {
            let i = num;
            let mut w0 = s0;
            let mut w1 = s1;
            let mut h0 = [F128b::ZERO; SECURITY_PARAM / N];
            let mut h1 = [F128b::ZERO; SECURITY_PARAM / N];
            for slice in recv.iter() {
                for (j, v) in slice.iter().enumerate() {
                    h0[j] += v * w0;
                    h1[j] += v * w1;
                }

                w0 *= s0;
                w1 *= s1;
            }
            send_i.send((i, h0, h1)).unwrap();
        });
        handles.push(handle);
        num += 1;
    }

    for arr in x0_vec {
        let mut i = 0;
        for _ in 0..N {
            senders[i]
                .send(
                    arr[i * (SECURITY_PARAM / N)..(i + 1) * (SECURITY_PARAM / N)]
                        .try_into()
                        .unwrap(),
                )
                .unwrap();
            i += 1;
        }
    }
    drop(senders);

    let mut h0 = [F128b::ZERO; SECURITY_PARAM];
    let mut h1 = [F128b::ZERO; SECURITY_PARAM];
    for _ in 0..N {
        let (i, h0_i, h1_i) = result_receiver.recv().unwrap();
        h0[i * (SECURITY_PARAM / N)..(i + 1) * (SECURITY_PARAM / N)].copy_from_slice(&h0_i);
        h1[i * (SECURITY_PARAM / N)..(i + 1) * (SECURITY_PARAM / N)].copy_from_slice(&h1_i);
    }

    // END OPTION #3

    let mut h2 = [F128b::ZERO; SECURITY_PARAM];
    let mut h3 = [F128b::ZERO; SECURITY_PARAM];
    for j in 0..SECURITY_PARAM {
        h2[j] = r0 * h0[j] + r1 * h1[j];
        h3[j] = r2 * h0[j] + r3 * h1[j];
    }

    let mut out = [HashConsistency::default(); SECURITY_PARAM];

    let x1_packed = pack_f128b(x1);

    for j in 0..SECURITY_PARAM {
        let h2_bits = h2[j].bit_decomposition();
        let h3_bits = h3[j].bit_decomposition();

        let mut all_bits = Vec::with_capacity(SECURITY_PARAM + B);
        all_bits.extend_from_slice(h2_bits.as_slice());
        all_bits.extend_from_slice(h3_bits.as_slice());

        all_bits.truncate(x1.len());
        assert_eq!(all_bits.len(), SECURITY_PARAM + B);

        let mut single_out = [F2::ZERO; SECURITY_PARAM + B];

        let mut x1_bits = [false; SECURITY_PARAM + B];
        for col in 0..SECURITY_PARAM + B {
            x1_bits[col] = x1_packed[col].bit_decomposition()[j];
        }
        single_out.copy_from_slice(
            all_bits
                .iter()
                .zip(x1_bits)
                .map(|(b1, b2)| F2::from(*b1) + F2::from(b2))
                .collect::<Vec<_>>()
                .as_slice(),
        );
        out[j] = HashConsistency(single_out);
    }
    out
}

#[cfg(test)]
mod test {
    use super::{to_field_f128_and_pad, vole_hash};
    use crate::parameters::SECURITY_PARAM;
    use crate::vole::commit_reconstruct::B;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F128b;
    use swanky_field_binary::F2;
    use swanky_serialization::CanonicalSerialize;

    #[test]
    fn test_padding_of_to_field_f128_and_pad() {
        let v = vec![F2::ZERO; 1000];
        let t = to_field_f128_and_pad(v.into_iter(), 1000);
        assert_eq!(t.len(), 1000 / 128 + 1);

        let v = vec![F2::ZERO; 128];
        let t = to_field_f128_and_pad(v.into_iter(), 128);
        assert_eq!(t.len(), 1);

        let v = vec![F2::ZERO; 129];
        let t = to_field_f128_and_pad(v.into_iter(), 129);
        assert_eq!(t.len(), 2);

        let mut v = vec![F2::ZERO; 130];
        v[0] = F2::ONE;
        v[129] = F2::ONE;
        let t = to_field_f128_and_pad(v.into_iter(), 129);
        let mut res1 = [0u8; 16];
        res1[0] = 1u8;
        assert_eq!(t[0], F128b::from_bytes(&res1.into()).unwrap());
        let mut res2 = [0u8; 16];
        res2[0] = 2u8;
        assert_eq!(t[1], F128b::from_bytes(&res2.into()).unwrap());
        // TODO: Could generate random values and decompose the generated F128b and check the equivalence
    }

    // Test that [`vole_hash`] returns 0 when all the inputs are 0.
    #[test]
    fn test_vole_hash_zero() {
        let seeds = [0u8; (SECURITY_PARAM * 6) / 8];

        const HOW_MANY: usize = 1000;
        let x0 = [F2::ZERO; HOW_MANY + SECURITY_PARAM];
        let x1 = [F2::ZERO; SECURITY_PARAM + B];
        let v = vole_hash(
            &seeds,
            x0.into_iter(),
            HOW_MANY + SECURITY_PARAM,
            x1.into_iter(),
            SECURITY_PARAM + B,
        );
        for b in v.0.iter() {
            assert_eq!(*b, F2::ZERO);
        }
    }

    // Test the xor part at the end of [`vole_hash`]
    #[test]
    fn test_vole_hash_last_xor() {
        let seeds = [0u8; (SECURITY_PARAM * 6) / 8];

        const HOW_MANY: usize = 1000;
        let x0 = [F2::ZERO; HOW_MANY + SECURITY_PARAM];
        let mut x1 = [F2::ZERO; SECURITY_PARAM + B];
        let pos = 13;
        x1[pos] = F2::ONE;
        let v = vole_hash(
            &seeds,
            x0.into_iter(),
            HOW_MANY + SECURITY_PARAM,
            x1.into_iter(),
            SECURITY_PARAM + B,
        );
        for (i, b) in v.0.iter().enumerate() {
            if i == pos {
                assert_eq!(*b, F2::ONE);
            } else {
                assert_eq!(*b, F2::ZERO);
            }
        }
    }

    // Test the xor part at the end of [`vole_hash`]
    #[test]
    fn test_vole_hash_is_linear() {
        let seeds = [1u8; (SECURITY_PARAM * 6) / 8];

        const HOW_MANY: usize = 1000;
        const BOUND: usize = HOW_MANY + SECURITY_PARAM;
        const LAST: usize = SECURITY_PARAM + B;
        let x0 = [F2::ONE; HOW_MANY + 2 * SECURITY_PARAM + B];
        let x1 = [F2::ZERO; HOW_MANY + 2 * SECURITY_PARAM + B];
        let x2 = [F2::ONE; HOW_MANY + 2 * SECURITY_PARAM + B];

        let v0 = vole_hash(
            &seeds,
            x0.into_iter().take(BOUND),
            BOUND,
            x0.into_iter().skip(BOUND),
            LAST,
        );
        let v1 = vole_hash(
            &seeds,
            x1.into_iter().take(BOUND),
            BOUND,
            x1.into_iter().skip(BOUND),
            LAST,
        );
        let v2 = vole_hash(
            &seeds,
            x2.into_iter().take(BOUND),
            BOUND,
            x2.into_iter().skip(BOUND),
            LAST,
        );
        for ((a, b), c) in v0.0.iter().zip(v1.0.iter()).zip(v2.0.iter()) {
            assert_eq!(*a + *b, *c);
        }
    }

    #[test]
    fn test_transpose_lockstep_equals_enumerator() {
        use super::{pack_f128b, to_field_f128_and_pad_lockstep, ColumnEnumState};
        use crate::parameters::REPETITION_PARAM;
        use swanky_field_binary::F8b;

        fn f8(x: u8) -> F8b {
            F8b::from_bytes(&[x].into()).unwrap()
        }

        // Try different lengths
        let lengths = [
            0usize, 1, 15, 16, 17, 127, 128, 129, 200, 255, 256, 511, 512, 513,
        ];

        for &len in &lengths {
            // Build len rows of 16 bytes each to pack into F128b values
            let mut rows: Vec<[F8b; REPETITION_PARAM]> = Vec::with_capacity(len);
            for i in 0..len {
                let mut row = [F8b::ZERO; REPETITION_PARAM];
                for (j, cell) in row.iter_mut().enumerate() {
                    // Deterministic, non-trivial pattern
                    let byte = (i as u8)
                        .wrapping_mul(31)
                        .wrapping_add(j as u8)
                        .wrapping_mul(17);
                    *cell = f8(byte);
                }
                rows.push(row);
            }

            let packed = pack_f128b(&rows);

            let via_lockstep = to_field_f128_and_pad_lockstep(&packed);
            let via_enum: Vec<[F128b; SECURITY_PARAM]> = ColumnEnumState::new(&packed).collect();

            assert_eq!(
                via_lockstep.len(),
                via_enum.len(),
                "mismatched chunk count for len={}",
                len
            );
            for (i, (a, b)) in via_lockstep.iter().zip(via_enum.iter()).enumerate() {
                for j in 0..SECURITY_PARAM {
                    assert_eq!(
                        a[j], b[j],
                        "mismatch at len={}, chunk={}, col={} ",
                        len, i, j
                    );
                }
            }
        }
    }
}
