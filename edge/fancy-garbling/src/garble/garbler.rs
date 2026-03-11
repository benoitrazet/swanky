use crate::{
    AllWire, ArithmeticWire, FancyArithmetic, FancyBinary, FancyInput, HasModulus, WireLabel,
    WireMod2, check_binary,
    fancy::{BinaryBundle, CrtBundle, Fancy, FancyReveal},
    garble::binary_and::BinaryWireLabel,
    hash_wires,
    util::{RngExt, output_tweak, tweak, tweak2},
};
use rand::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use swanky_block::Block;
use swanky_channel::Channel;

use super::security_warning::warn_proj;

/// Streams garbled circuit ciphertexts through a callback.
pub struct Garbler<RNG, Wire> {
    // Zero wirelabel used for binary negation.
    zero: Wire,
    // Map from modulus to associated delta wirelabel.
    deltas: HashMap<u16, Wire>,
    current_output: usize,
    current_gate: usize,
    rng: RNG,
}

#[cfg(feature = "serde")]
impl<RNG: CryptoRng + RngCore, Wire: WireLabel + DeserializeOwned> Garbler<RNG, Wire> {
    /// Load pre-chosen deltas from a file
    pub fn load_deltas(&mut self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let f = std::fs::File::open(filename)?;
        let reader = std::io::BufReader::new(f);
        let deltas: HashMap<u16, Wire> = serde_json::from_reader(reader)?;
        self.deltas.extend(deltas.into_iter());
        Ok(())
    }
}

impl<RNG: CryptoRng + RngCore, Wire: WireLabel> Garbler<RNG, Wire> {
    /// Create a new [`Garbler`].
    pub fn new(mut rng: RNG, channel: &mut Channel) -> swanky_error::Result<Self> {
        let zero = Wire::rand(&mut rng, 2);
        let delta = Wire::rand_delta(&mut rng, 2);
        let one = zero.clone() + delta.clone();
        let mut deltas = HashMap::new();
        deltas.insert(2, delta);
        // Send the one wirelabel to the evaluator. This is used to make binary
        // negation free.
        channel.write(&one.to_block())?;
        Ok(Garbler {
            zero,
            deltas,
            current_gate: 0,
            current_output: 0,
            rng,
        })
    }

    /// The current non-free gate index of the garbling computation
    fn current_gate(&mut self) -> usize {
        let current = self.current_gate;
        self.current_gate += 1;
        current
    }

    /// Create a delta if it has not been created yet for this modulus, otherwise just
    /// return the existing one.
    pub fn delta(&mut self, q: u16) -> Wire {
        if let Some(delta) = self.deltas.get(&q) {
            return delta.clone();
        }
        let w = Wire::rand_delta(&mut self.rng, q);
        self.deltas.insert(q, w.clone());
        w
    }

    /// The current output index of the garbling computation.
    fn current_output(&mut self) -> usize {
        let current = self.current_output;
        self.current_output += 1;
        current
    }

    /// Get the deltas, consuming the Garbler.
    ///
    /// This is useful for reusing wires in multiple garbled circuit instances.
    pub fn get_deltas(self) -> HashMap<u16, Wire> {
        self.deltas
    }

    /// Send a wire over the established channel.
    pub fn send_wire(&mut self, wire: &Wire, channel: &mut Channel) -> swanky_error::Result<()> {
        channel.write(&wire.to_block())?;
        Ok(())
    }

    /// Encode a wire, producing the zero wire as well as the encoded value.
    pub fn encode_wire(&mut self, val: u16, modulus: u16) -> (Wire, Wire) {
        let zero = Wire::rand(&mut self.rng, modulus);
        let delta = self.delta(modulus);
        let enc = zero.clone() + delta.cmul(val);
        (zero, enc)
    }

    /// Encode many wires, producing zero wires as well as encoded values.
    ///
    /// # Panics
    /// Panics if the length of `vals` and `moduli` are not equal.
    pub fn encode_many_wires(&mut self, vals: &[u16], moduli: &[u16]) -> (Vec<Wire>, Vec<Wire>) {
        assert_eq!(vals.len(), moduli.len());

        let mut gbs = Vec::with_capacity(vals.len());
        let mut evs = Vec::with_capacity(vals.len());
        for (x, q) in vals.iter().zip(moduli.iter()) {
            let (gb, ev) = self.encode_wire(*x, *q);
            gbs.push(gb);
            evs.push(ev);
        }
        (gbs, evs)
    }

    /// Encode a `CrtBundle`, producing zero wires as well as encoded values.
    pub fn crt_encode_wire(
        &mut self,
        val: u128,
        modulus: u128,
    ) -> (CrtBundle<Wire>, CrtBundle<Wire>) {
        let ms = crate::util::factor(modulus);
        let xs = crate::util::crt(val, &ms);
        let (gbs, evs) = self.encode_many_wires(&xs, &ms);
        (CrtBundle::new(gbs), CrtBundle::new(evs))
    }

    /// Encode a `BinaryBundle`, producing zero wires as well as encoded values.
    pub fn bin_encode_wire(
        &mut self,
        val: u128,
        nbits: usize,
    ) -> (BinaryBundle<Wire>, BinaryBundle<Wire>) {
        let xs = crate::util::u128_to_bits(val, nbits);
        let ms = vec![2; nbits];
        let (gbs, evs) = self.encode_many_wires(&xs, &ms);
        (BinaryBundle::new(gbs), BinaryBundle::new(evs))
    }
}

impl<RNG: CryptoRng + RngCore, Wire: WireLabel> FancyInput for Garbler<RNG, Wire> {
    type Item = Wire;

    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        let (zero, encoded) = self.encode_many_wires(values, moduli);
        for wire in encoded {
            channel.write(&wire.to_block())?;
        }
        Ok(zero)
    }

    fn receive_many(
        &mut self,
        _moduli: &[u16],
        _: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        unimplemented!("Garbler cannot receive values")
    }
}

impl<RNG: RngCore + CryptoRng, Wire: WireLabel> FancyReveal for Garbler<RNG, Wire> {
    fn reveal(&mut self, x: &Wire, channel: &mut Channel) -> swanky_error::Result<u16> {
        // The evaluator needs our cooperation in order to see the output.
        // Hence, we call output() ourselves.
        self.output(x, channel)?;
        let val = channel.read::<u16>()?;
        Ok(val)
    }
}

impl<RNG: RngCore + CryptoRng, W: BinaryWireLabel> FancyBinary for Garbler<RNG, W> {
    fn and(
        &mut self,
        A: &Self::Item,
        B: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let delta = self.delta(2);
        let gate_num = self.current_gate();
        let (gate0, gate1, C) = W::garble_and_gate(gate_num, A, B, &delta);
        channel.write(&gate0)?;
        channel.write(&gate1)?;
        Ok(C)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        x.clone() + y.clone()
    }

    /// We can negate by having garbler xor wire with Delta
    ///
    /// Since we treat all garbler wires as zero,
    /// xoring with delta conceptually negates the value of the wire
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        let zero = self.zero.clone();
        self.xor(&zero, x)
    }
}

impl<RNG: RngCore + CryptoRng> FancyBinary for Garbler<RNG, AllWire> {
    /// We can negate by having garbler xor wire with Delta
    ///
    /// Since we treat all garbler wires as zero,
    /// xoring with delta conceptually negates the value of the wire
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        check_binary!(x);

        let zero = self.zero.clone();
        self.xor(&zero, x)
    }

    /// Xor is just addition
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        check_binary!(x);
        check_binary!(y);

        self.add(x, y)
    }

    /// Use binary and_gate
    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        if let (AllWire::Mod2(A), AllWire::Mod2(B), AllWire::Mod2(ref delta)) =
            (x, y, self.delta(2))
        {
            let gate_num = self.current_gate();
            let (gate0, gate1, C) = WireMod2::garble_and_gate(gate_num, A, B, delta);
            channel.write(&gate0)?;
            channel.write(&gate1)?;
            return Ok(AllWire::Mod2(C));
        }
        // If we got here, one of the wires isn't binary
        check_binary!(x);
        check_binary!(y);

        // Shouldn't be reachable, unless the wire has modulus 2 but is not AllWire::Mod2()
        unreachable!()
    }
}

impl<RNG: RngCore + CryptoRng, Wire: WireLabel + ArithmeticWire> FancyArithmetic
    for Garbler<RNG, Wire>
{
    fn add(&mut self, x: &Wire, y: &Wire) -> Wire {
        assert_eq!(x.modulus(), y.modulus());
        x.clone() + y.clone()
    }

    fn sub(&mut self, x: &Wire, y: &Wire) -> Wire {
        assert_eq!(x.modulus(), y.modulus());
        x.minus(y)
    }

    fn cmul(&mut self, x: &Wire, c: u16) -> Wire {
        x.cmul(c)
    }

    fn mul(&mut self, A: &Wire, B: &Wire, channel: &mut Channel) -> swanky_error::Result<Wire> {
        if A.modulus() < B.modulus() {
            return self.mul(B, A, channel);
        }

        let q = A.modulus();
        let qb = B.modulus();
        let gate_num = self.current_gate();

        let D = self.delta(q);
        let Db = self.delta(qb);

        let r;
        let mut gate = vec![Block::default(); q as usize + qb as usize - 2];

        // hack for unequal moduli
        if q != qb {
            // would need to pack minitable into more than one u128 to support qb > 8
            assert!(
                qb <= 8,
                "`B.modulus()` with asymmetric moduli is capped at 8"
            );

            r = self.rng.gen_u16() % q;
            let t = tweak2(gate_num as u64, 1);

            let mut minitable = vec![u128::default(); qb as usize];
            let mut B_ = B.clone();
            for b in 0..qb {
                if b > 0 {
                    B_ += Db.clone();
                }
                let new_color = ((r + b) % q) as u128;
                let ct = (u128::from(B_.hash(t)) & 0xFFFF) ^ new_color;
                minitable[B_.color() as usize] = ct;
            }

            let mut packed = 0;
            for i in 0..qb as usize {
                packed += minitable[i] << (16 * i);
            }
            gate.push(Block::from(packed));
        } else {
            r = B.color(); // secret value known only to the garbler (ev knows r+b)
        }

        let g = tweak2(gate_num as u64, 0);

        // X = H(A+aD) + arD such that a + A.color == 0
        let alpha = (q - A.color()) % q; // alpha = -A.color
        let X1 = A.clone() + D.cmul(alpha);

        // Y = H(B + bD) + (b + r)A such that b + B.color == 0
        let beta = (qb - B.color()) % qb;
        let Y1 = B.clone() + Db.cmul(beta);

        let [hashX, hashY] = hash_wires([&X1, &Y1], g);

        let X = Wire::hash_to_mod(hashX, q) + D.cmul(alpha * r % q);
        let Y = Wire::hash_to_mod(hashY, q) + A.cmul((beta + r) % q);

        let mut precomp = Vec::with_capacity(q as usize);
        // precompute a lookup table of X.minus(&D_cmul[(a * r % q)])
        //                            = X.plus(&D_cmul[((q - (a * r % q)) % q)])
        let mut X_ = X.clone();
        precomp.push(X_.to_block());
        for _ in 1..q {
            X_ += D.clone();
            precomp.push(X_.to_block());
        }

        // We can vectorize the hashes here too, but then we need to precompute all `q` sums of A
        // with delta [A, A + D, A + D + D, etc.]
        // Would probably need another alloc which isn't great
        let mut A_ = A.clone();
        for a in 0..q {
            if a > 0 {
                A_ += D.clone();
            }
            // garbler's half-gate: outputs X-arD
            // G = H(A+aD) ^ X+a(-r)D = H(A+aD) ^ X-arD
            if A_.color() != 0 {
                gate[A_.color() as usize - 1] =
                    A_.hash(g) ^ precomp[((q - (a * r % q)) % q) as usize];
            }
        }
        precomp.clear();

        // precompute a lookup table of Y.minus(&A_cmul[((b+r) % q)])
        //                            = Y.plus(&A_cmul[((q - ((b+r) % q)) % q)])
        let mut Y_ = Y.clone();
        precomp.push(Y_.to_block());
        for _ in 1..q {
            Y_ += A.clone();
            precomp.push(Y_.to_block());
        }

        // Same note about vectorization as A
        let mut B_ = B.clone();
        for b in 0..qb {
            if b > 0 {
                B_ += Db.clone();
            }
            // evaluator's half-gate: outputs Y-(b+r)D
            // G = H(B+bD) + Y-(b+r)A
            if B_.color() != 0 {
                gate[q as usize - 1 + B_.color() as usize - 1] =
                    B_.hash(g) ^ precomp[((q - ((b + r) % q)) % q) as usize];
            }
        }

        for block in gate.iter() {
            channel.write(block)?;
        }
        Ok(X + Y)
    }

    fn proj(
        &mut self,
        A: &Wire,
        q_out: u16,
        tt: Option<Vec<u16>>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Wire> {
        warn_proj();
        assert!(tt.is_some(), "`tt` must not be `None`");
        let tt = tt.unwrap();

        let q_in = A.modulus();
        let mut gate = vec![Block::default(); q_in as usize - 1];

        let tao = A.color();
        let g = tweak(self.current_gate());

        let Din = self.delta(q_in);
        let Dout = self.delta(q_out);

        // output zero-wire
        // W_g^0 <- -H(g, W_{a_1}^0 - \tao\Delta_m) - \phi(-\tao)\Delta_n
        let C = (A.clone() + Din.cmul((q_in - tao) % q_in)).hashback(g, q_out)
            + Dout.cmul((q_out - tt[((q_in - tao) % q_in) as usize]) % q_out);

        // precompute `let C_ = C.plus(&Dout.cmul(tt[x as usize]))`
        let C_precomputed = {
            let mut C_ = C.clone();
            (0..q_out)
                .map(|x| {
                    if x > 0 {
                        C_ += Dout.clone();
                    }
                    C_.to_block()
                })
                .collect::<Vec<Block>>()
        };

        let mut A_ = A.clone();
        for x in 0..q_in {
            if x > 0 {
                A_ += Din.clone(); // avoiding expensive cmul for `A_ = A.plus(&Din.cmul(x))`
            }

            let ix = (tao as usize + x as usize) % q_in as usize;
            if ix == 0 {
                continue;
            }

            let ct = A_.hash(g) ^ C_precomputed[tt[x as usize] as usize];
            gate[ix - 1] = ct;
        }

        for block in gate.iter() {
            channel.write(block)?;
        }
        Ok(C)
    }
}

impl<RNG: RngCore + CryptoRng, Wire: WireLabel> Fancy for Garbler<RNG, Wire> {
    type Item = Wire;

    fn constant(&mut self, x: u16, q: u16, channel: &mut Channel) -> swanky_error::Result<Wire> {
        let zero = Wire::rand(&mut self.rng, q);
        let wire = zero.clone() + self.delta(q).cmul_eq(x).clone();
        self.send_wire(&wire, channel)?;
        Ok(zero)
    }

    fn output(&mut self, X: &Wire, channel: &mut Channel) -> swanky_error::Result<Option<u16>> {
        let q = X.modulus();
        let i = self.current_output();
        let D = self.delta(q);
        for k in 0..q {
            let block = (X.clone() + D.cmul(k)).hash(output_tweak(i, k));
            channel.write(&block)?;
        }
        Ok(None)
    }
}
