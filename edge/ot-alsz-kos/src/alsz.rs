//! Implementation of the Asharov-Lindell-Schneider-Zohner oblivious transfer
//! extension protocol (cf. <https://eprint.iacr.org/2016/602>, Protocol 4).

#![allow(non_upper_case_globals)]

use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use std::marker::PhantomData;
use swanky_adversary::SemiHonest;
use swanky_aes_hash::CorrelationRobustHash;
use swanky_block::Block;
use swanky_bytearray_utils as scutils;
use swanky_channel_legacy::AbstractChannel;
use swanky_ocelot_error::Error;
use swanky_ot_traits::{
    CorrelatedReceiver, CorrelatedSender, FixedKeyInitializer, RandomReceiver, RandomSender,
    Receiver as OtReceiver, Sender as OtSender,
};
use swanky_rng::AesRng;

/// Oblivious transfer sender.
pub struct Sender<OT: OtReceiver<Msg = Block> + SemiHonest = swanky_ot_chou_orlandi::Receiver> {
    _ot: PhantomData<OT>,
    s: Vec<bool>,
    pub(super) s_: Block,
    rngs: Vec<AesRng>,
}
/// Oblivious transfer receiver.
pub struct Receiver<OT: OtSender<Msg = Block> + SemiHonest = swanky_ot_chou_orlandi::Sender> {
    _ot: PhantomData<OT>,
    rngs: Vec<(AesRng, AesRng)>,
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> FixedKeyInitializer for Sender<OT> {
    fn init_fixed_key<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        s_: [u8; 16],
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut ot = OT::init(channel, rng)?;
        let s = swanky_deprecated_bitwise_utils::u8vec_to_boolvec(&s_);
        let ks = ot.receive(channel, &s, rng)?;
        let rngs = ks
            .into_iter()
            .map(AesRng::from_seed)
            .collect::<Vec<AesRng>>();
        Ok(Self {
            _ot: PhantomData::<OT>,
            s,
            s_: Block::from(s_),
            rngs,
        })
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> Sender<OT> {
    pub(super) fn send_setup<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        m: usize,
    ) -> Result<Vec<u8>, Error> {
        const nrows: usize = 128;
        let ncols = if !m.is_multiple_of(8) {
            m + (8 - m % 8)
        } else {
            m
        };
        let mut qs = vec![0u8; nrows * ncols / 8];
        let mut u = vec![0u8; ncols / 8];
        let zero = vec![0u8; ncols / 8];
        for (j, (b, rng)) in self.s.iter().zip(self.rngs.iter_mut()).enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let q = &mut qs[range];
            channel.read_bytes(&mut u)?;
            rng.fill_bytes(q);
            scutils::xor_inplace(q, if *b { &u } else { &zero });
        }
        Ok(swanky_bit_matrix_transpose::transpose(&qs, nrows, ncols))
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> OtSender for Sender<OT> {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut s_ = [0u8; 16];
        rng.fill_bytes(&mut s_);
        Sender::<OT>::init_fixed_key(channel, s_, rng)
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Self::Msg, Self::Msg)],
        _: &mut RNG,
    ) -> Result<(), Error> {
        let m = inputs.len();
        let qs = self.send_setup(channel, m)?;
        for (j, input) in inputs.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let y0 = CorrelationRobustHash::fixed_key().hash(q) ^ input.0;
            let q = q ^ self.s_;
            let y1 = CorrelationRobustHash::fixed_key().hash(q) ^ input.1;
            channel.write_block(&y0)?;
            channel.write_block(&y1)?;
        }
        channel.flush()?;
        Ok(())
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> std::fmt::Display for Sender<OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ALSZ Sender")
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> CorrelatedSender for Sender<OT> {
    fn send_correlated<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        m: usize,
        delta: Self::Msg,
        _: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error> {
        let qs = self.send_setup(channel, m)?;
        let mut out = Vec::with_capacity(m);
        for j in 0..m {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let x0 = CorrelationRobustHash::fixed_key().hash(q);
            let x1 = x0 ^ delta;
            let q = q ^ self.s_;
            let y = CorrelationRobustHash::fixed_key().hash(q) ^ x1;
            channel.write_block(&y)?;
            out.push(x0);
        }
        channel.flush()?;
        Ok(out)
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> RandomSender for Sender<OT> {
    fn send_random<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        m: usize,
        _: &mut RNG,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error> {
        let qs = self.send_setup(channel, m)?;
        let mut out = Vec::with_capacity(m);
        for j in 0..m {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let x0 = CorrelationRobustHash::fixed_key().hash(q);
            let q = q ^ self.s_;
            let x1 = CorrelationRobustHash::fixed_key().hash(q);
            out.push((x0, x1));
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> Receiver<OT> {
    pub(super) fn receive_setup<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        r: &[u8],
        m: usize,
    ) -> Result<Vec<u8>, Error> {
        const nrows: usize = 128;
        let ncols = if !m.is_multiple_of(8) {
            m + (8 - m % 8)
        } else {
            m
        };
        let mut ts = vec![0u8; nrows * ncols / 8];
        let mut g = vec![0u8; ncols / 8];
        for j in 0..self.rngs.len() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let t = &mut ts[range];
            self.rngs[j].0.fill_bytes(t);
            self.rngs[j].1.fill_bytes(&mut g);
            scutils::xor_inplace(&mut g, t);
            scutils::xor_inplace(&mut g, r);
            channel.write_bytes(&g)?;
        }
        channel.flush()?;
        Ok(swanky_bit_matrix_transpose::transpose(&ts, nrows, ncols))
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> OtReceiver for Receiver<OT> {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut ot = OT::init(channel, rng)?;
        let mut ks = Vec::with_capacity(128);
        let mut k0 = Block::default();
        let mut k1 = Block::default();
        for _ in 0..128 {
            rng.fill_bytes(k0.as_mut());
            rng.fill_bytes(k1.as_mut());
            ks.push((k0, k1));
        }
        ot.send(channel, &ks, rng)?;
        let rngs = ks
            .into_iter()
            .map(|(k0, k1)| (AesRng::from_seed(k0), AesRng::from_seed(k1)))
            .collect::<Vec<(AesRng, AesRng)>>();
        Ok(Self {
            _ot: PhantomData::<OT>,
            rngs,
        })
    }

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        _: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error> {
        let r = swanky_deprecated_bitwise_utils::boolvec_to_u8vec(inputs);
        let ts = self.receive_setup(channel, &r, inputs.len())?;
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let y0 = channel.read_block()?;
            let y1 = channel.read_block()?;
            let y = if *b { y1 } else { y0 };
            let y = y ^ CorrelationRobustHash::fixed_key().hash(Block::from(t));
            out.push(y);
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> CorrelatedReceiver for Receiver<OT> {
    fn receive_correlated<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        _: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error> {
        let r = swanky_deprecated_bitwise_utils::boolvec_to_u8vec(inputs);
        let ts = self.receive_setup(channel, &r, inputs.len())?;
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let y = channel.read_block()?;
            let y = if *b { y } else { Block::default() };
            let h = CorrelationRobustHash::fixed_key().hash(Block::from(t));
            out.push(y ^ h);
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> RandomReceiver for Receiver<OT> {
    fn receive_random<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        _: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error> {
        let r = swanky_deprecated_bitwise_utils::boolvec_to_u8vec(inputs);
        let ts = self.receive_setup(channel, &r, inputs.len())?;
        let mut out = Vec::with_capacity(inputs.len());
        for j in 0..inputs.len() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let h = CorrelationRobustHash::fixed_key().hash(Block::from(t));
            out.push(h);
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> std::fmt::Display for Receiver<OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ALSZ Receiver")
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> SemiHonest for Sender<OT> {}
impl<OT: OtSender<Msg = Block> + SemiHonest> SemiHonest for Receiver<OT> {}

#[test]
fn test_functionality() {
    let ninputs = 1 << 10;
    swanky_ot_test::test_otext::<Sender, Receiver>(ninputs);
    swanky_ot_test::test_cotext::<Sender, Receiver>(ninputs);
    swanky_ot_test::test_rotext::<Sender, Receiver>(ninputs);
    let ninputs = (1 << 10) + 1;
    swanky_ot_test::test_otext::<Sender, Receiver>(ninputs);
    swanky_ot_test::test_cotext::<Sender, Receiver>(ninputs);
    swanky_ot_test::test_rotext::<Sender, Receiver>(ninputs);
}
