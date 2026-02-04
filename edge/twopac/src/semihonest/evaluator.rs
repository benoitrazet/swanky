use crate::errors::Error;
use fancy_garbling::{
    AllWire, ArithmeticWire, Evaluator as Ev, Fancy, FancyArithmetic, FancyBinary, FancyInput,
    FancyReveal, WireLabel, WireMod2,
};
use rand::{CryptoRng, Rng};
use swanky_adversary::SemiHonest;
use swanky_block::Block;
use swanky_channel::Channel;
use swanky_ot_traits::Receiver as OtReceiver;

/// Semi-honest evaluator.
pub struct Evaluator<RNG, OT, Wire> {
    evaluator: Ev<Wire>,
    ot: OT,
    rng: RNG,
}

impl<RNG, OT, Wire> Evaluator<RNG, OT, Wire> {}

impl<RNG: CryptoRng + Rng, OT: OtReceiver<Msg = Block> + SemiHonest, Wire: WireLabel>
    Evaluator<RNG, OT, Wire>
{
    /// Make a new `Evaluator`.
    pub fn new(channel: &mut Channel, mut rng: RNG) -> Result<Self, Error> {
        let ot = OT::init(channel, &mut rng)?;
        let evaluator = Ev::new();
        Ok(Self { evaluator, ot, rng })
    }

    fn run_ot(&mut self, inputs: &[bool], channel: &mut Channel) -> Result<Vec<Block>, Error> {
        self.ot
            .receive(channel, inputs, &mut self.rng)
            .map_err(Error::from)
    }
}

impl<RNG: CryptoRng + Rng, OT: OtReceiver<Msg = Block> + SemiHonest, Wire: WireLabel> FancyInput
    for Evaluator<RNG, OT, Wire>
{
    type Item = Wire;
    type Error = Error;

    /// Receive a garbler input wire.
    fn receive(&mut self, modulus: u16, channel: &mut Channel) -> Result<Wire, Error> {
        let w = self.evaluator.read_wire(modulus, channel)?;
        Ok(w)
    }

    /// Receive garbler input wires.
    fn receive_many(&mut self, moduli: &[u16], channel: &mut Channel) -> Result<Vec<Wire>, Error> {
        moduli.iter().map(|q| self.receive(*q, channel)).collect()
    }

    /// Perform OT and obtain wires for the evaluator's inputs.
    fn encode_many(
        &mut self,
        inputs: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> Result<Vec<Wire>, Error> {
        let mut lens = Vec::new();
        let mut bs = Vec::new();
        for (x, q) in inputs.iter().zip(moduli.iter()) {
            let len = f32::from(*q).log(2.0).ceil() as usize;
            for b in (0..len).map(|i| x & (1 << i) != 0) {
                bs.push(b);
            }
            lens.push(len);
        }
        let wires = self.run_ot(&bs, channel)?;
        let mut start = 0;
        Ok(lens
            .into_iter()
            .zip(moduli.iter())
            .map(|(len, q)| {
                let range = start..start + len;
                let chunk = &wires[range];
                start += len;
                combine(chunk, *q)
            })
            .collect::<Vec<Wire>>())
    }
}

fn combine<Wire: WireLabel>(wires: &[Block], q: u16) -> Wire {
    wires.iter().enumerate().fold(Wire::zero(q), |acc, (i, w)| {
        let w = Wire::from_block(*w, q);
        acc.plus(&w.cmul(1 << i))
    })
}

impl<RNG, OT> FancyBinary for Evaluator<RNG, OT, WireMod2> {
    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> Result<Self::Item, Self::Error> {
        self.evaluator.and(x, y, channel).map_err(Self::Error::from)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        self.evaluator.xor(x, y)
    }

    fn negate(&mut self, x: &Self::Item, channel: &mut Channel) -> Result<Self::Item, Self::Error> {
        self.evaluator.negate(x, channel).map_err(Self::Error::from)
    }
}

impl<RNG, OT> FancyBinary for Evaluator<RNG, OT, AllWire> {
    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> Result<Self::Item, Self::Error> {
        self.evaluator.and(x, y, channel).map_err(Self::Error::from)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        self.evaluator.xor(x, y)
    }

    fn negate(&mut self, x: &Self::Item, channel: &mut Channel) -> Result<Self::Item, Self::Error> {
        self.evaluator.negate(x, channel).map_err(Self::Error::from)
    }
}

impl<RNG, OT, Wire: WireLabel + ArithmeticWire> FancyArithmetic for Evaluator<RNG, OT, Wire> {
    fn add(&mut self, x: &Wire, y: &Wire) -> Self::Item {
        self.evaluator.add(x, y)
    }

    fn sub(&mut self, x: &Wire, y: &Wire) -> Result<Self::Item, Self::Error> {
        self.evaluator.sub(x, y).map_err(Self::Error::from)
    }

    fn cmul(&mut self, x: &Wire, c: u16) -> Result<Self::Item, Self::Error> {
        self.evaluator.cmul(x, c).map_err(Self::Error::from)
    }

    fn mul(
        &mut self,
        x: &Wire,
        y: &Wire,
        channel: &mut Channel,
    ) -> Result<Self::Item, Self::Error> {
        self.evaluator.mul(x, y, channel).map_err(Self::Error::from)
    }

    fn proj(
        &mut self,
        x: &Wire,
        q: u16,
        tt: Option<Vec<u16>>,
        channel: &mut Channel,
    ) -> Result<Self::Item, Self::Error> {
        self.evaluator
            .proj(x, q, tt, channel)
            .map_err(Self::Error::from)
    }
}

impl<RNG, OT, Wire: WireLabel> Fancy for Evaluator<RNG, OT, Wire> {
    type Item = Wire;
    type Error = Error;

    fn constant(
        &mut self,
        x: u16,
        q: u16,
        channel: &mut Channel,
    ) -> Result<Self::Item, Self::Error> {
        self.evaluator
            .constant(x, q, channel)
            .map_err(Self::Error::from)
    }

    fn output(&mut self, x: &Wire, channel: &mut Channel) -> Result<Option<u16>, Self::Error> {
        self.evaluator.output(x, channel).map_err(Self::Error::from)
    }
}

impl<RNG: CryptoRng + Rng, OT, Wire: WireLabel> FancyReveal for Evaluator<RNG, OT, Wire> {
    fn reveal(&mut self, x: &Self::Item, channel: &mut Channel) -> Result<u16, Self::Error> {
        self.evaluator.reveal(x, channel).map_err(Self::Error::from)
    }
}

impl<RNG, OT, Wire> SemiHonest for Evaluator<RNG, OT, Wire> {}
