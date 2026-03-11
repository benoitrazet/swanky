use fancy_garbling::{
    AllWire, ArithmeticWire, Evaluator as Ev, Fancy, FancyArithmetic, FancyBinary, FancyInput,
    FancyReveal, WireLabel, WireMod2,
};
use rand::{CryptoRng, Rng};
use swanky_adversary::SemiHonest;
use swanky_block::Block;
use swanky_channel::Channel;
use swanky_error::{ErrorKind, WrapErr};
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
    pub fn new(channel: &mut Channel, mut rng: RNG) -> swanky_error::Result<Self> {
        let ot = OT::init(channel, &mut rng)
            .wrap_err_with(ErrorKind::InitializationError, || {
                "Failed to initialize OT.".to_string()
            })?;
        let evaluator = Ev::new(channel)?;
        Ok(Self { evaluator, ot, rng })
    }

    fn run_ot(
        &mut self,
        inputs: &[bool],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Block>> {
        self.ot
            .receive(channel, inputs, &mut self.rng)
            .wrap_err_with(ErrorKind::OtherError, || "Failed to run OT.".to_string())
    }
}

impl<RNG: CryptoRng + Rng, OT: OtReceiver<Msg = Block> + SemiHonest, Wire: WireLabel> FancyInput
    for Evaluator<RNG, OT, Wire>
{
    type Item = Wire;

    /// Receive a garbler input wire.
    fn receive(&mut self, modulus: u16, channel: &mut Channel) -> swanky_error::Result<Wire> {
        let w = self.evaluator.read_wire(modulus, channel)?;
        Ok(w)
    }

    /// Receive garbler input wires.
    fn receive_many(
        &mut self,
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Wire>> {
        moduli.iter().map(|q| self.receive(*q, channel)).collect()
    }

    /// Perform OT and obtain wires for the evaluator's inputs.
    fn encode_many(
        &mut self,
        inputs: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Wire>> {
        let mut lens = Vec::new();
        let mut bs = Vec::new();
        for (x, q) in inputs.iter().zip(moduli.iter()) {
            let len = f32::from(*q).log(2.0).ceil() as usize;
            for b in (0..len).map(|i| x & (1 << i) != 0) {
                bs.push(b);
            }
            lens.push(len);
        }
        let wires = self
            .run_ot(&bs, channel)
            .wrap_err_with(ErrorKind::OtherError, || {
                "Failed to run oblivious transfer.".to_string()
            })?;
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
        acc + w.cmul(1 << i)
    })
}

impl<RNG, OT> FancyBinary for Evaluator<RNG, OT, WireMod2> {
    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        self.evaluator.and(x, y, channel)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        self.evaluator.xor(x, y)
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        self.evaluator.negate(x)
    }
}

impl<RNG, OT> FancyBinary for Evaluator<RNG, OT, AllWire> {
    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        self.evaluator.and(x, y, channel)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        self.evaluator.xor(x, y)
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        self.evaluator.negate(x)
    }
}

impl<RNG, OT, Wire: WireLabel + ArithmeticWire> FancyArithmetic for Evaluator<RNG, OT, Wire> {
    fn add(&mut self, x: &Wire, y: &Wire) -> Self::Item {
        self.evaluator.add(x, y)
    }

    fn sub(&mut self, x: &Wire, y: &Wire) -> Self::Item {
        self.evaluator.sub(x, y)
    }

    fn cmul(&mut self, x: &Wire, c: u16) -> Self::Item {
        self.evaluator.cmul(x, c)
    }

    fn mul(
        &mut self,
        x: &Wire,
        y: &Wire,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        self.evaluator.mul(x, y, channel)
    }

    fn proj(
        &mut self,
        x: &Wire,
        q: u16,
        tt: Option<Vec<u16>>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        self.evaluator.proj(x, q, tt, channel)
    }
}

impl<RNG, OT, Wire: WireLabel> Fancy for Evaluator<RNG, OT, Wire> {
    type Item = Wire;

    fn constant(
        &mut self,
        x: u16,
        q: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        self.evaluator.constant(x, q, channel)
    }

    fn output(&mut self, x: &Wire, channel: &mut Channel) -> swanky_error::Result<Option<u16>> {
        self.evaluator.output(x, channel)
    }
}

impl<RNG: CryptoRng + Rng, OT, Wire: WireLabel> FancyReveal for Evaluator<RNG, OT, Wire> {
    fn reveal(&mut self, x: &Self::Item, channel: &mut Channel) -> swanky_error::Result<u16> {
        self.evaluator.reveal(x, channel)
    }
}

impl<RNG, OT, Wire> SemiHonest for Evaluator<RNG, OT, Wire> {}
