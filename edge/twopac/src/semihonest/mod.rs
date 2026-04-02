//! Implementation of semi-honest two-party computation.

mod evaluator;
mod garbler;

pub use evaluator::Evaluator;
pub use garbler::Garbler;

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_garbling::{
        AllWire, CrtBundle, CrtGadgets, Fancy, FancyArithmetic, FancyBinary, WireLabel, WireMod2,
        circuit::{BinaryCircuit, CircuitInfo, EvaluableCircuit, eval_plain},
        dummy::Dummy,
        util::RngExt,
    };
    use itertools::Itertools;
    use swanky_channel::Channel;
    use swanky_ot_chou_orlandi::{Receiver as ChouOrlandiReceiver, Sender as ChouOrlandiSender};
    use swanky_rng::SwankyRng;

    fn addition<F: FancyArithmetic>(
        f: &mut F,
        a: &F::Item,
        b: &F::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<u16>> {
        let c = f.add(a, b);
        f.output(&c, channel)
    }

    #[test]
    fn test_addition_circuit() {
        for a in 0..2 {
            for b in 0..2 {
                let (_, output) = swanky_channel::local::local_channel_pair(
                    |channel| {
                        let rng = SwankyRng::new();
                        let mut gb =
                            Garbler::<SwankyRng, ChouOrlandiSender, AllWire>::new(channel, rng)
                                .unwrap();
                        let x = gb.encode(a, 3, channel).unwrap();
                        let ys = gb.receive_many(&[3], channel).unwrap();
                        addition(&mut gb, &x, &ys[0], channel).unwrap();
                        Ok(())
                    },
                    |channel| {
                        let rng = SwankyRng::new();
                        let mut ev =
                            Evaluator::<SwankyRng, ChouOrlandiReceiver, AllWire>::new(channel, rng)
                                .unwrap();
                        let x = ev.receive(3, channel).unwrap();
                        let ys = ev.encode_many(&[b], &[3], channel).unwrap();
                        Ok(addition(&mut ev, &x, &ys[0], channel).unwrap().unwrap())
                    },
                )
                .unwrap();
                assert_eq!((a + b) % 3, output);
            }
        }
    }

    fn relu<F: FancyArithmetic + FancyBinary>(
        b: &mut F,
        xs: &[CrtBundle<F::Item>],
        channel: &mut Channel,
    ) -> Option<Vec<u128>> {
        let mut outputs = Vec::new();
        for x in xs.iter() {
            let q = x.composite_modulus();
            let c = b.crt_constant_bundle(1, q, channel).unwrap();
            let y = b.crt_mul(x, &c, channel).unwrap();
            let z = b.crt_relu(&y, "100%", None, channel).unwrap();
            outputs.push(b.crt_output(&z, channel).unwrap());
        }
        outputs.into_iter().collect()
    }

    #[test]
    fn test_relu() {
        let mut rng = rand::thread_rng();
        let n = 10;
        let ps = fancy_garbling::util::primes_with_width(10);
        let q = fancy_garbling::util::product(&ps);
        let input = (0..n).map(|_| rng.gen_u128() % q).collect::<Vec<u128>>();

        // Run dummy version.
        let target = Channel::with(std::io::empty(), |channel| {
            let mut dummy = Dummy::new();
            let dummy_input = input
                .iter()
                .map(|x| dummy.crt_encode(*x, q, channel).unwrap())
                .collect_vec();
            Ok(relu(&mut dummy, &dummy_input, channel).unwrap())
        })
        .unwrap();

        // Run 2PC version.
        let (_, result) = swanky_channel::local::local_channel_pair(
            |channel| {
                let rng = SwankyRng::new();
                let mut gb =
                    Garbler::<SwankyRng, ChouOrlandiSender, AllWire>::new(channel, rng).unwrap();
                let xs = gb.crt_encode_many(&input, q, channel).unwrap();
                relu(&mut gb, &xs, channel);
                Ok(())
            },
            |channel| {
                let rng = SwankyRng::new();
                let mut ev =
                    Evaluator::<SwankyRng, ChouOrlandiReceiver, AllWire>::new(channel, rng)
                        .unwrap();
                let xs = ev.crt_receive_many(n, q, channel).unwrap();
                Ok(relu(&mut ev, &xs, channel).unwrap())
            },
        )
        .unwrap();
        assert_eq!(target, result);
    }

    type GB<Wire> = Garbler<SwankyRng, ChouOrlandiSender, Wire>;
    type EV<Wire> = Evaluator<SwankyRng, ChouOrlandiReceiver, Wire>;

    fn test_circuit<CIRC, Wire: WireLabel>(circ: CIRC)
    where
        CIRC: EvaluableCircuit<Dummy>
            + EvaluableCircuit<GB<Wire>>
            + EvaluableCircuit<EV<Wire>>
            + CircuitInfo
            + Send
            + Sync
            + 'static,
    {
        circ.print_info().unwrap();

        let (_, out) = swanky_channel::local::local_channel_pair(
            |channel| {
                let rng = SwankyRng::new();
                let mut gb =
                    Garbler::<SwankyRng, ChouOrlandiSender, Wire>::new(channel, rng).unwrap();
                let mut xs = gb
                    .encode_many(&vec![0_u16; 128], &vec![2; 128], channel)
                    .unwrap();
                let ys = gb.receive_many(&vec![2; 128], channel).unwrap();
                xs.extend(ys);
                circ.eval(&mut gb, &xs, channel).unwrap();
                Ok(())
            },
            |channel| {
                let rng = SwankyRng::new();
                let mut ev =
                    Evaluator::<SwankyRng, ChouOrlandiReceiver, Wire>::new(channel, rng).unwrap();
                let mut xs = ev.receive_many(&vec![2; 128], channel).unwrap();
                let ys = ev
                    .encode_many(&vec![0_u16; 128], &vec![2; 128], channel)
                    .unwrap();
                xs.extend(ys);
                let out = circ.eval(&mut ev, &xs, channel).unwrap().unwrap();
                Ok(out)
            },
        )
        .unwrap();

        let target = eval_plain(&circ, &vec![0_u16; 256]).unwrap();
        assert_eq!(out, target);
    }

    #[test]
    fn test_aes_arithmetic() {
        let circ = BinaryCircuit::parse(std::io::Cursor::<&'static [u8]>::new(include_bytes!(
            "../../../fancy-garbling/circuits/AES-non-expanded.txt"
        )))
        .unwrap();
        test_circuit::<_, AllWire>(circ);
    }

    #[test]
    fn test_aes_binary() {
        let circ = BinaryCircuit::parse(std::io::Cursor::<&'static [u8]>::new(include_bytes!(
            "../../../fancy-garbling/circuits/AES-non-expanded.txt"
        )))
        .unwrap();
        test_circuit::<_, WireMod2>(circ);
    }
}
