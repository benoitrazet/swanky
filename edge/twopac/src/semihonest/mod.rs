//! Implementation of semi-honest two-party computation.

mod evaluator;
mod garbler;

pub use evaluator::Evaluator;
pub use garbler::Garbler;

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_garbling::{
        AllWire, CrtBundle, CrtGadgets, Fancy, FancyArithmetic, FancyBinary, FancyProj, WireLabel,
        WireMod2,
        circuit_analyzer::CircuitAnalyzer,
        circuits::{
            aes::AesNonExpanded,
            arithmetic::{Multiplication, ReLU},
        },
        dummy::{Dummy, DummyVal},
        util::RngExt,
        {Circuit, CircuitInputMapper, Flatten, test_circuits::arithmetic::TestAddition},
    };
    use itertools::Itertools;
    use swanky_channel::Channel;
    use swanky_ot_chou_orlandi::{Receiver as ChouOrlandiReceiver, Sender as ChouOrlandiSender};
    use swanky_rng::SwankyRng;

    #[test]
    fn test_addition() {
        let modulus = 3;
        let circuit = TestAddition(modulus);
        for a in 0..2 {
            for b in 0..2 {
                let (_, output) = swanky_channel::local::local_channel_pair(
                    |channel| {
                        let rng = SwankyRng::new();
                        let mut gb =
                            Garbler::<SwankyRng, ChouOrlandiSender, AllWire>::new(channel, rng)?;
                        let x = gb.encode(a, modulus, channel)?;
                        let y = gb.receive(modulus, channel)?;
                        let outputs = circuit.execute(
                            &mut gb,
                            &<TestAddition as CircuitInputMapper<
                                Garbler<SwankyRng, ChouOrlandiSender, _>,
                            >>::map(&circuit, [x, y].to_vec()),
                            channel,
                        )?;
                        let result = gb.output(&outputs, channel)?;
                        assert!(result.is_none());
                        Ok(())
                    },
                    |channel| {
                        let rng = SwankyRng::new();
                        let mut ev = Evaluator::<SwankyRng, ChouOrlandiReceiver, AllWire>::new(
                            channel, rng,
                        )?;
                        let x = ev.receive(modulus, channel)?;
                        let y = ev.encode(b, modulus, channel)?;
                        let output = circuit.execute(
                            &mut ev,
                            &<TestAddition as CircuitInputMapper<
                                Evaluator<SwankyRng, ChouOrlandiReceiver, _>,
                            >>::map(&circuit, [x, y].to_vec()),
                            channel,
                        )?;
                        let result = ev.output(&output, channel)?;
                        Ok(result.unwrap())
                    },
                )
                .unwrap();
                assert_eq!((a + b) % modulus, output);
            }
        }
    }

    fn relu<F: FancyArithmetic + FancyBinary + FancyProj>(
        b: &mut F,
        xs: &[CrtBundle<F::Item>],
        channel: &mut Channel,
    ) -> Option<Vec<u128>> {
        let mut outputs = Vec::new();
        for x in xs.iter() {
            let q = x.composite_modulus();
            let c = b.crt_constant_bundle(1, q, channel).unwrap();
            let y = Multiplication::new().execute(b, &(x, &c), channel).unwrap();
            let z = ReLU::new()
                .execute(b, &(&y, "100%", None), channel)
                .unwrap();
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

    fn test_aes<C, Wire: WireLabel + Send>(circ: &C)
    where
        C: CircuitInputMapper<Dummy>
            + CircuitInputMapper<CircuitAnalyzer>
            + CircuitInputMapper<GB<Wire>>
            + CircuitInputMapper<EV<Wire>>
            + Send
            + Sync
            + 'static,
    {
        let mut analyzer = CircuitAnalyzer::new();
        analyzer.eval(circ).unwrap();
        println!("{analyzer}");

        let (_, out) = swanky_channel::local::local_channel_pair(
            |channel| {
                let rng = SwankyRng::new();
                let mut gb = Garbler::<SwankyRng, ChouOrlandiSender, Wire>::new(channel, rng)?;
                let mut xs = gb.encode_many(&vec![0; 128], &vec![2; 128], channel)?;
                let ys = gb.receive_many(&vec![2; 128], channel)?;
                xs.extend(ys);
                let outputs = circ.execute(
                    &mut gb,
                    &<C as CircuitInputMapper<GB<_>>>::map(circ, xs),
                    channel,
                )?;
                gb.outputs(&outputs.flatten(), channel)?;
                Ok(())
            },
            |channel| {
                let rng = SwankyRng::new();
                let mut ev = Evaluator::<SwankyRng, ChouOrlandiReceiver, Wire>::new(channel, rng)?;
                let mut xs = ev.receive_many(&vec![2; 128], channel)?;
                let ys = ev.encode_many(&vec![0; 128], &vec![2; 128], channel)?;
                xs.extend(ys);
                let wirelabels = circ.execute(
                    &mut ev,
                    &<C as CircuitInputMapper<EV<_>>>::map(circ, xs),
                    channel,
                )?;
                let out = ev.outputs(&wirelabels.flatten(), channel)?;
                Ok(out.unwrap())
            },
        )
        .unwrap();

        let target = Dummy::eval(
            circ,
            &<C as CircuitInputMapper<Dummy>>::map(circ, vec![DummyVal::new(0, 2); 256]),
        )
        .unwrap();
        let target = target
            .flatten()
            .into_iter()
            .map(|x| x.val())
            .collect::<Vec<_>>();
        assert_eq!(out, target);
    }

    #[test]
    fn test_aes_arithmetic() {
        let aes = AesNonExpanded::new();
        test_aes::<_, AllWire>(&aes);
    }

    #[test]
    fn test_aes_binary() {
        let aes = AesNonExpanded::new();
        test_aes::<_, WireMod2>(&aes);
    }
}
