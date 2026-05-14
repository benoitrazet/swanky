//! Structs and functions for creating, streaming, and evaluating garbled circuits.

mod binary_and;
mod evaluator;
mod garbler;
mod security_warning;

pub use crate::garble::{evaluator::Evaluator, garbler::Garbler};
pub use binary_and::BinaryWireLabel;

#[cfg(test)]
mod nonstreaming {
    use crate::{
        AllWire, Evaluator, Garbler, WireLabel, WireMod2,
        circuit::{CircuitExecutor, circuits},
        classic::GarbledCircuit,
        dummy::Dummy,
        util::RngExt,
    };
    use rand::thread_rng;
    use swanky_rng::SwankyRng;

    // Check that non-streaming evaluation of a circuit execution equals the
    // dummy evaluation of the same function.
    fn garble_test_helper<
        W: WireLabel,
        Ex: CircuitExecutor<Dummy>
            + CircuitExecutor<Garbler<SwankyRng, W>>
            + CircuitExecutor<Evaluator<W>>,
    >(
        circuit: &Ex,
    ) {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let (en, ev, output_mapping) =
                GarbledCircuit::garble::<W, _, _>(circuit, SwankyRng::new()).unwrap();
            for _ in 0..16 {
                let mut inputs = Vec::new();
                for i in 0..<Ex as CircuitExecutor<Dummy>>::ninputs(circuit) {
                    let q = <Ex as CircuitExecutor<Dummy>>::modulus(circuit, i);
                    let x = rng.gen_u16() % q;
                    inputs.push(x);
                }
                // Run the garbled circuit evaluator.
                let xs = en.encode_inputs(&inputs);
                let wirelabels = ev.eval_to_wirelabels(circuit, &xs).unwrap();
                let decoded = output_mapping.to_outputs(&wirelabels).unwrap();

                // Run the dummy evaluator.
                let should_be = Dummy::eval(circuit, &inputs).unwrap();
                assert_eq!(decoded, should_be);
            }
        }
    }

    #[test]
    fn add() {
        let q = thread_rng().gen_prime();
        garble_test_helper::<AllWire, _>(&circuits::arithmetic::TestAddition(q));
    }

    #[test]
    fn add_many() {
        let q = thread_rng().gen_prime();
        garble_test_helper::<AllWire, _>(&circuits::arithmetic::TestAddMany(q, 16));
    }

    #[test]
    fn or_many() {
        garble_test_helper::<WireMod2, _>(&circuits::binary::TestOrGateFanN(16));
    }

    #[test]
    fn sub() {
        let q = thread_rng().gen_prime();
        garble_test_helper::<AllWire, _>(&circuits::arithmetic::TestSubtraction(q));
    }

    #[test]
    fn cmul() {
        let q = thread_rng().gen_prime();
        let c = thread_rng().gen_u16() % q;
        garble_test_helper::<AllWire, _>(&circuits::arithmetic::TestCmul(q, c));
    }

    #[test]
    fn proj() {
        let q = thread_rng().gen_prime();
        garble_test_helper::<AllWire, _>(&circuits::proj::TestProj(q));
    }

    #[test]
    fn proj_rand() {
        let q = thread_rng().gen_prime();
        let tab = (0..q)
            .map(|_| thread_rng().gen_u16() % q)
            .collect::<Vec<_>>();

        garble_test_helper::<AllWire, _>(&circuits::proj::TestProjRand(q, tab));
    }

    #[test]
    fn mod_change() {
        let q = thread_rng().gen_prime();
        garble_test_helper::<AllWire, _>(&circuits::proj::TestModChange(q, q * 2));
    }

    #[test]
    fn arithmetic_half_gate() {
        let q = thread_rng().gen_prime();
        garble_test_helper::<AllWire, _>(&circuits::arithmetic::TestMulGate(q));
    }

    #[test]
    fn half_gate_unequal_mods() {
        let q = thread_rng().gen_prime();
        // Lower modulus is capped at 8.
        let p = 2 + thread_rng().gen_prime() % 6;
        garble_test_helper::<AllWire, _>(&circuits::arithmetic::TestMulGateUnequalMods([q, p]));
    }

    #[test]
    fn mixed_radix_addition() {
        let mut rng = thread_rng();
        let nargs = 2 + rng.gen_usize() % 100;
        let mods = vec![3, 7, 10, 2, 13];
        garble_test_helper::<AllWire, _>(
            &circuits::arithmetic_proj_bundle_gadgets::TestMixedRadixAddition(mods, nargs),
        );
    }

    #[test]
    fn constants() {
        let q = thread_rng().gen_modulus();
        let c = thread_rng().gen_u16() % q;
        garble_test_helper::<AllWire, _>(&circuits::arithmetic::TestConstants(q, c));
    }
}

#[cfg(test)]
mod streaming {
    use crate::circuit::{Flatten, circuits};
    use crate::{
        AllWire, Evaluator, Fancy, Garbler, WireLabel, circuit::CircuitExecutor, dummy::Dummy,
        util::RngExt,
    };
    use rand::thread_rng;
    use swanky_channel::Channel;
    use swanky_rng::SwankyRng;

    // Check that streaming evaluation of a circuit execution equals the dummy
    // evaluation of the same function.
    fn streaming_test_helper<
        W: WireLabel + Send,
        Ex: CircuitExecutor<Dummy>
            + CircuitExecutor<Garbler<SwankyRng, W>>
            + CircuitExecutor<Evaluator<W>>
            + Send
            + Sync,
    >(
        circuit: &Ex,
    ) {
        let mut rng = SwankyRng::new();
        let moduli = (0..<Ex as CircuitExecutor<Dummy>>::ninputs(circuit))
            .map(|i| <Ex as CircuitExecutor<Dummy>>::modulus(circuit, i))
            .collect::<Vec<_>>();
        let inputs = moduli.iter().map(|q| rng.gen_u16() % q).collect::<Vec<_>>();

        // evaluate f_gb as a dummy
        let should_be = Channel::with(std::io::empty(), |channel| {
            let mut dummy = Dummy::new();
            let inputs = dummy.encode_many(&inputs, &moduli, channel)?;
            let outputs = circuit.execute(&mut dummy, &inputs, channel)?;
            Ok(dummy.outputs(&outputs.flatten(), channel)?.unwrap())
        })
        .unwrap();

        let (_, result) = swanky_channel::local::local_channel_pair(
            |channel| {
                let mut gb = Garbler::new(rng, channel)?;
                let zeros = gb.encode_many(&inputs, &moduli, channel)?;
                let outputs = circuit.execute(&mut gb, &zeros, channel)?;
                gb.outputs(&outputs.flatten(), channel)?;
                Ok(())
            },
            |channel| {
                let mut ev = Evaluator::new(channel)?;
                let wires = ev.receive_many(&moduli, channel)?;
                let outputs = circuit.execute(&mut ev, &wires, channel)?;
                Ok(ev.outputs(&outputs.flatten(), channel)?.unwrap())
            },
        )
        .unwrap();

        assert_eq!(result, should_be);
    }

    #[test]
    fn addition() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test_helper::<AllWire, _>(&circuits::arithmetic::TestAddition(q));
        }
    }

    #[test]
    fn subtraction() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test_helper::<AllWire, _>(&circuits::arithmetic::TestSubtraction(q));
        }
    }

    #[test]
    fn multiplication() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test_helper::<AllWire, _>(&circuits::arithmetic::TestMulGate(q));
        }
    }

    #[test]
    fn cmul() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            let c = rng.gen_u16() % q;
            streaming_test_helper::<AllWire, _>(&circuits::arithmetic::TestCmul(q, c));
        }
    }

    #[test]
    fn proj() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test_helper::<AllWire, _>(&circuits::proj::TestProj(q));
        }
    }

    #[test]
    fn complex_gadget() {
        let N = 10;
        let qs = crate::util::primes_with_width(10);
        for _ in 0..16 {
            streaming_test_helper::<AllWire, _>(&circuits::crt_proj_gadgets::TestComplexGadget(
                qs.clone(),
                N,
            ));
        }
    }
}
