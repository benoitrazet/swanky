//! Structs and functions for creating, streaming, and evaluating garbled circuits.

mod binary_and;
mod evaluator;
mod garbler;
mod security_warning;

pub use crate::garble::{evaluator::Evaluator, garbler::Garbler};
pub use binary_and::BinaryWireLabel;

////////////////////////////////////////////////////////////////////////////////
// tests

#[cfg(test)]
mod nonstreaming {
    use crate::{
        AllWire, FancyArithmetic, FancyBinary, FancyProj,
        circuit::{ArithmeticCircuit, CircuitBuilder, CircuitType, eval_plain},
        classic::GarbledCircuit,
        fancy::{ArithmeticProjBundleGadgets, Bundle, BundleGadgets, Fancy},
        util::{self, RngExt},
    };
    use itertools::Itertools;
    use rand::{SeedableRng, thread_rng};
    use swanky_channel::Channel;
    use swanky_rng::SwankyRng;
    use vectoreyes::U8x16;

    // helper
    fn garble_test_helper<F>(f: F)
    where
        F: Fn(u16, &mut Channel) -> ArithmeticCircuit,
    {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_prime();
            let c = Channel::with(std::io::empty(), |channel| Ok(f(q, channel))).unwrap();
            let (en, ev, output_mapping) =
                GarbledCircuit::garble::<AllWire, _, _>(&c, SwankyRng::new()).unwrap();
            for _ in 0..16 {
                let mut inps = Vec::new();
                for i in 0..c.num_inputs() {
                    let q = c.input_mod(i);
                    let x = rng.gen_u16() % q;
                    inps.push(x);
                }
                // Run the garbled circuit evaluator.
                let xs = &en.encode_inputs(&inps);
                let wirelabels = ev.eval_to_wirelabels(&c, xs).unwrap();
                let decoded = output_mapping.to_outputs(&wirelabels).unwrap();

                // Run the dummy evaluator.
                let should_be = eval_plain(&c, &inps).unwrap();
                assert_eq!(decoded[0], should_be[0]);
            }
        }
    }

    #[test] // add
    fn add() {
        garble_test_helper(|q, channel| {
            let mut b = CircuitBuilder::new();
            let x = b.input(q);
            let y = b.input(q);
            let z = b.add(&x, &y);
            b.output(&z, channel).unwrap();
            b.finish()
        });
    }

    #[test] // add_many
    fn add_many() {
        garble_test_helper(|q, channel| {
            let mut b = CircuitBuilder::new();
            let xs = b.inputs(&[q; 16]);
            let z = b.add_many(&xs);
            b.output(&z, channel).unwrap();
            b.finish()
        });
    }

    #[test] // or_many
    fn or_many() {
        garble_test_helper(|_, channel| {
            let mut b: CircuitBuilder<ArithmeticCircuit> = CircuitBuilder::new();
            let xs = b.inputs(&[2; 16]);
            let z = b.or_many(&xs, channel).unwrap();
            b.output(&z, channel).unwrap();
            b.finish()
        });
    }

    #[test] // sub
    fn sub() {
        garble_test_helper(|q, channel| {
            let mut b = CircuitBuilder::new();
            let x = b.input(q);
            let y = b.input(q);
            let z = b.sub(&x, &y);
            b.output(&z, channel).unwrap();
            b.finish()
        });
    }

    #[test] // cmul
    fn cmul() {
        garble_test_helper(|q, channel| {
            let mut b = CircuitBuilder::new();
            let x = b.input(q);
            let z = if q > 2 { b.cmul(&x, 2) } else { b.cmul(&x, 1) };
            b.output(&z, channel).unwrap();
            b.finish()
        });
    }

    #[test] // proj_cycle
    fn proj_cycle() {
        garble_test_helper(|q, channel| {
            let mut tab = Vec::new();
            for i in 0..q {
                tab.push((i + 1) % q);
            }
            let mut b = CircuitBuilder::new();
            let x = b.input(q);
            let z = b.proj(&x, q, Some(tab), channel).unwrap();
            b.output(&z, channel).unwrap();
            b.finish()
        });
    }

    #[test] // proj_rand
    fn proj_rand() {
        garble_test_helper(|q, channel| {
            let mut rng = thread_rng();
            let mut tab = Vec::new();
            for _ in 0..q {
                tab.push(rng.gen_u16() % q);
            }
            let mut b = CircuitBuilder::new();
            let x = b.input(q);
            let z = b.proj(&x, q, Some(tab), channel).unwrap();
            b.output(&z, channel).unwrap();
            b.finish()
        });
    }

    #[test] // mod_change
    fn mod_change() {
        garble_test_helper(|q, channel| {
            let mut b = CircuitBuilder::new();
            let x = b.input(q);
            let z = b.mod_change(&x, q * 2, channel).unwrap();
            b.output(&z, channel).unwrap();
            b.finish()
        });
    }

    #[test] // half_gate
    fn half_gate() {
        garble_test_helper(|q, channel| {
            let mut b = CircuitBuilder::new();
            let x = b.input(q);
            let y = b.input(q);
            let z = b.mul(&x, &y, channel).unwrap();
            b.output(&z, channel).unwrap();
            b.finish()
        });
    }

    #[test] // half_gate_unequal_mods
    fn half_gate_unequal_mods() {
        let mut rng = SwankyRng::from_seed(U8x16::from(0_u128));
        for q in 3..16 {
            let ymod = 2 + rng.gen_u16() % 6; // lower mod is capped at 8 for now
            println!("\nTESTING MOD q={} ymod={}", q, ymod);

            let c = Channel::with(std::io::empty(), |channel| {
                let mut b = CircuitBuilder::new();
                let x = b.input(q);
                let y = b.input(ymod);
                let z = b.mul(&x, &y, channel).unwrap();
                b.output(&z, channel).unwrap();
                let c = b.finish();
                Ok(c)
            })
            .unwrap();

            let (en, ev, map) =
                GarbledCircuit::garble::<AllWire, _, _>(&c, SwankyRng::new()).unwrap();

            for x in 0..q {
                for y in 0..ymod {
                    println!("TEST x={} y={}", x, y);
                    let xs = &en.encode_inputs(&[x, y]);
                    let decoded = ev.eval(&c, xs, &map).unwrap();
                    let should_be = eval_plain(&c, &[x, y]).unwrap();
                    assert_eq!(decoded[0], should_be[0]);
                }
            }
        }
    }

    #[test] // mixed_radix_addition
    fn mixed_radix_addition() {
        let mut rng = thread_rng();

        let nargs = 2 + rng.gen_usize() % 100;
        let mods = vec![3, 7, 10, 2, 13];

        let circ = Channel::with(std::io::empty(), |channel| {
            let mut b = CircuitBuilder::new();
            let xs = (0..nargs)
                .map(|_| Bundle::new(b.inputs(&mods)))
                .collect_vec();
            let z = b.mixed_radix_addition(&xs, channel).unwrap();
            b.output_bundle(&z, channel).unwrap();
            let circ = b.finish();
            Ok(circ)
        })
        .unwrap();

        let (en, ev, map) =
            GarbledCircuit::garble::<AllWire, _, _>(&circ, SwankyRng::new()).unwrap();
        println!("mods={:?} nargs={} size={}", mods, nargs, ev.size());

        let Q: u128 = mods.iter().map(|&q| q as u128).product();

        // test random values
        for _ in 0..16 {
            let mut should_be = 0;
            let mut ds = Vec::new();
            for _ in 0..nargs {
                let x = rng.gen_u128() % Q;
                should_be = (should_be + x) % Q;
                ds.extend(util::as_mixed_radix(x, &mods).iter());
            }
            let X = en.encode_inputs(&ds);
            let outputs = ev.eval(&circ, &X, &map).unwrap();
            assert_eq!(util::from_mixed_radix(&outputs, &mods), should_be);
        }
    }

    #[test] // basic constants
    fn basic_constant() {
        let mut b = CircuitBuilder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let circ: ArithmeticCircuit = Channel::with(std::io::empty(), |channel| {
            let y = b.constant(c, q, channel).unwrap();
            b.output(&y, channel).unwrap();
            Ok(b.finish())
        })
        .unwrap();
        let (_, ev, map) =
            GarbledCircuit::garble::<AllWire, _, _>(&circ, SwankyRng::new()).unwrap();

        for _ in 0..64 {
            let outputs = eval_plain(&circ, &[]).unwrap();
            assert_eq!(outputs[0], c, "plaintext eval failed");
            let outputs = ev.eval::<AllWire, _>(&circ, &[], &map).unwrap();
            assert_eq!(outputs[0], c, "garbled eval failed");
        }
    }

    #[test] // constants
    fn constants() {
        let mut b = CircuitBuilder::new();
        let mut rng = thread_rng();

        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;

        let circ = Channel::with(std::io::empty(), |channel| {
            let x = b.input(q);
            let y = b.constant(c, q, channel).unwrap();
            let z = b.add(&x, &y);
            b.output(&z, channel).unwrap();
            Ok(b.finish())
        })
        .unwrap();

        let (en, ev, map) =
            GarbledCircuit::garble::<AllWire, _, _>(&circ, SwankyRng::new()).unwrap();

        for _ in 0..64 {
            let x = rng.gen_u16() % q;
            let outputs = eval_plain(&circ, &[x]).unwrap();
            assert_eq!(outputs[0], (x + c) % q, "plaintext");

            let X = en.encode_inputs(&[x]);
            let Y = ev.eval(&circ, &X, &map).unwrap();
            assert_eq!(Y[0], (x + c) % q, "garbled");
        }
    }
}

#[cfg(test)]
mod streaming {
    use crate::circuit::circuits;
    use crate::{
        AllWire, Evaluator, Fancy, Garbler, WireLabel, circuit::CircuitExecutor, dummy::Dummy,
        util::RngExt,
    };
    use rand::thread_rng;
    use swanky_channel::Channel;
    use swanky_rng::SwankyRng;

    // Checks that streaming evaluation of a circuit execution equals the dummy
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
            Ok(dummy.outputs(&outputs, channel)?.unwrap())
        })
        .unwrap();

        let (_, result) = swanky_channel::local::local_channel_pair(
            |channel| {
                let mut gb = Garbler::new(rng, channel)?;
                let zeros = gb.encode_many(&inputs, &moduli, channel)?;
                let outputs = circuit.execute(&mut gb, &zeros, channel)?;
                gb.outputs(&outputs, channel)?;
                Ok(())
            },
            |channel| {
                let mut ev = Evaluator::new(channel)?;
                let wires = ev.receive_many(&moduli, channel)?;
                let outputs = circuit.execute(&mut ev, &wires, channel)?;
                Ok(ev.outputs(&outputs, channel)?.unwrap())
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
            streaming_test_helper::<AllWire, _>(&circuits::TestAddition(q));
        }
    }

    #[test]
    fn subtraction() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test_helper::<AllWire, _>(&circuits::TestSubtraction(q));
        }
    }

    #[test]
    fn multiplication() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test_helper::<AllWire, _>(&circuits::TestMulGate(q));
        }
    }

    #[test]
    fn cmul() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            let c = rng.gen_u16() % q;
            streaming_test_helper::<AllWire, _>(&circuits::TestCmul(q, c));
        }
    }

    #[test]
    fn proj() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test_helper::<AllWire, _>(&circuits::TestProj(q));
        }
    }

    #[test]
    fn complex_gadget() {
        let N = 10;
        let qs = crate::util::primes_with_width(10);
        for _ in 0..16 {
            streaming_test_helper::<AllWire, _>(&circuits::TestComplexGadget(qs.clone(), N));
        }
    }
}
