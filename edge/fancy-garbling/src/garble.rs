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
        fancy::{ArithmeticBundleGadgets, Bundle, BundleGadgets, Fancy},
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

            let (en, ev, _) =
                GarbledCircuit::garble::<AllWire, _, _>(&c, SwankyRng::new()).unwrap();

            for x in 0..q {
                for y in 0..ymod {
                    println!("TEST x={} y={}", x, y);
                    let xs = &en.encode_inputs(&[x, y]);
                    let decoded = ev.eval(&c, xs).unwrap();
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

        let (en, ev, _) = GarbledCircuit::garble::<AllWire, _, _>(&circ, SwankyRng::new()).unwrap();
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
            let outputs = ev.eval(&circ, &X).unwrap();
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
        let (_, ev, _) = GarbledCircuit::garble::<AllWire, _, _>(&circ, SwankyRng::new()).unwrap();

        for _ in 0..64 {
            let outputs = eval_plain(&circ, &[]).unwrap();
            assert_eq!(outputs[0], c, "plaintext eval failed");
            let outputs = ev.eval::<AllWire, _>(&circ, &[]).unwrap();
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

        let (en, ev, _) = GarbledCircuit::garble::<AllWire, _, _>(&circ, SwankyRng::new()).unwrap();

        for _ in 0..64 {
            let x = rng.gen_u16() % q;
            let outputs = eval_plain(&circ, &[x]).unwrap();
            assert_eq!(outputs[0], (x + c) % q, "plaintext");

            let X = en.encode_inputs(&[x]);
            let Y = ev.eval(&circ, &X).unwrap();
            assert_eq!(Y[0], (x + c) % q, "garbled");
        }
    }
}

#[cfg(test)]
mod streaming {
    use crate::{
        AllWire, Evaluator, Fancy, FancyArithmetic, FancyProj, Garbler, WireLabel,
        dummy::{Dummy, DummyVal},
        util::RngExt,
    };
    use itertools::Itertools;
    use rand::thread_rng;
    use swanky_channel::Channel;
    use swanky_rng::SwankyRng;

    // helper - checks that Streaming evaluation of a fancy function equals Dummy
    // evaluation of the same function
    fn streaming_test<FGB, FEV, FDU, Wire>(
        mut f_gb: FGB,
        mut f_ev: FEV,
        mut f_du: FDU,
        input_mods: &[u16],
    ) where
        Wire: WireLabel,
        FGB: FnMut(&mut Garbler<SwankyRng, Wire>, &[Wire], &mut Channel) -> Option<u16>
            + Send
            + Sync
            + 'static,
        FEV: FnMut(&mut Evaluator<Wire>, &[Wire], &mut Channel) -> Option<u16> + Send,
        FDU: FnMut(&mut Dummy, &[DummyVal], &mut Channel) -> Option<u16>,
    {
        let mut rng = SwankyRng::new();
        let inputs = input_mods.iter().map(|q| rng.gen_u16() % q).collect_vec();
        let input_mods_ = input_mods.to_vec();

        // evaluate f_gb as a dummy
        let should_be = Channel::with(std::io::empty(), |channel| {
            let mut dummy = Dummy::new();
            let dinps = dummy.encode_many(&inputs, input_mods, channel).unwrap();
            let should_be = f_du(&mut dummy, &dinps, channel).unwrap();
            Ok(should_be)
        })
        .unwrap();

        let (_, result) = swanky_channel::local::local_channel_pair(
            |channel| {
                let mut gb = Garbler::new(rng, channel).unwrap();
                let (gb_inp, ev_inp) = gb.encode_many_wires(&inputs, &input_mods_);
                for w in ev_inp.iter() {
                    gb.send_wire(w, channel).unwrap();
                }
                f_gb(&mut gb, &gb_inp, channel);
                Ok(())
            },
            |channel| {
                let mut ev = Evaluator::new(channel).unwrap();
                let ev_inp = input_mods
                    .iter()
                    .map(|q| ev.read_wire(*q, channel).unwrap())
                    .collect_vec();
                Ok(f_ev(&mut ev, &ev_inp, channel).unwrap())
            },
        )
        .unwrap();

        assert_eq!(result, should_be)
    }

    #[test]
    fn addition() {
        fn fancy_addition<F: FancyArithmetic>(
            b: &mut F,
            xs: &[F::Item],
            channel: &mut Channel,
        ) -> Option<u16> {
            let z = b.add(&xs[0], &xs[1]);
            b.output(&z, channel).unwrap()
        }

        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test(
                move |b, xs: &[AllWire], channel| fancy_addition(b, xs, channel),
                move |b, xs: &[AllWire], channel| fancy_addition(b, xs, channel),
                fancy_addition,
                &[q, q],
            );
        }
    }

    #[test]
    fn subtraction() {
        fn fancy_subtraction<F: FancyArithmetic>(
            b: &mut F,
            xs: &[F::Item],
            channel: &mut Channel,
        ) -> Option<u16> {
            let z = b.sub(&xs[0], &xs[1]);
            b.output(&z, channel).unwrap()
        }

        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test(
                move |b, xs: &[AllWire], channel| fancy_subtraction(b, xs, channel),
                move |b, xs: &[AllWire], channel| fancy_subtraction(b, xs, channel),
                fancy_subtraction,
                &[q, q],
            );
        }
    }

    #[test]
    fn multiplication() {
        fn fancy_multiplication<F: FancyArithmetic>(
            b: &mut F,
            xs: &[F::Item],
            channel: &mut Channel,
        ) -> Option<u16> {
            let z = b.mul(&xs[0], &xs[1], channel).unwrap();
            b.output(&z, channel).unwrap()
        }

        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test(
                move |b, xs: &[AllWire], channel| fancy_multiplication(b, xs, channel),
                move |b, xs: &[AllWire], channel| fancy_multiplication(b, xs, channel),
                fancy_multiplication,
                &[q, q],
            );
        }
    }

    #[test]
    fn cmul() {
        fn fancy_cmul<F: FancyArithmetic>(
            b: &mut F,
            xs: &[F::Item],
            channel: &mut Channel,
        ) -> Option<u16> {
            let z = b.cmul(&xs[0], 5);
            b.output(&z, channel).unwrap()
        }

        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test(
                move |b, xs: &[AllWire], channel| fancy_cmul(b, xs, channel),
                move |b, xs: &[AllWire], channel| fancy_cmul(b, xs, channel),
                fancy_cmul,
                &[q],
            );
        }
    }

    #[test]
    fn proj() {
        fn fancy_projection<F: FancyArithmetic + FancyProj>(
            b: &mut F,
            xs: &[F::Item],
            q: u16,
            channel: &mut Channel,
        ) -> Option<u16> {
            let tab = (0..q).map(|i| (i + 1) % q).collect_vec();
            let z = b.proj(&xs[0], q, Some(tab), channel).unwrap();
            b.output(&z, channel).unwrap()
        }

        let mut rng = thread_rng();
        for _ in 0..16 {
            let q = rng.gen_modulus();
            streaming_test(
                move |b, xs: &[AllWire], channel| fancy_projection(b, xs, q, channel),
                move |b, xs: &[AllWire], channel| fancy_projection(b, xs, q, channel),
                move |b, xs, channel| fancy_projection(b, xs, q, channel),
                &[q],
            );
        }
    }
}

#[cfg(test)]
mod complex {
    use crate::{
        AllWire, CrtBundle, CrtGadgets, Evaluator, Fancy, FancyArithmetic, FancyBinary, FancyProj,
        Garbler, dummy::Dummy, util::RngExt,
    };
    use itertools::Itertools;
    use rand::thread_rng;
    use swanky_channel::Channel;
    use swanky_rng::SwankyRng;

    fn complex_gadget<F: FancyArithmetic + FancyBinary + FancyProj>(
        b: &mut F,
        xs: &[CrtBundle<F::Item>],
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<Vec<u128>>> {
        let mut zs = Vec::with_capacity(xs.len());
        for x in xs.iter() {
            let c = b.crt_constant_bundle(1, x.composite_modulus(), channel)?;
            let y = b.crt_mul(x, &c, channel)?;
            let z = b.crt_relu(&y, "100%", None, channel)?;
            zs.push(z);
        }
        b.crt_outputs(&zs, channel)
    }

    #[test]
    fn test_complex_gadgets() {
        let mut rng = thread_rng();
        let N = 10;
        let qs = crate::util::primes_with_width(10);
        let Q = crate::util::product(&qs);
        for _ in 0..16 {
            let input = (0..N).map(|_| rng.gen_u128() % Q).collect_vec();

            // Compute the correct answer using `Dummy`.
            let should_be = Channel::with(std::io::empty(), |channel| {
                let mut dummy = Dummy::new();
                let dinps = input
                    .iter()
                    .map(|x| {
                        let xs = crate::util::crt(*x, &qs);
                        CrtBundle::new(dummy.encode_many(&xs, &qs, channel).unwrap())
                    })
                    .collect_vec();
                let should_be = complex_gadget(&mut dummy, &dinps, channel).unwrap();
                Ok(should_be)
            })
            .unwrap();

            let (_, result) = swanky_channel::local::local_channel_pair(
                |channel| {
                    let mut garbler = Garbler::<_, AllWire>::new(SwankyRng::new(), channel)?;

                    // encode input and send it to the evaluator
                    let mut gb_inp = Vec::with_capacity(N);
                    for X in &input {
                        let (zero, enc) = garbler.crt_encode_wire(*X, Q);
                        for w in enc.iter() {
                            garbler.send_wire(w, channel).unwrap();
                        }
                        gb_inp.push(zero);
                    }
                    complex_gadget(&mut garbler, &gb_inp, channel).unwrap();
                    Ok(())
                },
                |channel| {
                    let mut evaluator = Evaluator::<AllWire>::new(channel)?;

                    // receive encoded wires from the garbler thread
                    let mut ev_inp = Vec::with_capacity(N);
                    for _ in 0..N {
                        let ws = qs
                            .iter()
                            .map(|q| evaluator.read_wire(*q, channel).unwrap())
                            .collect_vec();
                        ev_inp.push(CrtBundle::new(ws));
                    }

                    let result = complex_gadget(&mut evaluator, &ev_inp, channel).unwrap();
                    Ok(result)
                },
            )
            .unwrap();
            assert_eq!(result, should_be);
        }
    }
}
