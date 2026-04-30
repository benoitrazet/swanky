#![cfg(test)]

use crate::evaluator::Evaluator;
use crate::garbler::Garbler;

use fancy_garbling::{
    Fancy,
    circuit::{CircuitExecutor, circuits},
    dummy::Dummy,
};
use rand::Rng;
use swanky_rng::SwankyRng;

#[test]
fn test_party_construction_passes() {
    swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            Garbler::new(c, rng)
        },
        |c| {
            let rng = SwankyRng::new();
            Evaluator::new(c, rng)
        },
    )
    .unwrap();
}
#[test]
fn test_party_preprocessing_passes() {
    let input_size = 400;
    let circuit = circuits::TestAndGateFanN(input_size);
    swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(c, rng).unwrap();
            gb.preprocess_circuit(&circuit, c)
        },
        |c| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::new(c, rng).unwrap();
            ev.preprocess_circuit(&circuit, c)
        },
    )
    .unwrap();
}
#[test]
fn test_party_encoding_receiving_passes() {
    let input_size_gb = 400;
    let input_size_ev = 400;
    let circuit = circuits::TestAndGateFanN(input_size_gb + input_size_ev);

    swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(c, rng)?;
            gb.preprocess_circuit(&circuit, c)?;
            gb.encode_many(&vec![0; input_size_gb], &vec![2; input_size_gb], c)?;
            gb.receive_many(&vec![2; input_size_ev], c)?;
            Ok(())
        },
        |c| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::new(c, rng)?;
            ev.preprocess_circuit(&circuit, c)?;
            ev.receive_many(&vec![2; input_size_gb], c)?;
            ev.encode_many(&vec![0; input_size_ev], &vec![2; input_size_ev], c)?;
            Ok(())
        },
    )
    .unwrap();
}
#[test]
fn test_party_gb_encoding_ev_receiving_correct() {
    let input_size_gb = 400;
    let input_size_ev = 400;
    let circuit = circuits::TestAndGateFanN(input_size_gb + input_size_ev);
    let mut rng = SwankyRng::new();
    let inputs: Vec<u16> = (0..input_size_ev).map(|_| rng.r#gen::<u16>() % 2).collect();
    let (gb_wires, ev_wires) = swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(c, rng)?;
            gb.preprocess_circuit(&circuit, c)?;
            let res = gb.encode_many(&inputs, &vec![2; input_size_gb], c)?;
            Ok(res)
        },
        |c| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::new(c, rng)?;
            ev.preprocess_circuit(&circuit, c)?;
            let res = ev.receive_many(&vec![2; input_size_gb], c)?;

            Ok(res)
        },
    )
    .unwrap();
    for (i, (w_gb, w_ev)) in gb_wires.iter().zip(ev_wires).enumerate() {
        let mask = w_gb.auth_share().bit() + w_ev.auth_share().bit();
        assert_eq!(
            w_gb.masked_value() + mask,
            inputs[i].into(),
            "The Garbler's value is incorrectly masked"
        );
        assert_eq!(
            w_ev.masked_value() + mask,
            inputs[i].into(),
            "The Evaluator received a wrong masked value from the Garbler"
        );
    }
}

#[test]
fn test_party_ev_encoding_gb_receiving_correct() {
    let input_size_gb = 400;
    let input_size_ev = 400;
    let circuit = circuits::TestAndGateFanN(input_size_gb + input_size_ev);
    let mut rng = SwankyRng::new();
    let inputs: Vec<u16> = (0..input_size_ev).map(|_| rng.r#gen::<u16>() % 2).collect();

    let (gb_wires, ev_wires) = swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(c, rng)?;
            gb.preprocess_circuit(&circuit, c)?;
            let res = gb.receive_many(&vec![2; input_size_gb], c)?;
            Ok(res)
        },
        |c| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::new(c, rng)?;
            ev.preprocess_circuit(&circuit, c)?;
            let res = ev.encode_many(&inputs, &vec![2; input_size_gb], c)?;

            Ok(res)
        },
    )
    .unwrap();
    for (i, (w_gb, w_ev)) in gb_wires.iter().zip(ev_wires).enumerate() {
        let mask = w_gb.auth_share().bit() + w_ev.auth_share().bit();
        assert_eq!(
            w_gb.masked_value() + mask,
            inputs[i].into(),
            "The Garbler received a wrong masked value from the Evaluator"
        );
        assert_eq!(
            w_ev.masked_value() + mask,
            inputs[i].into(),
            "The Evaluator's value is incorrectly masked"
        );
    }
}

#[test]
fn test_single_and_gate() {
    let ninputs_gb = 5;
    let ninputs_ev = 5;
    let circuit = circuits::TestAndGateFanN(ninputs_gb + ninputs_ev);

    swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(c, rng)?;
            gb.preprocess_circuit(&circuit, c)?;
            let mut inputs = gb.encode_many(&vec![0; ninputs_gb], &vec![2; ninputs_gb], c)?;
            let theirs = gb.receive_many(&vec![2; ninputs_ev], c)?;
            inputs.extend(theirs);
            circuit.execute(&mut gb, &inputs, c)?;
            Ok(())
        },
        |c| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::new(c, rng)?;
            ev.preprocess_circuit(&circuit, c)?;
            let mut inputs = ev.receive_many(&vec![2; ninputs_gb], c)?;
            let mine = ev.encode_many(&vec![0; ninputs_ev], &vec![2; ninputs_ev], c)?;
            inputs.extend(mine);
            circuit.execute(&mut ev, &inputs, c)?;
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn test_and_gate_fan_n() {
    let ninputs_gb = 10;
    let ninputs_ev = 0;
    let circuit = circuits::TestAndGateFanN(ninputs_gb + ninputs_ev);

    let inputs = vec![0; ninputs_gb + ninputs_ev];
    let expected = Dummy::eval(&circuit, &inputs).unwrap();

    let (outputs_gb, outputs_ev) = swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(c, rng)?;
            gb.preprocess_circuit(&circuit, c)?;
            let mut inputs = gb.encode_many(&vec![0; ninputs_gb], &vec![2; ninputs_gb], c)?;
            let theirs = gb.receive_many(&vec![2; ninputs_ev], c)?;
            inputs.extend(theirs);
            let outputs = circuit.execute(&mut gb, &inputs, c)?;
            gb.outputs(&outputs, c)
        },
        |c| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::new(c, rng)?;
            ev.preprocess_circuit(&circuit, c)?;
            let mut inputs = ev.receive_many(&vec![2; ninputs_gb], c)?;
            let mine = ev.encode_many(&vec![0; ninputs_ev], &vec![2; ninputs_ev], c)?;
            inputs.extend(mine);
            let outputs = circuit.execute(&mut ev, &inputs, c)?;
            ev.outputs(&outputs, c)
        },
    )
    .unwrap();
    assert!(outputs_gb.is_none());
    let outputs = outputs_ev.unwrap();
    assert_eq!(outputs, expected)
}

#[test]
fn test_or_gate_fan_n() {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = circuits::TestOrGateFanN(ninputs_gb + ninputs_ev);
    let inputs = vec![0; ninputs_gb + ninputs_ev];
    let expected = Dummy::eval(&circuit, &inputs).unwrap();

    let (outputs_gb, outputs_ev) = swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(c, rng)?;
            gb.preprocess_circuit(&circuit, c)?;
            let mut inputs = gb.encode_many(&vec![0; ninputs_gb], &vec![2; ninputs_gb], c)?;
            let theirs = gb.receive_many(&vec![2; ninputs_ev], c)?;
            inputs.extend(theirs);
            let outputs = circuit.execute(&mut gb, &inputs, c)?;
            gb.outputs(&outputs, c)
        },
        |c| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::new(c, rng)?;
            ev.preprocess_circuit(&circuit, c)?;
            let mut inputs = ev.receive_many(&vec![2; ninputs_gb], c)?;
            let mine = ev.encode_many(&vec![0; ninputs_ev], &vec![2; ninputs_ev], c)?;
            inputs.extend(mine);
            let outputs = circuit.execute(&mut ev, &inputs, c)?;
            ev.outputs(&outputs, c)
        },
    )
    .unwrap();
    assert!(outputs_gb.is_none());
    let outputs = outputs_ev.unwrap();
    assert_eq!(outputs, expected)
}

#[test]
fn test_xor_gate_fan_n() {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = circuits::TestXorGateFanN(ninputs_gb + ninputs_ev);
    let inputs = vec![0; ninputs_gb + ninputs_ev];
    let expected = Dummy::eval(&circuit, &inputs).unwrap();

    let (outputs_gb, outputs_ev) = swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(c, rng)?;
            gb.preprocess_circuit(&circuit, c)?;
            let mut inputs = gb.encode_many(&vec![0; ninputs_gb], &vec![2; ninputs_gb], c)?;
            let theirs = gb.receive_many(&vec![2; ninputs_ev], c)?;
            inputs.extend(theirs);
            let outputs = circuit.execute(&mut gb, &inputs, c)?;
            gb.outputs(&outputs, c)
        },
        |c| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::new(c, rng)?;
            ev.preprocess_circuit(&circuit, c)?;
            let mut inputs = ev.receive_many(&vec![2; ninputs_gb], c)?;
            let mine = ev.encode_many(&vec![0; ninputs_ev], &vec![2; ninputs_ev], c)?;
            inputs.extend(mine);
            let outputs = circuit.execute(&mut ev, &inputs, c)?;
            ev.outputs(&outputs, c)
        },
    )
    .unwrap();
    assert!(outputs_gb.is_none());
    let outputs = outputs_ev.unwrap();
    assert_eq!(outputs, expected)
}

#[test]
fn test_binary_addition() {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = circuits::TestBinaryAddition(ninputs_gb + ninputs_ev);
    let inputs = vec![0; ninputs_gb + ninputs_ev];
    let expected = Dummy::eval(&circuit, &inputs).unwrap();

    let (outputs_gb, outputs_ev) = swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(c, rng)?;
            gb.preprocess_circuit(&circuit, c)?;
            let mut inputs = gb.encode_many(&vec![0; ninputs_gb], &vec![2; ninputs_gb], c)?;
            let theirs = gb.receive_many(&vec![2; ninputs_ev], c)?;
            inputs.extend(theirs);
            let outputs = circuit.execute(&mut gb, &inputs, c)?;
            gb.outputs(&outputs, c)
        },
        |c| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::new(c, rng)?;
            ev.preprocess_circuit(&circuit, c)?;
            let mut inputs = ev.receive_many(&vec![2; ninputs_gb], c)?;
            let mine = ev.encode_many(&vec![0; ninputs_ev], &vec![2; ninputs_ev], c)?;
            inputs.extend(mine);
            let outputs = circuit.execute(&mut ev, &inputs, c)?;
            ev.outputs(&outputs, c)
        },
    )
    .unwrap();
    assert!(outputs_gb.is_none());
    let outputs = outputs_ev.unwrap();
    assert_eq!(outputs, expected)
}

#[test]
fn test_binary_subtraction() {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = circuits::TestBinarySubtraction(ninputs_gb + ninputs_ev);
    let inputs = vec![0; ninputs_gb + ninputs_ev];
    let expected = Dummy::eval(&circuit, &inputs).unwrap();

    let (outputs_gb, outputs_ev) = swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(c, rng)?;
            gb.preprocess_circuit(&circuit, c)?;
            let mut inputs = gb.encode_many(&vec![0; ninputs_gb], &vec![2; ninputs_gb], c)?;
            let theirs = gb.receive_many(&vec![2; ninputs_ev], c)?;
            inputs.extend(theirs);
            let outputs = circuit.execute(&mut gb, &inputs, c)?;
            gb.outputs(&outputs, c)
        },
        |c| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::new(c, rng)?;
            ev.preprocess_circuit(&circuit, c)?;
            let mut inputs = ev.receive_many(&vec![2; ninputs_gb], c)?;
            let mine = ev.encode_many(&vec![0; ninputs_ev], &vec![2; ninputs_ev], c)?;
            inputs.extend(mine);
            let outputs = circuit.execute(&mut ev, &inputs, c)?;
            ev.outputs(&outputs, c)
        },
    )
    .unwrap();
    assert!(outputs_gb.is_none());
    let outputs = outputs_ev.unwrap();
    assert_eq!(outputs, expected)
}
