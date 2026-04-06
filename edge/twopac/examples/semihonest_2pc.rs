use fancy_garbling::{
    Fancy, WireMod2,
    circuit::{BinaryCircuit as Circuit, CircuitExecutor},
};
use std::{fs::File, io::BufReader, time::SystemTime};
use swanky_ot_alsz_kos::alsz::{Receiver as OtReceiver, Sender as OtSender};
use swanky_rng::SwankyRng;
use swanky_twopac::semihonest::{Evaluator, Garbler};

fn circuit(fname: &str) -> Circuit {
    println!("* Circuit: {}", fname);
    Circuit::parse(BufReader::new(File::open(fname).unwrap())).unwrap()
}

fn run_circuit(circ: &mut Circuit, gb_inputs: Vec<u16>, ev_inputs: Vec<u16>) {
    let circ_ = circ.clone();
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();

    let total = SystemTime::now();
    swanky_channel::local::local_channel_pair(
        |channel| {
            let rng = SwankyRng::new();
            let start = SystemTime::now();
            let mut gb = Garbler::<SwankyRng, OtSender, WireMod2>::new(channel, rng).unwrap();
            println!(
                "Garbler :: Initialization: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            let mut xs = gb
                .encode_many(&gb_inputs, &vec![2; n_gb_inputs], channel)
                .unwrap();
            let ys = gb.receive_many(&vec![2; n_ev_inputs], channel).unwrap();
            xs.extend(ys);
            println!(
                "Garbler :: Encoding inputs: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            circ_.execute(&mut gb, &xs, channel).unwrap();
            println!(
                "Garbler :: Circuit garbling: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            Ok(())
        },
        |channel| {
            let rng = SwankyRng::new();
            let start = SystemTime::now();
            let mut ev = Evaluator::<SwankyRng, OtReceiver, WireMod2>::new(channel, rng).unwrap();
            println!(
                "Evaluator :: Initialization: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            let mut xs = ev.receive_many(&vec![2; n_gb_inputs], channel).unwrap();
            let ys = ev
                .encode_many(&ev_inputs, &vec![2; n_ev_inputs], channel)
                .unwrap();
            xs.extend(ys);
            println!(
                "Evaluator :: Encoding inputs: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            circ.execute(&mut ev, &xs, channel).unwrap();
            println!(
                "Evaluator :: Circuit evaluation: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            Ok(())
        },
    )
    .unwrap();
    println!("Total: {} ms", total.elapsed().unwrap().as_millis());
}

fn main() {
    let mut circ = circuit("circuits/AES-non-expanded.txt");
    run_circuit(&mut circ, vec![0; 128], vec![0; 128]);
    let mut circ = circuit("circuits/sha-1.txt");
    run_circuit(&mut circ, vec![0; 512], vec![]);
    let mut circ = circuit("circuits/sha-256.txt");
    run_circuit(&mut circ, vec![0; 512], vec![]);
}
