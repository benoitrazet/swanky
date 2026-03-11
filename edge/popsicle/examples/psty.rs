//! Private set intersection (PSTY) benchmarks using `criterion`.

use popsicle::psty::{Receiver, Sender};
use std::time::SystemTime;
use swanky_aes_rng::AesRng;

const NBYTES: usize = 16;
const NINPUTS: usize = 1 << 16;

fn rand_vec(nbytes: usize) -> Vec<u8> {
    (0..nbytes).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(ninputs: usize, nbytes: usize) -> Vec<Vec<u8>> {
    (0..ninputs).map(|_| rand_vec(nbytes)).collect()
}

fn psty(inputs1: Vec<Vec<u8>>, inputs2: Vec<Vec<u8>>) {
    let total = SystemTime::now();

    let _ = swanky_channel::local::local_channel_pair(
        |channel| {
            let mut rng = AesRng::new();

            let start = SystemTime::now();
            let mut sender = Sender::init(channel, &mut rng).unwrap();
            println!(
                "Sender :: init time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            let state = sender.send(&inputs1, channel, &mut rng).unwrap();
            println!(
                "Sender :: send time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            state.compute_intersection(channel, &mut rng).unwrap();
            println!(
                "Sender :: intersection time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            Ok(())
        },
        |channel| {
            let mut rng = AesRng::new();

            let start = SystemTime::now();
            let mut receiver = Receiver::init(channel, &mut rng).unwrap();
            println!(
                "Receiver :: init time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            let state = receiver.receive(&inputs2, channel, &mut rng).unwrap();
            println!(
                "Receiver :: receive time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            let start = SystemTime::now();
            let _ = state.compute_intersection(channel, &mut rng).unwrap();
            println!(
                "Receiver :: intersection time: {} ms",
                start.elapsed().unwrap().as_millis()
            );
            Ok(())
        },
    )
    .unwrap();
    println!("Total time: {} ms", total.elapsed().unwrap().as_millis());
}

fn main() {
    println!(
        "* Running PSTY on {} inputs each of length {} bytes",
        NINPUTS, NBYTES
    );
    let rs = rand_vec_vec(NINPUTS, NBYTES);
    psty(rs.clone(), rs.clone());
}
