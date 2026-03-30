use popsicle::psty::{Receiver, Sender};
use std::time::SystemTime;
use swanky_rng::AesRng;

const NBYTES: usize = 16;
const NINPUTS: usize = 1000;
const PAYLOAD_SIZE: usize = 64;

fn rand_vec(nbytes: usize) -> Vec<u8> {
    (0..nbytes).map(|_| rand::random::<u8>()).collect()
}

fn rand_vec_vec(ninputs: usize, nbytes: usize) -> Vec<Vec<u8>> {
    (0..ninputs).map(|_| rand_vec(nbytes)).collect()
}

fn psty_payload(inputs1: Vec<Vec<u8>>, inputs2: Vec<Vec<u8>>, payloads: Vec<Vec<u8>>) {
    let payload_size = payloads[0].len();
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
            let _ = state.receive_payloads(payload_size, channel).unwrap();
            println!(
                "Sender :: payload intersection time: {} ms",
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
            state.send_payloads(&payloads, channel, &mut rng).unwrap();
            println!(
                "Receiver :: payload intersection time: {} ms",
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
        "* Running PSTY on {} inputs each of length {} bytes with {} byte payloads",
        NINPUTS, NBYTES, PAYLOAD_SIZE
    );
    let rs = rand_vec_vec(NINPUTS, NBYTES);
    let payloads = rand_vec_vec(NINPUTS, PAYLOAD_SIZE);
    psty_payload(rs.clone(), rs.clone(), payloads);
}
