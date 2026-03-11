use rand::Rng;
use std::time::SystemTime;
use swanky_aes_rng::AesRng;
use swanky_block::{Block, Block512};
use swanky_channel_legacy::track_unix_channel_pair;

fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}

fn run(ninputs: usize, npoints: usize) {
    println!("npoints = {}, ninputs = {}", npoints, ninputs);
    let inputs = rand_block_vec(ninputs);
    let mut rng = AesRng::new();
    let points = (0..npoints)
        .map(|_| (rng.r#gen(), rng.r#gen()))
        .collect::<Vec<(Block, Block512)>>();
    let (mut sender, mut receiver) = track_unix_channel_pair();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let mut rng = AesRng::new();
        let start = SystemTime::now();
        let mut oprf: swanky_oprf_kmprt::Sender =
            swanky_oprf_kmprt::Sender::init(&mut sender, &mut rng).unwrap();
        println!(
            "Sender init time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        oprf.send(&mut sender, &points, ninputs, &mut rng).unwrap();
        println!(
            "Sender send time: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        println!(
            "Sender communication (read): {:.2} Mb",
            sender.kilobits_read() / 1000.0
        );
        println!(
            "Sender communication (write): {:.2} Mb",
            sender.kilobits_written() / 1000.0
        );
    });
    let mut rng = AesRng::new();
    let start = SystemTime::now();
    let mut oprf: swanky_oprf_kmprt::Receiver =
        swanky_oprf_kmprt::Receiver::init(&mut receiver, &mut rng).unwrap();
    println!(
        "Receiver init time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let _ = oprf.receive(&mut receiver, &inputs, &mut rng).unwrap();
    println!(
        "Receiver send time: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    handle.join().unwrap();
    println!(
        "Receiver communication (read): {:.2} Mb",
        receiver.kilobits_read() / 1000.0
    );
    println!(
        "Receiver communication (write): {:.2} Mb",
        receiver.kilobits_written() / 1000.0
    );
    println!("Total time: {} ms", total.elapsed().unwrap().as_millis());
}

fn main() {
    run(83231, 196608);
}
