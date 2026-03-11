use simple_arith_circuit::Circuit;
use std::io::{BufWriter, Write};

fn bench_reader_scalability() {
    let mut tmp = BufWriter::new(tempfile::NamedTempFile::new().unwrap());
    let gate_count = 100000000;
    let wire_count = gate_count + 1;
    writeln!(tmp, "{gate_count} {wire_count}").unwrap();
    writeln!(tmp, "1 1").unwrap(); // number-of-input-values number-of-wires-each-input-value...
    writeln!(tmp, "1 1").unwrap(); // number-of-output-values number-of-wires-each-output-value...
    writeln!(tmp).unwrap();
    for i in 0..wire_count {
        writeln!(tmp, "1 1 {i} {} INV", i + 1).unwrap();
    }
    tmp.flush().unwrap();
    let tmp = tmp.into_inner().unwrap();
    println!("Starting benchmark");
    let start = std::time::Instant::now();
    Circuit::read_bristol_fashion(tmp.path(), None).unwrap();
    let elapsed = start.elapsed();
    println!("Total: {:#?}", elapsed);
    println!(
        "Gates per second: {}",
        100_000_000.0 / elapsed.as_secs_f64()
    );
}

fn main() {
    bench_reader_scalability();
}
