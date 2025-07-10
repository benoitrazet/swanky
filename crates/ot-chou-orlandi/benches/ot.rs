use criterion::{Criterion, criterion_group, criterion_main};
fn do_bench(c: &mut Criterion) {
    swanky_ot_test::bench::bench_block_ot::<
        swanky_ot_chou_orlandi::Sender,
        swanky_ot_chou_orlandi::Receiver,
    >(c, 128);
}
criterion_group!(benches, do_bench,);
criterion_main!(benches);
