use criterion::{Criterion, criterion_group, criterion_main};
fn do_bench(c: &mut Criterion) {
    swanky_ot_test::bench::bench_block_ot::<swanky_ot_dummy::Sender, swanky_ot_dummy::Receiver>(
        c, 128,
    );
}
criterion_group!(benches, do_bench,);
criterion_main!(benches);
