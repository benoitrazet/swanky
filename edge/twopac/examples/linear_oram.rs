//! An example that secretly retrieves an element from an ORAM in a binary garbled circuit
//! using fancy-garbling.
use fancy_garbling::{
    AllWire, BinaryBundle, BinaryGadgets, Fancy, FancyArithmetic, FancyBinary, util,
};
use swanky_twopac::semihonest::{Evaluator, Garbler};

use swanky_channel::Channel;
use swanky_ot_alsz_kos::alsz::{Receiver as OtReceiver, Sender as OtSender};
use swanky_rng::SwankyRng;

/// A structure that contains both the garbler and the evaluators
/// wires. This structure simplifies the API of the garbled circuit.
struct ORAMInputs<F> {
    ram: Vec<BinaryBundle<F>>,
    query: BinaryBundle<F>,
}
/// The garbler's main method:
/// (1) The garbler is first created using the passed rng and value.
/// (2) The garbler then exchanges their wires obliviously with the evaluator.
/// (3) The garbler and the evaluator then run the garbled circuit.
/// (4) The garbler and the evaluator open the result of the computation.
fn gb_linear_oram(rng: SwankyRng, channel: &mut Channel, inputs: &[u128]) {
    // (1)
    let mut gb = Garbler::<SwankyRng, OtSender, AllWire>::new(channel, rng).unwrap();
    // The size of the RAM is assumed to be public. The garbler sends their number of
    // of input wires. We note that every element of the RAM has a fixed size of 128 bits.
    let _ = channel.write(&inputs.len());
    // (2)
    let circuit_wires = gb_set_fancy_inputs(&mut gb, inputs, channel);
    // (3)
    let query =
        fancy_linear_oram::<Garbler<SwankyRng, OtSender, AllWire>>(&mut gb, circuit_wires, channel)
            .unwrap();
    // (4)
    gb.outputs(query.wires(), channel).unwrap();
}

/// The garbler's wire exchange method
fn gb_set_fancy_inputs<F>(gb: &mut F, inputs: &[u128], channel: &mut Channel) -> ORAMInputs<F::Item>
where
    F: Fancy<Item = AllWire> + BinaryGadgets,
{
    // The number of bits needed to represent a single input value
    let nbits = 128;
    // The garbler encodes their wires with the appropriate moduli per wire.
    let ram: Vec<BinaryBundle<F::Item>> = gb.bin_encode_many(inputs, nbits, channel).unwrap();
    // The evaluator receives their input labels using Oblivious Transfer (OT)
    let query: BinaryBundle<F::Item> = gb.bin_receive(nbits, channel).unwrap();

    ORAMInputs { ram, query }
}

/// The evaluator's main method:
/// (1) The evaluator is first created using the passed rng and value.
/// (2) The evaluator then exchanges their wires obliviously with the garbler.
/// (3) The evaluator and the garbler then run the garbled circuit.
/// (4) The evaluator and the garbler open the result of the computation.
/// (5) The evaluator translates the binary output of the circuit into its decimal
///     representation.
fn ev_linear_oram(rng: SwankyRng, channel: &mut Channel, input: u128) -> u128 {
    // (1)
    let mut ev = Evaluator::<SwankyRng, OtReceiver, AllWire>::new(channel, rng).unwrap();
    let ram_size = channel.read::<usize>().unwrap();
    // (2)
    let circuit_wires = ev_set_fancy_inputs(&mut ev, input, ram_size, channel);
    // (3)
    let query = fancy_linear_oram::<Evaluator<SwankyRng, OtReceiver, AllWire>>(
        &mut ev,
        circuit_wires,
        channel,
    )
    .unwrap();
    // (4)
    let query_binary = ev
        .outputs(query.wires(), channel)
        .unwrap()
        .expect("evaluator should produce outputs");

    // (5)
    util::u128_from_bits(&query_binary)
}
fn ev_set_fancy_inputs<F>(
    ev: &mut F,
    input: u128,
    ram_size: usize,
    channel: &mut Channel,
) -> ORAMInputs<F::Item>
where
    F: Fancy<Item = AllWire> + BinaryGadgets,
{
    // The number of bits needed to represent a single input value
    let nbits = 128;
    // The evaluator receives the garblers input labels.
    let ram: Vec<BinaryBundle<F::Item>> = ev.bin_receive_many(ram_size, nbits, channel).unwrap();
    // The evaluator encodes their input labels.
    let query: BinaryBundle<F::Item> = ev.bin_encode(input, nbits, channel).unwrap();

    ORAMInputs { ram, query }
}

/// The main fancy function which describes the garbled circuit for linear ORAM.
fn fancy_linear_oram<F>(
    f: &mut F,
    wire_inputs: ORAMInputs<F::Item>,
    channel: &mut Channel,
) -> swanky_error::Result<BinaryBundle<F::Item>>
where
    F: Fancy + BinaryGadgets + FancyBinary + FancyArithmetic,
{
    let ram: Vec<BinaryBundle<_>> = wire_inputs.ram;
    let index: BinaryBundle<_> = wire_inputs.query;

    let mut result = f.bin_constant_bundle(0, 128, channel)?;
    let zero = f.bin_constant_bundle(0, 128, channel)?;

    // We traverse the garbler's RAM one element at a time, and multiplex
    // the result based on whether the evaluator's query matches the current
    // index.
    for (i, item) in ram.iter().enumerate() {
        // The current index is turned into a binary constant bundle.
        let current_index = f.bin_constant_bundle(i as u128, 128, channel)?;
        // We check if the evaluator's query matches the current index obliviously.
        let mux_bit = f.bin_eq_bundles(&index, &current_index, channel)?;
        // We use the result of the prior equality check to multiplex by either adding 0 to
        // the result of the computation and keeping it as is, or adding RAM[i] to it
        // and updating it. The evaluator's query can only correspond to a single index.
        let mux = f.bin_multiplex(&mux_bit, &zero, item, channel)?;
        result = f.bin_addition_no_carry(&result, &mux, channel)?;
    }

    Ok(result)
}

fn ram_in_clear(index: usize, ram: &[u128]) -> u128 {
    ram[index]
}

use clap::Parser;
#[derive(Parser)]
/// Example usage:
///
/// cargo run --example linear_oram 5 1 2 3 7 7 25
///
/// Computes RAM([1,2,3,7,7,25], at index: 5)
struct Cli {
    /// The first integer specifies the evaluator's query
    query: u128,
    /// The rest of the integers contitute the garbler's RAM
    ram: Vec<u128>,
}

fn main() {
    let cli = Cli::parse();

    let ev_index: u128 = cli.query;
    let gb_ram = cli.ram;

    let (_, result) = swanky_channel::local::local_channel_pair(
        |channel| {
            let rng_gb = SwankyRng::new();
            gb_linear_oram(rng_gb, channel, &gb_ram);
            Ok(())
        },
        |channel| {
            let rng_ev = SwankyRng::new();
            let result = ev_linear_oram(rng_ev, channel, ev_index);
            Ok(result)
        },
    )
    .unwrap();

    let resut_in_clear = ram_in_clear(ev_index as usize, &gb_ram);
    println!("Garbled Circuit result is : RAM([{gb_ram:?}], at index:{ev_index}) = {result}");
    assert!(
        result == resut_in_clear,
        "The result is incorrect and should be {resut_in_clear}"
    );
}
