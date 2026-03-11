use crate::{HasModulus, WireLabel, WireMod2, hash_wires, util::tweak2};
use subtle::ConditionallySelectable;
use swanky_block::Block;

/// The [`BinaryWireLabel`] provides the subroutines to implement AND gates
/// for the garbler and evaluator in [`crate::fancy::FancyBinary`].
pub trait BinaryWireLabel: WireLabel + ConditionallySelectable {
    /// Garbles an 'and' gate given two input wires and the delta.
    ///
    /// Outputs a tuple consisting of the two gates (that should be transfered to the evaluator)
    /// and the next wirelabel for the garbler.
    fn garble_and_gate(gate_num: usize, A: &Self, B: &Self, delta: &Self) -> (Block, Block, Self);

    /// Evaluates an 'and' gate given two inputs wires and two half-gates from the garbler.
    ///
    /// Outputs C = A & B
    fn evaluate_and_gate(gate_num: usize, A: &Self, B: &Self, gate0: &Block, gate1: &Block)
    -> Self;
}

impl BinaryWireLabel for WireMod2 {
    fn garble_and_gate(gate_num: usize, A: &Self, B: &Self, delta: &Self) -> (Block, Block, Self) {
        let q = A.modulus();
        let D = delta;

        let r = B.color(); // secret value known only to the garbler (ev knows r+b)

        let g = tweak2(gate_num as u64, 0);

        // X = H(A+aD) + arD such that a + A.color == 0
        let alpha = A.color(); // alpha = -A.color
        let X1 = *A + *D * alpha;

        // Y = H(B + bD) + (b + r)A such that b + B.color == 0
        let beta = (q - B.color()) % q;
        let Y1 = *B + *D * beta;

        let AD = *A + *D;
        let BD = *B + *D;

        // idx is always boolean for binary gates, so it can be represented as a `u8`
        let a_selector = (A.color() as u8).into();
        let b_selector = (B.color() as u8).into();

        let B = Self::conditional_select(&BD, B, b_selector);
        let newA = Self::conditional_select(&AD, A, a_selector);
        let idx = u8::conditional_select(&(r as u8), &0u8, a_selector);

        let [hashA, hashB, hashX, hashY] = hash_wires([&newA, &B, &X1, &Y1], g);

        let X = Self::hash_to_mod(hashX, q) + *D * (alpha * r % q);
        let Y = Self::hash_to_mod(hashY, q);

        let gate0 =
            hashA ^ Block::conditional_select(&X.to_block(), &(X + *D).to_block(), idx.into());
        let gate1 = hashB ^ (Y + *A).to_block();

        (gate0, gate1, X + Y)
    }

    fn evaluate_and_gate(
        gate_num: usize,
        A: &Self,
        B: &Self,
        gate0: &Block,
        gate1: &Block,
    ) -> Self {
        let g = tweak2(gate_num as u64, 0);

        let [hashA, hashB] = hash_wires([A, B], g);

        // garbler's half gate
        let L = Self::from_block(
            Block::conditional_select(&hashA, &(hashA ^ *gate0), (A.color() as u8).into()),
            2,
        );

        // evaluator's half gate
        let R = Self::from_block(
            Block::conditional_select(&hashB, &(hashB ^ *gate1), (B.color() as u8).into()),
            2,
        );

        L + R + *A * B.color()
    }
}
