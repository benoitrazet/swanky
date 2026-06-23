use crate::{Fancy, HasModulus};
use swanky_channel::Channel;
use swanky_error::Result;

/// Trait for flattening the output of a [`Circuit`] into a vector of wires.
pub trait Flatten {
    /// The type of the elements in the output vector.
    type Item;

    /// Flatten a set of wires into a single vector of wires.
    fn flatten(self) -> Vec<Self::Item>;
}

impl<T: Clone + HasModulus> Flatten for Vec<T> {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        self
    }
}

impl<T: Clone + HasModulus> Flatten for T {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        vec![self]
    }
}

impl<T: Clone + HasModulus> Flatten for (T, T) {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        vec![self.0]
    }
}

impl<T: Clone + HasModulus, const N: usize> Flatten for [T; N] {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        self.to_vec()
    }
}

/// Trait for defining computations over [`Fancy`] objects.
///
/// A `Circuit` computation is defined by a [`Circuit::Input`] associated type,
/// a [`Circuit::Output`] associated type, and a [`Circuit::execute`] method
/// that maps [`Circuit::Input`] to [`Circuit::Output`]. The body of
/// [`Circuit::execute`] may use other `Circuit`s internally.
///
/// For mapping arbitrary inputs into the correct `Circuit` input
/// representation, use the [`CircuitInputMapper`] trait.
///
/// # Example
/// Below is a simple circuit computing an add gate. The computation is defined
/// in `execute` by directly calling operations on the underlying [`Fancy`]
/// backend ([`crate::FancyArithmetic`] in this example).
/// ```
/// # use fancy_garbling::{FancyArithmetic, Circuit};
/// # use swanky_channel::Channel;
/// # use swanky_error::Result;
/// struct AddCircuit;
/// impl<F: FancyArithmetic> Circuit<F> for AddCircuit {
///     type Input = (F::Item, F::Item);
///     type Output = F::Item;
///
///     fn execute(
///         &self,
///         backend: &mut F,
///         inputs: Self::Input,
///         channel: &mut Channel,
///     ) -> Result<Self::Output> {
///         Ok(backend.add(&inputs.0, &inputs.1))
///     }
/// }
/// ```
/// Given `AddCircuit`, any object instantiating the required [`Fancy`] traits
/// can evaluate the circuit by calling `AddMany.execute(...)`.
pub trait Circuit<F: Fancy> {
    /// The input type of the circuit.
    type Input;
    /// The output type of the circuit.
    ///
    /// The [`Flatten`] trait allows the output type to be converted into a
    /// `Vec<F::Item>`.
    type Output: Flatten<Item = F::Item>;

    /// Execute a circuit on a given [`Fancy`] backend using the provided inputs.
    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output>;
}

/// Trait for defining input-size-dependent [`Circuit`]s.
///
/// The [`Circuit`] trait allows one to write circuits for arbitrary-length
/// inputs, which becomes a problem when needing to be used in, for example, a
/// garbled circuit protocol, where the input length needs to be know during the
/// Oblivious Transfer phase of the protocol. This is where `CircuitInputMapper`
/// comes in: it provides a [`CircuitInputMapper::map`] method for mapping
/// vectors of inputs to the appropriate input type as required to run
/// [`Circuit::execute`], alongside [`CircuitInputMapper::ninputs`] for
/// determining the number of inputs for the circuit. Finally,
/// [`CircuitInputMapper::modulus`] outputs the particular modulus required for
/// the `i`th input wire.
///
/// While certain [`Fancy`] instantiations can evaluate [`Circuit`]s directly,
/// several, including garbled circuits and zero knowledge protocols, operate
/// over `CircuitInputMapper`s instead, and any [`Circuit`] to be run under
/// these protocols needs to implement `CircuitInputMapper` as well.
///
/// # Example
/// The below code extends the `AddCircuit` example from the [`Circuit`]
/// documentation to support mapping a vector of inputs into the appropriate
/// input type for the given circuit.
/// ```
/// # use fancy_garbling::{FancyArithmetic, Circuit, CircuitInputMapper};
/// # use swanky_channel::Channel;
/// # use swanky_error::Result;
/// # struct AddCircuit;
/// # impl<F: FancyArithmetic> Circuit<F> for AddCircuit {
/// #     type Input = (F::Item, F::Item);
/// #     type Output = F::Item;
/// #
/// #     fn execute(
/// #         &self,
/// #         backend: &mut F,
/// #         inputs: Self::Input,
/// #         channel: &mut Channel,
/// #     ) -> Result<Self::Output> {
/// #         Ok(backend.add(&inputs.0, &inputs.1))
/// #     }
/// # }
/// impl<F: FancyArithmetic> CircuitInputMapper<F> for AddCircuit {
///     fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
///         assert_eq!(inputs.len(), 2);
///         (inputs[0].clone(), inputs[1].clone())
///     }
///
///     fn ninputs(&self) -> usize {
///         2
///     }
///
///     fn modulus(&self, _: usize) -> u16 {
///         2
///     }
/// }
/// ```
pub trait CircuitInputMapper<F: Fancy>: Circuit<F> {
    /// Map a vector of inputs to [`Circuit::Input`].
    ///
    /// # Panics
    /// This panics if the number of inputs does not match the expected input
    /// size.
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input;
    /// The number of inputs to provide to [`CircuitInputMapper::map`].
    fn ninputs(&self) -> usize;
    /// The modulus of the `i`th input.
    fn modulus(&self, i: usize) -> u16;
}
