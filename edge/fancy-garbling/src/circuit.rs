//! DSL for creating circuits compatible with fancy-garbling in the old-fashioned way,
//! where you create a circuit for a computation then garble it.

use crate::{BinaryBundle, Bundle, CrtBundle, HasModulus, fancy::Fancy};
use itertools::Itertools;
use swanky_channel::Channel;
use swanky_error::Result;

mod binary;
pub use binary::{BinaryCircuit, BinaryGate};

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

impl<T: Clone + HasModulus> Flatten for Bundle<T> {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        self.wires().to_vec()
    }
}

impl<T: Clone + HasModulus> Flatten for BinaryBundle<T> {
    type Item = T;

    fn flatten(self) -> Vec<T> {
        self.wires().to_vec()
    }
}

impl<T: Clone + HasModulus> Flatten for CrtBundle<T> {
    type Item = T;

    fn flatten(self) -> Vec<T> {
        self.extract().wires().to_vec()
    }
}

impl<T: Clone + HasModulus> Flatten for Vec<CrtBundle<T>> {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        self.into_iter().map(|bundle| bundle.flatten()).concat()
    }
}

impl<T: Clone + HasModulus> Flatten for (T, BinaryBundle<T>) {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        [vec![self.0], self.1.flatten()].concat()
    }
}

impl<T: Clone + HasModulus> Flatten for (BinaryBundle<T>, T) {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        [self.0.flatten(), vec![self.1]].concat()
    }
}

impl<T: Clone + HasModulus, const N: usize> Flatten for [T; N] {
    type Item = T;

    fn flatten(self) -> Vec<Self::Item> {
        self.to_vec()
    }
}

/// Trait for defining input-size-dependent [`Circuit`]s.
///
/// A `CircuitInputMapper` can map vectors of inputs to the appropriate input
/// type as required to run [`Circuit::execute`].
///
/// # Example
/// Below extends the `AddCircuit` example from the [`Circuit`] documentation to
/// support mapping a vector of inputs into the appropriate input type for the
/// given circuit.
/// ```
/// # use fancy_garbling::{FancyArithmetic, circuit::{Circuit, CircuitInputMapper}};
/// # use swanky_channel::Channel;
/// # use swanky_error::Result;
/// struct AddCircuit(u16);
/// impl<F: FancyArithmetic> Circuit<F> for AddCircuit {
///     type Input = (F::Item, F::Item);
///     type Output = F::Item;
///
///     fn execute(
///         &self,
///         backend: &mut F,
///         inputs: &Self::Input,
///         channel: &mut Channel,
///     ) -> Result<Self::Output> {
///         Ok(backend.add(&inputs.0, &inputs.1))
///     }
/// }
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
    /// This panics of the number of inputs does not match the expected input size.
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input;
    /// The number of inputs to provide to [`Circuit::execute`].
    fn ninputs(&self) -> usize;
    /// The modulus for input `i`.
    fn modulus(&self, i: usize) -> u16;
}

/// Trait for defining computations over [`Fancy`] objects.
///
/// A `Circuit` computation is defined by an [`Circuit::Input`] associated type,
/// a [`Circuit::Output`] associated type, and a [`Circuit::execute`] method
/// that maps a [`Circuit::Input`] to a [`Circuit::Output`].
///
/// For mapping arbitrary inputs into the correct `Circuit` input
/// representation, use the [`CircuitInputMapper`] trait.
///
/// # Example
/// Below is a simple example of computing an add gate over an arbitrary
/// modulus. The computation is defined in `execute` by directly calling
/// operations on the underlying [`Fancy`] backend.
/// ```
/// # use fancy_garbling::{FancyArithmetic, circuit::Circuit};
/// # use swanky_channel::Channel;
/// # use swanky_error::Result;
/// struct AddCircuit(u16);
/// impl<F: FancyArithmetic> Circuit<F> for AddCircuit {
///     type Input = (F::Item, F::Item);
///     type Output = F::Item;
///
///     fn execute(
///         &self,
///         backend: &mut F,
///         inputs: &Self::Input,
///         channel: &mut Channel,
///     ) -> Result<Self::Output> {
///         Ok(backend.add(&inputs.0, &inputs.1))
///     }
/// }
/// ```
pub trait Circuit<F: Fancy> {
    /// The input type of the circuit.
    type Input;
    /// The output type of the circuit.
    type Output: Flatten<Item = F::Item>;

    /// Execute a circuit on a given [`Fancy`] backend using the provided inputs.
    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output>;
}

pub mod circuits {
    //! A collection of test circuits.

    pub mod fancy {
        //! Circuits that test [`Fancy`].

        use crate::{
            Fancy,
            circuit::{Circuit, CircuitInputMapper},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`Fancy::constant`] on binary values.
        pub struct TestBinaryConstant;
        impl<F: Fancy> Circuit<F> for TestBinaryConstant {
            type Input = ();
            type Output = Vec<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                _: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                let outputs = vec![
                    backend.constant(0, 2, channel)?,
                    backend.constant(1, 2, channel)?,
                ];
                Ok(outputs)
            }
        }
        impl<F: Fancy> CircuitInputMapper<F> for TestBinaryConstant {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert!(inputs.is_empty());
            }

            fn ninputs(&self) -> usize {
                0
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }
    }

    pub mod binary {
        //! Circuits that test [`FancyBinary`].

        use crate::{
            FancyBinary,
            circuit::{Circuit, CircuitInputMapper},
            circuits::binary::{AndMany, OrMany, XorMany},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`FancyBinary::negate`].
        pub struct TestNegateGate;
        impl<F: FancyBinary> Circuit<F> for TestNegateGate {
            type Input = F::Item;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(backend.negate(input))
            }
        }
        impl<F: FancyBinary> CircuitInputMapper<F> for TestNegateGate {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 1);
                inputs[0].clone()
            }

            fn ninputs(&self) -> usize {
                1
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }

        /// Circuit for testing [`FancyBinary::and`].
        pub struct TestAndGate;
        impl<F: FancyBinary> Circuit<F> for TestAndGate {
            type Input = (F::Item, F::Item);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.and(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: FancyBinary> CircuitInputMapper<F> for TestAndGate {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 2);
                (inputs[0].clone(), inputs[1].clone())
            }

            fn ninputs(&self) -> usize {
                2
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }

        /// Circuit for testing [`AndMany`].
        pub struct TestAndGateFanN(pub usize);
        impl<F: FancyBinary> Circuit<F> for TestAndGateFanN {
            type Input = Vec<F::Item>;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                AndMany.execute(backend, inputs, channel)
            }
        }

        impl<F: FancyBinary> CircuitInputMapper<F> for TestAndGateFanN {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0);
                inputs
            }

            fn ninputs(&self) -> usize {
                self.0
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }

        /// Circuit for testing [`OrMany`].
        pub struct TestOrGateFanN(pub usize);
        impl<F: FancyBinary> Circuit<F> for TestOrGateFanN {
            type Input = Vec<F::Item>;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                OrMany.execute(backend, inputs, channel)
            }
        }
        impl<F: FancyBinary> CircuitInputMapper<F> for TestOrGateFanN {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0);
                inputs
            }

            fn ninputs(&self) -> usize {
                self.0
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }

        /// Circuit for testing [`XorMany`].
        pub struct TestXorGateFanN(pub usize);
        impl<F: FancyBinary> Circuit<F> for TestXorGateFanN {
            type Input = Vec<F::Item>;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                XorMany.execute(backend, inputs, channel)
            }
        }
        impl<F: FancyBinary> CircuitInputMapper<F> for TestXorGateFanN {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0);
                inputs
            }

            fn ninputs(&self) -> usize {
                self.0
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }
    }

    pub mod arithmetic {
        //! Circuits that test [`FancyArithmetic`].

        use crate::{
            FancyArithmetic,
            circuit::{Circuit, CircuitInputMapper},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`FancyArithmetic::add`].
        pub struct TestAddition(pub u16);
        impl<F: FancyArithmetic> Circuit<F> for TestAddition {
            type Input = (F::Item, F::Item);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(backend.add(&inputs.0, &inputs.1))
            }
        }
        impl<F: FancyArithmetic> CircuitInputMapper<F> for TestAddition {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 2);
                (inputs[0].clone(), inputs[1].clone())
            }

            fn ninputs(&self) -> usize {
                2
            }

            fn modulus(&self, _: usize) -> u16 {
                self.0
            }
        }

        /// Circuit for testing [`FancyArithmetic::add_many`].
        pub struct TestAddMany(pub u16, pub usize);
        impl<F: FancyArithmetic> Circuit<F> for TestAddMany {
            type Input = Vec<F::Item>;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(backend.add_many(inputs))
            }
        }
        impl<F: FancyArithmetic> CircuitInputMapper<F> for TestAddMany {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.1);
                inputs
            }

            fn ninputs(&self) -> usize {
                self.1
            }

            fn modulus(&self, _: usize) -> u16 {
                self.0
            }
        }

        /// Circuit for testing [`FancyArithmetic::sub`].
        pub struct TestSubtraction(pub u16);
        impl<F: FancyArithmetic> Circuit<F> for TestSubtraction {
            type Input = (F::Item, F::Item);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(backend.sub(&inputs.0, &inputs.1))
            }
        }
        impl<F: FancyArithmetic> CircuitInputMapper<F> for TestSubtraction {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 2);
                (inputs[0].clone(), inputs[1].clone())
            }

            fn ninputs(&self) -> usize {
                2
            }

            fn modulus(&self, _: usize) -> u16 {
                self.0
            }
        }

        /// Circuit for testing [`FancyArithmetic::mul`].
        pub struct TestMulGate(pub u16);
        impl<F: FancyArithmetic> Circuit<F> for TestMulGate {
            type Input = (F::Item, F::Item);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.mul(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: FancyArithmetic> CircuitInputMapper<F> for TestMulGate {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 2);
                (inputs[0].clone(), inputs[1].clone())
            }

            fn ninputs(&self) -> usize {
                2
            }

            fn modulus(&self, _: usize) -> u16 {
                self.0
            }
        }

        /// Circuit for testing [`FancyArithmetic::mul`] using two different moduli
        /// for the inputs.
        pub struct TestMulGateUnequalMods(pub [u16; 2]);
        impl<F: FancyArithmetic> Circuit<F> for TestMulGateUnequalMods {
            type Input = (F::Item, F::Item);
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.mul(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: FancyArithmetic> CircuitInputMapper<F> for TestMulGateUnequalMods {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 2);
                (inputs[0].clone(), inputs[1].clone())
            }

            fn ninputs(&self) -> usize {
                2
            }

            fn modulus(&self, i: usize) -> u16 {
                self.0[i]
            }
        }

        /// Circuit for testing [`FancyArithmetic::cmul`].
        pub struct TestCmul(pub u16, pub u16);
        impl<F: FancyArithmetic> Circuit<F> for TestCmul {
            type Input = F::Item;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                _: &mut Channel,
            ) -> Result<Self::Output> {
                Ok(backend.cmul(input, self.1))
            }
        }
        impl<F: FancyArithmetic> CircuitInputMapper<F> for TestCmul {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 1);
                inputs[0].clone()
            }

            fn ninputs(&self) -> usize {
                1
            }

            fn modulus(&self, _: usize) -> u16 {
                self.0
            }
        }

        /// Circuit for testing constant gates.
        pub struct TestConstants(pub u16, pub u16);
        impl<F: FancyArithmetic> Circuit<F> for TestConstants {
            type Input = F::Item;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                let constant = backend.constant(self.1, self.0, channel)?;
                Ok(backend.add(input, &constant))
            }
        }
        impl<F: FancyArithmetic> CircuitInputMapper<F> for TestConstants {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 1);
                inputs[0].clone()
            }

            fn ninputs(&self) -> usize {
                1
            }

            fn modulus(&self, _: usize) -> u16 {
                self.0
            }
        }
    }

    pub mod proj {
        //! Circuits that test [`FancyProj`].

        use crate::{
            FancyArithmetic, FancyProj,
            circuit::{Circuit, CircuitInputMapper},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`FancyProj::proj`].
        pub struct TestProj(pub u16);
        impl<F: FancyProj> Circuit<F> for TestProj {
            type Input = F::Item;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                let tab = (0..self.0).map(|i| (i + 1) % self.0).collect();
                backend.proj(input, self.0, Some(tab), channel)
            }
        }
        impl<F: FancyProj> CircuitInputMapper<F> for TestProj {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 1);
                inputs[0].clone()
            }

            fn ninputs(&self) -> usize {
                1
            }

            fn modulus(&self, _: usize) -> u16 {
                self.0
            }
        }

        /// Circuit for testing [`FancyProj::proj`] using a custom truth table.
        pub struct TestProjRand(pub u16, pub Vec<u16>);
        impl<F: FancyProj> Circuit<F> for TestProjRand {
            type Input = F::Item;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.proj(input, self.0, Some(self.1.clone()), channel)
            }
        }
        impl<F: FancyProj> CircuitInputMapper<F> for TestProjRand {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 1);
                inputs[0].clone()
            }

            fn ninputs(&self) -> usize {
                1
            }

            fn modulus(&self, _: usize) -> u16 {
                self.0
            }
        }

        /// Circuit for testing [`FancyProj::mod_change`].
        pub struct TestModChange(pub u16, pub u16);
        impl<F: FancyProj> Circuit<F> for TestModChange {
            type Input = F::Item;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                let y = backend.mod_change(input, self.1, channel)?;
                backend.mod_change(&y, self.0, channel)
            }
        }
        impl<F: FancyProj> CircuitInputMapper<F> for TestModChange {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), 1);
                inputs[0].clone()
            }

            fn ninputs(&self) -> usize {
                1
            }

            fn modulus(&self, _: usize) -> u16 {
                self.0
            }
        }

        /// Circuit for testing [`FancyProj::mod_change`] followed by
        /// [`FancyArithmetic::add_many`].
        pub struct TestAddManyModChange(pub usize);
        impl<F: FancyProj + FancyArithmetic> Circuit<F> for TestAddManyModChange {
            type Input = Vec<F::Item>;
            type Output = F::Item;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                let wires = inputs
                    .iter()
                    .map(|x| backend.mod_change(x, self.0 as u16 + 1, channel))
                    .collect::<Result<Vec<_>>>()?;
                Ok(backend.add_many(&wires))
            }
        }
        impl<F: FancyProj + FancyArithmetic> CircuitInputMapper<F> for TestAddManyModChange {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0);
                inputs
            }

            fn ninputs(&self) -> usize {
                self.0
            }

            fn modulus(&self, _: usize) -> u16 {
                2
            }
        }
    }

    pub mod arithmetic_bundle_gadgets {
        //! Circuits that test [`ArithmeticBundleGadgets`].

        use crate::{
            ArithmeticBundleGadgets, Bundle,
            circuit::{Circuit, CircuitInputMapper},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`ArithmeticBundleGadgets::mask`].
        pub struct TestMask(pub Vec<u16>);
        impl<F: ArithmeticBundleGadgets> Circuit<F> for TestMask {
            type Input = (F::Item, Bundle<F::Item>);
            type Output = Bundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.mask(&inputs.0, &inputs.1, channel)
            }
        }
        impl<F: ArithmeticBundleGadgets> CircuitInputMapper<F> for TestMask {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len() + 1);
                (inputs[0].clone(), Bundle::new(inputs[1..].to_vec()))
            }

            fn ninputs(&self) -> usize {
                self.0.len() + 1
            }

            fn modulus(&self, i: usize) -> u16 {
                if i == 0 { 2 } else { self.0[i - 1] }
            }
        }
    }

    pub mod crt_proj_gadgets {
        //! Circuits for testing [`CrtProjGadgets`].

        use crate::{
            CrtBundle, CrtProjGadgets,
            circuit::{Circuit, CircuitInputMapper},
            circuits::arithmetic::{Multiplication, ReLU},
        };
        use swanky_channel::Channel;
        use swanky_error::Result;

        /// Circuit for testing [`CrtProjGadgets::crt_cexp`].
        pub struct TestCrtCexp(pub Vec<u16>, pub u16);
        impl<F: CrtProjGadgets> Circuit<F> for TestCrtCexp {
            type Input = CrtBundle<F::Item>;
            type Output = CrtBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.crt_cexp(input, self.1, channel)
            }
        }
        impl<F: CrtProjGadgets> CircuitInputMapper<F> for TestCrtCexp {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len());
                CrtBundle::new(inputs)
            }

            fn ninputs(&self) -> usize {
                self.0.len()
            }

            fn modulus(&self, i: usize) -> u16 {
                self.0[i]
            }
        }

        /// Circuit for testing [`CrtProjGadgets::crt_rem`].
        pub struct TestCrtRemainder(pub Vec<u16>, pub u16);
        impl<F: CrtProjGadgets> Circuit<F> for TestCrtRemainder {
            type Input = CrtBundle<F::Item>;
            type Output = CrtBundle<F::Item>;

            fn execute(
                &self,
                backend: &mut F,
                input: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                backend.crt_rem(input, self.1, channel)
            }
        }
        impl<F: CrtProjGadgets> CircuitInputMapper<F> for TestCrtRemainder {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len());
                CrtBundle::new(inputs)
            }

            fn ninputs(&self) -> usize {
                self.0.len()
            }

            fn modulus(&self, i: usize) -> u16 {
                self.0[i]
            }
        }

        /// Circuit for testing multiple CRT operations.
        pub struct TestComplexGadget(pub Vec<u16>, pub usize);
        impl<F: CrtProjGadgets> Circuit<F> for TestComplexGadget {
            type Input = Vec<CrtBundle<F::Item>>;
            type Output = Vec<CrtBundle<F::Item>>;

            fn execute(
                &self,
                backend: &mut F,
                inputs: &Self::Input,
                channel: &mut Channel,
            ) -> Result<Self::Output> {
                let mut outputs = Vec::with_capacity(inputs.len());
                for x in inputs.iter() {
                    let c = backend.crt_constant_bundle(1, x.composite_modulus(), channel)?;
                    let y = Multiplication.execute(backend, &(x.clone(), c), channel)?;
                    let z = ReLU.execute(backend, &(y, "100%".to_string(), None), channel)?;
                    outputs.push(z);
                }
                Ok(outputs)
            }
        }
        impl<F: CrtProjGadgets> CircuitInputMapper<F> for TestComplexGadget {
            fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
                assert_eq!(inputs.len(), self.0.len() * self.1);
                inputs
                    .chunks_exact(self.0.len())
                    .map(|x| CrtBundle::new(x.to_vec()))
                    .collect()
            }

            fn ninputs(&self) -> usize {
                self.0.len() * self.1
            }

            fn modulus(&self, i: usize) -> u16 {
                self.0[i % self.0.len()]
            }
        }
    }
}

#[cfg(test)]
mod fancy_arithmetic {
    use crate::{
        circuit::circuits,
        dummy::{Dummy, DummyVal},
        util::RngExt,
    };
    use rand::thread_rng;

    #[test]
    fn constants() {
        let mut rng = thread_rng();
        let q = rng.gen_modulus();
        let c = rng.gen_u16() % q;
        let circ = circuits::arithmetic::TestConstants(q, c);

        for _ in 0..64 {
            let x = DummyVal::rand(q, &mut rng);
            let output = Dummy::eval(&circ, &x).unwrap();
            assert_eq!(output.val(), (x.val() + c) % q);
        }
    }

    #[test]
    fn arithmetic_half_gate() {
        let mut rng = thread_rng();
        let q = rng.gen_prime();
        let c = circuits::arithmetic::TestMulGate(q);

        for _ in 0..16 {
            let x = DummyVal::rand(q, &mut rng);
            let y = DummyVal::rand(q, &mut rng);
            let output = Dummy::eval(&c, &(x, y)).unwrap();
            assert_eq!(output.val(), (x.val() * y.val()) % q);
        }
    }
}

#[cfg(test)]
mod fancy_proj {
    use crate::{
        circuit::{CircuitInputMapper, circuits},
        dummy::{Dummy, DummyVal},
        util::RngExt,
    };
    use rand::thread_rng;

    #[test]
    fn mod_change() {
        let mut rng = thread_rng();
        let p = rng.gen_prime();
        let q = rng.gen_prime();
        let c = circuits::proj::TestModChange(p, q);

        for _ in 0..16 {
            let x = DummyVal::rand(p, &mut rng);
            let output = Dummy::eval(&c, &x).unwrap();
            assert_eq!(output.val(), x.val() % q);
        }
    }

    #[test]
    fn add_many_mod_change() {
        let mut rng = thread_rng();
        let n = 113;
        let c = circuits::proj::TestAddManyModChange(n);

        for _ in 0..64 {
            let inputs = (0
                ..<circuits::proj::TestAddManyModChange as CircuitInputMapper<Dummy>>::ninputs(&c))
                .map(|i| {
                    DummyVal::rand(
                        <circuits::proj::TestAddManyModChange as CircuitInputMapper<Dummy>>::modulus(
                            &c, i,
                        ),
                        &mut rng,
                    )
                })
                .collect::<Vec<_>>();
            let expected: u16 = inputs.iter().map(|x| x.val()).sum();
            let output = Dummy::eval(&c, &inputs).unwrap();
            assert_eq!(output.val(), expected);
        }
    }
}

#[cfg(test)]
mod arithmetic_bundle_gadgets {
    use rand::thread_rng;

    use crate::{
        circuit::circuits,
        dummy::{Dummy, DummyVal},
        util::{RngExt, factor},
    };

    #[test]
    fn test_mask() {
        let mut rng = thread_rng();
        let q = rng.gen_usable_composite_modulus();
        let c = circuits::arithmetic_bundle_gadgets::TestMask(factor(q));

        for _ in 0..16 {
            let b = rng.gen_bool();
            let x = rng.gen_u128() % q;

            let b_input = DummyVal::new(b as u16, 2);
            let x_input = DummyVal::to_crt(x, q);
            let z = Dummy::eval(&c, &(b_input, x_input.extract())).unwrap();
            let output = DummyVal::from_crt(&z, q);
            if b {
                assert_eq!(output, x);
            } else {
                assert_eq!(output, 0);
            }
        }
    }
}

#[cfg(test)]
mod crt_proj_gadgets {
    use crate::{
        circuit::circuits,
        dummy::{Dummy, DummyVal},
        util::{RngExt, factor, modulus_with_width},
    };
    use rand::thread_rng;

    #[test]
    fn test_cexp() {
        let mut rng = thread_rng();
        let q = modulus_with_width(10);
        let y = rng.gen_u16() % 10;
        let c = circuits::crt_proj_gadgets::TestCrtCexp(factor(q), y);

        for _ in 0..64 {
            let x = rng.gen_u16() as u128 % q;
            let x_input = DummyVal::to_crt(x, q);
            let z = Dummy::eval(&c, &x_input).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, x.pow(y as u32) % q);
        }
    }

    #[test]
    fn test_remainder() {
        let mut rng = thread_rng();
        let ps = rng.gen_usable_factors();
        let q = ps.iter().fold(1, |acc, &x| (x as u128) * acc);
        let p = ps[rng.gen_u16() as usize % ps.len()];
        let c = circuits::crt_proj_gadgets::TestCrtRemainder(ps, p);

        for _ in 0..64 {
            let x = rng.gen_u128() % q;
            let x_input = DummyVal::to_crt(x, q);
            let z = Dummy::eval(&c, &x_input).unwrap();
            let output = DummyVal::from_crt(&z, q);
            assert_eq!(output, x % p as u128);
        }
    }
}
