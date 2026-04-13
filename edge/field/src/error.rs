//! Errors that may occur during ring / field operations or
//! serialization.

/// The error which occurs if the inputted value or bit pattern doesn't correspond to
/// an element.
#[derive(Debug, Clone, Copy)]
pub struct BiggerThanModulus;
impl std::error::Error for BiggerThanModulus {}
impl std::fmt::Display for BiggerThanModulus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
