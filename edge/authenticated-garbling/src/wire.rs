//! Authenticated Wires

use fancy_garbling::{HasModulus, WireMod2};
use swanky_authenticated_bits::authshares::AuthShare;
use swanky_field_binary::F2;
use swanky_party::GenericParty;

/// The [`AuthenticatedWireMod2`] structure extends a [`WireMod2`] to include the wire's
/// authenticated [`AndTriple`], authenticated [`AuthShare`], and the wire's current index.
#[derive(Clone)]
pub struct AuthenticatedWireMod2<P: GenericParty> {
    /// value
    pub value: Option<F2>,
    /// The party's share of the validation bit c_γ
    pub validation_share: Option<F2>,
    /// The wire label.
    pub wire_label: WireMod2,
    /// The authenticated share associated with the wire.
    pub auth_share: Option<AuthShare<P>>,
    /// The wire's index.
    pub index: usize,
}

impl<P: GenericParty> AuthenticatedWireMod2<P> {
    /// The [`AuthenticatedWireMod2`]'s constructor takes a  [`WireMod2`], an
    /// authenticated share [`AuthShare`] and an index.
    pub fn new(wire_label: WireMod2, auth_share: AuthShare<P>, index: usize) -> Self {
        AuthenticatedWireMod2 {
            value: None, 
            validation_share: None,
            wire_label,
            auth_share: Some(auth_share),
            index,
        }
    }
    /// This [`AuthenticatedWireMod2`]'s constructor takes a  [`WireMod2`] and index only.
    pub fn new_without_share(wire_label: WireMod2, index: usize) -> Self {
        AuthenticatedWireMod2 {
            value: None, 
            validation_share: None,
            wire_label,
            auth_share: None,
            index,
        }
    }
    /// The [`AuthenticatedWireMod2`]'s constructor takes a wire value, [`WireMod2`], an authenticated share 
    /// [`AuthShare`] and an index.
    pub fn new_with_value(value: F2, wire_label: WireMod2, auth_share: AuthShare<P>, index: usize) -> Self {
        AuthenticatedWireMod2 {
            value: Some(value),
            validation_share: None, 
            wire_label,
            auth_share: Some(auth_share),
            index,
        }
    }
    /// Returns the value/masked value associated with the current [`AuthenticatedWireMod2`]
    /// 
    /// Panics if there is no value associated with this wire
    pub fn value(&self) -> F2 {
        self.value.unwrap()
    }
    /// Sets the value associated with the current [`AuthenticatedWireMod2`]
    pub fn set_value(&mut self, value: F2) {
        self.value = Some(value);
    }
    /// Returns the validation share associated with the current [`AuthenticatedWireMod2`]
    pub fn validation_share(&mut self) -> F2 {
        self.validation_share.unwrap()
    }
    /// Sets the value associated with the current [`AuthenticatedWireMod2`]
    pub fn set_validation_share(&mut self, validation_share: F2) {
        self.validation_share = Some(validation_share);
    }
    /// Returns the wire label of type [`WireMod2`] associated with the current [`AuthenticatedWireMod2`]
    pub fn wire_label(&self) -> WireMod2 {
        self.wire_label
    }
    /// Sets the wire label associated with the current [`AuthenticatedWireMod2`]
    pub fn set_wire_label(&mut self, wire_label: WireMod2) {
        self.wire_label = wire_label;
    }
    /// Returns the [`AuthShare`] associated with the current [`AuthenticatedWireMod2`]
    pub fn auth_share(&self) -> AuthShare<P> {
        self.auth_share.unwrap()
    }
    /// Returns the bit associated with the current [`AuthenticatedWireMod2`]
    pub fn bit(&self) -> F2 {
        self.auth_share().bit()
    }
    /// Returns the index associated with the current [`AuthenticatedWireMod2`]
    pub fn index(&self) -> usize {
        self.index
    }
    /// Sets the index associated with the current [`AuthenticatedWireMod2`]
    pub fn set_index(&mut self, i: usize) {
        self.index = i;
    }
}
impl<P: GenericParty> HasModulus for AuthenticatedWireMod2<P> {
    fn modulus(&self) -> u16 {
        2
    }
}
