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
    masked_value: Option<F2>,
    /// The wire label.
    wire_label: WireMod2,
    /// The authenticated share associated with the wire.
    auth_share: Option<AuthShare<P>>,
    /// The wire's index.
    index: usize,
}

impl<P: GenericParty> AuthenticatedWireMod2<P> {
    /// The [`AuthenticatedWireMod2`]'s constructor takes a  [`WireMod2`], an
    /// authenticated share [`AuthShare`] and an index.
    pub(crate) fn new(wire_label: WireMod2, auth_share: AuthShare<P>, index: usize) -> Self {
        AuthenticatedWireMod2 {
            masked_value: None,
            wire_label,
            auth_share: Some(auth_share),
            index,
        }
    }

    /// The [`AuthenticatedWireMod2`]'s constructor takes a wire value, [`WireMod2`], an authenticated share
    /// [`AuthShare`] and an index.
    pub(crate) fn new_with_value(
        masked_value: F2,
        wire_label: WireMod2,
        auth_share: AuthShare<P>,
        index: usize,
    ) -> Self {
        AuthenticatedWireMod2 {
            masked_value: Some(masked_value),
            wire_label,
            auth_share: Some(auth_share),
            index,
        }
    }
    /// Returns the masked value associated with the current [`AuthenticatedWireMod2`]
    ///
    /// Panics if there is no value associated with this wire
    pub(crate) fn masked_value(&self) -> F2 {
        self.masked_value.unwrap()
    }
    /// Sets the value associated with the current [`AuthenticatedWireMod2`]
    pub(crate) fn set_masked_value(&mut self, value: F2) {
        self.masked_value = Some(value);
    }
    /// Returns the wire label of type [`WireMod2`] associated with the current [`AuthenticatedWireMod2`]
    pub(crate) fn wire_label(&self) -> WireMod2 {
        self.wire_label
    }
    /// Returns the [`AuthShare`] associated with the current [`AuthenticatedWireMod2`]
    pub(crate) fn auth_share(&self) -> AuthShare<P> {
        self.auth_share.unwrap()
    }
    /// Returns the index associated with the current [`AuthenticatedWireMod2`]
    pub(crate) fn index(&self) -> usize {
        self.index
    }
}

impl<P: GenericParty> HasModulus for AuthenticatedWireMod2<P> {
    fn modulus(&self) -> u16 {
        2
    }
}
