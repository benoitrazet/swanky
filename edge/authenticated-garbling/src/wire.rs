//! Authenticated Wires

use fancy_garbling::{HasModulus, WireMod2};
use swanky_authenticated_bits::{
    and_triples::{AndTriple, AndTripleGenerator},
    authshares::{AuthShare, AuthShareGenerator},
};
use swanky_channel::Channel;
use swanky_party::GenericParty;
use vectoreyes::U8x16;

/// The [`AuthenticatedWireMod2`] structure extends a [`WireMod2`] to include the wire's
/// authenticated [`AndTriple`], authenticated [`AuthShare`], and the wire's current index.
#[derive(Clone)]
pub struct AuthenticatedWireMod2<P: GenericParty> {
    /// The wire label.
    pub wire_label: WireMod2,
    /// The authenticated share associated with the wire.
    pub auth_share: AuthShare<P>,
    /// The wire's index.
    pub index: usize,
}

impl<P: GenericParty> AuthenticatedWireMod2<P> {
    /// The [`AuthenticatedWireMod2`]'s constructor takes a  [`WireMod2`], an
    /// authenticated share [`AuthShare`].
    pub fn new(auth_share: AuthShare<P>, wire_label: WireMod2) -> Self {
        AuthenticatedWireMod2 {
            wire_label,
            auth_share,
            index: 0,
        }
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
        self.auth_share
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