//! Wirelabel representation for authenticated garbling.

use fancy_garbling::WireMod2;
use fancy_traits::HasModulus;
use swanky_authenticated_bits::authshares::AuthShare;
use swanky_field_binary::F2;
use swanky_party::GenericParty;

use crate::PartyGarbler;

#[derive(Clone, Copy)]
pub struct OfflineWire {
    wirelabel: WireMod2,
    auth_share: AuthShare<PartyGarbler>,
}

impl OfflineWire {
    pub(crate) fn new(wirelabel: WireMod2, auth_share: AuthShare<PartyGarbler>) -> Self {
        Self {
            wirelabel,
            auth_share,
        }
    }

    pub(crate) fn wirelabel(&self) -> WireMod2 {
        self.wirelabel
    }

    pub(crate) fn auth_share(&self) -> AuthShare<PartyGarbler> {
        self.auth_share
    }
}

impl HasModulus for OfflineWire {
    fn modulus(&self) -> u16 {
        2
    }
}

impl core::fmt::Debug for OfflineWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wire")
            .field("wirelabel", &self.wirelabel)
            .field("auth_share", &())
            .finish()
    }
}

#[derive(Clone, Copy)]
pub struct ValidatorWire<P: GenericParty> {
    masked_value: F2,
    auth_share: AuthShare<P>,
}

impl<P: GenericParty> ValidatorWire<P> {
    pub(crate) fn new(masked_value: F2, auth_share: AuthShare<P>) -> Self {
        Self {
            masked_value,
            auth_share,
        }
    }

    pub(crate) fn masked_value(&self) -> F2 {
        self.masked_value
    }

    pub(crate) fn auth_share(&self) -> AuthShare<P> {
        self.auth_share
    }
}

impl<P: GenericParty> HasModulus for ValidatorWire<P> {
    fn modulus(&self) -> u16 {
        2
    }
}

impl<P: GenericParty> core::fmt::Debug for ValidatorWire<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatorWire")
            .field("masked_value", &self.masked_value)
            .field("auth_share", &())
            .finish()
    }
}

/// Wirelabel representation for authenticated garbling.
///
/// An authenticated garbling wirelabel is a wirelabel $`L`$ alongside (1) an
/// [`AuthShare`] $`\lambda`$ of $`L`$s color bit, and (2) an optional value
/// representing the masked value $`w \oplus \lambda`$, where $`w`$ is the
/// actual bit represented by the wirelabel.
#[derive(Clone, Copy)]
pub struct AuthenticatedWireMod2<P: GenericParty> {
    /// A masked value $`w \oplus \lambda`$.
    masked_value: F2,
    /// An optional  wirelabel $`L`$.
    wire_label: WireMod2,
    /// Sharing of the color bit $`\lambda`$.
    auth_share: AuthShare<P>,
}

impl<P: GenericParty> AuthenticatedWireMod2<P> {
    /// Create a new `AuthenticatedWireMod2` given a masked value, the underlying wirelabel
    /// $`L`$, and its associated color bit share $`\langle \lambda \rangle`$.
    pub(crate) fn new(masked_value: F2, wire_label: WireMod2, auth_share: AuthShare<P>) -> Self {
        AuthenticatedWireMod2 {
            masked_value,
            wire_label,
            auth_share,
        }
    }

    /// The masked value associated with this wire.
    pub(crate) fn masked_value(&self) -> F2 {
        self.masked_value
    }

    /// The wirelabel $`L`$ associated with this wire.
    pub(crate) fn wire_label(&self) -> WireMod2 {
        self.wire_label
    }

    /// The authenticated share $`\langle \lambda \rangle`$ associated with this
    /// wire.
    pub(crate) fn auth_share(&self) -> AuthShare<P> {
        self.auth_share
    }
}

impl<P: GenericParty> HasModulus for AuthenticatedWireMod2<P> {
    fn modulus(&self) -> u16 {
        2
    }
}

impl<P: GenericParty> core::fmt::Debug for AuthenticatedWireMod2<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedWireMod2")
            .field("masked_value", &self.masked_value)
            .field("wire_label", &self.wire_label)
            .field("auth_share", &())
            .finish()
    }
}
