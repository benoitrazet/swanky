//! Wirelabel representation for authenticated garbling.

use fancy_garbling::{HasModulus, WireMod2};
use swanky_authenticated_bits::authshares::AuthShare;
use swanky_field_binary::F2;
use swanky_party::GenericParty;

/// Wirelabel representation for authenticated garbling.
///
/// An authenticated garbling wirelabel is a wirelabel $`L`$ alongside (1) an
/// [`AuthShare`] $`\lambda`$ of $`L`$s color bit, and (2) an optional value
/// representing the masked value $`w \oplus \lambda`$, where $`w`$ is the
/// actual bit represented by the wirelabel.
#[derive(Clone)]
pub struct AuthenticatedWireMod2<P: GenericParty> {
    /// Masked value $`w \oplus \lambda`$.
    masked_value: Option<F2>,
    /// The wirelabel $`L`$.
    wire_label: WireMod2,
    /// Sharing of the color bit $`\lambda`$.
    auth_share: AuthShare<P>,
}

impl<P: GenericParty> AuthenticatedWireMod2<P> {
    /// Create a new `AuthenticatedWireMod2` given an underlying wirelabel
    /// $`L`$, its associated color bit share $`\langle \lambda \rangle`$, and
    /// the index of this wire in the circuit.
    pub(crate) fn new(wire_label: WireMod2, auth_share: AuthShare<P>) -> Self {
        AuthenticatedWireMod2 {
            masked_value: None,
            wire_label,
            auth_share,
        }
    }

    /// Create a new `AuthenticatedWireMod2` as in
    /// [`AuthenticatedWireMod2::new`], but additionally provide the masked
    /// value $`w \oplus \lambda`$.
    pub(crate) fn new_with_value(
        masked_value: F2,
        wire_label: WireMod2,
        auth_share: AuthShare<P>,
    ) -> Self {
        AuthenticatedWireMod2 {
            masked_value: Some(masked_value),
            wire_label,
            auth_share,
        }
    }

    /// The masked value associated with this wire.
    ///
    /// # Panics
    /// This panics if there is no masked value associated with the wire.
    pub(crate) fn masked_value(&self) -> F2 {
        self.masked_value.unwrap()
    }

    /// Sets the masked value of this wire.
    pub(crate) fn set_masked_value(&mut self, value: F2) {
        self.masked_value = Some(value);
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
