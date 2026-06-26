use crate::{AuthenticatedWireMod2, ps::PartyGarbler};

type AuthenticatedWire = AuthenticatedWireMod2<PartyGarbler>;

mod offline;
pub use offline::GarblerOffline;
mod online;
pub use online::GarblerOnline;
