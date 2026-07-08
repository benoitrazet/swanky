use crate::{ps::PartyEvaluator, wire::AuthenticatedWireMod2};

type AuthenticatedWire = AuthenticatedWireMod2<PartyEvaluator>;

mod offline;
pub use offline::EvaluatorOffline;
mod online;
pub use online::EvaluatorOnline;
