use swanky_field_binary::F8b;
use swanky_serialization::CanonicalSerialize;

pub(crate) fn u8_to_f8b(x: u8) -> F8b {
    // Safe to unwrap here
    F8b::from_bytes(&[x].into()).unwrap()
}
