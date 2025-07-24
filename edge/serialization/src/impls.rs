use super::{
    ByteElementDeserializer, ByteElementSerializer, BytesDeserializationCannotFail,
    CanonicalSerialize,
};
use generic_array::GenericArray;
use generic_array::typenum::{self, U};

macro_rules! pod_impl {
    ($($ty:ty),*$(,)?) => {$(
        impl CanonicalSerialize for $ty {
            type Serializer = ByteElementSerializer<Self>;
            type Deserializer = ByteElementDeserializer<Self>;
            type ByteReprLen = U<{ std::mem::size_of::<$ty>() }>;
            type FromBytesError = BytesDeserializationCannotFail;
            fn from_bytes(
                bytes: &GenericArray<u8, Self::ByteReprLen>,
            ) -> Result<Self, Self::FromBytesError> {
                let arr: [u8; std::mem::size_of::<$ty>()] = bytes.into_array();
                Ok(bytemuck::cast(arr))
            }
            fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
                let arr: [u8; std::mem::size_of::<$ty>()] = bytemuck::cast(*self);
                GenericArray::from_array(arr)
            }
        }
    )*};
}
pod_impl!(
    i8,
    u8,
    i16,
    u16,
    i32,
    u32,
    i64,
    u64,
    i128,
    u128,
    vectoreyes::I8x16,
    vectoreyes::I8x32,
    vectoreyes::I16x8,
    vectoreyes::I16x16,
    vectoreyes::I32x4,
    vectoreyes::I32x8,
    vectoreyes::I64x2,
    vectoreyes::I64x4,
    vectoreyes::U8x16,
    vectoreyes::U8x32,
    vectoreyes::U16x8,
    vectoreyes::U16x16,
    vectoreyes::U32x4,
    vectoreyes::U32x8,
    vectoreyes::U64x2,
    vectoreyes::U64x4,
);

/// An integer could fit in a u64, but not in a usize
#[derive(Debug, Clone, Copy)]
pub struct ValueTooBigForUsize;
impl std::fmt::Display for ValueTooBigForUsize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "An integer could fit in a u64, but not in a usize")
    }
}
impl std::error::Error for ValueTooBigForUsize {}
impl CanonicalSerialize for usize {
    type Serializer = ByteElementSerializer<Self>;
    type Deserializer = ByteElementDeserializer<Self>;
    type ByteReprLen = <u64 as CanonicalSerialize>::ByteReprLen;
    type FromBytesError = ValueTooBigForUsize;
    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        match u64::from_bytes(bytes) {
            Ok(x) => Self::try_from(x).map_err(|_| ValueTooBigForUsize),
            Err(e) => {
                let _: BytesDeserializationCannotFail = e;
                unreachable!("Byte deserialization cannot fail")
            }
        }
    }
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        ((*self) as u64).to_bytes()
    }
}

/// An integer could fit in a i64, but not in a isize
#[derive(Debug, Clone, Copy)]
pub struct ValueTooBigForIsize;
impl std::fmt::Display for ValueTooBigForIsize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "An integer could fit in a i64, but not in a isize")
    }
}
impl std::error::Error for ValueTooBigForIsize {}
impl CanonicalSerialize for isize {
    type Serializer = ByteElementSerializer<Self>;
    type Deserializer = ByteElementDeserializer<Self>;
    type ByteReprLen = <i64 as CanonicalSerialize>::ByteReprLen;
    type FromBytesError = ValueTooBigForIsize;
    fn from_bytes(
        bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        match i64::from_bytes(bytes) {
            Ok(x) => Self::try_from(x).map_err(|_| ValueTooBigForIsize),
            Err(e) => {
                let _: BytesDeserializationCannotFail = e;
                unreachable!("Byte deserialization cannot fail")
            }
        }
    }
    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        ((*self) as i64).to_bytes()
    }
}

impl CanonicalSerialize for () {
    type Serializer = ByteElementSerializer<Self>;
    type Deserializer = ByteElementDeserializer<Self>;
    type ByteReprLen = typenum::U0;
    type FromBytesError = BytesDeserializationCannotFail;

    fn from_bytes(
        _bytes: &GenericArray<u8, Self::ByteReprLen>,
    ) -> Result<Self, Self::FromBytesError> {
        Ok(())
    }

    fn to_bytes(&self) -> GenericArray<u8, Self::ByteReprLen> {
        Default::default()
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;
    fn roundtrip<T: CanonicalSerialize>(t: T) -> T {
        T::from_bytes(&t.to_bytes()).unwrap()
    }
    macro_rules! test_serialize {
        ($(fn $name:ident => $strategy:expr),*$(,)?) => {$(
            proptest! {
                #[test]
                fn $name(x in $strategy) {
                    prop_assert_eq!(x, roundtrip(x));
                }
            }
        )*};
    }
    test_serialize! {
        fn roundtrip_i8 => any::<i8>(),
        fn roundtrip_u8 => any::<u8>(),
        fn roundtrip_i16 => any::<i16>(),
        fn roundtrip_u16 => any::<u16>(),
        fn roundtrip_i32 => any::<i32>(),
        fn roundtrip_u32 => any::<u32>(),
        fn roundtrip_i64 => any::<i64>(),
        fn roundtrip_u64 => any::<u64>(),
        fn roundtrip_i128 => any::<i128>(),
        fn roundtrip_u128 => any::<u128>(),
        fn roundtrip_usize => any::<usize>(),
        fn roundtrip_isize => any::<isize>(),
        fn roundtrip_unit => any::<()>(),
        fn roundtrip_vectoreyes_i8x16 => any::<[i8; 16]>().prop_map(vectoreyes::I8x16::from),
        fn roundtrip_vectoreyes_i8x32 => any::<[i8; 32]>().prop_map(vectoreyes::I8x32::from),
        fn roundtrip_vectoreyes_i16x8 => any::<[i16; 8]>().prop_map(vectoreyes::I16x8::from),
        fn roundtrip_vectoreyes_i16x16 => any::<[i16; 16]>().prop_map(vectoreyes::I16x16::from),
        fn roundtrip_vectoreyes_i32x4 => any::<[i32; 4]>().prop_map(vectoreyes::I32x4::from),
        fn roundtrip_vectoreyes_i32x8 => any::<[i32; 8]>().prop_map(vectoreyes::I32x8::from),
        fn roundtrip_vectoreyes_i64x2 => any::<[i64; 2]>().prop_map(vectoreyes::I64x2::from),
        fn roundtrip_vectoreyes_i64x4 => any::<[i64; 4]>().prop_map(vectoreyes::I64x4::from),
        fn roundtrip_vectoreyes_u8x16 => any::<[u8; 16]>().prop_map(vectoreyes::U8x16::from),
        fn roundtrip_vectoreyes_u8x32 => any::<[u8; 32]>().prop_map(vectoreyes::U8x32::from),
        fn roundtrip_vectoreyes_u16x8 => any::<[u16; 8]>().prop_map(vectoreyes::U16x8::from),
        fn roundtrip_vectoreyes_u16x16 => any::<[u16; 16]>().prop_map(vectoreyes::U16x16::from),
        fn roundtrip_vectoreyes_u32x4 => any::<[u32; 4]>().prop_map(vectoreyes::U32x4::from),
        fn roundtrip_vectoreyes_u32x8 => any::<[u32; 8]>().prop_map(vectoreyes::U32x8::from),
        fn roundtrip_vectoreyes_u64x2 => any::<[u64; 2]>().prop_map(vectoreyes::U64x2::from),
        fn roundtrip_vectoreyes_u64x4 => any::<[u64; 4]>().prop_map(vectoreyes::U64x4::from),
    }
}
