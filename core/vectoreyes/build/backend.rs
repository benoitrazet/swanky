use cfg::Cfg;
use proc_macro2::TokenStream;

use quote::{ToTokens, format_ident, quote};
use types::VectorType;

mod avx2;
mod cfg;
mod code_block;
mod generate;
mod neon;
mod types;
mod utils;
pub use generate::*;
use utils::index_literals;

/// Markdown formatted documentation which will be added to the documentation of wrapper functions.
///
/// For example, the AVX2 pairwise addition function for U32x4 might note that it uses the `PADD`
/// instruction.
type Docs = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairwiseOperator {
    WrappingAdd,
    WrappingSub,
    Xor,
    Or,
    And,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesSize {
    Aes128,
    Aes256,
}
impl std::fmt::Display for AesSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.bits())
    }
}
impl AesSize {
    pub fn all() -> impl Iterator<Item = Self> {
        [Self::Aes128, Self::Aes256].into_iter()
    }
    pub fn bits(&self) -> usize {
        match self {
            AesSize::Aes128 => 128,
            AesSize::Aes256 => 256,
        }
    }
    pub fn num_rounds(&self) -> usize {
        match self {
            AesSize::Aes128 => 11,
            AesSize::Aes256 => 15,
        }
    }
}

/// A vector backend for vectoreyes
///
/// The default implementations of methods in this trait implement the scalar backend. As a result,
/// backends can incrementally implement the features they support, while falling back to the
/// scalar implementation by default.
pub trait VectorBackend {
    /// What [`Cfg`] string is required to be true for this backend to be usable.
    fn cfg(&self) -> Cfg;

    /// Which `vectoreyes::VectorBackend` enum variant does this backend map to?
    fn vector_backend_variant(&self) -> &str;

    /// Emit code for a runtime check to panic if the current CPU doesn't have the features we
    /// assumed at compile-time.
    fn check_cpu(&self) -> TokenStream;

    /// What's the internal type/representation for vector `ty`?
    fn vector_contents(&self, ty: VectorType) -> TokenStream {
        ty.array()
    }

    /// What documentation should be generated for scalar implementations in this backend?
    ///
    /// As an example, the AVX2 implementation might have this function return "The AVX2 backend
    /// currently uses a slow scalar implementation for this function."
    fn scalar_docs(&self) -> Docs;

    fn pairwise(
        &self,
        ty: VectorType,
        op: PairwiseOperator,
        lhs: &dyn ToTokens,
        rhs: &dyn ToTokens,
    ) -> (TokenStream, Docs) {
        let idx = index_literals(ty.count());
        let fn_body = |fn_name: TokenStream| {
            quote! {
                #ty::from([#(
                    #lhs.as_array()[#idx].#fn_name(#rhs.as_array()[#idx]),
                )*])
            }
        };
        let op_body = |op: TokenStream| {
            quote! {
                #ty::from([#(
                    #lhs.as_array()[#idx] #op #rhs.as_array()[#idx],
                )*])
            }
        };
        (
            match op {
                PairwiseOperator::WrappingAdd => fn_body(quote! {wrapping_add}),
                PairwiseOperator::WrappingSub => fn_body(quote! {wrapping_sub}),
                PairwiseOperator::Xor => op_body(quote! { ^ }),
                PairwiseOperator::Or => op_body(quote! { | }),
                PairwiseOperator::And => op_body(quote! { & }),
            },
            self.scalar_docs(),
        )
    }

    /// What's type of a scheduled AES key?
    fn aes_key_schedule_type(&self, size: AesSize, encrypt_only: bool) -> TokenStream {
        let _ = encrypt_only;
        let aes_name = format_ident!("Aes{}", size.bits(),);
        quote! { aes::#aes_name }
    }

    /// Return an AES key schedule of type `self.aes_key_schedule_type()` from `key`.
    ///
    /// `key` is either `U8x32` or `U8x16`, depending on `size`.
    fn aes_key_expand(
        &self,
        size: AesSize,
        encrypt_only: bool,
        key: &dyn ToTokens,
    ) -> (TokenStream, Docs) {
        let _ = encrypt_only;
        let name = format_ident!("Aes{size}");
        (
            quote! {
                <aes::#name as aes::cipher::KeyInit>::new_from_slice(#key.as_ref())
                    .expect("AES size is statically correct")
            },
            self.scalar_docs(),
        )
    }

    /// Return AES encrypted `blocks` under `key`.
    ///
    /// `blocks` is of type `[U8x16; N]` and `key` is of type `self.aes_key_schedule_type()`
    fn aes_encrypt(
        &self,
        size: AesSize,
        key: &dyn ToTokens,
        n: &dyn ToTokens,
        blocks: &dyn ToTokens,
    ) -> (TokenStream, Docs) {
        let _ = n;
        let _ = size;
        (
            quote! {
                let mut out = #blocks;
                for block in out.iter_mut() {
                    let block =
                        aes::cipher::Array::from_mut_slice(block.as_mut());
                    aes::cipher::BlockModeEncrypt::encrypt_block(#key, block);
                }
                out
            },
            self.scalar_docs(),
        )
    }

    /// Return AES decrypted `blocks` under `key`.
    ///
    /// `blocks` is of type `[U8x16; N]` and `key` is of type `self.aes_contents()`
    fn aes_decrypt(
        &self,
        size: AesSize,
        key: &dyn ToTokens,
        n: &dyn ToTokens,
        blocks: &dyn ToTokens,
    ) -> (TokenStream, Docs) {
        let _ = n;
        let _ = size;
        (
            quote! {
                let mut out = #blocks;
                for block in out.iter_mut() {
                    let block =
                        aes::cipher::Array::from_mut_slice(block.as_mut());
                    aes::cipher::BlockModeDecrypt::decrypt_block(#key, block);
                }
                out
            },
            self.scalar_docs(),
        )
    }
}

/// The scalar (non-vector) backend for vectoreyes.
pub struct Scalar;
impl VectorBackend for Scalar {
    fn cfg(&self) -> Cfg {
        // The scalar backend unconditionally works.
        Cfg::true_()
    }
    fn scalar_docs(&self) -> Docs {
        String::new()
    }
    fn vector_backend_variant(&self) -> &str {
        "Scalar"
    }
    fn check_cpu(&self) -> TokenStream {
        quote! {}
    }
}
