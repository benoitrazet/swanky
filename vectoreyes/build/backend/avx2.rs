use std::collections::{BTreeSet, HashMap};
use std::fmt::Write;
use std::io::Cursor;

use proc_macro2::TokenStream;
use quote::{ToTokens, TokenStreamExt, format_ident, quote};

use super::AesSize;
use super::types::VectorType;

use super::{Docs, PairwiseOperator};
use super::{VectorBackend, cfg::Cfg};

/// An intel intrinsic.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Intrinsic {
    name: String,
    /// does the intrinsic correspond to an instruction sequence?
    sequence: bool,
    /// what cpu features are required for this intrinsic?
    cpuid: Vec<String>,
    /// what instructions does/might this intrinsic correspond to?
    instructions: Vec<String>,
}

const REQUIRED_FEATURES: &[&str] = &[
    "avx",
    "avx2",
    "sse4.1",
    "aes",
    "sse4.2",
    "ssse3",
    "pclmulqdq",
];

struct Builder<'a> {
    avx2: &'a Avx2,
    // We want a deterministic order.
    intrinsics_used: BTreeSet<&'a Intrinsic>,
}
impl Builder<'_> {
    /// Document the intrinsics used in this builder.
    fn docs(&self) -> Docs {
        if self.intrinsics_used.is_empty() {
            return String::new();
        }
        let mut out = "# AVX2 Intrinsics Used\n\n".to_string();
        for intrinsic in self.intrinsics_used.iter() {
            const BASE_URL: &str =
                "https://software.intel.com/sites/landingpage/IntrinsicsGuide/#text=";
            writeln!(
                &mut out,
                "* [`{}`]({BASE_URL}{})",
                intrinsic.name, intrinsic.name
            )
            .unwrap();
            if intrinsic.sequence {
                writeln!(&mut out, "    - Instruction sequence").unwrap();
            }
            for insn in intrinsic.instructions.iter() {
                writeln!(&mut out, "    - `{insn}`").unwrap();
            }
        }
        out
    }
    /// Return the identifier of the intel intrinsic of the given `name`.
    ///
    /// This function also records that the intrinsic was used.
    fn intrinsic(&mut self, name: &str) -> TokenStream {
        let intrinsic = self
            .avx2
            .intrinsics
            .get(name)
            .unwrap_or_else(|| panic!("unknown intrinsic {name:?}"));
        for feature in intrinsic.cpuid.iter() {
            if feature == "SSE2" {
                // SSE2 is inherent to x86_64, and rust won't let us require it, so we'll manually
                // allow it here.
                continue;
            }
            if !REQUIRED_FEATURES.contains(&feature.to_lowercase().as_str()) {
                panic!(
                    "intrinsic {name:?} requires cpu feature {feature:?} which the avx2 backend doesn't require"
                );
            }
        }
        self.intrinsics_used.insert(intrinsic);
        let name = format_ident!("{name}");
        quote! { std::arch::x86_64::#name }
    }
}

pub fn aes_key_schedule_type(size: super::AesSize, encrypt_only: bool) -> TokenStream {
    let num_rounds = size.num_rounds();
    let name = format_ident!(
        "Aes{}KeySchedule",
        if encrypt_only { "EncryptOnly" } else { "" }
    );
    quote! { crate::utils::#name<#num_rounds> }
}

/// (Return the code for performing) AES key expansion in terms of the AVX2 intrinsics.
///
/// The code yields a value of type `aes_key_schedule_type()`
pub fn key_schedule(
    size: AesSize,
    encrypt_only: bool,
    key: &dyn ToTokens,
    mm_aeskeygenassist_si128: &dyn ToTokens,
    mm_aesimc_si128: &dyn ToTokens,
) -> TokenStream {
    // Based on
    // https://github.com/RustCrypto/block-ciphers/blob/ae1892c8600131227531504812260e3d2821d01e/aes/src/ni/aes128.rs
    // and
    // https://github.com/RustCrypto/block-ciphers/blob/ae1892c8600131227531504812260e3d2821d01e/aes/src/ni/aes256.rs
    //
    // It's licensed under:
    // Copyright (c) 2018 Artyom Pavlov
    // Permission is hereby granted, free of charge, to any
    // person obtaining a copy of this software and associated
    // documentation files (the "Software"), to deal in the
    // Software without restriction, including without
    // limitation the rights to use, copy, modify, merge,
    // publish, distribute, sublicense, and/or sell copies of
    // the Software, and to permit persons to whom the Software
    // is furnished to do so, subject to the following
    // conditions:
    //
    // The above copyright notice and this permission notice
    // shall be included in all copies or substantial portions
    // of the Software.
    //
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
    // ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
    // TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
    // PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
    // SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    // CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    // OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
    // IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    // DEALINGS IN THE SOFTWARE.
    let num_rounds = size.num_rounds();
    let mut out = TokenStream::new();
    out.append_all(quote! {
        let mut encrypt_keys: [U32x4; #num_rounds] = Default::default();
    });
    match size {
        AesSize::Aes128 => {
            out.append_all(quote! {
                encrypt_keys[0] = bytemuck::cast(#key);
            });
            for (i, round) in [
                0x01_i32, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
            ]
            .into_iter()
            .enumerate()
            {
                out.append_all(quote! {{
                    let t1 = encrypt_keys[#i];
                    let t2 = #mm_aeskeygenassist_si128::<#round>(t1);
                    let t2 = t2.shuffle::<3, 3, 3, 3>();
                    let t3: U32x4 = U8x16::from(t1).shift_bytes_left::<4>().into();
                    let t1 = t1 ^ t3;
                    let t3: U32x4 = U8x16::from(t3).shift_bytes_left::<4>().into();
                    let t1 = t1 ^ t3;
                    let t3: U32x4 = U8x16::from(t3).shift_bytes_left::<4>().into();
                    let t1 = t1 ^ t3;
                    let t1 = t1 ^ t2;
                    encrypt_keys[#i + 1] = t1;
                }});
            }
        }
        AesSize::Aes256 => {
            out.append_all(quote! {
                let key: [U8x16; 2] = #key.into();
                let k1: U32x4 = key[0].into();
                let k2: U32x4 = key[1].into();
                encrypt_keys[0] = k1;
                encrypt_keys[1] = k2;
            });
            for (i, round) in [0x01_i32, 0x02, 0x04, 0x08, 0x10, 0x20]
                .into_iter()
                .enumerate()
            {
                out.append_all(quote! {{
                    let pos = #i * 2 + 2;
                    let mut t1: U32x4 = encrypt_keys[pos - 2];
                    let mut t2: U32x4;
                    let mut t3: U32x4 = encrypt_keys[pos - 1];
                    let mut t4: U32x4;
                    t2 = #mm_aeskeygenassist_si128::<#round>(t3);
                    t2 = t2.shuffle::<3, 3, 3, 3>();
                    t4 = U8x16::from(t1).shift_bytes_left::<0x4>().into();
                    t1 ^= t4;
                    t4 = U8x16::from(t4).shift_bytes_left::<0x4>().into();
                    t1 ^= t4;
                    t4 = U8x16::from(t4).shift_bytes_left::<0x4>().into();
                    t1 ^= t4;
                    t1 ^= t2;

                    encrypt_keys[pos] = t1;

                    t4 = #mm_aeskeygenassist_si128::<0x00>(t1);
                    t2 = t4.shuffle::<2, 2, 2, 2>();
                    t4 = U8x16::from(t3).shift_bytes_left::<0x4>().into();
                    t3 ^= t4;
                    t4 = U8x16::from(t4).shift_bytes_left::<0x4>().into();
                    t3 ^= t4;
                    t4 = U8x16::from(t4).shift_bytes_left::<0x4>().into();
                    t3 ^= t4;
                    t3 ^= t2;

                    encrypt_keys[pos + 1] = t3;
                }});
            }
            // last round
            out.append_all(quote! {{
                let mut t1: U32x4 = encrypt_keys[14 - 2];
                let mut t2: U32x4;
                let t3: U32x4 = encrypt_keys[14 - 1];
                let mut t4: U32x4;

                t2 = #mm_aeskeygenassist_si128::<0x40>(t3);
                t2 = t2.shuffle::<3, 3, 3, 3>();
                t4 = U8x16::from(t1).shift_bytes_left::<0x4>().into();
                t1 ^= t4;
                t4 = U8x16::from(t4).shift_bytes_left::<0x4>().into();
                t1 ^= t4;
                t4 = U8x16::from(t4).shift_bytes_left::<0x4>().into();
                t1 ^= t4;
                t1 ^= t2;

                encrypt_keys[14] = t1;
            }});
        }
    }

    if encrypt_only {
        quote! {{
            #out
            crate::utils::AesEncryptOnlyKeySchedule { encrypt_keys }
        }}
    } else {
        let mut decrypt_keys = Vec::new();
        for i in 0..size.num_rounds() {
            let round_key = quote! { encrypt_keys[#i] };
            decrypt_keys.push(if i == 0 || i == size.num_rounds() - 1 {
                round_key
            } else {
                quote! {#mm_aesimc_si128(#round_key)}
            });
        }
        decrypt_keys.reverse();
        quote! {{
            #out
            let decrypt_keys = [#(#decrypt_keys),*];
            crate::utils::AesKeySchedule { encrypt_keys, decrypt_keys }
        }}
    }
}

/// Apply the AES operation given the normal_round and last_round intrinsics.
fn apply_aes(
    blocks: &dyn ToTokens,
    key: &dyn ToTokens,
    normal_round: &dyn ToTokens,
    last_round: &dyn ToTokens,
    size: AesSize,
) -> TokenStream {
    let mut out = quote! {
        let key = #key;
        let mut blocks = #blocks;
    };
    out.append_all(quote! {
        blocks = blocks.array_map(
            #[inline(always)]
            |block| block ^ key[0].into()
        );
    });
    for round in 1..size.num_rounds() - 1 {
        out.append_all(quote! {
            blocks = blocks.array_map(
                #[inline(always)]
                |block| bytemuck::cast(unsafe {
                    #normal_round (
                        bytemuck::cast(block),
                        bytemuck::cast(key[#round]),
                    )
                })
            );
        });
    }
    let num_rounds = size.num_rounds();
    out.append_all(quote! {
        blocks.array_map(#[inline(always)] |block| {
            bytemuck::cast(unsafe {
                #last_round(
                    bytemuck::cast(block),
                    bytemuck::cast(key[#num_rounds - 1])
                )
            })
        })
    });
    out
}

struct Avx2 {
    intrinsics: HashMap<String, Intrinsic>,
}
impl Avx2 {
    /// Return the output of `body()` as well as the documentation of which intrsinics it used.
    fn build(&self, body: &mut dyn FnMut(&mut Builder) -> TokenStream) -> (TokenStream, Docs) {
        let mut builder = Builder {
            avx2: self,
            intrinsics_used: BTreeSet::new(),
        };
        let out = body(&mut builder);
        (out, builder.docs())
    }
    fn prefix(&self, ty: VectorType) -> &str {
        match ty.bits() {
            128 => "_mm",
            256 => "_mm256",
            bits => panic!("Unexpected vector size {bits}"),
        }
    }
}
impl VectorBackend for Avx2 {
    fn check_cpu(&self) -> TokenStream {
        let required_features = REQUIRED_FEATURES;
        quote! {#(
            assert!(
                std::is_x86_feature_detected!(#required_features),
                "This binary was compiled assuming {:?}, but the current CPU doesn't support that",
                #required_features,
            );
        )*}
    }
    fn scalar_docs(&self) -> Docs {
        "# AVX2\nThis function uses a scalar polyfill.\n".to_string()
    }
    fn vector_backend_variant(&self) -> &str {
        "Avx2"
    }
    fn cfg(&self) -> Cfg {
        let mut requirements = vec![Cfg::Contains {
            key: "target_arch".to_string(),
            value: "x86_64".to_string(),
        }];
        for feature in REQUIRED_FEATURES {
            requirements.push(Cfg::Contains {
                key: "target_feature".to_string(),
                value: feature.to_string(),
            });
        }
        Cfg::All(requirements)
    }
    fn vector_contents(&self, ty: VectorType) -> TokenStream {
        let bits = ty.bits();
        let name = format_ident!("__m{bits}i");
        quote! { std::arch::x86_64::#name }
    }
    fn pairwise(
        &self,
        ty: VectorType,
        op: super::PairwiseOperator,
        lhs: &dyn quote::ToTokens,
        rhs: &dyn quote::ToTokens,
    ) -> (TokenStream, Docs) {
        self.build(&mut |b| {
            let epi = format!("epi{}", ty.of().bits());
            let si = format!("si{}", ty.bits());
            let (op_name, suffix) = match op {
                PairwiseOperator::WrappingAdd => ("add", epi),
                PairwiseOperator::WrappingSub => ("sub", epi),
                PairwiseOperator::Xor => ("xor", si),
                PairwiseOperator::Or => ("or", si),
                PairwiseOperator::And => ("and", si),
            };
            let intrinsic = b.intrinsic(&format!("{}_{op_name}_{suffix}", self.prefix(ty)));
            quote! {
                unsafe {
                    #ty(#intrinsic(#lhs.0, #rhs.0))
                }
            }
        })
    }

    fn aes_key_schedule_type(&self, size: AesSize, encrypt_only: bool) -> TokenStream {
        aes_key_schedule_type(size, encrypt_only)
    }

    fn aes_key_expand(
        &self,
        size: super::AesSize,
        encrypt_only: bool,
        key: &dyn quote::ToTokens,
    ) -> (TokenStream, Docs) {
        self.build(&mut |b| {
            let mut out = TokenStream::new();
            let intrinsic_mm_aeskeygenassist_si128 = b.intrinsic("_mm_aeskeygenassist_si128");
            out.append_all(quote! {
                #[inline(always)]
                fn mm_aeskeygenassist_si128<const IMM: i32>(input: U32x4) -> U32x4 {
                    U32x4(unsafe { #intrinsic_mm_aeskeygenassist_si128(input.0, IMM) })
                }
            });
            if !encrypt_only {
                let intrinsic_mm_aesimc_si128 = b.intrinsic("_mm_aesimc_si128");
                out.append_all(quote! {
                    fn mm_aesimc_si128(input: U32x4) -> U32x4 {
                        U32x4(unsafe { #intrinsic_mm_aesimc_si128(input.0) })
                    }
                });
            }
            out.append_all(key_schedule(
                size,
                encrypt_only,
                key,
                &quote! { mm_aeskeygenassist_si128 },
                &quote! { mm_aesimc_si128 },
            ));
            out
        })
    }

    fn aes_encrypt(
        &self,
        size: super::AesSize,
        key: &dyn quote::ToTokens,
        _n: &dyn quote::ToTokens,
        blocks: &dyn quote::ToTokens,
    ) -> (TokenStream, Docs) {
        self.build(&mut |b| {
            let mm_aesenc_si128 = b.intrinsic("_mm_aesenc_si128");
            let mm_aesenclast_si128 = b.intrinsic("_mm_aesenclast_si128");
            apply_aes(
                blocks,
                &quote! { &#key.encrypt_keys },
                &mm_aesenc_si128,
                &mm_aesenclast_si128,
                size,
            )
        })
    }

    fn aes_decrypt(
        &self,
        size: super::AesSize,
        key: &dyn quote::ToTokens,
        _n: &dyn quote::ToTokens,
        blocks: &dyn quote::ToTokens,
    ) -> (TokenStream, Docs) {
        self.build(&mut |b| {
            let mm_aesdec_si128 = b.intrinsic("_mm_aesdec_si128");
            let mm_aesdeclast_si128 = b.intrinsic("_mm_aesdeclast_si128");
            apply_aes(
                blocks,
                &quote! { &#key.decrypt_keys },
                &mm_aesdec_si128,
                &mm_aesdeclast_si128,
                size,
            )
        })
    }
}

mod xml {
    use serde::{Deserialize, Deserializer};
    #[derive(Deserialize, Debug)]
    pub struct Root {
        pub intrinsic: Vec<Intrinsic>,
    }
    #[derive(Deserialize, Debug)]
    pub struct Intrinsic {
        #[serde(rename = "@name")]
        pub name: String,
        #[serde(
            rename = "@sequence",
            default,
            deserialize_with = "deserialize_bool_permissive"
        )]
        pub sequence: Option<bool>,
        #[serde(rename = "CPUID")]
        pub cpuid: Option<Vec<String>>,
        pub instruction: Option<Vec<Instruction>>,
    }
    #[derive(Deserialize, Debug)]
    pub struct Instruction {
        #[serde(rename = "@name")]
        pub name: String,
        #[serde(rename = "@form")]
        pub form: Option<String>,
    }

    // quick-xml 0.37.0 fixed a bug in the Boolean handling, where it was too
    // permissive (per the Xml Schema). Since the Intel intrinsics XML file uses
    // these disallowed forms ("TRUE" and "FALSE"), we manually restore the
    // previous functionality, per the table at
    // https://github.com/tafia/quick-xml/releases/tag/v0.37.0
    fn deserialize_bool_permissive<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            None => Ok(None),
            Some(s) => match s.to_lowercase().as_str() {
                "true" | "t" | "yes" | "y" | "1" => Ok(Some(true)),
                "false" | "f" | "no" | "n" | "0" => Ok(Some(false)),
                s => Err(serde::de::Error::custom(format!(
                    "Invalid Boolean string: {s}"
                ))),
            },
        }
    }
}

pub fn avx2_backend() -> Box<dyn VectorBackend> {
    let intel_intrinsics_xml = String::from_utf8(
        zstd::decode_all(Cursor::new(
            include_bytes!("avx2/intel-intrinsics.xml.zst").as_slice(),
        ))
        .unwrap(),
    )
    .unwrap();
    let intrinsics: xml::Root = quick_xml::de::from_str(&intel_intrinsics_xml).unwrap();
    let intrinsics: HashMap<String, Intrinsic> = intrinsics
        .intrinsic
        .into_iter()
        .map(|intrinsic| {
            (
                intrinsic.name.clone(),
                Intrinsic {
                    name: intrinsic.name.clone(),
                    sequence: intrinsic.sequence.unwrap_or_default(),
                    cpuid: intrinsic.cpuid.unwrap_or_default(),
                    instructions: intrinsic
                        .instruction
                        .unwrap_or_default()
                        .into_iter()
                        .map(|insn| format!("{} {}", insn.name, insn.form.unwrap_or_default()))
                        .collect(),
                },
            )
        })
        .collect();
    Box::new(Avx2 { intrinsics })
}
