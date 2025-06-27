use proc_macro2::TokenStream;
use quote::{ToTokens, TokenStreamExt, format_ident, quote};
use std::collections::{BTreeSet, HashMap};
use std::fmt::Write;

use super::types::{IntType, VectorType};

use super::Docs;
use super::{VectorBackend, cfg::Cfg};

const REQUIRED_FEATURES: &[&str] = &["neon", "aes"];

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Intrinsic {
    /// The function call name of the intrinsic
    name: String,
    /// What `target_feature`s are required for this intrinsic to be used
    required_features: Vec<String>,
    /// Which instructions might this intrinsic generate.
    instructions: Vec<InstructionJson>,
}

struct Builder<'a> {
    neon: &'a Neon,
    intrinsics_used: BTreeSet<&'a Intrinsic>,
}
impl Builder<'_> {
    fn intrinsic(&mut self, name: &str) -> TokenStream {
        let intrinsic = self
            .neon
            .intrinsics
            .get(name)
            .unwrap_or_else(|| panic!("unknown intrinsic {name:?}"));
        for feature in intrinsic.required_features.iter() {
            if !REQUIRED_FEATURES.contains(&feature.to_lowercase().as_str()) {
                panic!(
                    "intrinsic {name:?} requires cpu feature {feature:?} which the avx2 backend doesn't require"
                );
            }
        }
        self.intrinsics_used.insert(intrinsic);
        let name = format_ident!("{name}");
        quote! { std::arch::aarch64::#name }
    }
}

/// The ARM NEON vectoreyes backend
///
/// Vectoreyes supports 256-bit vectors, but NEON only supports 128-bit vectors. So the neon
/// backend will represent a 256-bit vector as an array of two 128-bit vectors. To keep our code
/// consistent between the 128-bit and 256-bit vector types, _all_ neon vectors are arrays.
struct Neon {
    intrinsics: HashMap<String, Intrinsic>,
}
impl Neon {
    fn build(&self, body: &mut dyn FnMut(&mut Builder) -> TokenStream) -> (TokenStream, Docs) {
        let mut builder = Builder {
            neon: self,
            intrinsics_used: Default::default(),
        };
        let out = body(&mut builder);
        let mut docs = String::new();
        if !builder.intrinsics_used.is_empty() {
            docs.push_str("# Neon Intrinsics Used\n\n");
            for intrinsic in builder.intrinsics_used.iter() {
                const BASE_URL: &str =
                    "https://developer.arm.com/architectures/instruction-sets/intrinsics/";
                writeln!(
                    &mut docs,
                    "* [`{}`]({BASE_URL}{})",
                    intrinsic.name, intrinsic.name
                )
                .unwrap();
                for instruction in intrinsic.instructions.iter() {
                    writeln!(&mut docs, "    - {}", instruction.preamble).unwrap();
                    for instruction in instruction.list.iter() {
                        writeln!(
                            &mut docs,
                            "        * [`{} {}`]({})",
                            instruction.base_instruction, instruction.operands, instruction.url,
                        )
                        .unwrap();
                    }
                }
            }
        }
        (out, docs)
    }
    fn arm_int(&self, ty: IntType) -> String {
        let su = match ty.signedness() {
            super::types::Signedness::Signed => "s",
            super::types::Signedness::Unsigned => "u",
        };
        format!("{su}{}", ty.bits())
    }
}

/// Apply the AES operation given the single_round and mix_column intrinsics.
fn apply_aes(
    blocks: &dyn ToTokens,
    key: &dyn ToTokens,
    single_round: &dyn ToTokens,
    mix_columns: &dyn ToTokens,
    size: super::AesSize,
) -> TokenStream {
    let mut out = quote! {
        let key = #key;
        let mut blocks = #blocks;
    };
    for round in 0..size.num_rounds() - 2 {
        out.append_all(quote! {
            blocks = blocks.array_map(
                #[inline(always)]
                |block| bytemuck::cast(unsafe {
                    #mix_columns(#single_round(
                        bytemuck::cast(block),
                        bytemuck::cast(key[#round]),
                    ))
                })
            );
        });
    }
    let num_rounds = size.num_rounds();
    out.append_all(quote! {
        blocks.array_map(#[inline(always)] |block| {
            let block: U8x16 = bytemuck::cast(unsafe {
                #single_round(
                    bytemuck::cast(block),
                    bytemuck::cast(key[#num_rounds - 2])
                )
            });
            block ^ bytemuck::cast(key[#num_rounds - 1])
        })
    });
    out
}
impl VectorBackend for Neon {
    fn check_cpu(&self) -> TokenStream {
        let required_features = REQUIRED_FEATURES;
        quote! {#(
            assert!(
                std::arch::is_aarch64_feature_detected!(#required_features),
                "This binary was compiled assuming {:?}, but the current CPU doesn't support that",
                #required_features,
            );
        )*}
    }

    fn scalar_docs(&self) -> Docs {
        "# Neon\nThis function uses a scalar polyfill.\n".to_string()
    }

    fn vector_backend_variant(&self) -> &str {
        "Neon"
    }

    fn cfg(&self) -> Cfg {
        let mut requirements = vec![Cfg::Contains {
            key: "target_arch".to_string(),
            value: "aarch64".to_string(),
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
        // Number of 128-bit lanes
        let lane_count = ty.bits() / 128;
        // How many elements in each 128-bit lane?
        let elems_per_lane = ty.count() / lane_count;
        let sign = match ty.of().signedness() {
            super::types::Signedness::Signed => "",
            super::types::Signedness::Unsigned => "u",
        };
        let name = format_ident!("{sign}int{}x{elems_per_lane}_t", ty.of().bits());
        quote! { [std::arch::aarch64::#name; #lane_count] }
    }
    fn pairwise(
        &self,
        ty: VectorType,
        op: super::PairwiseOperator,
        lhs: &dyn quote::ToTokens,
        rhs: &dyn quote::ToTokens,
    ) -> (TokenStream, Docs) {
        self.build(&mut |b| {
            let op = match op {
                super::PairwiseOperator::WrappingAdd => "add",
                super::PairwiseOperator::WrappingSub => "sub",
                super::PairwiseOperator::Xor => "eor",
                super::PairwiseOperator::Or => "orr",
                super::PairwiseOperator::And => "and",
            };
            let intrinsic = b.intrinsic(&format!("v{op}q_{}", self.arm_int(ty.of())));
            quote! {
                #ty(
                    #lhs.0
                        .array_zip(#rhs.0)
                        .array_map(
                            #[inline(always)]
                            |(a, b)| unsafe { #intrinsic(a, b) }
                        )
                )
            }
        })
    }

    fn aes_key_schedule_type(&self, size: super::AesSize, encrypt_only: bool) -> TokenStream {
        crate::backend::avx2::aes_key_schedule_type(size, encrypt_only)
    }

    fn aes_key_expand(
        &self,
        size: super::AesSize,
        encrypt_only: bool,
        key: &dyn quote::ToTokens,
    ) -> (TokenStream, Docs) {
        self.build(&mut |b| {
            let mut out = TokenStream::new();
            let vaeseq_u8 = b.intrinsic("vaeseq_u8");
            out.append_all(quote! {
                #[inline(always)]
                fn mm_aeskeygenassist_si128<const RCON: i32>(a: U32x4) -> U32x4 {
                    /*
                        Based on https://github.com/DLTcollab/sse2neon/blob/0d6e9b3dd4687a0b98c0645e001f96659aae5854/sse2neon.h

                        Copyright (c) 2015-2022 SSE2NEON Contributors

                        Permission is hereby granted, free of charge, to any person obtaining a copy
                        of this software and associated documentation files (the "Software"), to deal
                        in the Software without restriction, including without limitation the rights
                        to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
                        copies of the Software, and to permit persons to whom the Software is
                        furnished to do so, subject to the following conditions:

                        The above copyright notice and this permission notice shall be included in all
                        copies or substantial portions of the Software.

                        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
                        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
                        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
                        AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
                        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
                        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
                        SOFTWARE.
                    */

                    let aes_out = U8x16(unsafe {
                        [#vaeseq_u8(
                            bytemuck::cast(a.0[0]),
                            U8x16::ZERO.0[0],
                        )]
                    });

                    const MASK: U8x16 = U8x16::from_array([
                        // Undo ShiftRows step from AESE and extract X1 and X3
                        0x4, 0x1, 0xE, 0xB,  // SubBytes(X1)
                        0x1, 0xE, 0xB, 0x4,  // ROT(SubBytes(X1))
                        0xC, 0x9, 0x6, 0x3,  // SubBytes(X3)
                        0x9, 0x6, 0x3, 0xC,  // ROT(SubBytes(X3))
                    ]);
                    let dest = aes_out.shuffle(MASK);
                    let r = U32x4::from(U64x2::broadcast(u64::from(RCON as u32) << 32));
                    U32x4::from(dest) ^ r
                }
            });
            if !encrypt_only {
                let intrinsic_vaesimcq_u8 = b.intrinsic("vaesimcq_u8");
                out.append_all(quote! {
                    fn mm_aesimc_si128(round_key: U32x4) -> U32x4 {
                        bytemuck::cast(unsafe {
                            #intrinsic_vaesimcq_u8(bytemuck::cast(round_key.0))
                        })
                    }
                });
            }
            out.append_all(super::avx2::key_schedule(
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
            let vaeseq_u8 = b.intrinsic("vaeseq_u8");
            let vaesmcq_u8 = b.intrinsic("vaesmcq_u8");
            apply_aes(
                blocks,
                &quote! { &#key.encrypt_keys },
                &vaeseq_u8,
                &vaesmcq_u8,
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
            let vaesdq_u8 = b.intrinsic("vaesdq_u8");
            let vaesimcq_u8 = b.intrinsic("vaesimcq_u8");
            apply_aes(
                blocks,
                &quote! { &#key.decrypt_keys },
                &vaesdq_u8,
                &vaesimcq_u8,
                size,
            )
        })
    }
}

/// Unlike Intel, ARM doesn't provide a list of which CPU features are requried for each intrinsic.
/// To fix this, we parse the `arm_neon.h` file from LLVM to figure out which target features are
// required for each intrinsic.
fn parse_target_features() -> HashMap<String, Vec<String>> {
    let arm_neon_h = String::from_utf8(
        zstd::decode_all(std::io::Cursor::new(
            include_bytes!("neon/arm_neon.h.zst").as_slice(),
        ))
        .unwrap(),
    )
    .unwrap();
    // Extract lines like:
    // __ai __attribute__((target("aes"))) uint8x16_t vaeseq_u8(...
    // __ai uint16x8_t vaddq_u16(...
    let mut out = HashMap::new();
    for line in arm_neon_h.lines() {
        let line = line.trim();
        if let Some(line) = line.strip_prefix("__ai ") {
            let features: Vec<_> = if line.contains("__attribute__") {
                line.split_once('"')
                    .expect("unable to parse")
                    .1
                    .split_once('"')
                    .expect("unable to parse")
                    .0
                    .split(',')
                    .map(|feature| feature.trim().to_string())
                    .collect()
            } else {
                Vec::new()
            };
            let name = line
                .rsplit_once('(')
                .expect("unable to parse")
                .0
                .split_whitespace()
                .last()
                .expect("unable to parse")
                .to_string();
            match out.entry(name) {
                std::collections::hash_map::Entry::Occupied(entry) => {
                    assert_eq!(
                        entry.get(),
                        &features,
                        "{:?} occured multiple time with different featurres",
                        entry.key()
                    );
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(features);
                }
            }
        }
    }
    out
}

#[derive(serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct InstructionListJson {
    base_instruction: String,
    operands: String,
    url: String,
}
#[derive(serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct InstructionJson {
    preamble: String,
    list: Vec<InstructionListJson>,
}
#[derive(serde::Deserialize)]
struct ArmIntrinsicJson {
    name: String,
    #[serde(default)]
    instructions: Vec<InstructionJson>,
}

pub fn neon_backend() -> Box<dyn VectorBackend> {
    let arm_intrinsics_json: Vec<ArmIntrinsicJson> = serde_json::from_slice(
        zstd::decode_all(std::io::Cursor::new(
            include_bytes!("neon/neon-intrinsics.json.zst").as_slice(),
        ))
        .unwrap()
        .as_slice(),
    )
    .unwrap();
    let mut arm_intrinsics_json: HashMap<String, ArmIntrinsicJson> = arm_intrinsics_json
        .into_iter()
        .map(|intrinsic| {
            let name = intrinsic.name.replace("[__arm_]", "");
            (name, intrinsic)
        })
        .collect();
    let intrinsics: HashMap<String, Intrinsic> = parse_target_features()
        .into_iter()
        .filter_map(|(name, required_features)| {
            arm_intrinsics_json.remove(&name).map(|json| {
                (
                    name.clone(),
                    Intrinsic {
                        name: name.clone(),
                        required_features,
                        instructions: json.instructions,
                    },
                )
            })
        })
        .collect();
    Box::new(Neon { intrinsics })
}
