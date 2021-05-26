#![cfg_attr(not(feature = "std"), no_std)]
#![deny(
    warnings,
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    // missing_docs
)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate ark_std;

#[macro_use]
extern crate derivative;

use ark_ff::fields::PrimeField;
use ark_ff::BigInteger;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::SynthesisError;
pub(crate) use ark_std::{borrow::ToOwned, boxed::Box, vec::Vec};

pub mod commitment;
pub mod crh;
pub mod merkle_tree;

pub mod prf;
pub mod signature;
pub mod snark;

pub use self::{
    commitment::CommitmentScheme,
    crh::CRH,
    merkle_tree::{MerkleTree, Path},
    prf::PRF,
    signature::SignatureScheme,
    snark::{CircuitSpecificSetupSNARK, UniversalSetupSNARK, SNARK},
};

#[cfg(feature = "r1cs")]
pub use self::{
    commitment::CommitmentGadget, crh::CRHGadget, merkle_tree::constraints::PathVar,
    prf::PRFGadget, signature::SigRandomizePkGadget, snark::SNARKGadget,
};

pub type Error = Box<dyn ark_std::error::Error>;

#[derive(Debug)]
pub enum CryptoError {
    IncorrectInputLength(usize),
    NotPrimeOrder,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            CryptoError::IncorrectInputLength(len) => format!("input length is wrong: {}", len),
            CryptoError::NotPrimeOrder => "element is not prime order".to_owned(),
        };
        write!(f, "{}", msg)
    }
}

impl ark_std::error::Error for CryptoError {}

pub fn to_field_elements<F: PrimeField>(bytes: &[u8]) -> Result<Vec<F>, Error> {
    let max_size_bytes = F::BigInt::NUM_LIMBS * 8;
    let res = bytes
        .chunks(max_size_bytes)
        .map(|chunk| F::read(chunk))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(res)
}

pub fn to_field_var_elements<F: PrimeField>(
    bytes: &[UInt8<F>],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let max_size = F::BigInt::NUM_LIMBS * 8;
    let res = bytes
        .chunks(max_size)
        .map(|chunk| Boolean::le_bits_to_fp_var(chunk.to_bits_le()?.as_slice()))
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    Ok(res)
}
