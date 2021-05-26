use crate::to_field_elements;
use crate::{CryptoError, Error, Vec, CRH as CRHTrait};
use ark_ff::fields::PrimeField;
use ark_ff::BigInteger;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub struct CRH<F: PrimeField> {
    field: PhantomData<F>,
}

impl<F: PrimeField> CRHTrait for CRH<F> {
    const INPUT_SIZE_BITS: usize = F::BigInt::NUM_LIMBS * 64;
    type Output = F;
    type Parameters = ();

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate(_: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let f_inputs: Vec<F> = to_field_elements(input)?;

        assert!(f_inputs.len() == 1);

        Ok(f_inputs
            .get(0)
            .cloned()
            .ok_or(CryptoError::IncorrectInputLength(f_inputs.len()))?)
    }
}

#[cfg(test)]
mod test {
    use super::CRH;
    use crate::crh::CRH as CRHTrait;
    use ark_ed_on_bn254::Fq;
    use ark_ff::to_bytes;

    type IdentityCRH = CRH<Fq>;
    #[test]
    fn should_return_same_data() {
        let val = Fq::from(4u64);

        let bytes = to_bytes![val].unwrap();
        let res = IdentityCRH::evaluate(&(), &bytes).unwrap();

        assert_eq!(res, val);
    }
}
