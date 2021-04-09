use super::sbox::constraints::SboxConstraints;
use super::{PoseidonParameters, Rounds, CRH};
use crate::FixedLengthCRHGadget;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::{alloc::AllocVar, fields::FieldVar, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::marker::PhantomData;
use ark_std::vec::Vec;
use core::borrow::Borrow;

#[derive(Default, Clone)]
pub struct PoseidonParametersVar<F: PrimeField> {
    /// The round key constants
    pub round_keys: Vec<FpVar<F>>,
    /// The MDS matrix to apply in the mix layer.
    pub mds_matrix: Vec<Vec<FpVar<F>>>,
}

pub struct CRHGadget<F: PrimeField, P: Rounds> {
    field: PhantomData<F>,
    params: PhantomData<P>,
}

impl<F: PrimeField, P: Rounds> CRHGadget<F, P> {
    fn permute(
        parameters: &PoseidonParametersVar<F>,
        mut state: Vec<FpVar<F>>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let width = P::WIDTH;

        let mut round_keys_offset = 0;

        // full Sbox rounds
        for _ in 0..(P::FULL_ROUNDS / 2) {
            // Substitution (S-box) layer
            for i in 0..width {
                state[i] += &parameters.round_keys[round_keys_offset];
                state[i] = P::SBOX.synthesize_sbox(&state[i])?;
                round_keys_offset += 1;
            }
            // Apply linear layer
            state = Self::apply_linear_layer(&state, &parameters.mds_matrix);
        }

        // middle partial Sbox rounds
        for _ in 0..P::PARTIAL_ROUNDS {
            // Substitution (S-box) layer
            for i in 0..width {
                state[i] += &parameters.round_keys[round_keys_offset];
                round_keys_offset += 1;
            }
            // apply Sbox to only 1 element of the state.
            // Here the last one is chosen but the choice is arbitrary.
            state[0] = P::SBOX.synthesize_sbox(&state[0])?;
            // Linear layer
            state = Self::apply_linear_layer(&state, &parameters.mds_matrix);
        }

        // last full Sbox rounds
        for _ in 0..(P::FULL_ROUNDS / 2) {
            // Substitution (S-box) layer
            for i in 0..width {
                state[i] += &parameters.round_keys[round_keys_offset];
                state[i] = P::SBOX.synthesize_sbox(&state[i])?;
                round_keys_offset += 1;
            }
            // Linear layer
            state = Self::apply_linear_layer(&state, &parameters.mds_matrix);
        }

        Ok(state)
    }

    fn apply_linear_layer(state: &Vec<FpVar<F>>, mds_matrix: &Vec<Vec<FpVar<F>>>) -> Vec<FpVar<F>> {
        let mut new_state: Vec<FpVar<F>> = Vec::new();
        for i in 0..state.len() {
            let mut sc = FpVar::<F>::zero();
            for j in 0..state.len() {
                let mij = &mds_matrix[i][j];
                sc += mij * &state[j];
            }
            new_state.push(sc);
        }
        new_state
    }
}

// https://github.com/arkworks-rs/r1cs-std/blob/master/src/bits/uint8.rs#L343
impl<F: PrimeField, P: Rounds> FixedLengthCRHGadget<CRH<F, P>, F> for CRHGadget<F, P> {
    type OutputVar = FpVar<F>;
    type ParametersVar = PoseidonParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[UInt8<F>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        if (input.len() / 32) > P::WIDTH {
            panic!(
                "incorrect input length {:?} for width {:?}",
                input.len() / 32,
                P::WIDTH,
            );
        }
        // Not giving expected results
        // let f_var_inputs: Vec<FpVar<F>> = input.to_constraint_field()?;

        let mut buffer = vec![UInt8::constant(0); P::WIDTH * 32];
        buffer
            .iter_mut()
            .zip(input)
            .for_each(|(b, l_b)| *b = l_b.clone());

        let f_var_inputs = buffer
            .chunks(32)
            .map(|x| {
                let fp_var_x = Boolean::le_bits_to_fp_var(&x.to_bits_le()?.as_slice());
                fp_var_x
            })
            .collect::<Result<Vec<FpVar<F>>, SynthesisError>>()?;

        let result = Self::permute(&parameters, f_var_inputs);
        result.map(|x| x.get(1).cloned().unwrap())
    }
}

impl<F: PrimeField> AllocVar<PoseidonParameters<F>, F> for PoseidonParametersVar<F> {
    #[tracing::instrument(target = "r1cs", skip(_cs, f))]
    fn new_variable<T: Borrow<PoseidonParameters<F>>>(
        _cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let params = f()?.borrow().clone();

        let mut round_keys_var = Vec::new();
        for rk in params.round_keys {
            round_keys_var.push(FpVar::Constant(rk));
        }
        let mut mds_var = Vec::new();
        for row in params.mds_matrix {
            let mut row_var = Vec::new();
            for mk in row {
                row_var.push(FpVar::Constant(mk));
            }
            mds_var.push(row_var);
        }
        Ok(Self {
            round_keys: round_keys_var,
            mds_matrix: mds_var,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crh::FixedLengthCRH;
    use ark_ed_on_bn254::Fq;
    use ark_ff::to_bytes;
    use ark_ff::Zero;
    use ark_relations::r1cs::ConstraintSystem;

    use crate::crh::poseidon::test_data::{get_mds_3, get_rounds_3};
    use crate::crh::poseidon::PoseidonSbox;

    #[derive(Default, Clone)]
    struct PoseidonRounds3;

    impl Rounds for PoseidonRounds3 {
        const WIDTH: usize = 3;
        const PARTIAL_ROUNDS: usize = 57;
        const FULL_ROUNDS: usize = 8;
        const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
    }

    type PoseidonCRH3 = CRH<Fq, PoseidonRounds3>;
    type PoseidonCRH3Gadget = CRHGadget<Fq, PoseidonRounds3>;

    #[test]
    fn test_poseidon_native_equality() {
        let rounds = get_rounds_3::<Fq>();
        let mds = get_mds_3::<Fq>();

        let cs = ConstraintSystem::<Fq>::new_ref();

        let inp = to_bytes![Fq::zero(), Fq::from(1u128), Fq::from(2u128)].unwrap();

        let mut inp_u8 = Vec::new();
        for byte in inp.iter() {
            inp_u8.push(UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap());
        }

        let params = PoseidonParameters::<Fq>::new(rounds, mds);
        let params_var = PoseidonParametersVar::new_variable(
            cs.clone(),
            || Ok(&params),
            AllocationMode::Constant,
        );

        let res = PoseidonCRH3::evaluate(&params, &inp).unwrap();
        let res_var = PoseidonCRH3Gadget::evaluate(&params_var.unwrap(), &inp_u8).unwrap();
        assert_eq!(res, res_var.value().unwrap());
    }
}
