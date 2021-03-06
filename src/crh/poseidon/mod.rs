use crate::crh::poseidon::sbox::PoseidonSbox;
use crate::crh::FixedLengthCRH;
use crate::{Error, Vec};
use ark_ff::fields::PrimeField;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;

pub mod sbox;

#[cfg(test)]
pub mod test_data;

#[cfg(feature = "r1cs")]
pub mod constraints;

// Choice is arbitrary
pub const PADDING_CONST: u64 = 101;
pub const ZERO_CONST: u64 = 0;

pub trait Rounds: Default + Clone {
    /// The size of the permutation, in field elements.
    const WIDTH: usize;
    /// Number of full SBox rounds
    const FULL_ROUNDS: usize;
    /// Number of partial rounds
    const PARTIAL_ROUNDS: usize;
    /// The S-box to apply in the sub words layer.
    const SBOX: PoseidonSbox;
}

/// The Poseidon permutation.
#[derive(Default, Clone)]
pub struct PoseidonParameters<F> {
    /// The round key constants
    pub round_keys: Vec<F>,
    /// The MDS matrix to apply in the mix layer.
    pub mds_matrix: Vec<Vec<F>>,
}

impl<F: PrimeField> PoseidonParameters<F> {
    pub fn new(round_keys: Vec<F>, mds_matrix: Vec<Vec<F>>) -> Self {
        Self {
            round_keys,
            mds_matrix,
        }
    }

    pub fn generate<R: Rng>(rng: &mut R) -> Self {
        Self {
            round_keys: Self::create_round_keys(rng),
            mds_matrix: Self::create_mds(rng),
        }
    }
    pub fn create_mds<R: Rng>(_rng: &mut R) -> Vec<Vec<F>> {
        let mds_matrix = Vec::new();
        mds_matrix
    }

    pub fn create_round_keys<R: Rng>(_rng: &mut R) -> Vec<F> {
        let round_keys = Vec::new();
        round_keys
    }
}

pub struct CRH<F: PrimeField, P: Rounds> {
    field: PhantomData<F>,
    rounds: PhantomData<P>,
}

impl<F: PrimeField, P: Rounds> CRH<F, P> {
    fn permute(params: &PoseidonParameters<F>, input: Vec<F>) -> Vec<F> {
        let width = P::WIDTH;

        let partial_rounds = P::PARTIAL_ROUNDS;
        let full_rounds = P::FULL_ROUNDS / 2;
        let mut current_state = input.to_vec();
        let mut round_keys_offset = 0;

        // full Sbox rounds
        for _ in 0..full_rounds {
            // Sbox layer
            for i in 0..width {
                current_state[i] += params.round_keys[round_keys_offset];
                current_state[i] = P::SBOX.apply_sbox(current_state[i]);
                round_keys_offset += 1;
            }
            // linear layer
            current_state = Self::apply_linear_layer(&current_state, &params.mds_matrix);
        }

        // middle partial Sbox rounds
        for _ in 0..partial_rounds {
            for i in 0..width {
                current_state[i] += params.round_keys[round_keys_offset];
                round_keys_offset += 1;
            }
            // partial Sbox layer, apply Sbox to only 1 element of the state.
            // Here the last one is chosen but the choice is arbitrary.
            current_state[0] = P::SBOX.apply_sbox(current_state[0]);
            // linear layer
            current_state = Self::apply_linear_layer(&current_state, &params.mds_matrix);
        }

        // last full Sbox rounds
        for _ in 0..full_rounds {
            // Sbox layer
            for i in 0..width {
                current_state[i] += params.round_keys[round_keys_offset];
                current_state[i] = P::SBOX.apply_sbox(current_state[i]);
                round_keys_offset += 1;
            }
            // linear layer
            current_state = Self::apply_linear_layer(&current_state, &params.mds_matrix);
        }

        // Finally the current_state becomes the output
        current_state
    }

    fn apply_linear_layer(state: &Vec<F>, mds: &Vec<Vec<F>>) -> Vec<F> {
        let mut new_state: Vec<F> = Vec::new();
        for i in 0..state.len() {
            let mut sc = F::zero();
            for j in 0..state.len() {
                let mij = mds[i][j];
                sc += mij * state[j];
            }
            new_state.push(sc);
        }
        new_state
    }
}

impl<F: PrimeField, P: Rounds> FixedLengthCRH for CRH<F, P> {
    const INPUT_SIZE_BITS: usize = 32 * 8 * P::WIDTH;
    type Output = F;
    type Parameters = PoseidonParameters<F>;

    // Not sure what's the purpose of this function of we are going to pass parameters
    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(Self::Parameters::generate(rng))
    }

    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let eval_time = start_timer!(|| "PoseidonCRH::Eval");

        if (input.len() * 8) != Self::INPUT_SIZE_BITS {
            panic!(
                "incorrect input length {:?} for width {:?}",
                input.len() / 32,
                P::WIDTH,
            );
        }

        // Not giving expected results
        // let elts: Vec<F> = input.to_field_elements().unwrap_or(Vec::new());

        let f_inputs: Vec<F> = input
            .chunks(32)
            .map(|x| F::from_le_bytes_mod_order(x))
            .collect();

        let result = Self::permute(&parameters, f_inputs);

        end_timer!(eval_time);

        Ok(result.get(1).cloned().unwrap())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ed_on_bn254::Fq;
    use ark_ff::to_bytes;
    use ark_ff::Zero;

    use test_data::{
        get_mds_3, get_mds_5, get_results_3, get_results_5, get_rounds_3, get_rounds_5,
    };

    #[derive(Default, Clone)]
    struct PoseidonRounds3;
    #[derive(Default, Clone)]
    struct PoseidonRounds5;

    impl Rounds for PoseidonRounds3 {
        const WIDTH: usize = 3;
        const PARTIAL_ROUNDS: usize = 57;
        const FULL_ROUNDS: usize = 8;
        const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
    }

    impl Rounds for PoseidonRounds5 {
        const WIDTH: usize = 5;
        const PARTIAL_ROUNDS: usize = 60;
        const FULL_ROUNDS: usize = 8;
        const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
    }

    type PoseidonCRH3 = CRH<Fq, PoseidonRounds3>;
    type PoseidonCRH5 = CRH<Fq, PoseidonRounds5>;

    #[test]
    fn test_width_3_bn_254() {
        let rounds = get_rounds_3::<Fq>();
        let mds = get_mds_3::<Fq>();
        let res = get_results_3::<Fq>();

        let params = PoseidonParameters::<Fq>::new(rounds, mds);

        let inp = to_bytes![Fq::zero(), Fq::from(1u128), Fq::from(2u128)].unwrap();

        let poseidon_res = PoseidonCRH3::evaluate(&params, &inp).unwrap();
        assert_eq!(res[1], poseidon_res);
    }

    #[test]
    fn test_width_5_bn_254() {
        let rounds = get_rounds_5::<Fq>();
        let mds = get_mds_5::<Fq>();
        let res = get_results_5::<Fq>();

        let params = PoseidonParameters::<Fq>::new(rounds, mds);

        let inp = to_bytes![
            Fq::zero(),
            Fq::from(1u128),
            Fq::from(2u128),
            Fq::from(3u128),
            Fq::from(4u128)
        ]
        .unwrap();

        let poseidon_res = PoseidonCRH5::evaluate(&params, &inp).unwrap();
        assert_eq!(res[1], poseidon_res);
    }
}
