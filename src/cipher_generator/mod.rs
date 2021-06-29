pub mod mds;
pub mod sboxes;


use franklin_crypto::plonk::circuit::{
    allocated_num::Num,
    boolean::{self, AllocatedBit, Boolean}
};
use franklin_crypto::bellman::pairing::{
    Engine,
	bn256::{Bn256, Fr},
};
use franklin_crypto::bellman::SynthesisError;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use rand::{Rand, Rng};
use franklin_crypto::bellman::pairing::ff::{
    Field,
    PrimeField,
    PrimeFieldRepr,
    BitIterator
};
use std::marker::PhantomData;
use mds::{MdsMatrix, generate_mds_matrix, inverse_matrix, generate_vectors_for_matrix};
use sboxes::{QuinticSBox, QuinticInverseSBox};

pub struct CipherParams<
    E: Engine,
    const SIZE: usize,
    const RNUMBER: usize> {
    pub vect_for_matrix: [Vec<E::Fr>; 2],
    pub sbox1: QuinticSBox<E, SIZE>,
    pub sbox2: QuinticInverseSBox<E, SIZE>,
    pub round_constants: [[E::Fr; SIZE]; RNUMBER]
}

pub fn cipher_params_generate<
    E: Engine, 
    R: Rng, 
    const SIZE: usize,
    const RNUMBER: usize>(rng: &mut R)-> CipherParams<E, SIZE, RNUMBER> {
    
    let vect_for_matrix = generate_vectors_for_matrix::<E, R, SIZE>(rng);

    let sbox1 = QuinticSBox::<E, SIZE>{
        _marker: PhantomData::<E>::default()
    };
    let sbox2 = QuinticInverseSBox::<E, SIZE>{
        _marker: PhantomData::<E>::default()
    };
    let round_constants = generate_round_constants::<E, R, SIZE, RNUMBER>(rng);

    CipherParams{
        vect_for_matrix,
        sbox1,
        sbox2,
        round_constants
    }
}

fn generate_round_constants<
    E: Engine,
    R: Rng, 
    const SIZE: usize,
    const RNUMBER: usize
>(
    rng: &mut R
)-> [[E::Fr; SIZE]; RNUMBER] {
    let mut roconst = [[E::Fr::zero(); SIZE]; RNUMBER];
    let zero = E::Fr::zero();
    for i in 0..RNUMBER {
        for j in 0..SIZE {
            loop {
                let n = rng.gen();
                if n == zero {
                    continue;
                }
                roconst[i][j] = n;
                break;
            } 
        }
    }
    roconst
}
