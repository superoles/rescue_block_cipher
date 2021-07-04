use franklin_crypto::plonk::circuit::allocated_num::Num;
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use super::cipher_generator::{
    CipherParams,
    mds::{MdsMatrix, generate_mds_matrix, inverse_matrix, dot_product, sum_vectors, sub_vectors},
    sboxes::{QuinticSBox, QuinticInverseSBox}
};
use std::marker::PhantomData;

pub struct ReadyCipherParams<
    E: Engine,
    const SIZE: usize,
    const RNUMBER: usize> {
    pub matrix: MdsMatrix<E, SIZE>,
    pub inv_matrix: MdsMatrix<E, SIZE>,
    pub sbox1: QuinticSBox<E, SIZE>,
    pub sbox2: QuinticInverseSBox<E, SIZE>,
    pub round_constants: [[Num<E>; SIZE]; RNUMBER]
}

pub fn generate_ready_params<
    E: Engine, 
    CS: ConstraintSystem<E>, 
    const SIZE: usize,
    const RNUMBER: usize>(
    cs: &mut CS,
    params: &mut CipherParams<E, SIZE, RNUMBER>
    )-> ReadyCipherParams<E, SIZE, RNUMBER>{
    let matrix = generate_mds_matrix::<E, CS, SIZE>(cs, &mut params.vect_for_matrix);
    let inv_matrix = inverse_matrix::<E, CS, SIZE>(cs, &matrix).unwrap();
    let sbox1 = QuinticSBox::<E, SIZE>{
        _marker: PhantomData::<E>::default()
    };
    let sbox2 = QuinticInverseSBox::<E, SIZE>{
        _marker: PhantomData::<E>::default()
    };
    let mut round_constants = [[Num::<E>::zero(); SIZE]; RNUMBER];
    for i in 0..RNUMBER {
        for j in 0..SIZE {
            round_constants[i][j] = Num::alloc(cs, Some(params.round_constants[i][j])).unwrap();
        }
    }
    ReadyCipherParams {
        matrix,
        inv_matrix,
        sbox1,
        sbox2,
        round_constants
    }
}

pub fn rescue_encryption<
    E: Engine, 
    CS: ConstraintSystem<E>, 
    const SIZE: usize,
    const RNUMBER: usize>(
    cs: &mut CS,
    params: &ReadyCipherParams<E, SIZE, RNUMBER>, 
    key: &[Num<E>; SIZE], 
    plaintext: &[Num<E>; SIZE])->[Num<E>; SIZE]{
	
    let subkeys = generate_subkeys(cs, &params, *key);

    let mut ciphertext = sum_vectors(cs, &plaintext, &subkeys[0]);
    let mut helptext = ciphertext;
    let matrix = &params.matrix;

    for i in 1..RNUMBER {
        for j in 0..SIZE {
            helptext[j] = dot_product(cs, &ciphertext, &matrix.row(j));
        }
        ciphertext = helptext;
        if i%2 == 1 {
            params.sbox1.apply(cs, &mut ciphertext);
        } else {
            params.sbox2.apply(cs, &mut ciphertext);
        }
        ciphertext = sum_vectors(cs, &ciphertext, &subkeys[i]);
    }
    ciphertext
}

pub fn rescue_decryption<
    E: Engine, 
    CS: ConstraintSystem<E>, 
    const SIZE: usize,
    const RNUMBER: usize>(
    cs: &mut CS,
    params: &ReadyCipherParams<E, SIZE, RNUMBER>, 
    key: &[Num<E>; SIZE], 
    ciphertext: &[Num<E>; SIZE])->[Num<E>; SIZE]{

    let subkeys = generate_subkeys(cs, &params, *key);

    let mut plaintext = sub_vectors(cs, &ciphertext, &subkeys[RNUMBER-1]);
    let mut helptext = plaintext;
    let matrix = &params.inv_matrix;

    for i in 1..RNUMBER {

        if i%2 == 1 {
            params.sbox1.apply(cs, &mut plaintext);
        } else {
            params.sbox2.apply(cs, &mut plaintext);
        }
        
        for j in 0..SIZE {
            helptext[j] = dot_product(cs, &plaintext, &matrix.row(j));
        }
        plaintext = helptext;
                
        plaintext = sub_vectors(cs, &plaintext, &subkeys[RNUMBER-i-1]);
    }
    plaintext
}

pub fn generate_subkeys<
    E: Engine, 
    CS: ConstraintSystem<E>, 
    const SIZE: usize,
    const RNUMBER: usize>(
    cs: &mut CS,
    params: &ReadyCipherParams<E, SIZE, RNUMBER>, 
    key: [Num<E>; SIZE] )->[[Num<E>; SIZE]; RNUMBER]{

    let mut subkeys = [[Num::<E>::zero(); SIZE]; RNUMBER];
    let raconsts = params.round_constants;
    let matrix = &params.matrix;

    subkeys[0] = sum_vectors(cs, &key, &raconsts[0]);

    for i in 1..RNUMBER {
        for j in 0..SIZE {
            subkeys[i][j] = dot_product(cs, &subkeys[i-1], &matrix.row(j));
        }
        if i%2 == 1 {
            params.sbox1.apply(cs, &mut subkeys[i]);
        } else {
            params.sbox2.apply(cs, &mut subkeys[i]);
        }
        subkeys[i] = sum_vectors(cs, &subkeys[i], &raconsts[i]);
    }
    subkeys
}
