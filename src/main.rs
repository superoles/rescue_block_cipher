extern crate bellman;

use franklin_crypto::plonk::circuit::Assignment;
use rescue_block_cipher::{
	cipher_generator::{CipherParams, cipher_params_generate,
	mds::{MdsMatrix, generate_mds_matrix, inverse_matrix, dot_product, sum_vectors, sub_vectors}
	},
	EncDec::{rescue_decryption, rescue_encryption, generate_ready_params, generate_subkeys}
};
use franklin_crypto::plonk::circuit::{
    allocated_num::{Num, AllocatedNum},
    boolean::{self, AllocatedBit, Boolean},
    multieq::MultiEq,
    uint32::UInt32,
    linear_combination::LinearCombination,
	*
};
use rand::{XorShiftRng, SeedableRng, Rng, ThreadRng, thread_rng};
use franklin_crypto::bellman::pairing::{
    Engine,
	bn256::{Bn256, Fr},
	ff::{
        Field,
        PrimeField,
        PrimeFieldRepr,
        BitIterator
    }
};
use franklin_crypto::bellman::plonk::better_better_cs::cs::*;

//struct RescueBlockCipherCircuit<E: Engine> {
//	params: Option<CipherParams<E, 3, 5>>,
//	key: Option<[Num<E>; 3]>,
//	plaintext: Option<[Num<E>; 3]>,
//	ciphertext: Option<[Num<E>; 3]>
//}

//impl<E: Engine> Circuit<E> for RescueBlockCipherCircuit<E> {
//    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
//		Ok(())
//	}
//}

fn main() {
	
	let rng = &mut thread_rng();

	let mut my_params = cipher_params_generate::<Bn256, ThreadRng, 3, 7>(rng);

	let mut cs = TrivialAssembly::<Bn256, PlonkCsWidth4WithNextStepParams, Width4MainGateWithDNext>::new();

	let ready_params = generate_ready_params(&mut cs, &mut my_params);

	let key = [Num::<Bn256>::zero(); 3];
	let plaintext = [Num::<Bn256>::zero(); 3];

	let ciphertext = rescue_encryption(&mut cs, &ready_params, &key, &plaintext);

	let new_plaintext = rescue_decryption(&mut cs, &ready_params, &key, &ciphertext);


	for i in 0..3 {
		plaintext[i].enforce_equal(&mut cs, &new_plaintext[i]);
	}
}
