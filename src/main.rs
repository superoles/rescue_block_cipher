extern crate bellman;

use rand::{ThreadRng, thread_rng};
use rescue_block_cipher::{
	cipher_tools::generate_cipher_params,
	enc_dec::{rescue_decryption, rescue_encryption, construct_ready_params}
};
use franklin_crypto::plonk::circuit::allocated_num::Num;
use franklin_crypto::bellman::{
	pairing::bn256::Bn256,
	plonk::better_better_cs::cs::*
};

fn main() {
	let rng = &mut thread_rng();
	let mut cs = TrivialAssembly::<Bn256, PlonkCsWidth4WithNextStepParams, Width4MainGateWithDNext>::new();

	let mut my_params = generate_cipher_params::<Bn256, ThreadRng, 3, 7>(rng);
	let ready_params = construct_ready_params(&mut cs, &mut my_params);

	let key = [Num::<Bn256>::zero(); 3];
	let plaintext = [Num::<Bn256>::zero(); 3];

	let ciphertext = rescue_encryption(&mut cs, &ready_params, &key, &plaintext);
	let decrypted_plaintext = rescue_decryption(&mut cs, &ready_params, &key, &ciphertext);

	for i in 0..3 {
		plaintext[i].enforce_equal(&mut cs, &decrypted_plaintext[i]).unwrap();
	}
}
