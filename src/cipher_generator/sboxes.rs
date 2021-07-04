use franklin_crypto::plonk::circuit::allocated_num::Num;
use franklin_crypto::bellman::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use std::marker::PhantomData;

pub struct QuinticSBox<E: Engine, const SIZE: usize>{
    pub _marker: PhantomData<E>
}

impl<E: Engine, const SIZE: usize> QuinticSBox<E, SIZE> {
    pub fn apply<CS: ConstraintSystem<E>>(&self, cs: &mut CS, elements: &mut [Num<E>; SIZE]) {
        for element in elements.iter_mut() {
            let mut result = element.mul(cs, element).unwrap();
            result = result.mul(cs, element).unwrap();
            result = result.mul(cs, element).unwrap();
            result = result.mul(cs, element).unwrap();
            *element = result;
        }
    }
}

pub struct QuinticInverseSBox<E: Engine, const SIZE: usize>{
    pub _marker: PhantomData<E>
}

impl<E: Engine, const SIZE: usize> QuinticInverseSBox<E, SIZE> {
    pub fn apply<CS: ConstraintSystem<E>>(&self, cs: &mut CS, elements: &mut [Num<E>; SIZE]) {
        let alpha = 5;
        let alpha_inv = compute_inverse_alpha::<E, 4>(alpha);
        for element in elements.iter_mut() {
            let old_elem = (*element).clone();
            big_pow(cs, element, &alpha_inv);

            let mut elem = element.mul(cs, &element).unwrap();
            elem = elem.mul(cs, &element).unwrap();
            elem = elem.mul(cs, &element).unwrap();
            elem = elem.mul(cs, &element).unwrap();

            old_elem.enforce_equal(cs, &elem).unwrap();
        }
    }
}

fn compute_inverse_alpha<E: Engine, const N: usize>(alpha: u64) -> [u64; N] {
    rescue_poseidon::common::utils::compute_gcd::<E, N>(alpha).expect("inverse of alpha")
}

fn big_pow<E: Engine, CS: ConstraintSystem<E>, const N: usize>(cs: &mut CS, num: &mut Num<E>, power: &[u64; N]){
    let mut res = Num::<E>::one();
    let mut pow = *power;
    for n in 0..N {
        for _ in 0..(64 as usize) {
            if pow[n]%2 == 0 {
                *num = num.mul(cs, &num).unwrap();
                pow[n] = pow[n]/2;
            } else {
                res = res.mul(cs, &num).unwrap();
                *num = num.mul(cs, &num).unwrap();
                pow[n] = (pow[n]-1)/2;
            }
        }
    }
    *num = res;
}
