use franklin_crypto::plonk::circuit::allocated_num::Num;
use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use rand::Rng;

pub struct MdsMatrix<E: Engine, const SIZE: usize> {
	data: [[Num<E>; SIZE]; SIZE]
}

impl<E: Engine, const SIZE: usize> MdsMatrix<E,SIZE>{
	pub fn zero_matrix()-> Self {
		let data = [[Num::<E>::zero(); SIZE]; SIZE];
		MdsMatrix {
			data
		}
	}

    pub fn get_row(&self, n: usize) -> [Num<E>; SIZE] {
        if n >= SIZE {
            panic!();
        }
        self.data[n]
    }
}

pub fn generate_vectors_for_matrix<
    E: Engine, 
    R: Rng, 
    const SIZE: usize
>(
    rng: &mut R
)-> [Vec<E::Fr>;2] {
    loop {
        let x: Vec<E::Fr> = (0..SIZE).map(|_| rng.gen()).collect();
        let y: Vec<E::Fr> = (0..SIZE).map(|_| rng.gen()).collect();
        
        if okey_vectors::<E, SIZE>(&x, &y){
            return [x, y];
        }
    }
}

fn okey_vectors<E: Engine, const SIZE: usize>(x: & Vec<E::Fr>, y: & Vec<E::Fr>)->bool {
    
    for i in 0..(SIZE as usize) {
        let el = x[i];
        for other in x[(i+1)..].iter() {
            if el == *other {
                return false;
            }
        }
    }

    for i in 0..(SIZE as usize) {
        let el = y[i];
        for other in y[(i+1)..].iter() {
            if el == *other {
                return false;
            }
        }
    }

    for i in 0..(SIZE as usize) {
        let el = x[i];
        for other in y.iter() {
            if el == *other {
                return false;
            }
        }
    }

    return true;
}

pub fn construct_mds_matrix<
    E: Engine, 
    CS: ConstraintSystem<E>,
    const SIZE: usize
>(
    cs: &mut CS,
    vectors: &mut [Vec<E::Fr>; 2]
)-> MdsMatrix<E, SIZE> {
    let mut mds_matrix = MdsMatrix::<E,SIZE>::zero_matrix();

	let x: Vec<Num<E>> = vectors[0].iter_mut().map(|number| Num::alloc(cs, Some(*number)).unwrap()).collect();
	let y: Vec<Num<E>> = vectors[1].iter_mut().map(|number| Num::alloc(cs, Some(*number)).unwrap()).collect();

    if !veryfy_vector_corectnes::<E, CS, SIZE>(cs, &x, &y){
        panic!();
    }

    for (i, x) in x.into_iter().enumerate() {
        for (j, y) in y.iter().enumerate() {
            mds_matrix.data[i][j] = x.sub(cs,y).unwrap().inverse(cs).unwrap();
        }
    }
    mds_matrix
}

fn veryfy_vector_corectnes<
    E: Engine, 
    CS: ConstraintSystem<E>,
    const SIZE: usize
>(cs: &mut CS, x: & Vec<Num<E>>, y: & Vec<Num<E>>) -> bool{
    for i in 0..(SIZE as usize) {
        let el = x[i];
        for other in x[(i+1)..].iter() {
            if Num::equals(cs, &el, &other).unwrap().get_value().unwrap() {
                return false;
            }
        }
    }

    for i in 0..(SIZE as usize) {
        let el = y[i];
        for other in y[(i+1)..].iter() {
            if Num::equals(cs, &el, &other).unwrap().get_value().unwrap() {
                return false;
            }
        }
    }

    for i in 0..(SIZE as usize) {
        let el = x[i];
        for other in y.iter() {
            if Num::equals(cs, &el, &other).unwrap().get_value().unwrap() {
                return false;
            }
        }
    }
    return true;
}

fn compute_determinant<
    E: Engine, 
    CS: ConstraintSystem<E>, 
    const SIZE: usize
>(
    cs: &mut CS,
    mds_matrix: &MdsMatrix<E, SIZE>    
)->Option<Num<E>> {
    if SIZE != 3 {
        return None;
    }
    let s123 = mds_matrix.data[0][0].mul(cs, &mds_matrix.data[1][1]).unwrap().mul(cs, &mds_matrix.data[2][2]).unwrap();
    let s132 = mds_matrix.data[0][0].mul(cs, &mds_matrix.data[1][2]).unwrap().mul(cs, &mds_matrix.data[2][1]).unwrap();
    let s213 = mds_matrix.data[0][1].mul(cs, &mds_matrix.data[1][0]).unwrap().mul(cs, &mds_matrix.data[2][2]).unwrap();
    let s231 = mds_matrix.data[0][1].mul(cs, &mds_matrix.data[1][2]).unwrap().mul(cs, &mds_matrix.data[2][0]).unwrap();
    let s312 = mds_matrix.data[0][2].mul(cs, &mds_matrix.data[1][0]).unwrap().mul(cs, &mds_matrix.data[2][1]).unwrap();
    let s321 = mds_matrix.data[0][2].mul(cs, &mds_matrix.data[1][1]).unwrap().mul(cs, &mds_matrix.data[2][0]).unwrap();

    let result = s123.add(cs, &s231).unwrap()
        .add(cs, &s312).unwrap()
        .sub(cs, &s132).unwrap()
        .sub(cs, &s321).unwrap()
        .sub(cs, &s213).unwrap();

    Some(result)
}

pub fn construct_inverse_matrix<
    E: Engine, 
    CS: ConstraintSystem<E>, 
    const SIZE: usize    
>(
    cs: &mut CS,
    mds_matrix: &MdsMatrix<E, SIZE>  
)-> Option<MdsMatrix<E, SIZE>> {
    if SIZE != 3 {
        return None;
    }
    let det = compute_determinant(cs, mds_matrix).unwrap();
    if det.is_zero(cs).unwrap().get_value().unwrap() {
        return None;
    }

    let mut mds_invert_matrix = MdsMatrix::<E,SIZE>::zero_matrix();

    for i in 0..(SIZE as usize) {
        for j in 0..(SIZE as usize) {
            let a = mds_matrix.data[(i+1)%3][(j+1)%3].mul(cs, &mds_matrix.data[(i+2)%3][(j+2)%3]).unwrap();
            let b = mds_matrix.data[(i+1)%3][(j+2)%3].mul(cs, &mds_matrix.data[(i+2)%3][(j+1)%3]).unwrap();
            let c = a.sub(cs, &b).unwrap();
            mds_invert_matrix.data[j][i] = c.div(cs, &det).unwrap();
        }
    }

    Some(mds_invert_matrix)
}

pub fn dot_product<
    E: Engine, 
    CS: ConstraintSystem<E>, 
    const SIZE: usize>(
    cs: &mut CS, 
    x: &[Num<E>; SIZE], 
    y: &[Num<E>; SIZE])->Num<E>{
    let mut res = Num::<E>::zero();
    for i in 0..SIZE {
        let z = x[i].mul(cs, &y[i]).unwrap();
        res = res.add(cs, &z).unwrap();
    }
    res
}

pub fn add_vectors<
    E: Engine, 
    CS: ConstraintSystem<E>, 
    const SIZE: usize>(
    cs: &mut CS, 
    x: &[Num<E>; SIZE], 
    y: &[Num<E>; SIZE])->[Num<E>;SIZE]{
    let mut res = [Num::<E>::zero(); SIZE];
    for i in 0..SIZE {
        res[i] = x[i].add(cs, &y[i]).unwrap();
    }
    res
}

pub fn sub_vectors<
    E: Engine, 
    CS: ConstraintSystem<E>, 
    const SIZE: usize>(
    cs: &mut CS, 
    x: &[Num<E>; SIZE], 
    y: &[Num<E>; SIZE])->[Num<E>;SIZE]{
    let mut res = [Num::<E>::zero(); SIZE];
    for i in 0..SIZE {
        res[i] = x[i].sub(cs, &y[i]).unwrap();
    }
    res
}
