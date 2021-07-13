pub mod store;

use std::io::Write;

use crypto_hash::{Algorithm, Hasher};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{Zero, One};
use rand::Rng;

use store::Storer;

pub struct SetAccumulator<T: Storer> {
    pub store: T,
}

fn hash_byte_sequence(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new(Algorithm::SHA256);
    hasher.write_all(bytes).unwrap();
    hasher.finish()
}

fn miller_rabin(candidate: &BigUint) -> bool {
    let f0: BigUint = Zero::zero();
    let f1: BigUint = One::one();
    let f2: BigUint = BigUint::from_bytes_be(&2_u64.to_be_bytes().to_vec());

    let mut d: BigUint = candidate.clone() - f1.clone();
    let mut t: BigUint = f0.clone();
    while d.modpow(&f1, &f2) == f0 {
        d /= f2.clone();
        t += f1.clone();
    }

    for _trial in 0..5 {
        let mut rng = rand::thread_rng(); // thread-local random generator seeded by system: https://docs.rs/rand/0.8.4/rand/fn.thread_rng.html
        let a: BigUint = rng.gen_biguint_range(&f2, &(candidate - f1.clone()));
        let mut v: BigUint = a.modpow(&d, &candidate);
        if v != f1 {
            let mut i: BigUint = f0.clone();
            while v != (candidate.clone() - f1.clone()) {
                if i == t.clone() - f1.clone() {
                    return false;
                } else {
                    i = i + f1.clone();
                    v = v.modpow(&f2, &candidate);
                }
            }
        }

    }
    return true;
}

fn is_prime(candidate: &BigUint) -> bool {
    let f0: BigUint = Zero::zero();
    let f1: BigUint = One::one();

    // if less than two, not prime
    if *candidate == f0 || *candidate == f1 {
        return false;
    }

    let small_primes: Vec<u64> = vec![
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
        67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
        139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
        223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
        293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
        383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461,
        463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563,
        569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643,
        647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739,
        743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829,
        839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937,
        941, 947, 953, 967, 971, 977, 983, 991, 997
    ];

    // eliminate a good deal of candidates by checking first hundred or so primes
    for small_prime in small_primes.iter() {
        // make the prime into a BigUint
        let small_prime_bytes: Vec<u8> = small_prime.to_be_bytes().to_vec();
        let small_prime_biguint: BigUint = BigUint::from_bytes_be(&small_prime_bytes);

        // if the candidate *is* one of these small primes, candidate is prime
        if *candidate == small_prime_biguint {
            return true;
        }

        // if the candidate is divisible by the prime, candidate is not a prime
        if candidate.modpow(&f1, &small_prime_biguint) == f0 {
            return false;
        }
    }

    return miller_rabin(&candidate);
}

fn hash_value_to_prime(value: &[u8], nonce: &[u8]) -> BigUint {
    let f1: BigUint = One::one();
    let value_and_nonce: Vec<u8> = [value.to_vec(), nonce.to_vec()].concat();
    let hashed_value_and_nonce: Vec<u8> = hash_byte_sequence(&value_and_nonce);
    let mut candidate: BigUint = BigUint::from_bytes_be(&hashed_value_and_nonce);
    loop {
        if is_prime(&candidate) {
            return candidate.clone();
        }
        candidate += f1.clone();
    }
}

impl<T: Storer> SetAccumulator<T> {
    pub fn new(s: T) -> SetAccumulator<T> {
        SetAccumulator { store: s }
    }
    pub fn add(&mut self, value: &[u8]) {
        // get random once time use byte sequence
        let nonce = rand::thread_rng().gen::<[u8; 32]>();
        // hash the value and nonce concatentated and then map to prime
        let exponent: BigUint = hash_value_to_prime(value, &nonce);
        // get modulus
        let modulus: BigUint = self.store.get_modulus();
        // get current state of generator
        let state: BigUint = self.store.get_state();
        // compute the new state
        let new_state = state.modpow(&exponent, &modulus);
        // update the store with new state
        self.store.set_state(&new_state);
        // record the value and the nonce used for that value in the members list
        self.store.get_members_list().insert(value.to_vec(), nonce.to_vec());
    }
    pub fn get_witness(&mut self, value: &[u8]) -> Option<(BigUint, Vec<u8>)> {
        // if this value is not in the member list, no way to compute a witness, return
        if !self.store.get_members_list().contains_key(value) {
            return None;
        }
        // start with the value of the generator
        let mut witness: BigUint = self.store.get_generator();
        // get the modulus
        let modulus: BigUint = self.store.get_modulus();
        // for all members
        for (member, nonce) in self.store.get_members_list() {
            // except for the value in question
            if member != value {
                // compute the prime it was mapped to
                let exponent: BigUint = hash_value_to_prime(member, nonce);
                // exponentiate the current state of the witness mod n
                witness = witness.modpow(&exponent, &modulus);
            }
        }
        // return the completed status of witness, and the nonce used for this value
        // which the verifier will then hash to a prime (which is deterministic), and
        // check that current_state = witness ^ map_to_prime(value, nonce) mod n
        let nonce: Vec<u8> = self.store.get_members_list().get(value).unwrap().to_vec();
        return Some((witness.clone(), nonce));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::mem_store::MemStore;
    use std::collections::HashMap;
    use std::{thread, thread::{JoinHandle}};

    // NOTE: unnecessarily big for test cases
    // const RSA_KEY_SIZE: usize = 3072;
    // const RSA_PRIME_SIZE: usize = RSA_KEY_SIZE / 2;

    fn get_prime(size_in_bits: usize) -> BigUint {
        let mut rng = rand::thread_rng(); // thread-local random generator seeded by system: https://docs.rs/rand/0.8.4/rand/fn.thread_rng.html
        loop {
            let candidate: BigUint = rng.gen_biguint(size_in_bits as u64);
            if is_prime(&candidate) {
                return candidate.clone();
            }
        }
    }

    fn get_distinct_primes(size_in_bits: usize) -> (BigUint, BigUint) {
        let join_handle_a: JoinHandle<BigUint> = thread::spawn(move || get_prime(size_in_bits));
        let join_handle_b: JoinHandle<BigUint> = thread::spawn(move || get_prime(size_in_bits));
        let a: BigUint = join_handle_a.join().unwrap();
        let mut b: BigUint = join_handle_b.join().unwrap();
        loop {
            if a != b {
                return (a.clone(), b);
            }
            b = get_prime(size_in_bits);
        }
    }

    #[test]
    fn test_is_prime() {
        let zero: BigUint = BigUint::from_bytes_be(&0_u64.to_be_bytes().to_vec());
        let one: BigUint = BigUint::from_bytes_be(&1_u64.to_be_bytes().to_vec());
        let two: BigUint = BigUint::from_bytes_be(&2_u64.to_be_bytes().to_vec());
        let three: BigUint = BigUint::from_bytes_be(&3_u64.to_be_bytes().to_vec());
        let twenty_nine: BigUint = BigUint::from_bytes_be(&29_u64.to_be_bytes().to_vec());
        let eighty_seven: BigUint = twenty_nine.clone() * three;
        assert_eq!(false, is_prime(&zero));
        assert_eq!(false, is_prime(&one));
        assert_eq!(true, is_prime(&two));
        assert_eq!(true, is_prime(&twenty_nine));
        assert_eq!(false, is_prime(&eighty_seven));

        let prime: BigUint = BigUint::from_bytes_be(&55340232221128654847_u128.to_be_bytes().to_vec());
        assert_eq!(true, is_prime(&prime));

        let not_prime: BigUint = BigUint::from_bytes_be(&55340232221128654848_u128.to_be_bytes().to_vec());
        assert_eq!(false, is_prime(&not_prime));

        // these can be extended and improved
    }

    #[test]
    fn test_add_and_verify() {
        // choose distinct primes
        let primes: (BigUint, BigUint) = get_distinct_primes(512);
        // initialize an empty list of members <value, nonce> both Vec<u8>
        let members: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        // compute the modulus
        let modulus: BigUint = primes.0 * primes.1;
        // choose a generator (TODO: how do we know this is a generator?)
        let generator: BigUint = rand::thread_rng().gen_biguint_below(&modulus);
        // instantiate the set-accumulator with all this config
        let mut sa: SetAccumulator<MemStore> = SetAccumulator::new(
            MemStore::new(
                generator.clone(),
                members,
                modulus.clone(),
                generator.clone() // TODO: empty state is generator ^ 1?
            )
        );
        // add a value (value can be *ANY* sequence of bytes)
        let hello_world: String = "Hello World!".to_string();
        let value: &[u8] = hello_world.as_bytes();
        sa.add(value);
        // compute the witness of this value
        let (witness, nonce): (BigUint, Vec<u8>) = sa.get_witness(value).unwrap();
        // self-compute the mapped prime using the nonce (this is a publicly available, deterministic function)
        let exponent: BigUint = hash_value_to_prime(value, &nonce);
        // verify inclusion of this value, using the witness and the mapped prime
        assert_eq!(sa.store.get_state(), witness.modpow(&exponent, &modulus));
    }
}
