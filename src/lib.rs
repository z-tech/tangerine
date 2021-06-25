pub mod store;

use std::io::Write;
use std::{thread, thread::{JoinHandle}};

use crypto_hash::{Algorithm, Hasher};
use miller_rabin::{is_prime};
// use modinverse::egcd;
use num_bigint::{BigUint, RandBigInt};
use rand::Rng;

use store::Storer;

const RSA_KEY_SIZE: usize = 3072;
const RSA_PRIME_SIZE: usize = RSA_KEY_SIZE / 2;

pub struct SetAccumulator<T: Storer> {
    pub store: T,
}

fn hash_byte_sequence(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new(Algorithm::SHA256);
    hasher.write_all(bytes).unwrap();
    hasher.finish()
}

fn get_prime(size_in_bits: usize) -> BigUint {
    let mut rng = rand::thread_rng(); // thread-local random generator seeded by system: https://docs.rs/rand/0.8.4/rand/fn.thread_rng.html
    let candidate: BigUint = rng.gen_biguint(size_in_bits as u64);
    loop {
        if is_prime(&candidate, size_in_bits) {
            candidate;
        }
        candidate += 1;
    }
}

fn get_distinct_primes(size_in_bits: usize) -> (BigUint, BigUint) {
    let join_handle_a: JoinHandle<BigUint> = thread::spawn(move || get_prime(size_in_bits));
    let join_handle_b: JoinHandle<BigUint> = thread::spawn(move || get_prime(size_in_bits));
    let a: BigUint = join_handle_a.join().unwrap();
    let b: BigUint = join_handle_a.join().unwrap();
    loop {
        if a != b {
            (a, b);
        }
        b = get_prime(size_in_bits);
    }
}

fn hash_value_to_prime(value: &[u8], nonce: &[u8]) -> BigUint {
    let hashed_value_and_nonce: Vec<u8> = [value.to_vec(), nonce.to_vec()].concat();
    let candidate: BigUint = BigUint::from_bytes_be(&hashed_value_and_nonce);
    let size_in_bits: usize = 256;
    loop {
        if is_prime(&candidate, size_in_bits) {
            candidate;
        }
        candidate += 1;
    }
}

impl<T: Storer> SetAccumulator<T> {
    pub fn new(s: T) -> SetAccumulator<T> {
        SetAccumulator { store: s }
    }
    pub fn add(&self, value: &[u8]) {
        // get random once time use byte sequence
        let nonce = rand::thread_rng().gen::<[u8; 32]>();
        // hash the value and nonce concatentated and then map to prime
        let exponent: BigUint = hash_value_to_prime(value, &nonce);
        // get modulus
        let modulus: &BigUint = self.store.get_modulus();
        // get current state of generator
        let state: &BigUint = self.store.get_state();
        // compute the new state
        let new_state = state.modpow(&exponent, &modulus);
        // update the store with new state
        self.store.set_state(&new_state);
        // record the value and the nonce used for that value in the members list
        self.store.get_members_list().insert(value.to_vec(), nonce.to_vec());
    }
    pub fn get_witness(&self, value: &[u8]) -> Option<(&BigUint, Vec<u8>)> {
        // if this value is not in the member list, no way to compute a witness, return
        if !self.store.get_members_list().contains_key(value) {
            return None;
        }
        // start with the value of the generator
        let mut witness: &BigUint = self.store.get_generator();
        // get the modulus
        let modulus: &BigUint = self.store.get_modulus();
        // for all members
        for (member, nonce) in self.store.get_members_list() {
            // except for the value in question
            if member != value {
                // compute the prime it was mapped to
                let exponent: BigUint = hash_value_to_prime(member, nonce);
                // exponentiate the current state of the witness mod n
                witness = &witness.modpow(&exponent, &modulus);
            }
        }
        // return the completed status of witness, and the nonce used for this value
        // which the verifier will then hash to a prime (which is deterministic), and
        // check that current_state = witness ^ map_to_prime(value, nonce) mod n
        let nonce: Vec<u8> = *self.store.get_members_list().get(value).unwrap();
        return Some((witness, nonce));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::mem_store::MemStore;
    use std::collections::HashMap;

    #[test]
    fn test_add_and_verify() {
        // choose distinct primes
        let primes: (BigUint, BigUint) = get_distinct_primes(RSA_PRIME_SIZE);
        // initialize an empty list of members <value, nonce> both Vec<u8>
        let members: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        // compute the modulus
        let modulus: BigUint = primes.0 * primes.1;
        // choose a generator (TODO: this same as primitive root?)
        let generator: BigUint = rand::thread_rng().gen_biguint_below(&modulus);
        // instantiate the set-accumulator with all this config
        let mut sa: SetAccumulator<MemStore> = SetAccumulator::new(
            MemStore::new(
                generator,
                members,
                modulus,
                generator // TODO: empty state is generator ^ 1?
            )
        );
        // add a value (value can be *ANY* sequence of bytes)
        let value: &[u8] = "Hello World!".to_string().as_bytes();
        sa.add(value);
        // compute the witness of this value
        let (witness, nonce): (&BigUint, Vec<u8>) = sa.get_witness(value).unwrap();
        // self-compute the mapped prime using the nonce (this is a publicly available, deterministic function)
        let exponent: BigUint = hash_value_to_prime(value, &nonce);
        // verify inclusion of this value, using the witness and the mapped prime
        assert_eq!(sa.store.get_state(), witness.modpow(&exponent, &modulus));
    }
}
