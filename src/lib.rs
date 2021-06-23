use std::{thread, thread::{JoinHandle}};

use miller_rabin::{is_prime};
use num_bigint::{BigUint, RandBigInt};

fn get_prime(size_in_bits: usize) -> BigUint {
    let mut rng = rand::thread_rng(); // thread-local random generator seeded by system: https://docs.rs/rand/0.8.4/rand/fn.thread_rng.html
    let candidate: BigUint = rng.gen_biguint(size_in_bits as u64);

    loop {
        if is_prime(&candidate, size_in_bits) {
            return candidate;
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
            return (a, b);
        }
        b = get_prime(size_in_bits);
    }
}
