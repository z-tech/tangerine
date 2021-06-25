pub mod mem_store;

use std::collections::HashMap;
use num_bigint::{BigUint};

pub trait Storer {
    fn get_generator(&self) -> &BigUint;
    fn get_members_list(&self) -> &HashMap<Vec<u8>, Vec<u8>>;
    fn get_modulus(&self) -> &BigUint;
    fn get_state(&mut self) -> &BigUint;
    fn set_state(&mut self, new_state: &BigUint);
}
