use std::collections::HashMap;

use num_bigint::{BigUint};

use crate::store::Storer;

#[derive(Debug)]
pub struct MemStore {
    generator: BigUint,
    members: HashMap<Vec<u8>, Vec<u8>>,
    modulo: BigUint,
    state: BigUint,
}

impl MemStore {
    pub fn new(
        generator: BigUint,
        members: HashMap<Vec<u8>, Vec<u8>>,
        modulo: BigUint,
        state: BigUint
    ) -> Self {
        MemStore { generator, members, modulo, state }
    }
}

impl Storer for MemStore {
    fn get_generator(&self) -> &BigUint {
        &self.generator
    }
    fn get_members_list(&self) -> &HashMap<Vec<u8>, Vec<u8>> {
        &self.members
    }
    fn get_modulus(&self) -> &BigUint {
        &self.modulo
    }
    fn get_state(&mut self) -> &BigUint {
        &self.state
    }
    fn set_state(&mut self, new_state: &BigUint) {
        self.state = new_state.clone();
    }
}
