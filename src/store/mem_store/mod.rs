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
    fn get_generator(&mut self) -> BigUint {
        return self.generator.clone();
    }
    fn get_members_list(&mut self) -> &mut HashMap<Vec<u8>, Vec<u8>> {
        &mut self.members
    }
    fn get_modulus(&mut self) -> BigUint {
        return self.modulo.clone();
    }
    fn get_state(&mut self) -> BigUint {
        return self.state.clone();
    }
    fn set_state(&mut self, new_state: &BigUint) {
        self.state = new_state.clone();
    }
}
