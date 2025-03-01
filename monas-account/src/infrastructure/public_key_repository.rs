use crate::infrastructure::key_pair::KeyPair;

pub trait PersistenceKey {
    type Error;

    fn get(&self) -> Result<KeyPair, Self::Error>;

    fn save(&self, key_pair: &KeyPair) -> Result<(), Self::Error>;

    fn delete(&mut self) -> Result<(), Self::Error>;
}
