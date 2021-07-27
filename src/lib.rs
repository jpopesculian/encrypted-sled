#[macro_use]
extern crate bitflags;

use cipher::generic_array;
use cipher::{CipherKey, NewCipher, Nonce, StreamCipher};
use core::fmt;
use core::marker::PhantomData;
use core::ops;
use generic_array::typenum;
use generic_array::GenericArray;
use sled::IVec;
use std::path::Path;
use std::sync::Arc;
use typenum::Unsigned;

bitflags! {
pub struct EncryptionMode: u32 {
    const KEY = 0b0001;
    const VALUE = 0b0010;
    const TREE_NAME = 0b0100;
}
}

#[derive(Clone)]
pub struct EncryptionCipher<C>
where
    C: StreamCipher + NewCipher,
{
    cipher: PhantomData<C>,
    key: CipherKey<C>,
    nonce: Nonce<C>,
    mode: EncryptionMode,
}

impl<C> EncryptionCipher<C>
where
    C: StreamCipher + NewCipher,
{
    pub fn new(key: CipherKey<C>, nonce: Nonce<C>, mode: EncryptionMode) -> Self {
        Self {
            cipher: PhantomData,
            key,
            nonce,
            mode,
        }
    }

    pub fn new_from_slices(
        key: &[u8],
        nonce: &[u8],
        mode: EncryptionMode,
    ) -> Result<Self, cipher::errors::InvalidLength> {
        let kl = C::KeySize::to_usize();
        let nl = C::NonceSize::to_usize();
        if key.len() != kl || nonce.len() != nl {
            Err(cipher::errors::InvalidLength)
        } else {
            let key = GenericArray::clone_from_slice(key);
            let nonce = GenericArray::clone_from_slice(nonce);
            Ok(Self::new(key, nonce, mode))
        }
    }

    #[inline]
    pub fn cipher(&self) -> C {
        C::new(&self.key, &self.nonce)
    }

    fn apply_to_data(&self, mut data: IVec, mode: EncryptionMode) -> IVec {
        if self.mode.contains(mode) {
            self.cipher().apply_keystream(&mut data);
        }
        data
    }
}

impl<C> fmt::Debug for EncryptionCipher<C>
where
    C: StreamCipher + NewCipher,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionCipher")
            .field("cipher", &core::any::type_name::<C>())
            .field("mode", &self.mode)
            .finish()
    }
}

const DEFAULT_TREE_NAME: &[u8] = b"__sled__default";

pub trait Encryption {
    fn encrypt(&self, data: IVec, mode: EncryptionMode) -> IVec;
    fn decrypt(&self, data: IVec, mode: EncryptionMode) -> IVec;
    #[inline]
    fn encrypt_ref<T: AsRef<[u8]>>(&self, data: T, mode: EncryptionMode) -> IVec {
        self.encrypt(data.as_ref().into(), mode)
    }
    #[inline]
    fn encrypt_ivec<T: Into<IVec>>(&self, data: T, mode: EncryptionMode) -> IVec {
        self.encrypt(data.into(), mode)
    }
    #[inline]
    fn decrypt_ref<T: AsRef<[u8]>>(&self, data: T, mode: EncryptionMode) -> IVec {
        self.decrypt(data.as_ref().into(), mode)
    }
    #[inline]
    fn decrypt_ivec<T: Into<IVec>>(&self, data: T, mode: EncryptionMode) -> IVec {
        self.decrypt(data.into(), mode)
    }
    #[inline]
    fn encrypt_key_ref<T: AsRef<[u8]>>(&self, data: T) -> IVec {
        self.encrypt_ref(data, EncryptionMode::KEY)
    }
    #[inline]
    fn encrypt_key_ivec<T: Into<IVec>>(&self, data: T) -> IVec {
        self.encrypt_ivec(data, EncryptionMode::KEY)
    }
    #[inline]
    fn decrypt_key_ref<T: AsRef<[u8]>>(&self, data: T) -> IVec {
        self.decrypt_ref(data, EncryptionMode::KEY)
    }
    #[inline]
    fn decrypt_key_ivec<T: Into<IVec>>(&self, data: T) -> IVec {
        self.decrypt_ivec(data, EncryptionMode::KEY)
    }
    #[inline]
    fn encrypt_value_ref<T: AsRef<[u8]>>(&self, data: T) -> IVec {
        self.encrypt_ref(data, EncryptionMode::VALUE)
    }
    #[inline]
    fn encrypt_value_ivec<T: Into<IVec>>(&self, data: T) -> IVec {
        self.encrypt_ivec(data, EncryptionMode::VALUE)
    }
    #[inline]
    fn decrypt_value_ref<T: AsRef<[u8]>>(&self, data: T) -> IVec {
        self.decrypt_ref(data, EncryptionMode::VALUE)
    }
    #[inline]
    fn decrypt_value_ivec<T: Into<IVec>>(&self, data: T) -> IVec {
        self.decrypt_ivec(data, EncryptionMode::VALUE)
    }
    fn encrypt_tree_name_ref<T: AsRef<[u8]>>(&self, data: T) -> IVec {
        if data.as_ref() == DEFAULT_TREE_NAME {
            return data.as_ref().into();
        }
        self.encrypt_ref(data, EncryptionMode::TREE_NAME)
    }
    fn encrypt_tree_name_ivec<T: Into<IVec>>(&self, data: T) -> IVec {
        let data = data.into();
        if data == DEFAULT_TREE_NAME {
            return data;
        }
        self.encrypt(data, EncryptionMode::TREE_NAME)
    }
    fn decrypt_tree_name_ref<T: AsRef<[u8]>>(&self, data: T) -> IVec {
        if data.as_ref() == DEFAULT_TREE_NAME {
            return data.as_ref().into();
        }
        self.decrypt_ref(data, EncryptionMode::TREE_NAME)
    }
    fn decrypt_tree_name_ivec<T: Into<IVec>>(&self, data: T) -> IVec {
        let data = data.into();
        if data == DEFAULT_TREE_NAME {
            return data;
        }
        self.decrypt(data, EncryptionMode::TREE_NAME)
    }
}

impl<T> Encryption for T
where
    T: ops::Deref,
    T::Target: Encryption,
{
    fn encrypt(&self, data: IVec, mode: EncryptionMode) -> IVec {
        self.deref().encrypt(data, mode)
    }
    fn decrypt(&self, data: IVec, mode: EncryptionMode) -> IVec {
        self.deref().decrypt(data, mode)
    }
}

impl<C> Encryption for EncryptionCipher<C>
where
    C: StreamCipher + NewCipher,
{
    fn encrypt(&self, data: IVec, mode: EncryptionMode) -> IVec {
        self.apply_to_data(data, mode)
    }
    fn decrypt(&self, data: IVec, mode: EncryptionMode) -> IVec {
        self.apply_to_data(data, mode)
    }
}

#[derive(Debug, Clone)]
pub struct Tree<E> {
    inner: sled::Tree,
    encryption: Arc<E>,
}

#[derive(Debug, Clone)]
pub struct Db<E> {
    inner: sled::Db,
    tree: Tree<E>,
    encryption: Arc<E>,
}

impl<E> ops::Deref for Db<E> {
    type Target = Tree<E>;
    fn deref(&self) -> &Tree<E> {
        &self.tree
    }
}

impl<E> Tree<E> {
    fn new(inner: sled::Tree, encryption: Arc<E>) -> Self {
        Self { inner, encryption }
    }
}

impl<E> Db<E> {
    fn new(inner: sled::Db, encryption: Arc<E>) -> Self {
        let tree = Tree::new(sled::Tree::clone(&inner), encryption.clone());
        Self {
            inner,
            tree,
            encryption,
        }
    }
}

impl<E> Db<E>
where
    E: Encryption,
{
    pub fn open_tree<V: AsRef<[u8]>>(&self, name: V) -> sled::Result<Tree<E>> {
        self.inner
            .open_tree(self.encryption.encrypt_tree_name_ref(name))
            .map(|tree| Tree::new(tree, self.encryption.clone()))
    }
    pub fn drop_tree<V: AsRef<[u8]>>(&self, name: V) -> sled::Result<bool> {
        self.inner
            .drop_tree(self.encryption.encrypt_tree_name_ref(name))
    }
    pub fn tree_names(&self) -> Vec<IVec> {
        self.inner
            .tree_names()
            .into_iter()
            .map(|name| self.encryption.decrypt_tree_name_ivec(name))
            .collect()
    }
    #[inline]
    pub fn was_recovered(&self) -> bool {
        self.inner.was_recovered()
    }
    #[inline]
    pub fn generate_id(&self) -> sled::Result<u64> {
        self.inner.generate_id()
    }
    #[inline]
    pub fn checksum(&self) -> sled::Result<u32> {
        self.inner.checksum()
    }
    #[inline]
    pub fn size_on_disk(&self) -> sled::Result<u64> {
        self.inner.size_on_disk()
    }

    // TODO implement export and import
}

pub fn open<P: AsRef<Path>, E: Encryption>(path: P, encryption: E) -> sled::Result<Db<E>> {
    sled::open(path).map(|db| Db::new(db, Arc::new(encryption)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20::ChaCha20;

    const ENCRYPTION_KEY: &[u8] = b"an example very very secret key.";
    const ENCRYPTION_NONCE: &[u8] = b"secret nonce";

    #[test]
    fn it_works() {
        let db = open(
            "/tmp/test.db",
            EncryptionCipher::<ChaCha20>::new_from_slices(
                ENCRYPTION_KEY,
                ENCRYPTION_NONCE,
                EncryptionMode::VALUE | EncryptionMode::TREE_NAME,
            )
            .unwrap(),
        )
        .unwrap();
        let tree = db.open_tree("hello").unwrap();
        panic!(
            "{:?} {:?}",
            db.tree_names()
                .iter()
                .map(|name| String::from_utf8_lossy(&name).to_owned())
                .collect::<Vec<_>>(),
            db.inner
                .tree_names()
                .iter()
                .map(|name| String::from_utf8_lossy(&name).to_owned())
                .collect::<Vec<_>>(),
        );
    }
}
