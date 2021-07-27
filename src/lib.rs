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

pub type Result<T, E = sled::Error> = std::result::Result<T, E>;

bitflags! {
pub struct EncryptionMode: u32 {
    const KEY = 0b0001;
    const VALUE = 0b0010;
    const TREE_NAME = 0b0100;
}
}

impl Default for EncryptionMode {
    fn default() -> Self {
        EncryptionMode::VALUE
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
    fn decrypt_value_result(&self, res: Result<Option<IVec>>) -> Result<Option<IVec>> {
        res.map(|val| val.map(|val| self.decrypt(val, EncryptionMode::VALUE)))
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

impl<E> Tree<E> {
    fn new(inner: sled::Tree, encryption: Arc<E>) -> Self {
        Self { inner, encryption }
    }
}

#[derive(Debug, Clone)]
pub struct Db<E> {
    inner: sled::Db,
    tree: Tree<E>,
    encryption: Arc<E>,
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

impl<E> ops::Deref for Db<E> {
    type Target = Tree<E>;
    fn deref(&self) -> &Tree<E> {
        &self.tree
    }
}

#[derive(Debug, Clone)]
pub struct Config<E> {
    inner: sled::Config,
    encryption: Arc<E>,
}

macro_rules! config_fn {
    ($name:ident, $t:ty) => {
        pub fn $name(self, to: $t) -> Self {
            Self {
                inner: self.inner.$name(to),
                encryption: self.encryption,
            }
        }
    };
}

impl<E> Config<E>
where
    E: Encryption,
{
    pub fn new(encryption: E) -> Self {
        Self {
            inner: sled::Config::new(),
            encryption: Arc::new(encryption),
        }
    }
    pub fn path<P: AsRef<Path>>(self, path: P) -> Self {
        Self {
            inner: self.inner.path(path),
            encryption: self.encryption,
        }
    }
    pub fn open(&self) -> Result<Db<E>> {
        self.inner
            .open()
            .map(move |db| Db::new(db, self.encryption.clone()))
    }
    config_fn!(cache_capacity, u64);
    config_fn!(mode, sled::Mode);
    config_fn!(use_compression, bool);
    config_fn!(compression_factor, i32);
    config_fn!(temporary, bool);
    config_fn!(create_new, bool);
    config_fn!(print_profile_on_drop, bool);
}

impl<E> Db<E>
where
    E: Encryption,
{
    pub fn open_tree<V: AsRef<[u8]>>(&self, name: V) -> Result<Tree<E>> {
        self.inner
            .open_tree(self.encryption.encrypt_tree_name_ref(name))
            .map(|tree| Tree::new(tree, self.encryption.clone()))
    }
    pub fn drop_tree<V: AsRef<[u8]>>(&self, name: V) -> Result<bool> {
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
    pub fn generate_id(&self) -> Result<u64> {
        self.inner.generate_id()
    }
    #[inline]
    pub fn checksum(&self) -> Result<u32> {
        self.inner.checksum()
    }
    #[inline]
    pub fn size_on_disk(&self) -> Result<u64> {
        self.inner.size_on_disk()
    }

    // TODO implement export and import
}

impl<E> Tree<E>
where
    E: Encryption,
{
    pub fn insert<K, V>(&self, key: K, value: V) -> Result<Option<IVec>>
    where
        K: AsRef<[u8]>,
        V: Into<IVec>,
    {
        self.encryption.decrypt_value_result(self.inner.insert(
            self.encryption.encrypt_key_ref(key),
            self.encryption.encrypt_value_ivec(value),
        ))
    }

    // TODO implement transaction
    // TODO implement batch

    pub fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<IVec>> {
        self.encryption
            .decrypt_value_result(self.inner.get(self.encryption.encrypt_key_ref(key)))
    }

    pub fn remove<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<IVec>> {
        self.encryption
            .decrypt_value_result(self.inner.remove(self.encryption.encrypt_key_ref(key)))
    }

    pub fn compare_and_swap<K, OV, NV>(
        &self,
        key: K,
        old: Option<OV>,
        new: Option<NV>,
    ) -> Result<Result<(), sled::CompareAndSwapError>>
    where
        K: AsRef<[u8]>,
        OV: AsRef<[u8]>,
        NV: Into<IVec>,
    {
        self.inner.compare_and_swap(
            self.encryption.encrypt_key_ref(key),
            old.map(|val| self.encryption.encrypt_value_ref(val)),
            new.map(|val| self.encryption.encrypt_value_ivec(val)),
        )
    }

    pub fn update_and_fetch<K, V, F>(&self, key: K, mut f: F) -> Result<Option<IVec>>
    where
        K: AsRef<[u8]>,
        F: FnMut(Option<IVec>) -> Option<V>,
        V: Into<IVec>,
    {
        let new_f = move |old: Option<&[u8]>| {
            f(old.map(|val| self.encryption.decrypt_value_ref(val)))
                .map(|val| self.encryption.encrypt_value_ivec(val))
        };
        self.encryption.decrypt_value_result(
            self.inner
                .update_and_fetch(self.encryption.encrypt_key_ref(key), new_f),
        )
    }

    pub fn fetch_and_update<K, V, F>(&self, key: K, mut f: F) -> Result<Option<IVec>>
    where
        K: AsRef<[u8]>,
        F: FnMut(Option<IVec>) -> Option<V>,
        V: Into<IVec>,
    {
        let new_f = move |old: Option<&[u8]>| {
            f(old.map(|val| self.encryption.decrypt_value_ref(val)))
                .map(|val| self.encryption.encrypt_value_ivec(val))
        };
        self.encryption.decrypt_value_result(
            self.inner
                .fetch_and_update(self.encryption.encrypt_key_ref(key), new_f),
        )
    }

    #[inline]
    pub fn flush(&self) -> Result<usize> {
        self.inner.flush()
    }

    #[inline]
    pub async fn flush_async(&self) -> Result<usize> {
        self.inner.flush_async().await
    }
}

pub fn open<P: AsRef<Path>, E: Encryption>(path: P, encryption: E) -> Result<Db<E>> {
    sled::open(path).map(|db| Db::new(db, Arc::new(encryption)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20::ChaCha20;

    const ENCRYPTION_KEY: &[u8] = b"an example very very secret key.";
    const ENCRYPTION_NONCE: &[u8] = b"secret nonce";

    fn temp_db(mode: EncryptionMode) -> Db<EncryptionCipher<ChaCha20>> {
        Config::new(
            EncryptionCipher::<ChaCha20>::new_from_slices(ENCRYPTION_KEY, ENCRYPTION_NONCE, mode)
                .unwrap(),
        )
        .temporary(true)
        .open()
        .unwrap()
    }

    fn str_res(res: Result<Option<IVec>>) -> Result<Option<String>> {
        res.map(|val| val.map(|val| String::from_utf8_lossy(&val).to_string()))
    }

    #[test]
    fn insert() {
        let db = temp_db(EncryptionMode::all());
        let tree = db.open_tree("hello").unwrap();
        tree.insert("hello", "hi").unwrap();
        assert_eq!(Ok(Some("hi".to_string())), str_res(tree.get("hello")));
        assert_eq!(Ok(None), str_res(tree.inner.get("hello")));
        tree.remove("hello").unwrap();
        assert_eq!(Ok(None), str_res(tree.get("hello")));
        assert_eq!(Ok(None), str_res(tree.inner.get("hello")));
    }

    fn u64_to_ivec(number: u64) -> IVec {
        IVec::from(number.to_be_bytes().to_vec())
    }

    fn increment(old: Option<IVec>) -> Option<Vec<u8>> {
        let number = match old {
            Some(bytes) => {
                let mut array = [0; 8];
                array.copy_from_slice(&bytes);
                let number = u64::from_be_bytes(array);
                number + 1
            }
            None => 0,
        };

        Some(number.to_be_bytes().to_vec())
    }

    #[test]
    fn update_and_fetch() {
        let db = temp_db(EncryptionMode::all());

        let zero = u64_to_ivec(0);
        let one = u64_to_ivec(1);
        let two = u64_to_ivec(2);
        let three = u64_to_ivec(3);

        assert_eq!(db.update_and_fetch("counter", increment), Ok(Some(zero)));
        assert_eq!(db.update_and_fetch("counter", increment), Ok(Some(one)));
        assert_eq!(db.update_and_fetch("counter", increment), Ok(Some(two)));
        assert_eq!(db.update_and_fetch("counter", increment), Ok(Some(three)));
    }

    #[test]
    fn fetch_and_update() {
        let db = temp_db(EncryptionMode::all());

        let zero = u64_to_ivec(0);
        let one = u64_to_ivec(1);
        let two = u64_to_ivec(2);

        assert_eq!(db.fetch_and_update("counter", increment), Ok(None));
        assert_eq!(db.fetch_and_update("counter", increment), Ok(Some(zero)));
        assert_eq!(db.fetch_and_update("counter", increment), Ok(Some(one)));
        assert_eq!(db.fetch_and_update("counter", increment), Ok(Some(two)));
    }
}
