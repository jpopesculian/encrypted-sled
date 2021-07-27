#[macro_use]
extern crate bitflags;

use cipher::generic_array;
use cipher::{CipherKey, NewCipher, Nonce, StreamCipher};
use core::fmt;
use core::marker::PhantomData;
use core::ops;
use generic_array::typenum;
use generic_array::GenericArray;
use std::path::Path;
use std::sync::Arc;
use typenum::Unsigned;

pub use sled::{CompareAndSwapError, Error, Event, IVec, MergeOperator, Mode};

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
    fn decrypt_value_result<E>(&self, res: Result<Option<IVec>, E>) -> Result<Option<IVec>, E> {
        res.map(|val| val.map(|val| self.decrypt(val, EncryptionMode::VALUE)))
    }
    fn decrypt_key_value_result(
        &self,
        res: Result<Option<(IVec, IVec)>>,
    ) -> Result<Option<(IVec, IVec)>> {
        res.map(|val| {
            val.map(|(key, val)| {
                (
                    self.decrypt(key, EncryptionMode::KEY),
                    self.decrypt(val, EncryptionMode::VALUE),
                )
            })
        })
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
    pub(crate) fn new(inner: sled::Tree, encryption: Arc<E>) -> Self {
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
    pub(crate) fn new(inner: sled::Db, encryption: Arc<E>) -> Self {
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

#[derive(Debug, Clone)]
enum BatchCommand {
    Insert(IVec, IVec),
    Remove(IVec),
}

#[derive(Debug, Clone, Default)]
pub struct Batch {
    commands: Vec<BatchCommand>,
}

impl Batch {
    pub fn insert<K, V>(&mut self, key: K, value: V)
    where
        K: Into<IVec>,
        V: Into<IVec>,
    {
        self.commands
            .push(BatchCommand::Insert(key.into(), value.into()))
    }
    pub fn remove<K>(&mut self, key: K)
    where
        K: Into<IVec>,
    {
        self.commands.push(BatchCommand::Remove(key.into()))
    }
    fn to_encrypted<E: Encryption>(self, encryption: &E) -> sled::Batch {
        let mut batch = sled::Batch::default();
        for command in self.commands {
            match command {
                BatchCommand::Insert(k, v) => batch.insert(
                    encryption.encrypt_key_ivec(k),
                    encryption.encrypt_value_ivec(v),
                ),
                BatchCommand::Remove(k) => batch.remove(encryption.encrypt_key_ivec(k)),
            }
        }
        batch
    }
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

pub struct Iter<E> {
    inner: sled::Iter,
    encryption: Arc<E>,
}

impl<E> Iter<E> {
    pub(crate) fn new(inner: sled::Iter, encryption: Arc<E>) -> Self {
        Self { inner, encryption }
    }
}

impl<E> Iter<E>
where
    E: Encryption + Send + Sync,
{
    pub fn keys(self) -> impl DoubleEndedIterator<Item = Result<IVec>> + Send + Sync {
        let encryption = self.encryption;
        self.inner
            .keys()
            .map(move |key_res| key_res.map(|key| encryption.decrypt_key_ivec(key)))
    }
    pub fn values(self) -> impl DoubleEndedIterator<Item = Result<IVec>> + Send + Sync {
        let encryption = self.encryption;
        self.inner
            .values()
            .map(move |key_res| key_res.map(|key| encryption.decrypt_value_ivec(key)))
    }
}

impl<E> Iterator for Iter<E>
where
    E: Encryption,
{
    type Item = Result<(IVec, IVec)>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|res| {
            res.map(|(k, v)| {
                (
                    self.encryption.decrypt_key_ivec(k),
                    self.encryption.decrypt_value_ivec(v),
                )
            })
        })
    }
}

impl<E> DoubleEndedIterator for Iter<E>
where
    E: Encryption,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back().map(|res| {
            res.map(|(k, v)| {
                (
                    self.encryption.decrypt_key_ivec(k),
                    self.encryption.decrypt_value_ivec(v),
                )
            })
        })
    }
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

    // TODO implement watch_prefix

    pub fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<IVec>> {
        self.encryption
            .decrypt_value_result(self.inner.get(self.encryption.encrypt_key_ref(key)))
    }

    pub fn remove<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<IVec>> {
        self.encryption
            .decrypt_value_result(self.inner.remove(self.encryption.encrypt_key_ref(key)))
    }

    pub fn transaction<F, A, Error>(&self, f: F) -> transaction::TransactionResult<A, Error>
    where
        F: Fn(
            &transaction::TransactionalTree<E>,
        ) -> transaction::ConflictableTransactionResult<A, Error>,
    {
        self.inner.transaction(|tree| {
            f(&transaction::TransactionalTree::new(
                tree.clone(),
                self.encryption.clone(),
            ))
        })
    }

    pub fn apply_batch(&self, batch: Batch) -> Result<()> {
        self.inner.apply_batch(batch.to_encrypted(&self.encryption))
    }

    pub fn compare_and_swap<K, OV, NV>(
        &self,
        key: K,
        old: Option<OV>,
        new: Option<NV>,
    ) -> Result<Result<(), CompareAndSwapError>>
    where
        K: AsRef<[u8]>,
        OV: AsRef<[u8]>,
        NV: Into<IVec>,
    {
        self.inner
            .compare_and_swap(
                self.encryption.encrypt_key_ref(key),
                old.map(|val| self.encryption.encrypt_value_ref(val)),
                new.map(|val| self.encryption.encrypt_value_ivec(val)),
            )
            .map(|res| {
                res.map_err(|cas| CompareAndSwapError {
                    current: cas.current.map(|v| self.encryption.decrypt_value_ivec(v)),
                    proposed: cas.proposed.map(|v| self.encryption.decrypt_value_ivec(v)),
                })
            })
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

    pub fn contains_key<K: AsRef<[u8]>>(&self, key: K) -> Result<bool> {
        self.inner
            .contains_key(self.encryption.encrypt_key_ref(key))
    }

    pub fn get_lt<K>(&self, key: K) -> Result<Option<(IVec, IVec)>>
    where
        K: AsRef<[u8]>,
    {
        self.encryption
            .decrypt_key_value_result(self.inner.get_lt(self.encryption.encrypt_key_ref(key)))
    }

    pub fn get_gt<K>(&self, key: K) -> Result<Option<(IVec, IVec)>>
    where
        K: AsRef<[u8]>,
    {
        self.encryption
            .decrypt_key_value_result(self.inner.get_gt(self.encryption.encrypt_key_ref(key)))
    }

    pub fn first(&self) -> Result<Option<(IVec, IVec)>> {
        self.encryption.decrypt_key_value_result(self.inner.first())
    }
    pub fn last(&self) -> Result<Option<(IVec, IVec)>> {
        self.encryption.decrypt_key_value_result(self.inner.last())
    }
    pub fn pop_min(&self) -> Result<Option<(IVec, IVec)>> {
        self.encryption
            .decrypt_key_value_result(self.inner.pop_min())
    }
    pub fn pop_max(&self) -> Result<Option<(IVec, IVec)>> {
        self.encryption
            .decrypt_key_value_result(self.inner.pop_max())
    }

    pub fn iter(&self) -> Iter<E> {
        Iter::new(self.inner.iter(), self.encryption.clone())
    }

    pub fn range<K, R>(&self, range: R) -> Iter<E>
    where
        K: AsRef<[u8]>,
        R: ops::RangeBounds<K>,
    {
        let encrypt_bound = |bound: ops::Bound<&K>| -> ops::Bound<IVec> {
            match bound {
                ops::Bound::Unbounded => ops::Bound::Unbounded,
                ops::Bound::Included(x) => ops::Bound::Included(self.encryption.encrypt_key_ref(x)),
                ops::Bound::Excluded(x) => ops::Bound::Excluded(self.encryption.encrypt_key_ref(x)),
            }
        };
        let range = (
            encrypt_bound(range.start_bound()),
            encrypt_bound(range.end_bound()),
        );
        Iter::new(self.inner.range(range), self.encryption.clone())
    }

    pub fn scan_prefix<P>(&self, prefix: P) -> Iter<E>
    where
        P: AsRef<[u8]>,
    {
        Iter::new(
            self.inner
                .scan_prefix(self.encryption.encrypt_key_ref(prefix)),
            self.encryption.clone(),
        )
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    #[inline]
    pub fn clear(&self) -> Result<()> {
        self.inner.clear()
    }
    pub fn name(&self) -> IVec {
        self.encryption.decrypt_tree_name_ivec(self.inner.name())
    }
    #[inline]
    pub fn checksum(&self) -> Result<u32> {
        self.inner.checksum()
    }
}

impl<E> Tree<E>
where
    E: Encryption + 'static,
{
    pub fn merge<K, V>(&self, key: K, value: V) -> Result<Option<IVec>>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.encryption.decrypt_value_result(self.inner.merge(
            self.encryption.encrypt_key_ref(key),
            self.encryption.encrypt_value_ref(value),
        ))
    }

    pub fn set_merge_operator(&self, merge_operator: impl sled::MergeOperator + 'static) {
        let encryption = self.encryption.clone();
        let new_operator = move |key: &[u8], old: Option<&[u8]>, merged: &[u8]| {
            merge_operator(
                &encryption.decrypt_key_ref(key),
                old.map(|v| encryption.decrypt_value_ref(v)).as_deref(),
                &encryption.decrypt_value_ref(merged),
            )
            .map(|v| encryption.encrypt_value_ivec(v).to_vec())
        };
        self.inner.set_merge_operator(new_operator);
    }
}

pub mod transaction {
    use super::*;
    pub use sled::transaction::{
        abort, ConflictableTransactionError, ConflictableTransactionResult, TransactionError,
        TransactionResult, UnabortableTransactionError,
    };

    pub struct TransactionalTree<E> {
        inner: sled::transaction::TransactionalTree,
        encryption: Arc<E>,
    }

    impl<E> TransactionalTree<E>
    where
        E: Encryption,
    {
        pub(crate) fn new(inner: sled::transaction::TransactionalTree, encryption: Arc<E>) -> Self {
            Self { inner, encryption }
        }
        pub fn insert<K, V>(
            &self,
            key: K,
            value: V,
        ) -> Result<Option<IVec>, UnabortableTransactionError>
        where
            K: AsRef<[u8]>,
            V: Into<IVec>,
        {
            self.encryption.decrypt_value_result(self.inner.insert(
                self.encryption.encrypt_key_ref(key),
                self.encryption.encrypt_value_ivec(value),
            ))
        }

        pub fn get<K: AsRef<[u8]>>(
            &self,
            key: K,
        ) -> Result<Option<IVec>, UnabortableTransactionError> {
            self.encryption
                .decrypt_value_result(self.inner.get(self.encryption.encrypt_key_ref(key)))
        }

        pub fn remove<K: AsRef<[u8]>>(
            &self,
            key: K,
        ) -> Result<Option<IVec>, UnabortableTransactionError> {
            self.encryption
                .decrypt_value_result(self.inner.remove(self.encryption.encrypt_key_ref(key)))
        }

        pub fn apply_batch(&self, batch: Batch) -> Result<(), UnabortableTransactionError> {
            self.inner
                .apply_batch(&batch.to_encrypted(&self.encryption))
        }

        #[inline]
        pub fn flush(&self) {
            self.inner.flush()
        }

        #[inline]
        pub fn generate_id(&self) -> Result<u64> {
            self.inner.generate_id()
        }
    }
}

pub fn open<P: AsRef<Path>, E: Encryption>(path: P, encryption: E) -> Result<Db<E>> {
    sled::open(path).map(|db| Db::new(db, Arc::new(encryption)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20::ChaCha20;

    type TestCipher = EncryptionCipher<ChaCha20>;
    type TestDb = Db<TestCipher>;

    const ENCRYPTION_KEY: &[u8] = b"an example very very secret key.";
    const ENCRYPTION_NONCE: &[u8] = b"secret nonce";

    fn test_cipher(mode: EncryptionMode) -> TestCipher {
        EncryptionCipher::new_from_slices(ENCRYPTION_KEY, ENCRYPTION_NONCE, mode).unwrap()
    }

    fn temp_db(mode: EncryptionMode) -> TestDb {
        println!("opening test db with: {:?}", mode);
        Config::new(test_cipher(mode))
            .temporary(true)
            .open()
            .unwrap()
    }

    fn for_all_dbs<F>(f: F) -> Result<()>
    where
        F: Fn(TestDb) -> Result<()>,
    {
        for mode in &[
            EncryptionMode::KEY,
            EncryptionMode::VALUE,
            EncryptionMode::TREE_NAME,
            EncryptionMode::KEY | EncryptionMode::VALUE,
            EncryptionMode::KEY | EncryptionMode::TREE_NAME,
            EncryptionMode::VALUE | EncryptionMode::TREE_NAME,
            EncryptionMode::KEY | EncryptionMode::VALUE | EncryptionMode::TREE_NAME,
        ] {
            f(temp_db(*mode))?
        }
        Ok(())
    }

    fn str_res(res: Result<Option<IVec>>) -> Result<Option<String>> {
        res.map(|val| val.map(|val| String::from_utf8_lossy(&val).to_string()))
    }

    #[test]
    fn insert() -> Result<()> {
        for_all_dbs(|db| {
            let tree = db.open_tree("hello").unwrap();
            assert!(!tree.contains_key("hello").unwrap());
            tree.insert("hello", "hi").unwrap();
            assert!(tree.contains_key("hello").unwrap());
            assert_eq!(Ok(Some("hi".to_string())), str_res(tree.get("hello")));
            tree.remove("hello").unwrap();
            assert!(!tree.contains_key("hello").unwrap());
            assert_eq!(Ok(None), str_res(tree.get("hello")));
            Ok(())
        })
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
    fn update_and_fetch() -> Result<()> {
        for_all_dbs(|db| {
            let zero = u64_to_ivec(0);
            let one = u64_to_ivec(1);
            let two = u64_to_ivec(2);
            let three = u64_to_ivec(3);

            assert_eq!(db.update_and_fetch("counter", increment), Ok(Some(zero)));
            assert_eq!(db.update_and_fetch("counter", increment), Ok(Some(one)));
            assert_eq!(db.update_and_fetch("counter", increment), Ok(Some(two)));
            assert_eq!(db.update_and_fetch("counter", increment), Ok(Some(three)));
            Ok(())
        })
    }

    #[test]
    fn fetch_and_update() -> Result<()> {
        for_all_dbs(|db| {
            let zero = u64_to_ivec(0);
            let one = u64_to_ivec(1);
            let two = u64_to_ivec(2);

            assert_eq!(db.fetch_and_update("counter", increment), Ok(None));
            assert_eq!(db.fetch_and_update("counter", increment), Ok(Some(zero)));
            assert_eq!(db.fetch_and_update("counter", increment), Ok(Some(one)));
            assert_eq!(db.fetch_and_update("counter", increment), Ok(Some(two)));
            Ok(())
        })
    }

    #[test]
    fn merge() -> Result<()> {
        fn concatenate_merge(
            _key: &[u8],              // the key being merged
            old_value: Option<&[u8]>, // the previous value, if one existed
            merged_bytes: &[u8],      // the new bytes being merged in
        ) -> Option<Vec<u8>> {
            // set the new value, return None to delete
            let mut ret = old_value.map(|ov| ov.to_vec()).unwrap_or_else(|| vec![]);

            ret.extend_from_slice(merged_bytes);

            Some(ret)
        }

        for_all_dbs(|tree| {
            tree.set_merge_operator(concatenate_merge);

            let k = b"k1";

            tree.insert(k, vec![0]).unwrap();
            tree.merge(k, vec![1]).unwrap();
            tree.merge(k, vec![2]).unwrap();
            assert_eq!(tree.get(k), Ok(Some(IVec::from(vec![0, 1, 2]))));

            // Replace previously merged data. The merge function will not be called.
            tree.insert(k, vec![3]).unwrap();
            assert_eq!(tree.get(k), Ok(Some(IVec::from(vec![3]))));

            // Merges on non-present values will cause the merge function to be called
            // with `old_value == None`. If the merge function returns something (which it
            // does, in this case) a new value will be inserted.
            tree.remove(k).unwrap();
            tree.merge(k, vec![4]).unwrap();
            assert_eq!(tree.get(k), Ok(Some(IVec::from(vec![4]))));
            Ok(())
        })
    }

    #[test]
    fn batch() -> Result<()> {
        for_all_dbs(|db| {
            let mut batch = Batch::default();
            batch.insert("key_a", "val_a");
            batch.insert("key_b", "val_b");
            batch.insert("key_c", "val_c");
            batch.remove("key_0");

            db.apply_batch(batch)?;
            Ok(())
        })
    }

    #[test]
    fn transaction_err() -> Result<()> {
        #[derive(Debug, PartialEq)]
        struct MyBullshitError;

        for_all_dbs(|db| {
            // Use write-only transactions as a writebatch:
            let res = db
                .transaction(|tx_db| {
                    tx_db.insert(b"k1", b"cats")?;
                    tx_db.insert(b"k2", b"dogs")?;
                    // aborting will cause all writes to roll-back.
                    if true {
                        transaction::abort(MyBullshitError)?;
                    }
                    Ok(42)
                })
                .unwrap_err();

            assert_eq!(res, transaction::TransactionError::Abort(MyBullshitError));
            assert_eq!(db.get(b"k1")?, None);
            assert_eq!(db.get(b"k2")?, None);
            Ok(())
        })
    }

    #[test]
    fn iter() -> Result<()> {
        for_all_dbs(|db| {
            db.insert(&[1], vec![10])?;
            db.insert(&[2], vec![20])?;
            db.insert(&[3], vec![30])?;
            let mut out = db.iter().collect::<Vec<Result<(IVec, IVec)>>>();
            out.sort_by_key(|res| res.clone().unwrap());
            assert_eq!(
                &out,
                &[
                    Ok((IVec::from(&[1]), IVec::from(&[10]))),
                    Ok((IVec::from(&[2]), IVec::from(&[20]))),
                    Ok((IVec::from(&[3]), IVec::from(&[30])))
                ]
            );
            Ok(())
        })
    }
}
