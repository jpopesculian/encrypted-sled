# encrypted-sled

`encrypted-sled` is an (almost) drop in replacement / wrapper around the amazing
[`sled`](https://crates.io/crates/sled) embedded database. Just configure with an encryption
and use normally.

## Examples

```rust

let cipher = {
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    let mut key = Key::default();
    key.copy_from_slice(b"an example very very secret key.");
    encrypted_sled::EncryptionCipher::<ChaCha20Poly1305, _>::new(
        key,
        encrypted_sled::RandNonce::new(rand::thread_rng()),
        encrypted_sled::EncryptionMode::default(),
    )
};

let db = encrypted_sled::open("my_db", cipher).unwrap();

// insert and get
db.insert(b"yo!", b"v1");
assert_eq!(&db.get(b"yo!").unwrap().unwrap(), b"v1");

// Atomic compare-and-swap.
db.compare_and_swap(
    b"yo!",      // key
    Some(b"v1"), // old value, None for not present
    Some(b"v2"), // new value, None for delete
)
.unwrap();

// Iterates over key-value pairs, starting at the given key.
let scan_key: &[u8] = b"a non-present key before yo!";
let mut iter = db.range(scan_key..).unwrap();
assert_eq!(&iter.next().unwrap().unwrap().0, b"yo!");
assert_eq!(iter.next(), None);

db.remove(b"yo!");
assert_eq!(db.get(b"yo!"), Ok(None));

let other_tree = db.open_tree(b"cool db facts").unwrap();
other_tree.insert(
    b"k1",
    &b"a Db acts like a Tree due to implementing Deref<Target = Tree>"[..]
).unwrap();
```

## Todos

A few things are still not implemented:

* `TransactionalTrees` (e.g. performing a transaction on multiple trees at the same time)
* Database import/export

A few functions don't handle encryption/decryption gracefully and therefore may cause corrupted
data, so please use at your own risk! Encrypted keys will most likely break these

* `update_and_fetch` and `fetch_and_update`
* Merge operators

License: MIT
