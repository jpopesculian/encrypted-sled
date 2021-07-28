# encrypted-sled

`encrypted-sled` is a drop in replacement / wrapper around the amazing
[`sled`](https://crates.io/crates/sled) embedded database. Just configure with an encryption
and use normally.

## Examples

```rust
let cipher = encrypted_sled::EncryptionCipher::<chacha20::ChaCha20>::new_from_slices(
    b"an example very very secret key.",
    b"secret nonce",
    encrypted_sled::EncryptionMode::default(),
)
.unwrap();
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
let mut iter = db.range(scan_key..);
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

License: MIT
