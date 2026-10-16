# The Syncbox vault format

Version 1. This document is what `client/crates/crypto` and `client/crates/vault`
are written against, and what any other implementation must match to read a Syncbox
vault.

Status: the layout constants, the base32 encoding, the header structure, and the
parameter handling are implemented and tested. Argon2id, AES-SIV, and AES-GCM are
declared with their real signatures and currently return
`CryptoError::Unimplemented`; M1 fills them in.

## What a vault is

A vault is an ordinary directory the user chose, containing only ciphertext:

```text
vault/
  vault.json                 # KDF parameters + the wrapped master keys
  d/AB/CD/<dirId>.c9r        # empty marker, one per directory
  <dirId>/<name>.c9r         # an encrypted file
  <dirId>/<name>.c9s/<id>    # indirection for a name too long to store
```

Nothing in that tree is derivable from the plaintext tree without the key, and
nothing outside `vault.json` reveals a size, a name, or a structure.

## Key hierarchy

A vault holds two 256-bit master keys, generated randomly at creation:

| Key | Used for |
| --- | --- |
| `primaryMasterKey` | file content, filenames |
| `hmacMasterKey` | directory ids, chunk ids |

Splitting them means a leak of the directory-id key does not expose content, and
ciphertext alone cannot be used to confirm a guessed directory id.

Neither key is stored. A key-encryption key is derived from the user's password:

```
KEK = Argon2id(password, salt, m=64 MiB, t=3, p=4, len=32)
```

and both master keys are wrapped with it (AES-256-GCM, one nonce for both, recorded
in the header). `version_mac` is an HMAC over the header, so a wrong password is
caught before any file is decrypted against the wrong key.

The parameters are written into the header rather than assumed, so raising the
Argon2id cost later cannot strand an existing vault.

### `vault.json`

```json
{
  "version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 4,
    "output_len": 32,
    "salt": "<base64>"
  },
  "wrap_nonce": "<base64>",
  "wrapped_primary": "<base64>",
  "wrapped_hmac": "<base64>",
  "version_mac": "<base64>"
}
```

Unknown fields are rejected on read. A `version` above what the build supports is
refused rather than guessed at.

## Directory ids

Every directory has an id, and the id is what its *parent* stores it under:

```
dirId(root)          = BASE32( HMAC-SHA256(hmacMasterKey, "") )
dirId(child of dir)  = BASE32( HMAC-SHA256(hmacMasterKey, dirId(dir) || "\n" || encryptName(dir, name)) )
```

Because the parent's id is an input, a folder renamed or moved anywhere in the tree
produces a completely unrelated id for everything beneath it. That is the property
that makes the structure invisible to the server.

Base32 means Crockford's alphabet — `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, no padding,
uppercase. `I` and `L` decode as `1`, and `U` as `V`, for hand-entered ids.

Each directory also writes an empty marker at
`d/<id[0..2]>/<id[2..4]>/<id>.c9r`, so a client can rediscover the set of directories
without decrypting any content.

## Filenames

```
encryptName(dir, name) = BASE32( AES-SIV( key = HKDF(primaryMasterKey, "siv" || dirId(dir)),
                                          ad  = dirId(dir),
                                          pt  = UTF-8 name ) )
```

The directory id is both the key derivation input and the associated data, so the
same filename in two directories gives two unrelated ciphertexts, and a ciphertext
name cannot be moved between directories.

Stored file names take the suffix `.c9r`. An encrypted name longer than 220
characters becomes a directory suffixed `.c9s` holding the real name, matching the
255-byte limit most filesystems impose.

## Content

A file is a sequence of **content-defined** chunks. Each chunk is encrypted
independently:

```
chunkKey[i]  = HKDF(fileKey, "chunk" || uint64be(i))
stored[i]    = nonce[12] || AES-256-GCM(chunkKey[i], nonce[i], plaintext[i])
chunkId[i]   = BASE32( HMAC-SHA256(hmacMasterKey, plaintext[i]) )
```

Sizes: 8 KiB minimum, 64 KiB target, 512 KiB maximum.

An encrypted manifest — itself AES-GCM under the file key — records the chunk ids in
order, their ciphertext lengths, and the plaintext size. The server stores the
manifest as an opaque blob.

### Why content-defined rather than fixed chunks

Fixed 32 KiB chunks, as Cryptomator uses, cannot survive an insertion. Add one byte
near the start of a file and every later boundary shifts, so all of it looks new.
Content-defined boundaries are chosen from the bytes, so the chunks on either side of
an edit stay byte-identical and already sit on the server. This is the single biggest
reason Syncbox is a sync tool rather than a backup tool.

### What the server can therefore infer

`chunkId` is deterministic per vault, so the server can tell that two chunks *inside
one vault* hold identical plaintext. That is the standard convergent-encryption
tradeoff, and it is what makes deduplication and delta upload work at all. It reveals
nothing across vaults and nothing about what a chunk says. File sizes and modification
times are also plaintext, because the client cannot be told how much to fetch without
them.

## Relationship to Cryptomator

Syncbox follows Cryptomator's *design* — per-directory name encryption, HMAC directory
ids, chunked AES-GCM, a password-wrapped master key — and is deliberately **not**
byte-compatible with it. A Syncbox vault cannot be opened by Cryptomator and the
reverse is also true. The reason is the chunking decision above: Cryptomator's fixed
chunks and per-file header are incompatible with content-defined delta sync.

If interoperability is ever wanted, the honest way is a read-only importer that walks
a Cryptomator vault and re-encrypts it into this format, not a shared format.
