# The Syncbox vault format

Version 1. This document is what `client/crates/crypto` and `client/crates/vault`
are written against, and what any other implementation must match to read a Syncbox
vault.

Status: implemented and tested. Argon2id, AES-SIV filenames, AES-GCM content, the
HKDF key tree, and the master-key wrap all live in `client/crates/crypto`, and the
byte-level test vectors at the end of this document are pinned by
`client/crates/crypto/tests/format_vectors.rs` (regenerate them with
`cargo run --example vectors -p syncbox-crypto`).

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

and both master keys are wrapped with it. To keep the header to a single
`wrap_nonce` without the nonce-reuse hazard, the two keys are sealed under
*separate* AES-256-GCM subkeys derived from the KEK — `HKDF(KEK, "kwrap-primary")`
and `HKDF(KEK, "kwrap-hmac")` — and the one nonce is reused only across those
different keys, where reuse is harmless. `version_mac` is
`HMAC(HKDF(KEK, "header-mac"), canonicalHeader)`, so a wrong password is caught
before any file is decrypted against the wrong key.

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

`canonicalHeader` is the bytes `version_mac` covers: every field above *except*
`version_mac`, rendered so two different headers never render alike — big-endian
fixed-width integers, and length-prefixed byte strings (the base64 fields included as
their stored text). The MAC is computed over that rendering, not over the raw JSON.

### HKDF convention

Every `HKDF(secret, label)` in this document is **HKDF-SHA256 with an empty salt**
(the zero-filled salt of the RFC, which is what "no salt" expands to), where `label`
is the literal ASCII bytes of the string shown, concatenated with any following
input and no length prefix. `expand` produces exactly the length each use needs:
32 bytes for a chunk or wrap subkey, 64 bytes for an AES-SIV key (AES-SIV-512, two
AES-256 halves), 12 bytes for a chunk nonce.

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
chunkKey[i]  = HKDF(fileKey, "chunk" || uint64be(i))            # 32 bytes
nonce[i]     = HKDF(fileKey, "nonce" || uint64be(i))            # 12 bytes
stored[i]    = nonce[i] || AES-256-GCM(chunkKey[i], nonce[i], plaintext[i])   # …|| tag[16]
chunkId[i]   = BASE32( HMAC-SHA256(hmacMasterKey, plaintext[i]) )
```

Both the key and the nonce are derived from the file key and the chunk's position, so
no two positions of a file share a nonce and no chunk can be reordered or replayed at
another index without failing the tag check. The nonce is stored in the clear with the
ciphertext and read back on decrypt, so it stays authoritative even though derivation
would reproduce it.

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

## Test vectors

Every value below follows from only the fixed inputs shown, so an independent
implementation that reproduces them byte for byte has the format right. Keys are given
as byte ranges (`0x00..=0x1f` is the 32 bytes `00 01 … 1f`). Base32 is Crockford,
uppercase, no padding; hex is lowercase. These are asserted in
`client/crates/crypto/tests/format_vectors.rs`.

Fixed keys: `hmacMasterKey = 0x00..=0x1f`, `primaryMasterKey = 0x20..=0x3f`.

**Key derivation** — password `correct horse battery staple`,
salt `0xaa..=0xb9`, `m=64 KiB, t=2, p=1, len=32`:

```
KEK = 6fcf49613105db37e8238aa39a57a358bae0ff7cf4dc127361d787987a87fe60
```

**Directory id** — `dirId(root)` under `hmacMasterKey`:

```
TE5M42BDG3T5Z0KB8JMXAR3XWWJ9D90NTFTA3A68HRXVKPMDR75G
```

**Filename** — `encryptName(root, "meeting notes.txt")` under `primaryMasterKey`
(AES-SIV, so deterministic; `root` is the id above):

```
VQAF7BFK7Y9BACY4PNNH5NB4XS0C4DKDCRT15NVNF4Q9ZFE6FTVPP
```

**Chunk id** — `chunkId` of the plaintext `hello world` under `hmacMasterKey`:

```
84DSMMF8ASF1ZHWP8ESADH375X53RFJQ7GSX16AT11T8SDGJHT70
```

**Chunk encryption** — file key `0x40..=0x5f`, index `7`, plaintext `Syncbox` (7 bytes).
The stored blob is `nonce[12] || ciphertext[7] || tag[16]`, fully deterministic because
the nonce is derived — here nonce `12c4f97bd3ec79ae338a9229`, tag
`d9161ca32c41973a6aeeb511192193fc`:

```
12c4f97bd3ec79ae338a9229808217294b3c33d9161ca32c41973a6aeeb511192193fc
```

**Key wrapping** — KEK `0x11..=0x30`, nonce `0x01..=0x0c`, wrapping the two fixed keys
above (each output is a 32-byte key plus a 16-byte tag):

```
wrapped_primary = fe1f126aa658a4192778d0abbce43ece743b5a78fac863d4aa9b4c3e6e62a5e7d64f88f14ffdf10ce03f1a068b492f1f
wrapped_hmac    = 6847b0bca24d844cc947156168b88a8a01b56d3a5bda3a79b5f058babe0a011117976c7a6b794b8ae32e9656517ebb71
```

**Header MAC** — `header_mac(KEK 0x11..=0x30, "header")`:

```
42e0418e6620af50655becdd070e3a0171c9aa81f12eb1010ceb2616b244d655
```

## Relationship to Cryptomator

Syncbox follows Cryptomator's *design* — per-directory name encryption, HMAC directory
ids, chunked AES-GCM, a password-wrapped master key — and is deliberately **not**
byte-compatible with it. A Syncbox vault cannot be opened by Cryptomator and the
reverse is also true. The reason is the chunking decision above: Cryptomator's fixed
chunks and per-file header are incompatible with content-defined delta sync.

If interoperability is ever wanted, the honest way is a read-only importer that walks
a Cryptomator vault and re-encrypts it into this format, not a shared format.
