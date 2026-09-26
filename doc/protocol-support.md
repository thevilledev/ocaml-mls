# Protocol support

[README](../README.md) · [Getting started](getting-started.md) ·
[Development](development.md)

`mls` implements the wire formats, cryptographic operations, and group state
machine of [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html).
It is unaudited and intended for interoperability review. Passing test
vectors does not establish production readiness; see [Security](../SECURITY.md).

## Supported features

| Area | Coverage |
| --- | --- |
| Groups | Create a group, join via Welcome, or join via external Commit |
| Proposals | Add, Update, Remove, PreSharedKey, ReInit, ExternalInit, and GroupContextExtensions |
| Proposal delivery | By value or reference, from members, external senders, or new members, subject to the protocol's sender rules |
| Commits | With or without an UpdatePath; Welcome generation and signed GroupInfo publication |
| Handshakes | PublicMessage and PrivateMessage framing |
| Application data | Encrypted PrivateMessages with out-of-order delivery within a bounded skipped-key window, and optionally from a bounded number of past epochs |
| Key derivation | Key schedule, secret tree, external and resumption PSKs, and the MLS exporter |
| Validation | Membership tags, signatures, confirmation tags, tree and parent hashes, leaf-node and KeyPackage rules, and proposal-list rules |
| State | Immutable `Group.t` values; each operation returns its updated state |

ReInit proposal handling is supported, but completing the ReInit and branch
resumption flows is not automated.

## Cipher suites

| ID | RFC name | Status |
| --- | --- | --- |
| `0x0001` | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` | Supported |
| `0x0002` | `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` | Supported |
| `0x0003` | `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` | Supported |
| `0x0004` | `MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448` | Supported |
| `0x0005` | `MLS_256_DHKEMP521_AES256GCM_SHA512_P521` | Supported |
| `0x0006` | `MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448` | Supported |
| `0x0007` | `MLS_256_DHKEMP384_AES256GCM_SHA384_P384` | Supported |

Other suite values can be parsed, but `Crypto.create` returns
`Unsupported_cipher_suite` for them.

## Cryptographic dependencies

The library delegates cryptographic primitives to:

- [`hpke`](https://github.com/thevilledev/ocaml-hpke) 0.3.0 or later for
  RFC 9180 HPKE and for each cipher suite's HKDF and AEAD, through the
  primitives it exports for protocols layered on HPKE.
- [`mirage-crypto`](https://github.com/mirage/mirage-crypto) for Ed25519 and
  ECDSA signatures (`mirage-crypto-ec`) and random-number generation
  (`mirage-crypto-rng`).
- [`curve448`](https://github.com/thevilledev/ocaml-curve448) for Ed448
  signatures. It needs a 64-bit OCaml, so `mls` does too.
- [`digestif`](https://github.com/mirage/digestif) for hashes and HMAC.

Key derivation and AEAD operations return errors, not exceptions, for secrets
shorter than the hash output, out-of-range output lengths, and wrong-sized
keys or nonces.

## Application responsibilities and gaps

Applications own the Delivery Service, message ordering, storage of
KeyPackages and private keys, and PSK provisioning. They also need to handle:

- Identity verification: the library calls the application's credential
  validator in `Policy` for every credential introduced to a group (new
  members, the members of a group being joined, replaced credentials, and
  external senders), but does not authenticate identities or verify X.509
  certificate chains itself.
- Time validation: the library has no clock. Supply one, and the maximum
  lifetime RFC 9420 requires applications to define, through `Policy` so that
  KeyPackage lifetimes are checked when members are added.
- ReInit and branch resumption flows beyond proposal processing.

[Security](../SECURITY.md) describes these boundaries and the limitations of
secret storage and cryptographic operations.

## Interoperability coverage

The test suite exercises every applicable vector in the pinned
[`mlswg/mls-implementations`](https://github.com/mlswg/mls-implementations)
corpus for all seven cipher suites. The
[vector provenance](../test/vectors/PROVENANCE.md) records the upstream commit
and maps each vector file to its tests.

End-to-end tests cover joins, updates, removals, external joins, PSKs, group
context changes, and application messages on all seven suites.
See the [development guide](development.md#tests) for commands and the
additional property and fuzz tests.
