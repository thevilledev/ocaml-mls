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
| Application data | Encrypted PrivateMessages with out-of-order delivery within a bounded skipped-key window |
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
| `0x0004` | `MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448` | Recognised only |
| `0x0005` | `MLS_256_DHKEMP521_AES256GCM_SHA512_P521` | Supported |
| `0x0006` | `MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448` | Recognised only |
| `0x0007` | `MLS_256_DHKEMP384_AES256GCM_SHA384_P384` | Supported |

Messages naming `0x0004` or `0x0006` can be parsed, but `Crypto.create`
returns `Unsupported_cipher_suite`. These suites need X448 and Ed448
primitives and integration in both `hpke` and `mls`. Related dependency
packaging work is tracked in
[ocaml/opam-repository#30768](https://github.com/ocaml/opam-repository/pull/30768).

## Cryptographic dependencies

The library delegates cryptographic primitives to:

- [`hpke`](https://github.com/thevilledev/ocaml-hpke) for RFC 9180 HPKE.
- [`mirage-crypto`](https://github.com/mirage/mirage-crypto) for AEADs,
  signatures, and random-number generation.
- [`digestif`](https://github.com/mirage/digestif) for hashes and HMAC.
- [`kdf`](https://github.com/robur-coop/kdf) for HKDF.

## Application responsibilities and gaps

Applications own the Delivery Service, message ordering, storage of
KeyPackages and private keys, and PSK provisioning. They also need to handle:

- Identity verification: X.509 credentials are parsed, but certificate
  chains are not validated by the library.
- Time validation: leaf-node lifetimes are not checked against a clock.
- ReInit and branch resumption flows beyond proposal processing.

[Security](../SECURITY.md) describes these boundaries and the limitations of
secret storage and cryptographic operations.

## Interoperability coverage

The test suite exercises every applicable vector in the pinned
[`mlswg/mls-implementations`](https://github.com/mlswg/mls-implementations)
corpus. Vectors for `0x0004` and `0x0006` are skipped. The
[vector provenance](../test/vectors/PROVENANCE.md) records the upstream commit
and maps each vector file to its tests.

End-to-end tests cover joins, updates, removals, external joins, PSKs, group
context changes, and application messages on all five supported suites.
See the [development guide](development.md#tests) for commands and the
additional property and fuzz tests.
