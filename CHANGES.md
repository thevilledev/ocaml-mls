# Changelog

## 0.1.0 — 2026-09-18

- Initial implementation of the Messaging Layer Security protocol
  (RFC 9420): TLS presentation-language codec, tree math, cipher suite
  crypto layer over `hpke`, `mirage-crypto-ec`, and `digestif`, ratchet
  tree and TreeKEM, key schedule, secret tree, message framing and
  protection, and the group state machine (creation, Welcome and external
  joins, proposals, commits, application messages, external and resumption
  pre-shared keys, group context extensions).
- Support all seven RFC 9420 cipher suites (0x0001 to 0x0007), and validate
  against every file of the `mlswg/mls-implementations` test-vector corpus
  for each of them.
- Take X448 for suites 0x0004 and 0x0006 from `hpke`'s DHKEM(X448), and Ed448
  from `curve448`. `curve448` needs a 64-bit OCaml, so `mls` is not available
  on 32-bit architectures.
- Require `hpke` 0.3.0 and take each suite's HKDF and AEAD from its exported
  primitives, so the library no longer depends on `kdf` or `mirage-crypto`
  directly. Derivations and AEAD sealing return errors, never exceptions, for
  secrets shorter than the hash output, out-of-range lengths, and wrong-sized
  keys or nonces; `Group.export` returns a result accordingly.
- Fuzz the decoders with Crowbar and check codec, tree-math and secret-tree
  invariants with QCheck properties.
- Unaudited; intended for interoperability review, not production use.
