# Changelog

## 0.1.0 — 2026-09-18

- Initial implementation of the Messaging Layer Security protocol
  (RFC 9420): TLS presentation-language codec, tree math, cipher suite
  crypto layer over `hpke`, `mirage-crypto-ec`, and `digestif`, ratchet
  tree and TreeKEM, key schedule, secret tree, message framing and
  protection, and the group state machine (creation, Welcome and external
  joins, proposals, commits, application messages, external and resumption
  pre-shared keys, group context extensions).
- Validate against every file of the `mlswg/mls-implementations` test-vector
  corpus for the five cipher suites whose primitives are available in OCaml
  (0x0001, 0x0002, 0x0003, 0x0005, 0x0007).
- Cipher suites 0x0004 and 0x0006 (X448 and Ed448) are recognised but not
  usable until an OCaml X448/Ed448 primitive is available to `hpke`.
- Require `hpke` 0.2.0 and take each suite's HKDF and AEAD from its exported
  primitives, so the library no longer depends on `kdf` or `mirage-crypto`
  directly. Derivations and AEAD sealing return errors, never exceptions, for
  secrets shorter than the hash output, out-of-range lengths, and wrong-sized
  keys or nonces; `Group.export` returns a result accordingly.
- Fuzz the decoders with Crowbar and check codec, tree-math and secret-tree
  invariants with QCheck properties.
- Unaudited; intended for interoperability review, not production use.
