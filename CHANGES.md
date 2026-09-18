# Changelog

## Unreleased

- Initial implementation of the Messaging Layer Security protocol
  (RFC 9420): TLS presentation-language codec, tree math, cipher suite
  crypto layer over `hpke`, `mirage-crypto`, `digestif`, and `kdf`, ratchet
  tree and TreeKEM, key schedule, secret tree, message framing and
  protection, and the group state machine (creation, Welcome and external
  joins, proposals, commits, application messages, external and resumption
  pre-shared keys, group context extensions).
- Validate against every file of the `mlswg/mls-implementations` test-vector
  corpus for the five cipher suites whose primitives are available in OCaml
  (0x0001, 0x0002, 0x0003, 0x0005, 0x0007).
- Cipher suites 0x0004 and 0x0006 (X448 and Ed448) are recognised but not
  usable until an OCaml X448/Ed448 primitive is available to `hpke`.
- Unaudited; intended for interoperability review, not production use.
