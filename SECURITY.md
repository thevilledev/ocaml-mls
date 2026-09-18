# Security

This library has not received an independent cryptographic audit and is not
production-ready. It is published for interoperability review.

## Scope

- Wire-format parsing rejects non-minimal vector headers, trailing bytes, and
  unknown enum values. Decoding untrusted input is designed to fail closed.
- All handshake and application messages are authenticated before any state
  changes: membership tags, signatures, confirmation tags, parent hashes, tree
  hashes, and leaf-node validity are verified as required by RFC 9420.
- Group state is immutable. A state that fails to process a message is left
  unchanged, and a committer only adopts its new epoch by keeping the state
  returned from `Group.commit`.
- The secret tree retains keys for skipped generations within a bounded
  window and returns each key at most once.

## Limitations

- Secret key material lives in ordinary OCaml strings and cannot be reliably
  zeroised; the runtime and garbage collector may copy it.
- Signature-key operations delegate to `mirage-crypto-ec`, whose ECDSA
  nonce generation follows RFC 6979 without additional blinding.
- X.509 credentials are parsed but not validated; applications must verify
  certificate chains themselves.
- Lifetime fields of leaf nodes are not checked against a clock.
- ReInit and branch resumption flows are not automated beyond proposal
  processing.
- Applications own the Delivery Service, message ordering, storage of key
  packages and their private keys, and PSK provisioning.

## Reporting

Report suspected vulnerabilities privately to <ville@vesilehto.fi> rather
than through public issues.
