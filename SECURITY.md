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
- Past epochs' secret trees are kept only when the application sets
  `Policy.max_past_epochs`, and then only to decrypt application messages;
  handshake messages from past epochs are rejected. Retained secrets weaken
  forward secrecy until they age out.

## Limitations

- Secret key material lives in ordinary OCaml strings and cannot be reliably
  zeroised; the runtime and garbage collector may copy it.
- Signature-key operations delegate to `mirage-crypto-ec`, whose ECDSA
  nonce generation follows RFC 6979 without additional blinding.
- The library does not authenticate identities. It passes every credential
  introduced to a group to the application's validator in `Policy`, as
  RFC 9420 Section 5.3.1 requires; without one, any credential whose leaf
  node is otherwise valid is accepted. X.509 certificate chains are parsed
  but not verified.
- The library has no clock. KeyPackage lifetimes are checked only when the
  application supplies one, and a maximum lifetime, through `Policy`.
- Subgroup branching matches the members of a branch with members of the old
  group by credential equality unless the application supplies its own
  comparison.
- Applications own the Delivery Service, message ordering, storage of key
  packages and their private keys, and PSK provisioning.

## Reporting

Report suspected vulnerabilities privately to <ville@vesilehto.fi> rather
than through public issues.
