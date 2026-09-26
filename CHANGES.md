# Changelog

## Unreleased

- Add `Policy`, the application's validation policy, carried by each group
  and set with `?policy` on `Group.create`, `Group.join`, and
  `Group.external_join` or replaced with `Group.with_policy`. With a clock it
  rejects a KeyPackage whose lifetime does not contain the current time, and
  with `max_lifetime` one whose lifetime is longer than the application
  accepts (RFC 9420 Section 7.3). The checks apply to KeyPackages the group
  adds itself and to Add proposals it receives, and `Group.validate_key_package`
  takes the same `?policy`. The default policy checks nothing, as before.
- Add a credential validator to `Policy` (RFC 9420 Section 5.3.1). A group
  calls it for every credential introduced to it: KeyPackages in Add
  proposals it sends or receives, the joiner of an external Commit, the
  members of a group it joins by Welcome or external Commit, a credential or
  signature key replaced by an Update proposal or a Commit's UpdatePath (with
  the replaced credential, so the application can judge the successor), and
  new `external_senders` entries. A rejection fails the operation with the
  new `Error.Invalid_credential`.
- Decrypt application messages from past epochs (RFC 9420 Section 9.2). With
  `Policy.max_past_epochs` set, a group keeps the secret trees of that many
  past epochs, so a message sent before a Commit but delivered after it is
  still read. Handshake messages from past epochs are still rejected, and
  every key is still used once. `Application_received` gains the `epoch` the
  message was sent in. The default keeps no past epochs.
- Complete ReInit and subgroup branching (RFC 9420 Sections 11.2 and 11.3).
  A group whose ReInit Commit has been applied reports it through
  `Group.reinitialized` and refuses to send. `Group.reinit` creates the
  replacement group from the ReInit parameters and `Group.branch` a subgroup,
  each injecting a resumption PSK from the old group into the new group's
  first Commit and Welcome. `Group.join_reinit` and `Group.join_branch` join
  such a Welcome and check the new group against the old one, and
  `Group.join` now refuses one.

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
