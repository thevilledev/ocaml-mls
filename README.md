# mls

`mls` is an OCaml implementation of the Messaging Layer Security protocol
([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)): an end-to-end
group key-agreement and encryption protocol with forward secrecy and
post-compromise security for groups from two members to thousands.

The library covers the TLS presentation-language codec, the ratchet tree and
TreeKEM, the key schedule and secret tree, message framing and protection,
and the group state machine. Cryptographic primitives are delegated to
[`hpke`](https://github.com/thevilledev/ocaml-hpke) (RFC 9180),
[mirage-crypto](https://github.com/mirage/mirage-crypto),
[digestif](https://github.com/mirage/digestif), and
[kdf](https://github.com/robur-coop/kdf).

> **Status:** unaudited and not production-ready. The implementation passes
> every applicable vector of the MLS working group's interoperability corpus,
> but it is published for interoperability review. See
> [SECURITY.md](SECURITY.md).

## Cipher suites

| Suite | Name | Status |
| --- | --- | --- |
| 0x0001 | MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 | supported |
| 0x0002 | MLS_128_DHKEMP256_AES128GCM_SHA256_P256 | supported |
| 0x0003 | MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 | supported |
| 0x0004 | MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 | recognised, unusable |
| 0x0005 | MLS_256_DHKEMP521_AES256GCM_SHA512_P521 | supported |
| 0x0006 | MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 | recognised, unusable |
| 0x0007 | MLS_256_DHKEMP384_AES256GCM_SHA384_P384 | supported |

Suites 0x0004 and 0x0006 need X448 and Ed448, which neither `hpke` nor
`mirage-crypto-ec` provide. Messages naming them still parse; `Crypto.create`
returns `Unsupported_cipher_suite` for them.

## Features

- Group creation, joining via Welcome, and joining via external Commit.
- Add, Update, Remove, PreSharedKey (external and resumption), ReInit,
  ExternalInit, and GroupContextExtensions proposals, sent by value or by
  reference, from members, external senders, or new members.
- Commits with or without an UpdatePath, Welcome generation, and signed
  GroupInfo publication.
- PublicMessage and PrivateMessage handshake framing, encrypted application
  messages with out-of-order delivery, and the MLS exporter.
- Full validation on receipt: membership tags, signatures, confirmation tags,
  tree hashes, parent hashes, leaf-node and KeyPackage rules, and proposal
  list rules.
- Pure state: every operation returns a new `Group.t`, so a rejected Commit
  can simply be dropped.

Not covered: X.509 credential validation, leaf-node lifetime checks against a
clock, and the ReInit and branch resumption flows beyond proposal handling.

## Installation

```sh
opam install mls
```

Or from a checkout:

```sh
opam install . --deps-only --with-test --with-doc
dune build @all @doc
dune runtest
```

## Example

```ocaml
open Mls

let ( let* ) = Result.bind

let () =
  Mirage_crypto_rng_unix.use_default ();
  let rng = Mirage_crypto_rng.default_generator () in
  let c = Crypto.create_exn Cipher_suite.mls_128_dhkemx25519_aes128gcm_sha256_ed25519 in
  let result =
    (* Each client has a signature key and publishes KeyPackages. *)
    let alice_key = Crypto.generate_signature_key c ~rng in
    let bob_key = Crypto.generate_signature_key c ~rng in
    let* alice_kp = Key_package.generate c ~rng ~signature_key:alice_key ~credential:(Credential.Basic "alice") in
    let* bob_kp = Key_package.generate c ~rng ~signature_key:bob_key ~credential:(Credential.Basic "bob") in
    (* Alice creates a group and adds Bob. *)
    let* alice =
      Group.create c ~rng ~group_id:(Crypto.random ~rng 32) ~signature_key:alice_key
        ~leaf_node:alice_kp.key_package.leaf_node ~leaf_key:alice_kp.encryption_key
    in
    let* r = Group.commit ~inline:[ Proposal.Add bob_kp.key_package ] alice ~rng in
    let alice = r.state in
    (* Bob joins from the Welcome, which carries the ratchet tree. *)
    let* welcome =
      match r.welcome with Some (Mls_message.Welcome w) -> Ok w | _ -> Error (Error.Internal "no welcome")
    in
    let* bob =
      Group.join c ~key_package:bob_kp.key_package ~init_key:bob_kp.init_key
        ~encryption_key:bob_kp.encryption_key ~signature_key:bob_key welcome
    in
    (* Application messages are PrivateMessages. *)
    let* msg, _alice = Group.encrypt_application alice ~rng "hello bob" in
    let* event, _bob = Group.process bob msg in
    match event with
    | Group.Application_received { data; sender; _ } ->
        Printf.printf "leaf %d says %S\n" sender data;
        Ok ()
    | _ -> Error (Error.Internal "unexpected event")
  in
  match result with Ok () -> () | Error e -> prerr_endline (Error.to_string e)
```

Messages are exchanged as `Mls_message.t` values; `Mls_message.to_bytes` and
`Mls_message.of_bytes` convert to and from the wire encoding. The caller owns
RNG initialisation and passes the generator explicitly, as with `hpke`.

## Layout

| Module | Contents |
| --- | --- |
| `Tls`, `Hex` | Presentation-language codec and hex helpers |
| `Tree_math` | Array-based tree arithmetic (Appendix C) |
| `Cipher_suite`, `Crypto` | Suite registry and the cipher suite crypto layer |
| `Extension`, `Credential`, `Capabilities`, `Leaf_node`, `Key_package`, `Parent_node`, `Node`, `Psk`, `Proposal`, `Update_path`, `Commit`, `Group_context`, `Group_info`, `Welcome`, `Framing`, `Mls_message`, `Group_extensions` | Wire-format types with encoders and decoders |
| `Ratchet_tree`, `Treekem` | Public tree, tree and parent hashes, UpdatePath creation and processing |
| `Key_schedule`, `Transcript_hash`, `Secret_tree` | Epoch secrets, transcript hashes, hash ratchets |
| `Message_protection` | Signing, membership tags, PrivateMessage encryption |
| `Group` | The group state machine |

## Testing

`dune runtest` runs the unit tests and every file of the
[`mlswg/mls-implementations`](https://github.com/mlswg/mls-implementations)
test-vector corpus, pinned as described in
[test/vectors/PROVENANCE.md](test/vectors/PROVENANCE.md): tree math, vector
deserialization, crypto basics, message re-encoding, key schedule, PSK
secrets, transcript hashes, secret tree, tree validation and operations,
message protection, TreeKEM, and the passive-client Welcome, commit-handling,
and 200-epoch random scenarios. End-to-end tests additionally drive several
clients through joins, updates, removals, external joins, PSKs, group context
changes, and application messaging on every supported suite.

## License

ISC. See [LICENSE](LICENSE).
