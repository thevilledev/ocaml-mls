# Getting started

[README](../README.md) · [Protocol support](protocol-support.md) ·
[Development](development.md)

This guide installs `mls`, runs a two-member group, and explains how to use
the library from an application. The library is unaudited; read
[Security](../SECURITY.md) for its limitations and application responsibilities.

## Install

Requirements: OCaml **4.14 or later**, opam with an active switch, and Dune
**3.12 or later**. opam installs Dune and the library dependencies as needed.

### From source

Until the first opam release is published, install from a checkout:

```sh
git clone https://github.com/thevilledev/ocaml-mls.git
cd ocaml-mls
opam install .
```

`mls` needs `hpke` 0.2.0, which is released but not yet in the opam
repository. The checkout's `mls.opam` carries a `pin-depends` entry, so opam
offers to pin `hpke` to its `v0.2.0` tag during this install. To pin it
yourself, for example for another project:

```sh
opam pin add hpke.0.2.0 "git+https://github.com/thevilledev/ocaml-hpke.git#v0.2.0"
```

If you only want to build and run examples in the checkout, use
`opam install . --deps-only` instead. For test and documentation dependencies,
follow the [development setup](development.md#setup).

### From the opam repository

Once `mls` is published in the opam repository:

```sh
opam update
opam install mls
```

## Run the example

From the repository root:

```sh
opam exec -- dune exec examples/basic.exe
```

Expected output:

```text
leaf 0 says "hello bob"
```

The complete program is in [examples/basic.ml](../examples/basic.ml). It
keeps both clients in one process so you can follow the protocol without a
network service:

1. **Set up cryptography.** Initialise the RNG, obtain a generator, and select
   a supported cipher suite with `Crypto.create` or `Crypto.create_exn`.
   The example uses suite `0x0001` (X25519, AES-128-GCM, SHA-256, Ed25519).
2. **Prepare each client.** Generate a signature key and a signed KeyPackage.
   A KeyPackage contains public information for adding a member; keep its
   private init and encryption keys for joining later.
3. **Create the group.** Alice calls `Group.create` with her leaf node and
   encryption key. The returned `Group.t` is her view of the group.
4. **Add Bob.** Alice calls `Group.commit` with a `Proposal.Add` containing
   Bob's KeyPackage. She keeps the returned `state` and sends the Welcome
   to Bob. In a larger group, existing members also receive the Commit.
5. **Join.** Bob calls `Group.join` with the Welcome, his KeyPackage, and his
   private keys. By default, the Welcome includes the ratchet tree.
6. **Exchange a message.** Alice calls `Group.encrypt_application`; Bob
   passes the message to `Group.process` and receives an
   `Application_received` event containing the plaintext and sender index.

## Use it in a Dune project

After installing `mls`, add it to your executable's libraries. For a Unix
application using the RNG setup from the example:

```dune
(executable
 (name main)
 (libraries mls mirage-crypto-rng.unix))
```

Use `open Mls` to access the modules. The caller initialises the RNG and
passes the generator explicitly to operations that need randomness.
Most operations return `('a, Error.t) result`; the example uses
`let ( let* ) = Result.bind` to chain them and `Error.to_string` to display
failures.

## Carry state and messages forward

`Group.t` represents one member's view of a group at an epoch (a version of
the group's membership and secrets). Operations return new states. Keep
the state returned by **both sending and receiving**, including application
messages, so later operations use the advanced message ratchets. The example
names its final states `_alice` and `_bob` only because it stops there.

A Commit produces the committer's next state, a Commit to deliver to existing
members, and a Welcome when members are added. Coordinate adoption of that
state with your Delivery Service's acceptance of the Commit. A rejected
Commit can be discarded without changing the old state.

Messages are `Mls_message.t` values. Use `Mls_message.to_bytes` to encode
them for transport and `Mls_message.of_bytes` to decode received bytes.
Pass handshake and application messages to `Group.process`; use
`Group.join` for a Welcome.

Your application supplies transport, message ordering, key storage, and
identity verification. The example's `Credential.Basic "alice"` is an
identity label, not proof that a key belongs to a particular person. See
[Security](../SECURITY.md) before designing those parts of an application.

## Next steps

- [Protocol support](protocol-support.md): proposals, joins, cipher suites,
  and unsupported flows.
- [API documentation](development.md#api-documentation): build the reference
  and start with `Mls.Group`.
- [Development guide](development.md): run tests and find the implementation.
