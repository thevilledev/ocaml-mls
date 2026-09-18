# mls

**Messaging Layer Security for OCaml.** `mls` implements
[RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html), a protocol for
end-to-end encrypted groups with forward secrecy and post-compromise security.
Use it to create groups, manage membership, and exchange encrypted messages.

> **Status:** unaudited and not production-ready. Intended for interoperability
> review. Read the [security limitations](SECURITY.md) before using the library.

## Try it

You need OCaml **4.14 or later** and an active opam switch. While the first
opam release is being prepared, run the example from a checkout:

```sh
git clone https://github.com/thevilledev/ocaml-mls.git
cd ocaml-mls
opam install . --deps-only
opam exec -- dune exec examples/basic.exe
```

The example creates a group, adds Bob, and sends him an encrypted message:

```text
leaf 0 says "hello bob"
```

Read the [example source](examples/basic.ml) and the
[getting started guide](doc/getting-started.md) to use `mls` in your own project.

## What it provides

- Group creation, membership changes, and joining through Welcome or external
  Commit messages.
- Authenticated handshakes, encrypted application messages, pre-shared keys,
  and the MLS exporter.
- Five cipher suites, with interoperability vectors and end-to-end tests.
- An immutable group API: operations return an updated state for the caller
  to retain.

Applications provide identity verification, message delivery, and storage.
See [protocol support](doc/protocol-support.md) for the exact feature set,
cipher suites, and known gaps.

## Documentation

| I want to… | Start here |
| --- | --- |
| Install the library and understand the example | [Getting started](doc/getting-started.md) |
| Check supported features and cipher suites | [Protocol support](doc/protocol-support.md) |
| Build, test, or find a module | [Development guide](doc/development.md) |
| Prepare an opam release | [Release checklist](doc/releasing.md) |
| Review limitations or report a vulnerability | [Security](SECURITY.md) |
| See what changed | [Changelog](CHANGES.md) |

The [development guide](doc/development.md#api-documentation) also explains
how to build the API reference locally.

## License

[ISC](LICENSE).
