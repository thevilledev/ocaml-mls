# Development

[README](../README.md) · [Getting started](getting-started.md) ·
[Protocol support](protocol-support.md) · [Release checklist](releasing.md)

Run the commands below from the repository root, with an active opam switch
using OCaml 4.14 or later.

## Setup

Install the library, test, and documentation dependencies, then build:

```sh
opam install . --deps-only --with-test --with-doc
opam exec -- dune build @all @doc
```

To run the example:

```sh
opam exec -- dune exec examples/basic.exe
```

## API documentation

```sh
opam exec -- dune build @doc
```

Open `_build/default/_doc/_html/mls/index.html` in a browser. Start with
`Mls.Group` for the application API, `Mls.Key_package` for member setup,
and `Mls.Mls_message` for wire encoding. The reference includes the signatures
and comments from the library's `.mli` files.

## Tests

```sh
opam exec -- dune runtest
```

The suite combines:

- Unit tests for the codec, tree math, and protocol operations.
- The pinned MLS working group vectors: deserialization, crypto basics,
  message re-encoding, key schedule, PSK secrets, transcript hashes, secret
  tree, tree validation and operations, message protection, and TreeKEM.
- Passive-client scenarios for Welcome processing, Commit handling, and
  200-epoch random sequences.
- End-to-end group tests across all supported cipher suites.
- QCheck properties for the codec, tree math, and secret tree.

See [vector provenance](../test/vectors/PROVENANCE.md) for the pinned upstream
revision and exclusions. Changes to the fixtures must cite an immutable
upstream commit.

### Decoder fuzzing

The Crowbar target checks decoders for totality and byte-exact re-encoding.
It is enabled only under the `fuzz` profile:

```sh
opam exec -- dune build --profile fuzz fuzz/fuzz_mls.exe
opam exec -- _build/default/fuzz/fuzz_mls.exe --repeat 2000 --seed 9420
```

### Formatting

The repository uses ocamlformat 0.29.0:

```sh
opam install ocamlformat.0.29.0
opam exec -- dune build @fmt
```

## Repository map

| Path | Purpose |
| --- | --- |
| `lib/` | Public interfaces (`.mli`) and implementations (`.ml`) |
| `examples/basic.ml` | Runnable two-member group example |
| `test/` | Unit, interoperability, end-to-end, and property tests |
| `test/vectors/` | Pinned upstream JSON fixtures and provenance |
| `fuzz/` | Crowbar decoder target |
| `doc/` | These guides and the odoc API landing page |
| `mls.opam` | Package metadata, dependencies, and opam build commands |

### Module map

All modules live under `Mls`.

| Area | Modules |
| --- | --- |
| Application state machine | `Group` |
| Suite selection and cryptography | `Cipher_suite`, `Crypto` |
| Identity and member setup | `Credential`, `Capabilities`, `Leaf_node`, `Key_package` |
| Messages and membership changes | `Mls_message`, `Framing`, `Proposal`, `Commit`, `Update_path`, `Welcome`, `Group_info` |
| Group configuration | `Group_context`, `Extension`, `Group_extensions`, `Psk` |
| Tree representation and TreeKEM | `Node`, `Parent_node`, `Ratchet_tree`, `Treekem`, `Tree_math` |
| Key derivation and message protection | `Key_schedule`, `Transcript_hash`, `Secret_tree`, `Message_protection` |
| Encoding and errors | `Tls`, `Hex`, `Hpke_ciphertext`, `Error` |

## CI and packaging

The [CI workflow](https://github.com/thevilledev/ocaml-mls/blob/main/.github/workflows/ci.yml)
builds and tests on Linux with OCaml 4.14 and 5.4, and on macOS with OCaml
5.4. Separate jobs check opam installation, formatting, and decoder fuzzing.

For package validation and the steps before publication, use the
[release checklist](releasing.md).
