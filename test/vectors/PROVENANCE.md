# Test-vector provenance

The JSON files in this directory are copied unchanged from the MLS working
group's interoperability repository
[`mlswg/mls-implementations`](https://github.com/mlswg/mls-implementations),
directory `test-vectors/`, at commit
[`cfd450286d1bfd9cd2519b95c80f9771f94a5b1a`](https://github.com/mlswg/mls-implementations/tree/cfd450286d1bfd9cd2519b95c80f9771f94a5b1a/test-vectors)
(2026-04-23). Their format is documented in that repository's
`test-vectors.md`.

| File | Exercised by | Notes |
| --- | --- | --- |
| `tree-math.json` | `Test_tree_math` | |
| `deserialization.json` | `Test_tls` | variable-length headers |
| `crypto-basics.json` | `Test_crypto` | |
| `messages.json` | `Test_messages` | byte-exact re-encoding of 300 vectors |
| `key-schedule.json`, `psk_secret.json`, `transcript-hashes.json`, `secret-tree.json` | `Test_key_schedule` | |
| `tree-validation.json`, `tree-operations.json` | `Test_tree` | |
| `message-protection.json` | `Test_message_protection` | |
| `treekem.json` | `Test_treekem` | |
| `welcome.json` | covered by `passive-client-welcome.json` | |
| `passive-client-welcome.json`, `passive-client-handling-commit.json`, `passive-client-random.json` | `Test_passive` | |

Vectors for cipher suites 0x0004 and 0x0006 (X448, Ed448) are present but
skipped, because no OCaml implementation of those primitives is available.
Every other vector is verified.

The repository does not silently update vectors from a moving branch. Changes
to these fixtures must cite an immutable upstream commit.
