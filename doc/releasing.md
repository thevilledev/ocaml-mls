# Release checklist

[README](../README.md) · [Development](development.md) ·
[Changelog](../CHANGES.md)

Use this checklist to prepare an opam release. Build and validate the
candidate locally before tagging or publishing it.

## 1. Review the release contents

- Check the version, date, and user-visible changes in [CHANGES.md](../CHANGES.md).
- Review `mls.opam`: dependency lower bounds, OCaml and Dune requirements,
  synopsis, description, license, and repository links.
- Remove the `pin-depends` field from `mls.opam` once `hpke` 0.2.0 is in the
  opam repository. The repository rejects packages that carry it, and `mls`
  cannot be published before its `hpke` lower bound resolves there. Drop the
  matching note from the [getting started guide](getting-started.md) too.
- Keep the package description in `dune-project` consistent with `mls.opam`.
  This repository sets `generate_opam_files` to `false`, so edits to
  `dune-project` do not regenerate the opam file.
- Check [protocol support](protocol-support.md) and [Security](../SECURITY.md)
  against the release. Retain the unaudited status unless it has changed.
- Keep source-install instructions available until the package has been
  accepted into the opam repository; then update the README and
  [getting started guide](getting-started.md) to lead with `opam install mls`.

## 2. Run local checks

Follow the [development setup](development.md#setup), including installation
of ocamlformat 0.29.0 for the formatting check, then run:

```sh
opam lint mls.opam
opam exec -- dune build @all @doc @fmt
opam exec -- dune runtest
opam exec -- dune exec examples/basic.exe
opam exec -- dune build --profile fuzz fuzz/fuzz_mls.exe
opam exec -- _build/default/fuzz/fuzz_mls.exe --repeat 2000 --seed 9420
```

Check that the example prints `leaf 0 says "hello bob"`. Browse the generated
API reference at `_build/default/_doc/_html/mls/index.html` and check the
README's guide links.

## 3. Validate the package in a clean environment

From a clean checkout of the candidate, use a disposable opam switch with
OCaml 4.14 or later, then run:

```sh
opam install . --with-test --with-doc
```

This installs the candidate in that switch and exercises the build commands
in `mls.opam`. Check that its dependencies resolve from the public opam
repository without relying on local pins. Verify the supported compiler
versions through CI as well.

Inspect the installed documentation under `$(opam var doc)/mls`: the README,
guides in `doc/`, security policy, example source, and vector provenance
should be present. The guides are listed explicitly in `doc/dune`; add new
guides there when extending the documentation.

## 4. Publish the validated candidate

When the release is ready:

1. Commit the final release contents and create the version tag.
2. Build a source archive from that tag. Repeat the clean-environment package
   check using the extracted archive to catch missing release files.
3. Publish the tag and archive, then prepare the opam-repository submission
   with the matching version, archive URL, and checksums.
4. After acceptance, verify `opam install mls` from the public repository
   and update the installation instructions.

Keep the tag, archive, changelog version, and opam submission in agreement.
