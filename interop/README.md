# MLS interop client

A gRPC server implementing the `MLSClient` service of the
[mlswg/mls-implementations](https://github.com/mlswg/mls-implementations)
interop harness on top of `mls`, so that the harness's test runner can drive
this library through its scenarios. It is a separate dune project, built and
run by the `interop` CI job, and is not part of the `mls` package.

```sh
opam pin add -y -n mls .
opam install ./interop --deps-only
dune build --root interop
interop/_build/default/mls_interop.exe -port 50051
```

Then, from a checkout of mls-implementations with the Go protobuf code
generated (see its `interop/Makefile`):

```sh
cd interop
./test-runner/test-runner -client localhost:50051 -suite 1 -config configs/commit.json
```

The server keeps all state in memory. Group states retain two past epochs so
that application messages can be read across a Commit.
