(lang dune 3.12)
(name mls)
(generate_opam_files false)
(source (github thevilledev/ocaml-mls))
(license ISC)
(authors "Ville Vesilehto <ville@vesilehto.fi>")
(maintainers "Ville Vesilehto <ville@vesilehto.fi>")

(package
 (name mls)
 (synopsis "Messaging Layer Security (RFC 9420) for OCaml")
 (description
  "An implementation of the Messaging Layer Security protocol (RFC 9420): TLS presentation-language codec, ratchet tree (TreeKEM), key schedule, message framing and protection, and the group state machine. The cipher suite's KEM, KDF and AEAD come from the hpke package, signatures from mirage-crypto-ec, and hashing from digestif.")
 (tags (cryptography mls rfc9420 "messaging layer security" "end-to-end encryption")))
