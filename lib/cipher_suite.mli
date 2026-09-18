(** MLS cipher suites (RFC 9420 Section 17.1). The wire representation is a
    uint16; unknown values are carried through unchanged so that messages
    advertising private-use suites still parse. *)

type t = int

val mls_128_dhkemx25519_aes128gcm_sha256_ed25519 : t
val mls_128_dhkemp256_aes128gcm_sha256_p256 : t
val mls_128_dhkemx25519_chacha20poly1305_sha256_ed25519 : t
val mls_256_dhkemx448_aes256gcm_sha512_ed448 : t
val mls_256_dhkemp521_aes256gcm_sha512_p521 : t
val mls_256_dhkemx448_chacha20poly1305_sha512_ed448 : t
val mls_256_dhkemp384_aes256gcm_sha384_p384 : t

type hash = Sha256 | Sha384 | Sha512
type signature_scheme = Ed25519 | Ecdsa_p256 | Ecdsa_p384 | Ecdsa_p521

type params = {
  kem : Hpke.Kem.id;
  kdf : Hpke.Kdf.id;
  aead : Hpke.Aead.id;
  hash : hash;
  signature : signature_scheme;
}

val name : t -> string option

val params : t -> (params, Error.t) result
(** Fails for unknown suites and for 0x0004 and 0x0006, whose X448 and Ed448
    primitives are not available. *)

val all : t list
val supported : t list
val is_supported : t -> bool
val pp : Format.formatter -> t -> unit
