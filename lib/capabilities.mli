(** Capabilities advertised in a LeafNode (RFC 9420 Section 7.2). Elements are
    uint16 registry values; default proposal and extension types are implicit
    and must not be listed. *)

type t = {
  versions : int list;
  cipher_suites : int list;
  extensions : int list;
  proposals : int list;
  credentials : int list;
}

val protocol_version_mls10 : int
val encode : Tls.Encoder.t -> t -> unit
val decode : Tls.Decoder.t -> t

val default : cipher_suite:Cipher_suite.t -> t
(** MLS 1.0, the given suite, and basic credentials. *)

val supports_extension : t -> int -> bool
val supports_credential : t -> int -> bool
