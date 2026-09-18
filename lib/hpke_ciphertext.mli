(** HPKECiphertext (RFC 9420 Section 7.6). *)

type t = { kem_output : string; ciphertext : string }

val encode : Tls.Encoder.t -> t -> unit
val decode : Tls.Decoder.t -> t
