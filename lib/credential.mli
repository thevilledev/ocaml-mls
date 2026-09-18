(** Credentials (RFC 9420 Section 5.3). X.509 certificates are carried but not
    validated by this library. *)

type credential_type = int

val basic : credential_type
val x509 : credential_type

type t = Basic of string | X509 of string list

val credential_type : t -> credential_type
val encode : Tls.Encoder.t -> t -> unit
val decode : Tls.Decoder.t -> t
