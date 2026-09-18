(** Key packages (RFC 9420 Section 10). *)

type t = {
  version : int;
  cipher_suite : Cipher_suite.t;
  init_key : string;
  leaf_node : Leaf_node.t;
  extensions : Extension.t list;
  signature : string;
}

val encode : Tls.Encoder.t -> t -> unit
val decode : Tls.Decoder.t -> t
val encode_tbs : Tls.Encoder.t -> t -> unit
val tbs : t -> string
val to_bytes : t -> string
val of_bytes : string -> (t, Error.t) result
val signature_label : string

type generated = {
  key_package : t;
  init_key : Hpke.Private_key.t;  (** Private key for [init_key]. *)
  encryption_key : Hpke.Private_key.t;  (** Private key for the leaf node. *)
}

val sign : Crypto.t -> key:Crypto.signature_key -> t -> t

val generate :
  ?lifetime:Leaf_node.lifetime ->
  ?leaf_extensions:Extension.t list ->
  ?capabilities:Capabilities.t ->
  ?extensions:Extension.t list ->
  Crypto.t ->
  rng:Mirage_crypto_rng.g ->
  signature_key:Crypto.signature_key ->
  credential:Credential.t ->
  (generated, Error.t) result
(** A signed KeyPackage with fresh init and leaf keys. The caller must keep the
    private keys until the package is used in a Welcome. *)
