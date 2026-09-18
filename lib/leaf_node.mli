(** Leaf nodes (RFC 9420 Section 7.2). *)

type lifetime = { not_before : int64; not_after : int64 }
type source = Key_package of lifetime | Update | Commit of string

type t = {
  encryption_key : string;
  signature_key : string;
  credential : Credential.t;
  capabilities : Capabilities.t;
  leaf_node_source : source;
  extensions : Extension.t list;
  signature : string;
}

val encode : Tls.Encoder.t -> t -> unit
val decode : Tls.Decoder.t -> t

val encode_tbs : Tls.Encoder.t -> group_id:string -> leaf_index:int -> t -> unit
(** LeafNodeTBS. [group_id] and [leaf_index] are bound for the update and commit
    sources only. *)

val tbs : group_id:string -> leaf_index:int -> t -> string
val to_bytes : t -> string
val of_bytes : string -> (t, Error.t) result
val parent_hash : t -> string option
val signature_label : string

val unbounded_lifetime : lifetime
(** A lifetime that never expires; applications should prefer bounded ones. *)

val sign :
  Crypto.t ->
  key:Crypto.signature_key ->
  group_id:string ->
  leaf_index:int ->
  t ->
  t

val generate :
  ?lifetime:lifetime ->
  ?extensions:Extension.t list ->
  ?capabilities:Capabilities.t ->
  Crypto.t ->
  rng:Mirage_crypto_rng.g ->
  signature_key:Crypto.signature_key ->
  credential:Credential.t ->
  (t * Hpke.Private_key.t, Error.t) result
(** A signed KeyPackage-style leaf node and its HPKE private key. *)
