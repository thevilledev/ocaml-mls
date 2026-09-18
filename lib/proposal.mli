(** Proposals (RFC 9420 Section 12.1). *)

type re_init = {
  group_id : string;
  version : int;
  cipher_suite : Cipher_suite.t;
  extensions : Extension.t list;
}

type t =
  | Add of Key_package.t
  | Update of Leaf_node.t
  | Remove of int
  | Pre_shared_key of Psk.id
  | Re_init of re_init
  | External_init of string
  | Group_context_extensions of Extension.t list

val type_add : int
val type_update : int
val type_remove : int
val type_psk : int
val type_reinit : int
val type_external_init : int
val type_group_context_extensions : int
val default_types : int list
val proposal_type : t -> int

val encode_body : Tls.Encoder.t -> t -> unit
(** The proposal without its ProposalType prefix. *)

val decode_body : Tls.Decoder.t -> proposal_type:int -> t
val encode : Tls.Encoder.t -> t -> unit
val decode : Tls.Decoder.t -> t
val to_bytes : t -> string
