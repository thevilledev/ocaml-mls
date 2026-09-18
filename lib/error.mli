(** Errors returned by the public API. Messages describe classes of invalid
    input and never contain key material. *)

type t =
  | Decode of string
  | Unsupported_cipher_suite of int
  | Hpke of Hpke.Error.t
  | Invalid_signature
  | Invalid_key of string
  | Aead_failure
  | Invalid_tree of string
  | Invalid_leaf_node of string
  | Invalid_key_package of string
  | Invalid_proposal of string
  | Invalid_commit of string
  | Invalid_message of string
  | Invalid_welcome of string
  | Invalid_group_info of string
  | Unknown_psk of string
  | Wrong_epoch of { expected : int64; actual : int64 }
  | Wrong_group of string
  | Ratchet_exhausted
  | Generation_out_of_range of int
  | Invalid_extension of string
  | Internal of string

val to_string : t -> string
val pp : Format.formatter -> t -> unit
val of_decode : ('a, string) result -> ('a, t) result
