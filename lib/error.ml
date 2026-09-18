(* Errors returned by the public API. Messages describe classes of invalid input
   and never contain key material. *)

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

let to_string = function
  | Decode msg -> "decode error: " ^ msg
  | Unsupported_cipher_suite n ->
      Printf.sprintf "unsupported cipher suite 0x%04x" n
  | Hpke e -> Format.asprintf "hpke error: %a" Hpke.Error.pp e
  | Invalid_signature -> "invalid signature"
  | Invalid_key msg -> "invalid key: " ^ msg
  | Aead_failure -> "AEAD authentication failure"
  | Invalid_tree msg -> "invalid ratchet tree: " ^ msg
  | Invalid_leaf_node msg -> "invalid leaf node: " ^ msg
  | Invalid_key_package msg -> "invalid key package: " ^ msg
  | Invalid_proposal msg -> "invalid proposal: " ^ msg
  | Invalid_commit msg -> "invalid commit: " ^ msg
  | Invalid_message msg -> "invalid message: " ^ msg
  | Invalid_welcome msg -> "invalid welcome: " ^ msg
  | Invalid_group_info msg -> "invalid group info: " ^ msg
  | Unknown_psk msg -> "unknown pre-shared key: " ^ msg
  | Wrong_epoch { expected; actual } ->
      Printf.sprintf "wrong epoch: expected %Ld, got %Ld" expected actual
  | Wrong_group msg -> "wrong group: " ^ msg
  | Ratchet_exhausted -> "secret tree ratchet exhausted"
  | Generation_out_of_range g -> Printf.sprintf "generation %d out of range" g
  | Invalid_extension msg -> "invalid extension: " ^ msg
  | Internal msg -> "internal error: " ^ msg

let pp fmt e = Format.pp_print_string fmt (to_string e)
let of_decode = function Ok v -> Ok v | Error msg -> Error (Decode msg)
