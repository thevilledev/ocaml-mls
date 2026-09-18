(* Proposals (RFC 9420 Section 12.1). *)

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

let type_add = 1
let type_update = 2
let type_remove = 3
let type_psk = 4
let type_reinit = 5
let type_external_init = 6
let type_group_context_extensions = 7

let default_types =
  [
    type_add;
    type_update;
    type_remove;
    type_psk;
    type_reinit;
    type_external_init;
    type_group_context_extensions;
  ]

let proposal_type = function
  | Add _ -> type_add
  | Update _ -> type_update
  | Remove _ -> type_remove
  | Pre_shared_key _ -> type_psk
  | Re_init _ -> type_reinit
  | External_init _ -> type_external_init
  | Group_context_extensions _ -> type_group_context_extensions

let encode_body e = function
  | Add kp -> Key_package.encode e kp
  | Update ln -> Leaf_node.encode e ln
  | Remove idx -> Tls.Encoder.u32 e idx
  | Pre_shared_key id -> Psk.encode_id e id
  | Re_init r ->
      Tls.Encoder.opaque e r.group_id;
      Tls.Encoder.u16 e r.version;
      Tls.Encoder.u16 e r.cipher_suite;
      Extension.encode_list e r.extensions
  | External_init kem_output -> Tls.Encoder.opaque e kem_output
  | Group_context_extensions exts -> Extension.encode_list e exts

let decode_body d ~proposal_type =
  match proposal_type with
  | 1 -> Add (Key_package.decode d)
  | 2 -> Update (Leaf_node.decode d)
  | 3 -> Remove (Tls.Decoder.u32 d)
  | 4 -> Pre_shared_key (Psk.decode_id d)
  | 5 ->
      let group_id = Tls.Decoder.opaque d in
      let version = Tls.Decoder.u16 d in
      let cipher_suite = Tls.Decoder.u16 d in
      let extensions = Extension.decode_list d in
      Re_init { group_id; version; cipher_suite; extensions }
  | 6 -> External_init (Tls.Decoder.opaque d)
  | 7 -> Group_context_extensions (Extension.decode_list d)
  | n -> Tls.fail "unknown proposal type %d" n

let encode e t =
  Tls.Encoder.u16 e (proposal_type t);
  encode_body e t

let decode d =
  let proposal_type = Tls.Decoder.u16 d in
  decode_body d ~proposal_type

let to_bytes t = Tls.encode encode t
