(* Extensions (RFC 9420 Section 5.3.1 / 12.4.3). *)

type extension_type = int

let application_id = 0x0001
let ratchet_tree = 0x0002
let required_capabilities = 0x0003
let external_pub = 0x0004
let external_senders = 0x0005

type t = { extension_type : extension_type; extension_data : string }

let encode e t =
  Tls.Encoder.u16 e t.extension_type;
  Tls.Encoder.opaque e t.extension_data

let decode d =
  let extension_type = Tls.Decoder.u16 d in
  let extension_data = Tls.Decoder.opaque d in
  { extension_type; extension_data }

let encode_list e xs = Tls.Encoder.vector e encode xs
let decode_list d = Tls.Decoder.vector d decode
let find ty xs = List.find_opt (fun x -> x.extension_type = ty) xs

let is_default_type ty =
  ty = application_id || ty = ratchet_tree || ty = required_capabilities
  || ty = external_pub || ty = external_senders

(* Default extension types are implicitly supported (Section 7.2). *)
let default_types =
  [
    application_id;
    ratchet_tree;
    required_capabilities;
    external_pub;
    external_senders;
  ]
