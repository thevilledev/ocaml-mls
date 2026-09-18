(* GroupInfo (RFC 9420 Section 12.4.3.1). *)

type t = {
  group_context : Group_context.t;
  extensions : Extension.t list;
  confirmation_tag : string;
  signer : int;
  signature : string;
}

let encode_tbs e t =
  Group_context.encode e t.group_context;
  Extension.encode_list e t.extensions;
  Tls.Encoder.opaque e t.confirmation_tag;
  Tls.Encoder.u32 e t.signer

let encode e t =
  encode_tbs e t;
  Tls.Encoder.opaque e t.signature

let decode d =
  let group_context = Group_context.decode d in
  let extensions = Extension.decode_list d in
  let confirmation_tag = Tls.Decoder.opaque d in
  let signer = Tls.Decoder.u32 d in
  let signature = Tls.Decoder.opaque d in
  { group_context; extensions; confirmation_tag; signer; signature }

let tbs t = Tls.encode encode_tbs t
let to_bytes t = Tls.encode encode t
