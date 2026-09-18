(* GroupContext (RFC 9420 Section 8.1). *)

type t = {
  version : int;
  cipher_suite : Cipher_suite.t;
  group_id : string;
  epoch : int64;
  tree_hash : string;
  confirmed_transcript_hash : string;
  extensions : Extension.t list;
}

let encode e t =
  Tls.Encoder.u16 e t.version;
  Tls.Encoder.u16 e t.cipher_suite;
  Tls.Encoder.opaque e t.group_id;
  Tls.Encoder.u64 e t.epoch;
  Tls.Encoder.opaque e t.tree_hash;
  Tls.Encoder.opaque e t.confirmed_transcript_hash;
  Extension.encode_list e t.extensions

let decode d =
  let version = Tls.Decoder.u16 d in
  let cipher_suite = Tls.Decoder.u16 d in
  let group_id = Tls.Decoder.opaque d in
  let epoch = Tls.Decoder.u64 d in
  let tree_hash = Tls.Decoder.opaque d in
  let confirmed_transcript_hash = Tls.Decoder.opaque d in
  let extensions = Extension.decode_list d in
  {
    version;
    cipher_suite;
    group_id;
    epoch;
    tree_hash;
    confirmed_transcript_hash;
    extensions;
  }

let to_bytes t = Tls.encode encode t
