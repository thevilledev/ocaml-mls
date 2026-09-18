(* Parent nodes of the ratchet tree (RFC 9420 Section 7.1). *)

type t = {
  encryption_key : string;
  parent_hash : string;
  unmerged_leaves : int list;
}

let encode e t =
  Tls.Encoder.opaque e t.encryption_key;
  Tls.Encoder.opaque e t.parent_hash;
  Tls.Encoder.vector e Tls.Encoder.u32 t.unmerged_leaves

let decode d =
  let encryption_key = Tls.Decoder.opaque d in
  let parent_hash = Tls.Decoder.opaque d in
  let unmerged_leaves = Tls.Decoder.vector d Tls.Decoder.u32 in
  { encryption_key; parent_hash; unmerged_leaves }
