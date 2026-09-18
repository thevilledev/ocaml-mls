(* UpdatePath (RFC 9420 Section 7.6). *)

type node = {
  encryption_key : string;
  encrypted_path_secret : Hpke_ciphertext.t list;
}

type t = { leaf_node : Leaf_node.t; nodes : node list }

let encode_node e n =
  Tls.Encoder.opaque e n.encryption_key;
  Tls.Encoder.vector e Hpke_ciphertext.encode n.encrypted_path_secret

let decode_node d =
  let encryption_key = Tls.Decoder.opaque d in
  let encrypted_path_secret = Tls.Decoder.vector d Hpke_ciphertext.decode in
  { encryption_key; encrypted_path_secret }

let encode e t =
  Leaf_node.encode e t.leaf_node;
  Tls.Encoder.vector e encode_node t.nodes

let decode d =
  let leaf_node = Leaf_node.decode d in
  let nodes = Tls.Decoder.vector d decode_node in
  { leaf_node; nodes }
