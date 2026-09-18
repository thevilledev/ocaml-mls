(** UpdatePath (RFC 9420 Section 7.6). *)

type node = {
  encryption_key : string;
  encrypted_path_secret : Hpke_ciphertext.t list;
}

type t = { leaf_node : Leaf_node.t; nodes : node list }

val encode_node : Tls.Encoder.t -> node -> unit
val decode_node : Tls.Decoder.t -> node
val encode : Tls.Encoder.t -> t -> unit
val decode : Tls.Decoder.t -> t
