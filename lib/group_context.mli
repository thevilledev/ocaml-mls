(** GroupContext (RFC 9420 Section 8.1). *)

type t = {
  version : int;
  cipher_suite : Cipher_suite.t;
  group_id : string;
  epoch : int64;
  tree_hash : string;
  confirmed_transcript_hash : string;
  extensions : Extension.t list;
}

val encode : Tls.Encoder.t -> t -> unit
val decode : Tls.Decoder.t -> t
val to_bytes : t -> string
