(** Parent nodes of the ratchet tree (RFC 9420 Section 7.1). *)

type t = {
  encryption_key : string;
  parent_hash : string;
  unmerged_leaves : int list;
}

val encode : Tls.Encoder.t -> t -> unit
val decode : Tls.Decoder.t -> t
