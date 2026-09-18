(** GroupInfo (RFC 9420 Section 12.4.3.1). *)

type t = {
  group_context : Group_context.t;
  extensions : Extension.t list;
  confirmation_tag : string;
  signer : int;
  signature : string;
}

val encode : Tls.Encoder.t -> t -> unit
val decode : Tls.Decoder.t -> t
val encode_tbs : Tls.Encoder.t -> t -> unit
val tbs : t -> string
val to_bytes : t -> string
