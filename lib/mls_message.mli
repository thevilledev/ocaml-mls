(** MLSMessage (RFC 9420 Section 6). *)

type t =
  | Public_message of Framing.Public_message.t
  | Private_message of Framing.Private_message.t
  | Welcome of Welcome.t
  | Group_info of Group_info.t
  | Key_package of Key_package.t

val wire_format : t -> int
val encode : Tls.Encoder.t -> t -> unit
val decode : Tls.Decoder.t -> t
val to_bytes : t -> string
val of_bytes : string -> (t, Error.t) result
