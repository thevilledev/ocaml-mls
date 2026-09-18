(** Pre-shared keys (RFC 9420 Section 8.4). *)

type resumption_usage = Application | Reinit | Branch

type key =
  | External of string
  | Resumption of {
      usage : resumption_usage;
      psk_group_id : string;
      psk_epoch : int64;
    }

type id = { key : key; psk_nonce : string }
(** PreSharedKeyID *)

val encode_id : Tls.Encoder.t -> id -> unit
val decode_id : Tls.Decoder.t -> id

val encode_label : Tls.Encoder.t -> id * int * int -> unit
(** PSKLabel: [(id, index, count)]. *)

val psk_secret : Crypto.t -> (id * string) list -> (string, Error.t) result
(** [psk_secret] from PreSharedKeyIDs paired with their secrets, in proposal
    order. *)
