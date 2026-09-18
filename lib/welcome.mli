(** Welcome messages (RFC 9420 Section 12.4.3.1). *)

type encrypted_group_secrets = {
  new_member : string;
  encrypted_group_secrets : Hpke_ciphertext.t;
}

type t = {
  cipher_suite : Cipher_suite.t;
  secrets : encrypted_group_secrets list;
  encrypted_group_info : string;
}

val encode : Tls.Encoder.t -> t -> unit
val decode : Tls.Decoder.t -> t

module Group_secrets : sig
  type t = {
    joiner_secret : string;
    path_secret : string option;
    psks : Psk.id list;
  }

  val encode : Tls.Encoder.t -> t -> unit
  val decode : Tls.Decoder.t -> t
  val to_bytes : t -> string
  val of_bytes : string -> (t, Error.t) result
end
