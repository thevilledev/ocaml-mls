(** Key schedule (RFC 9420 Section 8). *)

type epoch_secrets = {
  joiner_secret : string;
  welcome_secret : string;
  epoch_secret : string;
  init_secret : string;
  sender_data_secret : string;
  encryption_secret : string;
  exporter_secret : string;
  external_secret : string;
  confirmation_key : string;
  membership_key : string;
  resumption_psk : string;
  epoch_authenticator : string;
}

val joiner_secret :
  Crypto.t ->
  init_secret:string ->
  commit_secret:string ->
  group_context:string ->
  string

val from_joiner_secret :
  Crypto.t ->
  joiner_secret:string ->
  psk_secret:string ->
  group_context:string ->
  epoch_secrets

val derive :
  Crypto.t ->
  init_secret:string ->
  commit_secret:string ->
  psk_secret:string ->
  group_context:string ->
  epoch_secrets

val from_epoch_secret : Crypto.t -> epoch_secret:string -> epoch_secrets
(** Epoch 0 of a new group (Section 11); joiner and welcome secrets are empty.
*)

val welcome_secret :
  Crypto.t -> joiner_secret:string -> psk_secret:string -> string

val welcome_key_nonce : Crypto.t -> welcome_secret:string -> string * string

val confirmation_tag :
  Crypto.t ->
  confirmation_key:string ->
  confirmed_transcript_hash:string ->
  string

val exporter :
  Crypto.t ->
  exporter_secret:string ->
  label:string ->
  context:string ->
  int ->
  string

val external_key_pair :
  Crypto.t ->
  external_secret:string ->
  (Hpke.Private_key.t * Hpke.Public_key.t, Error.t) result

val sender_data_key_nonce :
  Crypto.t -> sender_data_secret:string -> ciphertext:string -> string * string
