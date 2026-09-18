(* Key schedule (RFC 9420 Section 8). *)

let ( let* ) = Result.bind

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

let joiner_secret c ~init_secret ~commit_secret ~group_context =
  let prk = Crypto.hkdf_extract c ~salt:init_secret ~ikm:commit_secret in
  Crypto.expand_with_label c ~secret:prk ~label:"joiner" ~context:group_context
    (Crypto.hash_size c)

let of_epoch_secret c ~joiner_secret ~welcome_secret ~epoch_secret =
  let d label = Crypto.derive_secret c ~secret:epoch_secret ~label in
  let* sender_data_secret = d "sender data" in
  let* encryption_secret = d "encryption" in
  let* exporter_secret = d "exporter" in
  let* external_secret = d "external" in
  let* confirmation_key = d "confirm" in
  let* membership_key = d "membership" in
  let* resumption_psk = d "resumption" in
  let* epoch_authenticator = d "authentication" in
  let* init_secret = d "init" in
  Ok
    {
      joiner_secret;
      welcome_secret;
      epoch_secret;
      init_secret;
      sender_data_secret;
      encryption_secret;
      exporter_secret;
      external_secret;
      confirmation_key;
      membership_key;
      resumption_psk;
      epoch_authenticator;
    }

(* Derive the epoch secrets from a joiner secret, as a new member does. *)
let from_joiner_secret c ~joiner_secret ~psk_secret ~group_context =
  let member_secret =
    Crypto.hkdf_extract c ~salt:joiner_secret ~ikm:psk_secret
  in
  let* welcome_secret =
    Crypto.derive_secret c ~secret:member_secret ~label:"welcome"
  in
  let* epoch_secret =
    Crypto.expand_with_label c ~secret:member_secret ~label:"epoch"
      ~context:group_context (Crypto.hash_size c)
  in
  of_epoch_secret c ~joiner_secret ~welcome_secret ~epoch_secret

let derive c ~init_secret ~commit_secret ~psk_secret ~group_context =
  let* joiner_secret =
    joiner_secret c ~init_secret ~commit_secret ~group_context
  in
  from_joiner_secret c ~joiner_secret ~psk_secret ~group_context

(* Epoch 0 of a new group starts from a fresh random epoch secret (Section 11);
   there is no joiner or welcome secret. *)
let from_epoch_secret c ~epoch_secret =
  of_epoch_secret c ~joiner_secret:"" ~welcome_secret:"" ~epoch_secret

let welcome_secret c ~joiner_secret ~psk_secret =
  let member_secret =
    Crypto.hkdf_extract c ~salt:joiner_secret ~ikm:psk_secret
  in
  Crypto.derive_secret c ~secret:member_secret ~label:"welcome"

let key_nonce c ~secret ~context =
  let* key =
    Crypto.expand_with_label c ~secret ~label:"key" ~context
      (Crypto.aead_key_size c)
  in
  let* nonce =
    Crypto.expand_with_label c ~secret ~label:"nonce" ~context
      (Crypto.aead_nonce_size c)
  in
  Ok (key, nonce)

let welcome_key_nonce c ~welcome_secret =
  key_nonce c ~secret:welcome_secret ~context:""

let confirmation_tag c ~confirmation_key ~confirmed_transcript_hash =
  Crypto.mac c ~key:confirmation_key confirmed_transcript_hash

(* MLS-Exporter (Section 8.5) *)
let exporter c ~exporter_secret ~label ~context length =
  let* secret = Crypto.derive_secret c ~secret:exporter_secret ~label in
  Crypto.expand_with_label c ~secret ~label:"exported"
    ~context:(Crypto.hash c context) length

let external_key_pair c ~external_secret =
  Crypto.derive_key_pair c ~ikm:external_secret

(* Sender data key and nonce (Section 6.3.2). *)
let sender_data_key_nonce c ~sender_data_secret ~ciphertext =
  let sample_len = min (Crypto.hash_size c) (String.length ciphertext) in
  key_nonce c ~secret:sender_data_secret
    ~context:(String.sub ciphertext 0 sample_len)
