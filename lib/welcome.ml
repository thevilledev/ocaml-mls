(* Welcome messages (RFC 9420 Section 12.4.3.1). *)

type encrypted_group_secrets = {
  new_member : string;
  encrypted_group_secrets : Hpke_ciphertext.t;
}

type t = {
  cipher_suite : Cipher_suite.t;
  secrets : encrypted_group_secrets list;
  encrypted_group_info : string;
}

let encode_egs e s =
  Tls.Encoder.opaque e s.new_member;
  Hpke_ciphertext.encode e s.encrypted_group_secrets

let decode_egs d =
  let new_member = Tls.Decoder.opaque d in
  let encrypted_group_secrets = Hpke_ciphertext.decode d in
  { new_member; encrypted_group_secrets }

let encode e t =
  Tls.Encoder.u16 e t.cipher_suite;
  Tls.Encoder.vector e encode_egs t.secrets;
  Tls.Encoder.opaque e t.encrypted_group_info

let decode d =
  let cipher_suite = Tls.Decoder.u16 d in
  let secrets = Tls.Decoder.vector d decode_egs in
  let encrypted_group_info = Tls.Decoder.opaque d in
  { cipher_suite; secrets; encrypted_group_info }

module Group_secrets = struct
  type t = {
    joiner_secret : string;
    path_secret : string option;
    psks : Psk.id list;
  }

  let encode e t =
    Tls.Encoder.opaque e t.joiner_secret;
    Tls.Encoder.optional e Tls.Encoder.opaque t.path_secret;
    Tls.Encoder.vector e Psk.encode_id t.psks

  let decode d =
    let joiner_secret = Tls.Decoder.opaque d in
    let path_secret = Tls.Decoder.optional d Tls.Decoder.opaque in
    let psks = Tls.Decoder.vector d Psk.decode_id in
    { joiner_secret; path_secret; psks }

  let to_bytes t = Tls.encode encode t
  let of_bytes s = Error.of_decode (Tls.decode decode s)
end
