(* HPKECiphertext (RFC 9420 Section 7.6). *)

type t = { kem_output : string; ciphertext : string }

let encode e t =
  Tls.Encoder.opaque e t.kem_output;
  Tls.Encoder.opaque e t.ciphertext

let decode d =
  let kem_output = Tls.Decoder.opaque d in
  let ciphertext = Tls.Decoder.opaque d in
  { kem_output; ciphertext }
