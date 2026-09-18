(* Credentials (RFC 9420 Section 5.3). *)

type credential_type = int

let basic = 0x0001
let x509 = 0x0002

type t = Basic of string | X509 of string list

let credential_type = function Basic _ -> basic | X509 _ -> x509

let encode e = function
  | Basic identity ->
      Tls.Encoder.u16 e basic;
      Tls.Encoder.opaque e identity
  | X509 certs ->
      Tls.Encoder.u16 e x509;
      Tls.Encoder.vector e Tls.Encoder.opaque certs

let decode d =
  match Tls.Decoder.u16 d with
  | 0x0001 -> Basic (Tls.Decoder.opaque d)
  | 0x0002 -> X509 (Tls.Decoder.vector d Tls.Decoder.opaque)
  | n -> Tls.fail "unknown credential type %d" n
