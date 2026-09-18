(* MLS cipher suites (RFC 9420 Section 17.1). The wire representation is a
   uint16; unknown values are carried through unchanged so that messages
   advertising private-use suites still parse. *)

type t = int

let mls_128_dhkemx25519_aes128gcm_sha256_ed25519 = 0x0001
let mls_128_dhkemp256_aes128gcm_sha256_p256 = 0x0002
let mls_128_dhkemx25519_chacha20poly1305_sha256_ed25519 = 0x0003
let mls_256_dhkemx448_aes256gcm_sha512_ed448 = 0x0004
let mls_256_dhkemp521_aes256gcm_sha512_p521 = 0x0005
let mls_256_dhkemx448_chacha20poly1305_sha512_ed448 = 0x0006
let mls_256_dhkemp384_aes256gcm_sha384_p384 = 0x0007

type hash = Sha256 | Sha384 | Sha512
type signature_scheme = Ed25519 | Ecdsa_p256 | Ecdsa_p384 | Ecdsa_p521

type params = {
  kem : Hpke.Kem.id;
  kdf : Hpke.Kdf.id;
  aead : Hpke.Aead.id;
  hash : hash;
  signature : signature_scheme;
}

let name = function
  | 0x0001 -> Some "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
  | 0x0002 -> Some "MLS_128_DHKEMP256_AES128GCM_SHA256_P256"
  | 0x0003 -> Some "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519"
  | 0x0004 -> Some "MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448"
  | 0x0005 -> Some "MLS_256_DHKEMP521_AES256GCM_SHA512_P521"
  | 0x0006 -> Some "MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448"
  | 0x0007 -> Some "MLS_256_DHKEMP384_AES256GCM_SHA384_P384"
  | _ -> None

(* Suites 0x0004 and 0x0006 require X448 and Ed448, which neither the hpke
   package nor mirage-crypto-ec provide. They are recognised but not usable. *)
let params = function
  | 0x0001 ->
      Ok
        {
          kem = Hpke.Kem.X25519;
          kdf = Hpke.Kdf.Hkdf_sha256;
          aead = Hpke.Aead.Aes_128_gcm;
          hash = Sha256;
          signature = Ed25519;
        }
  | 0x0002 ->
      Ok
        {
          kem = Hpke.Kem.P256;
          kdf = Hpke.Kdf.Hkdf_sha256;
          aead = Hpke.Aead.Aes_128_gcm;
          hash = Sha256;
          signature = Ecdsa_p256;
        }
  | 0x0003 ->
      Ok
        {
          kem = Hpke.Kem.X25519;
          kdf = Hpke.Kdf.Hkdf_sha256;
          aead = Hpke.Aead.Chacha20_poly1305;
          hash = Sha256;
          signature = Ed25519;
        }
  | 0x0005 ->
      Ok
        {
          kem = Hpke.Kem.P521;
          kdf = Hpke.Kdf.Hkdf_sha512;
          aead = Hpke.Aead.Aes_256_gcm;
          hash = Sha512;
          signature = Ecdsa_p521;
        }
  | 0x0007 ->
      Ok
        {
          kem = Hpke.Kem.P384;
          kdf = Hpke.Kdf.Hkdf_sha384;
          aead = Hpke.Aead.Aes_256_gcm;
          hash = Sha384;
          signature = Ecdsa_p384;
        }
  | n -> Error (Error.Unsupported_cipher_suite n)

let all = [ 0x0001; 0x0002; 0x0003; 0x0004; 0x0005; 0x0006; 0x0007 ]
let supported = [ 0x0001; 0x0002; 0x0003; 0x0005; 0x0007 ]
let is_supported t = Result.is_ok (params t)

let pp fmt t =
  match name t with
  | Some n -> Format.pp_print_string fmt n
  | None -> Format.fprintf fmt "0x%04x" t
