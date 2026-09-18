(* Cryptographic operations for a cipher suite (RFC 9420 Section 5.1). Hashing
   and HMAC come from digestif, HKDF from kdf, AEADs and signature algorithms
   from mirage-crypto, and HPKE from the hpke package. *)

let ( let* ) = Result.bind

module type HASH = sig
  val size : int
  val digest : string -> string
  val hmac : key:string -> string -> string
  val extract : ?salt:string -> string -> string
  val expand : prk:string -> ?info:string -> int -> string
end

module Make_hash (H : Digestif.S) : HASH = struct
  let size = H.digest_size
  let digest s = H.to_raw_string (H.digest_string s)
  let hmac ~key s = H.to_raw_string (H.hmac_string ~key s)

  module K = Hkdf.Make (H)

  let extract = K.extract
  let expand = K.expand
end

module Sha256 = Make_hash (Digestif.SHA256)
module Sha384 = Make_hash (Digestif.SHA384)
module Sha512 = Make_hash (Digestif.SHA512)

type t = {
  suite : Cipher_suite.t;
  params : Cipher_suite.params;
  hash : (module HASH);
  hpke : Hpke.Suite.encryption Hpke.Suite.t;
}

let create suite =
  let* params = Cipher_suite.params suite in
  let hash =
    match params.hash with
    | Cipher_suite.Sha256 -> (module Sha256 : HASH)
    | Cipher_suite.Sha384 -> (module Sha384 : HASH)
    | Cipher_suite.Sha512 -> (module Sha512 : HASH)
  in
  let hpke =
    Hpke.Suite.create ~kem:params.kem ~kdf:params.kdf ~aead:params.aead
  in
  Ok { suite; params; hash; hpke }

let create_exn suite =
  match create suite with
  | Ok t -> t
  | Error e -> invalid_arg (Error.to_string e)

let suite t = t.suite
let kem t = t.params.kem

let hash_size t =
  let module H = (val t.hash) in
  H.size

let hash t s =
  let module H = (val t.hash) in
  H.digest s

let mac t ~key data =
  let module H = (val t.hash) in
  H.hmac ~key data

let random ~rng n = Mirage_crypto_rng.generate ~g:rng n

let hkdf_extract t ~salt ~ikm =
  let module H = (val t.hash) in
  H.extract ~salt ikm

let hkdf_expand t ~prk ~info length =
  let module H = (val t.hash) in
  H.expand ~prk ~info length

let zeros t = String.make (hash_size t) '\x00'
let label_prefix = "MLS 1.0 "

(* KDFLabel *)
let encode_kdf_label e (length, label, context) =
  Tls.Encoder.u16 e length;
  Tls.Encoder.opaque e (label_prefix ^ label);
  Tls.Encoder.opaque e context

let expand_with_label t ~secret ~label ~context length =
  let info = Tls.encode encode_kdf_label (length, label, context) in
  hkdf_expand t ~prk:secret ~info length

let derive_secret t ~secret ~label =
  expand_with_label t ~secret ~label ~context:"" (hash_size t)

let derive_tree_secret t ~secret ~label ~generation length =
  let context = Tls.encode Tls.Encoder.u32 generation in
  expand_with_label t ~secret ~label ~context length

(* RefHash *)
let encode_ref_hash_input e (label, value) =
  Tls.Encoder.opaque e label;
  Tls.Encoder.opaque e value

let ref_hash t ~label ~value =
  hash t (Tls.encode encode_ref_hash_input (label, value))

let key_package_ref t value =
  ref_hash t ~label:"MLS 1.0 KeyPackage Reference" ~value

let proposal_ref t value = ref_hash t ~label:"MLS 1.0 Proposal Reference" ~value

(* AEAD *)

let aead_key_size t =
  match t.params.aead with
  | Hpke.Aead.Aes_128_gcm -> 16
  | Hpke.Aead.Aes_256_gcm | Hpke.Aead.Chacha20_poly1305 -> 32

let aead_nonce_size _t = 12

let aead_seal t ~key ~nonce ~aad plaintext =
  match t.params.aead with
  | Hpke.Aead.Aes_128_gcm | Hpke.Aead.Aes_256_gcm ->
      let key = Mirage_crypto.AES.GCM.of_secret key in
      Mirage_crypto.AES.GCM.authenticate_encrypt ~key ~nonce ~adata:aad
        plaintext
  | Hpke.Aead.Chacha20_poly1305 ->
      let key = Mirage_crypto.Chacha20.of_secret key in
      Mirage_crypto.Chacha20.authenticate_encrypt ~key ~nonce ~adata:aad
        plaintext

let aead_open t ~key ~nonce ~aad ciphertext =
  let result =
    match t.params.aead with
    | Hpke.Aead.Aes_128_gcm | Hpke.Aead.Aes_256_gcm ->
        let key = Mirage_crypto.AES.GCM.of_secret key in
        Mirage_crypto.AES.GCM.authenticate_decrypt ~key ~nonce ~adata:aad
          ciphertext
    | Hpke.Aead.Chacha20_poly1305 ->
        let key = Mirage_crypto.Chacha20.of_secret key in
        Mirage_crypto.Chacha20.authenticate_decrypt ~key ~nonce ~adata:aad
          ciphertext
  in
  match result with Some pt -> Ok pt | None -> Error Error.Aead_failure

(* HPKE *)

let hpke_error = function Ok v -> Ok v | Error e -> Error (Error.Hpke e)

let hpke_public_key t bytes =
  hpke_error (Hpke.Public_key.of_bytes ~kem:t.params.kem bytes)

(* NIST-curve private keys are big-endian integers; tolerate encodings that are
   shorter than the field width (see [normalize_scalar] below). *)
let hpke_private_key t bytes =
  let kem = t.params.kem in
  let bytes =
    match kem with
    | Hpke.Kem.X25519 -> bytes
    | Hpke.Kem.P256 | Hpke.Kem.P384 | Hpke.Kem.P521 ->
        let size = Hpke.Kem.private_key_size kem in
        let n = String.length bytes in
        if n < size then String.make (size - n) '\x00' ^ bytes
        else if
          n > size
          && String.for_all
               (fun c -> c = '\x00')
               (String.sub bytes 0 (n - size))
        then String.sub bytes (n - size) size
        else bytes
  in
  hpke_error (Hpke.Private_key.of_bytes ~kem bytes)

let derive_key_pair t ~ikm = hpke_error (Hpke.derive_key_pair t.params.kem ~ikm)

let generate_key_pair t ~rng =
  hpke_error (Hpke.generate_key_pair ~rng t.params.kem)

(* EncryptContext *)
let encode_encrypt_context e (label, context) =
  Tls.Encoder.opaque e (label_prefix ^ label);
  Tls.Encoder.opaque e context

let encrypt_with_label t ~rng ~public_key ~label ~context plaintext =
  let* recipient = hpke_public_key t public_key in
  let info = Tls.encode encode_encrypt_context (label, context) in
  let* { Hpke.Rfc9180.encapsulated_key; ciphertext } =
    hpke_error
      (Hpke.Rfc9180.seal_base ~rng t.hpke ~recipient ~info ~aad:"" ~plaintext)
  in
  Ok (encapsulated_key, ciphertext)

let decrypt_with_label t ~private_key ~label ~context ~kem_output ciphertext =
  let info = Tls.encode encode_encrypt_context (label, context) in
  hpke_error
    (Hpke.Rfc9180.open_base t.hpke ~recipient:private_key ~info ~aad:""
       ~ciphertext:{ Hpke.Rfc9180.encapsulated_key = kem_output; ciphertext })

(* Signatures *)

module Ed25519 = Mirage_crypto_ec.Ed25519
module P256 = Mirage_crypto_ec.P256.Dsa
module P384 = Mirage_crypto_ec.P384.Dsa
module P521 = Mirage_crypto_ec.P521.Dsa

type signature_key =
  | Ed25519_key of Ed25519.priv
  | P256_key of P256.priv
  | P384_key of P384.priv
  | P521_key of P521.priv

let ec_error what = function
  | Ok v -> Ok v
  | Error e ->
      Error
        (Error.Invalid_key
           (Format.asprintf "%s: %a" what Mirage_crypto_ec.pp_error e))

(* ECDSA private keys are big-endian integers (Field-Element-to-Octet-String);
   accept encodings shorter than the field width by left-padding, and longer
   ones whose extra leading bytes are zero. *)
let normalize_scalar ~size bytes =
  let n = String.length bytes in
  if n = size then Some bytes
  else if n < size then Some (String.make (size - n) '\x00' ^ bytes)
  else if String.for_all (fun c -> c = '\x00') (String.sub bytes 0 (n - size))
  then Some (String.sub bytes (n - size) size)
  else None

let signature_key_of_bytes t bytes =
  let scalar ~size = function
    | Some b -> Ok b
    | None ->
        Error
          (Error.Invalid_key
             (Printf.sprintf "ECDSA private key exceeds %d bytes" size))
  in
  match t.params.signature with
  | Cipher_suite.Ed25519 ->
      let* k = ec_error "Ed25519" (Ed25519.priv_of_octets bytes) in
      Ok (Ed25519_key k)
  | Cipher_suite.Ecdsa_p256 ->
      let* b =
        scalar ~size:P256.byte_length
          (normalize_scalar ~size:P256.byte_length bytes)
      in
      let* k = ec_error "P-256" (P256.priv_of_octets b) in
      Ok (P256_key k)
  | Cipher_suite.Ecdsa_p384 ->
      let* b =
        scalar ~size:P384.byte_length
          (normalize_scalar ~size:P384.byte_length bytes)
      in
      let* k = ec_error "P-384" (P384.priv_of_octets b) in
      Ok (P384_key k)
  | Cipher_suite.Ecdsa_p521 ->
      let* b =
        scalar ~size:P521.byte_length
          (normalize_scalar ~size:P521.byte_length bytes)
      in
      let* k = ec_error "P-521" (P521.priv_of_octets b) in
      Ok (P521_key k)

let signature_key_to_bytes = function
  | Ed25519_key k -> Ed25519.priv_to_octets k
  | P256_key k -> P256.priv_to_octets k
  | P384_key k -> P384.priv_to_octets k
  | P521_key k -> P521.priv_to_octets k

let signature_public_key = function
  | Ed25519_key k -> Ed25519.pub_to_octets (Ed25519.pub_of_priv k)
  | P256_key k -> P256.pub_to_octets (P256.pub_of_priv k)
  | P384_key k -> P384.pub_to_octets (P384.pub_of_priv k)
  | P521_key k -> P521.pub_to_octets (P521.pub_of_priv k)

let generate_signature_key t ~rng =
  match t.params.signature with
  | Cipher_suite.Ed25519 -> Ed25519_key (fst (Ed25519.generate ~g:rng ()))
  | Cipher_suite.Ecdsa_p256 -> P256_key (fst (P256.generate ~g:rng ()))
  | Cipher_suite.Ecdsa_p384 -> P384_key (fst (P384.generate ~g:rng ()))
  | Cipher_suite.Ecdsa_p521 -> P521_key (fst (P521.generate ~g:rng ()))

(* DER encoding of ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } *)
module Der = struct
  let length n =
    if n < 0x80 then String.make 1 (Char.chr n)
    else if n < 0x100 then Printf.sprintf "\x81%c" (Char.chr n)
    else Printf.sprintf "\x82%c%c" (Char.chr (n lsr 8)) (Char.chr (n land 0xff))

  let integer s =
    let n = String.length s in
    let i = ref 0 in
    while !i < n - 1 && s.[!i] = '\x00' do
      incr i
    done;
    let s = String.sub s !i (n - !i) in
    let s = if Char.code s.[0] land 0x80 <> 0 then "\x00" ^ s else s in
    "\x02" ^ length (String.length s) ^ s

  let sequence body = "\x30" ^ length (String.length body) ^ body
  let encode_signature (r, s) = sequence (integer r ^ integer s)

  exception Bad

  let read_length s pos =
    let b = Char.code s.[pos] in
    if b < 0x80 then (b, pos + 1)
    else
      match b with
      | 0x81 ->
          let n = Char.code s.[pos + 1] in
          if n < 0x80 then raise Bad;
          (n, pos + 2)
      | 0x82 ->
          let n = (Char.code s.[pos + 1] lsl 8) lor Char.code s.[pos + 2] in
          if n < 0x100 then raise Bad;
          (n, pos + 3)
      | _ -> raise Bad

  let read_integer s pos ~size =
    if s.[pos] <> '\x02' then raise Bad;
    let n, pos = read_length s (pos + 1) in
    if n = 0 then raise Bad;
    let v = String.sub s pos n in
    if Char.code v.[0] land 0x80 <> 0 then raise Bad;
    if n > 1 && v.[0] = '\x00' && Char.code v.[1] land 0x80 = 0 then raise Bad;
    let v = if v.[0] = '\x00' then String.sub v 1 (n - 1) else v in
    if String.length v > size then raise Bad;
    (String.make (size - String.length v) '\x00' ^ v, pos + n)

  let decode_signature ~size der =
    try
      if der.[0] <> '\x30' then raise Bad;
      let n, pos = read_length der 1 in
      if pos + n <> String.length der then raise Bad;
      let r, pos = read_integer der pos ~size in
      let s, pos = read_integer der pos ~size in
      if pos <> String.length der then raise Bad;
      Some (r, s)
    with Bad | Invalid_argument _ -> None
end

let encode_sign_content e (label, content) =
  Tls.Encoder.opaque e (label_prefix ^ label);
  Tls.Encoder.opaque e content

let sign _t ~key content =
  match key with
  | Ed25519_key k -> Ed25519.sign ~key:k content
  | P256_key k ->
      Der.encode_signature (P256.sign ~key:k (Sha256.digest content))
  | P384_key k ->
      Der.encode_signature (P384.sign ~key:k (Sha384.digest content))
  | P521_key k ->
      Der.encode_signature (P521.sign ~key:k (Sha512.digest content))

let sign_with_label t ~key ~label content =
  sign t ~key (Tls.encode encode_sign_content (label, content))

let verify t ~public_key ~signature content =
  let ecdsa (type priv pub)
      (module D : Mirage_crypto_ec.Dsa with type priv = priv and type pub = pub)
      digest =
    match D.pub_of_octets public_key with
    | Error _ -> false
    | Ok key -> (
        match Der.decode_signature ~size:D.byte_length signature with
        | None -> false
        | Some rs -> D.verify ~key rs digest)
  in
  match t.params.signature with
  | Cipher_suite.Ed25519 -> (
      match Ed25519.pub_of_octets public_key with
      | Error _ -> false
      | Ok key -> Ed25519.verify ~key signature ~msg:content)
  | Cipher_suite.Ecdsa_p256 -> ecdsa (module P256) (Sha256.digest content)
  | Cipher_suite.Ecdsa_p384 -> ecdsa (module P384) (Sha384.digest content)
  | Cipher_suite.Ecdsa_p521 -> ecdsa (module P521) (Sha512.digest content)

let verify_with_label t ~public_key ~label ~signature content =
  verify t ~public_key ~signature
    (Tls.encode encode_sign_content (label, content))

let signature_key_matches t ~key ~public_key =
  let matches_suite =
    match (t.params.signature, key) with
    | Cipher_suite.Ed25519, Ed25519_key _
    | Cipher_suite.Ecdsa_p256, P256_key _
    | Cipher_suite.Ecdsa_p384, P384_key _
    | Cipher_suite.Ecdsa_p521, P521_key _ ->
        true
    | _ -> false
  in
  matches_suite && String.equal (signature_public_key key) public_key

(* HPKE export-only contexts, used for the external init secret (Section
   8.3). *)
let hpke_export_sender t ~rng ~public_key ~info ~context ~length =
  let* recipient = hpke_public_key t public_key in
  let* { Hpke.Rfc9180.encapsulated_key; context = ctx } =
    hpke_error (Hpke.Rfc9180.setup_base_sender ~rng t.hpke ~recipient ~info)
  in
  let* secret = hpke_error (Hpke.Rfc9180.Sender.export ctx ~context ~length) in
  Ok (encapsulated_key, secret)

let hpke_export_receiver t ~private_key ~encapsulated_key ~info ~context ~length
    =
  let* ctx =
    hpke_error
      (Hpke.Rfc9180.setup_base_receiver t.hpke ~recipient:private_key
         ~encapsulated_key ~info)
  in
  hpke_error (Hpke.Rfc9180.Receiver.export ctx ~context ~length)
