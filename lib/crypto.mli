(** Cryptographic operations for one cipher suite (RFC 9420 Section 5.1). The
    suite's KEM, KDF and AEAD come from the hpke package, hashing and HMAC from
    digestif, and signature algorithms from mirage-crypto-ec. *)

type t
(** A cipher suite provider. *)

val create : Cipher_suite.t -> (t, Error.t) result
(** Fails with [Unsupported_cipher_suite] for unknown suites and for the X448
    and Ed448 suites (0x0004 and 0x0006). *)

val create_exn : Cipher_suite.t -> t
val suite : t -> Cipher_suite.t
val kem : t -> Hpke.Kem.id

(** {1 Hashing and key derivation} *)

val hash_size : t -> int
(** [KDF.Nh], the hash output length. *)

val hash : t -> string -> string
val mac : t -> key:string -> string -> string
val random : rng:Mirage_crypto_rng.g -> int -> string
val hkdf_extract : t -> salt:string -> ikm:string -> string

val hkdf_expand :
  t -> prk:string -> info:string -> int -> (string, Error.t) result
(** Fails when [prk] is shorter than {!hash_size} or the length exceeds
    [255 * hash_size]. *)

val zeros : t -> string
(** [KDF.Nh] zero bytes. *)

val expand_with_label :
  t ->
  secret:string ->
  label:string ->
  context:string ->
  int ->
  (string, Error.t) result

val derive_secret :
  t -> secret:string -> label:string -> (string, Error.t) result

val derive_tree_secret :
  t ->
  secret:string ->
  label:string ->
  generation:int ->
  int ->
  (string, Error.t) result

val ref_hash : t -> label:string -> value:string -> string

val key_package_ref : t -> string -> string
(** [KeyPackageRef] of a serialized KeyPackage. *)

val proposal_ref : t -> string -> string
(** [ProposalRef] of a serialized AuthenticatedContent. *)

(** {1 AEAD} *)

val aead_key_size : t -> int
val aead_nonce_size : t -> int

val aead_seal :
  t ->
  key:string ->
  nonce:string ->
  aad:string ->
  string ->
  (string, Error.t) result

val aead_open :
  t ->
  key:string ->
  nonce:string ->
  aad:string ->
  string ->
  (string, Error.t) result

(** {1 HPKE} *)

val hpke_public_key : t -> string -> (Hpke.Public_key.t, Error.t) result

val hpke_private_key : t -> string -> (Hpke.Private_key.t, Error.t) result
(** Accepts NIST-curve scalars encoded with fewer bytes than the field width. *)

val derive_key_pair :
  t -> ikm:string -> (Hpke.Private_key.t * Hpke.Public_key.t, Error.t) result

val generate_key_pair :
  t ->
  rng:Mirage_crypto_rng.g ->
  (Hpke.Private_key.t * Hpke.Public_key.t, Error.t) result

val encrypt_with_label :
  t ->
  rng:Mirage_crypto_rng.g ->
  public_key:string ->
  label:string ->
  context:string ->
  string ->
  (string * string, Error.t) result
(** [EncryptWithLabel], returning [(kem_output, ciphertext)]. *)

val decrypt_with_label :
  t ->
  private_key:Hpke.Private_key.t ->
  label:string ->
  context:string ->
  kem_output:string ->
  string ->
  (string, Error.t) result

val hpke_export_sender :
  t ->
  rng:Mirage_crypto_rng.g ->
  public_key:string ->
  info:string ->
  context:string ->
  length:int ->
  (string * string, Error.t) result
(** Base-mode setup and export, returning [(kem_output, exported secret)]. *)

val hpke_export_receiver :
  t ->
  private_key:Hpke.Private_key.t ->
  encapsulated_key:string ->
  info:string ->
  context:string ->
  length:int ->
  (string, Error.t) result

(** {1 Signatures} *)

type signature_key
(** A signature private key for the suite's algorithm. *)

val signature_key_of_bytes : t -> string -> (signature_key, Error.t) result
val signature_key_to_bytes : signature_key -> string

val signature_public_key : signature_key -> string
(** The encoded public key, as carried in a LeafNode. *)

val generate_signature_key : t -> rng:Mirage_crypto_rng.g -> signature_key
val sign : t -> key:signature_key -> string -> string
val sign_with_label : t -> key:signature_key -> label:string -> string -> string
val verify : t -> public_key:string -> signature:string -> string -> bool

val verify_with_label :
  t -> public_key:string -> label:string -> signature:string -> string -> bool

val signature_key_matches : t -> key:signature_key -> public_key:string -> bool
