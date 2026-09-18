(** Content authentication and message protection (RFC 9420 Section 6). These
    functions take explicit keys so that they can be used and tested without a
    [Group]. *)

val framed_content_label : string

val sign :
  Crypto.t ->
  key:Crypto.signature_key ->
  wire_format:int ->
  group_context:Group_context.t option ->
  confirmation_tag:string option ->
  Framing.Framed_content.t ->
  Framing.Authenticated_content.t

val verify_signature :
  Crypto.t ->
  public_key:string ->
  group_context:Group_context.t option ->
  Framing.Authenticated_content.t ->
  (unit, Error.t) result

val membership_tag :
  Crypto.t ->
  membership_key:string ->
  group_context:Group_context.t ->
  Framing.Authenticated_content.t ->
  string

val protect_public :
  Crypto.t ->
  membership_key:string ->
  group_context:Group_context.t ->
  Framing.Authenticated_content.t ->
  (Framing.Public_message.t, Error.t) result

val unprotect_public :
  Crypto.t ->
  membership_key:string option ->
  group_context:Group_context.t ->
  Framing.Public_message.t ->
  (Framing.Authenticated_content.t, Error.t) result
(** Checks the membership tag of member messages; the signature is verified
    separately with {!verify_signature} once the sender's key is known. *)

val protect_private :
  Crypto.t ->
  rng:Mirage_crypto_rng.g ->
  secret_tree:Secret_tree.t ->
  sender_data_secret:string ->
  padding:int ->
  Framing.Authenticated_content.t ->
  (Framing.Private_message.t * Secret_tree.t, Error.t) result

val unprotect_private :
  ?own_leaf:int ->
  Crypto.t ->
  secret_tree:Secret_tree.t ->
  sender_data_secret:string ->
  Framing.Private_message.t ->
  (Framing.Authenticated_content.t * Secret_tree.t, Error.t) result
(** Messages whose sender data names [own_leaf] are rejected, since a member
    cannot decrypt its own messages. *)
