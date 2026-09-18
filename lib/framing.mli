(** Message framing (RFC 9420 Section 6). *)

val wire_format_public_message : int
val wire_format_private_message : int
val wire_format_welcome : int
val wire_format_group_info : int
val wire_format_key_package : int
val content_type_application : int
val content_type_proposal : int
val content_type_commit : int
val protocol_version_mls10 : int

module Sender : sig
  type t =
    | Member of int
    | External of int
    | New_member_proposal
    | New_member_commit

  val encode : Tls.Encoder.t -> t -> unit
  val decode : Tls.Decoder.t -> t
end

module Content : sig
  type t = Application of string | Proposal of Proposal.t | Commit of Commit.t

  val content_type : t -> int
  val encode_body : Tls.Encoder.t -> t -> unit
  val decode_body : Tls.Decoder.t -> content_type:int -> t
end

module Framed_content : sig
  type t = {
    group_id : string;
    epoch : int64;
    sender : Sender.t;
    authenticated_data : string;
    content : Content.t;
  }

  val encode : Tls.Encoder.t -> t -> unit
  val decode : Tls.Decoder.t -> t
  val content_type : t -> int

  val encode_tbs :
    Tls.Encoder.t ->
    wire_format:int ->
    group_context:Group_context.t option ->
    t ->
    unit
  (** FramedContentTBS; the group context is bound for member and
      new_member_commit senders and is required for them. *)

  val tbs :
    wire_format:int -> group_context:Group_context.t option -> t -> string
end

module Auth_data : sig
  type t = { signature : string; confirmation_tag : string option }
  (** FramedContentAuthData; [confirmation_tag] is present for commits. *)

  val encode : Tls.Encoder.t -> t -> unit
  val decode : Tls.Decoder.t -> content_type:int -> t
end

module Authenticated_content : sig
  type t = { wire_format : int; content : Framed_content.t; auth : Auth_data.t }

  val encode : Tls.Encoder.t -> t -> unit
  val decode : Tls.Decoder.t -> t

  val tbm : group_context:Group_context.t option -> t -> string
  (** AuthenticatedContentTBM, the membership tag input. *)

  val confirmed_transcript_hash_input : t -> string
end

module Public_message : sig
  type t = {
    content : Framed_content.t;
    auth : Auth_data.t;
    membership_tag : string option;
  }

  val encode : Tls.Encoder.t -> t -> unit
  val decode : Tls.Decoder.t -> t
end

module Private_message : sig
  type t = {
    group_id : string;
    epoch : int64;
    content_type : int;
    authenticated_data : string;
    encrypted_sender_data : string;
    ciphertext : string;
  }

  val encode : Tls.Encoder.t -> t -> unit
  val decode : Tls.Decoder.t -> t

  val encode_content : padding:int -> Content.t * Auth_data.t -> string
  (** PrivateMessageContent with zero padding. *)

  val decode_content :
    content_type:int -> string -> (Content.t * Auth_data.t, string) result

  val aad : t -> string
  (** PrivateContentAAD *)

  type sender_data = {
    leaf_index : int;
    generation : int;
    reuse_guard : string;
  }

  val encode_sender_data : Tls.Encoder.t -> sender_data -> unit
  val decode_sender_data : Tls.Decoder.t -> sender_data
  val sender_data_aad : t -> string
end
