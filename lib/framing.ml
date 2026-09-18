(* Message framing (RFC 9420 Section 6). *)

let wire_format_public_message = 1
let wire_format_private_message = 2
let wire_format_welcome = 3
let wire_format_group_info = 4
let wire_format_key_package = 5
let content_type_application = 1
let content_type_proposal = 2
let content_type_commit = 3
let protocol_version_mls10 = 1

module Sender = struct
  type t =
    | Member of int
    | External of int
    | New_member_proposal
    | New_member_commit

  let encode e = function
    | Member i ->
        Tls.Encoder.u8 e 1;
        Tls.Encoder.u32 e i
    | External i ->
        Tls.Encoder.u8 e 2;
        Tls.Encoder.u32 e i
    | New_member_proposal -> Tls.Encoder.u8 e 3
    | New_member_commit -> Tls.Encoder.u8 e 4

  let decode d =
    match Tls.Decoder.u8 d with
    | 1 -> Member (Tls.Decoder.u32 d)
    | 2 -> External (Tls.Decoder.u32 d)
    | 3 -> New_member_proposal
    | 4 -> New_member_commit
    | n -> Tls.fail "unknown sender type %d" n
end

module Content = struct
  type t = Application of string | Proposal of Proposal.t | Commit of Commit.t

  let content_type = function
    | Application _ -> content_type_application
    | Proposal _ -> content_type_proposal
    | Commit _ -> content_type_commit

  let encode_body e = function
    | Application data -> Tls.Encoder.opaque e data
    | Proposal p -> Proposal.encode e p
    | Commit c -> Commit.encode e c

  let decode_body d ~content_type =
    match content_type with
    | 1 -> Application (Tls.Decoder.opaque d)
    | 2 -> Proposal (Proposal.decode d)
    | 3 -> Commit (Commit.decode d)
    | n -> Tls.fail "unknown content type %d" n
end

module Framed_content = struct
  type t = {
    group_id : string;
    epoch : int64;
    sender : Sender.t;
    authenticated_data : string;
    content : Content.t;
  }

  let encode e t =
    Tls.Encoder.opaque e t.group_id;
    Tls.Encoder.u64 e t.epoch;
    Sender.encode e t.sender;
    Tls.Encoder.opaque e t.authenticated_data;
    Tls.Encoder.u8 e (Content.content_type t.content);
    Content.encode_body e t.content

  let decode d =
    let group_id = Tls.Decoder.opaque d in
    let epoch = Tls.Decoder.u64 d in
    let sender = Sender.decode d in
    let authenticated_data = Tls.Decoder.opaque d in
    let content_type = Tls.Decoder.u8 d in
    let content = Content.decode_body d ~content_type in
    { group_id; epoch; sender; authenticated_data; content }

  let content_type t = Content.content_type t.content

  (* FramedContentTBS. The group context is bound for member and
     new_member_commit senders. *)
  let encode_tbs e ~wire_format ~group_context t =
    Tls.Encoder.u16 e protocol_version_mls10;
    Tls.Encoder.u16 e wire_format;
    encode e t;
    match t.sender with
    | Sender.Member _ | Sender.New_member_commit -> (
        match group_context with
        | Some gc -> Group_context.encode e gc
        | None ->
            invalid_arg "Framed_content.encode_tbs: group context required")
    | Sender.External _ | Sender.New_member_proposal -> ()

  let tbs ~wire_format ~group_context t =
    Tls.encode (fun e t -> encode_tbs e ~wire_format ~group_context t) t
end

module Auth_data = struct
  type t = { signature : string; confirmation_tag : string option }

  let encode e t =
    Tls.Encoder.opaque e t.signature;
    match t.confirmation_tag with
    | Some tag -> Tls.Encoder.opaque e tag
    | None -> ()

  let decode d ~content_type =
    let signature = Tls.Decoder.opaque d in
    let confirmation_tag =
      if content_type = content_type_commit then Some (Tls.Decoder.opaque d)
      else None
    in
    { signature; confirmation_tag }
end

module Authenticated_content = struct
  type t = { wire_format : int; content : Framed_content.t; auth : Auth_data.t }

  let encode e t =
    Tls.Encoder.u16 e t.wire_format;
    Framed_content.encode e t.content;
    Auth_data.encode e t.auth

  let decode d =
    let wire_format = Tls.Decoder.u16 d in
    let content = Framed_content.decode d in
    let auth =
      Auth_data.decode d ~content_type:(Framed_content.content_type content)
    in
    { wire_format; content; auth }

  (* AuthenticatedContentTBM, the input to the membership tag. *)
  let tbm ~group_context t =
    Tls.encode
      (fun e t ->
        Framed_content.encode_tbs e ~wire_format:t.wire_format ~group_context
          t.content;
        Auth_data.encode e t.auth)
      t

  (* ConfirmedTranscriptHashInput *)
  let confirmed_transcript_hash_input t =
    Tls.encode
      (fun e t ->
        Tls.Encoder.u16 e t.wire_format;
        Framed_content.encode e t.content;
        Tls.Encoder.opaque e t.auth.Auth_data.signature)
      t
end

module Public_message = struct
  type t = {
    content : Framed_content.t;
    auth : Auth_data.t;
    membership_tag : string option;
  }

  let encode e t =
    Framed_content.encode e t.content;
    Auth_data.encode e t.auth;
    match (t.content.Framed_content.sender, t.membership_tag) with
    | Sender.Member _, Some tag -> Tls.Encoder.opaque e tag
    | Sender.Member _, None ->
        invalid_arg "Public_message.encode: membership tag required"
    | _, _ -> ()

  let decode d =
    let content = Framed_content.decode d in
    let auth =
      Auth_data.decode d ~content_type:(Framed_content.content_type content)
    in
    let membership_tag =
      match content.Framed_content.sender with
      | Sender.Member _ -> Some (Tls.Decoder.opaque d)
      | _ -> None
    in
    { content; auth; membership_tag }
end

module Private_message = struct
  type t = {
    group_id : string;
    epoch : int64;
    content_type : int;
    authenticated_data : string;
    encrypted_sender_data : string;
    ciphertext : string;
  }

  let encode e t =
    Tls.Encoder.opaque e t.group_id;
    Tls.Encoder.u64 e t.epoch;
    Tls.Encoder.u8 e t.content_type;
    Tls.Encoder.opaque e t.authenticated_data;
    Tls.Encoder.opaque e t.encrypted_sender_data;
    Tls.Encoder.opaque e t.ciphertext

  let decode d =
    let group_id = Tls.Decoder.opaque d in
    let epoch = Tls.Decoder.u64 d in
    let content_type = Tls.Decoder.u8 d in
    let authenticated_data = Tls.Decoder.opaque d in
    let encrypted_sender_data = Tls.Decoder.opaque d in
    let ciphertext = Tls.Decoder.opaque d in
    {
      group_id;
      epoch;
      content_type;
      authenticated_data;
      encrypted_sender_data;
      ciphertext;
    }

  (* PrivateMessageContent: content body, auth data, then zero padding. *)
  let encode_content ~padding (content, auth) =
    Tls.encode
      (fun e () ->
        Content.encode_body e content;
        Auth_data.encode e auth;
        Tls.Encoder.raw e (String.make padding '\x00'))
      ()

  let decode_content ~content_type bytes =
    Tls.decode
      (fun d ->
        let content = Content.decode_body d ~content_type in
        let auth = Auth_data.decode d ~content_type in
        let padding = Tls.Decoder.raw d (Tls.Decoder.remaining d) in
        if String.exists (fun c -> c <> '\x00') padding then
          Tls.fail "non-zero padding";
        (content, auth))
      bytes

  (* PrivateContentAAD *)
  let aad t =
    Tls.encode
      (fun e t ->
        Tls.Encoder.opaque e t.group_id;
        Tls.Encoder.u64 e t.epoch;
        Tls.Encoder.u8 e t.content_type;
        Tls.Encoder.opaque e t.authenticated_data)
      t

  type sender_data = {
    leaf_index : int;
    generation : int;
    reuse_guard : string;
  }

  let encode_sender_data e sd =
    Tls.Encoder.u32 e sd.leaf_index;
    Tls.Encoder.u32 e sd.generation;
    Tls.Encoder.fixed e 4 sd.reuse_guard

  let decode_sender_data d =
    let leaf_index = Tls.Decoder.u32 d in
    let generation = Tls.Decoder.u32 d in
    let reuse_guard = Tls.Decoder.raw d 4 in
    { leaf_index; generation; reuse_guard }

  (* SenderDataAAD *)
  let sender_data_aad t =
    Tls.encode
      (fun e t ->
        Tls.Encoder.opaque e t.group_id;
        Tls.Encoder.u64 e t.epoch;
        Tls.Encoder.u8 e t.content_type)
      t
end
