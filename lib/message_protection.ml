(* Content authentication and message protection (RFC 9420 Section 6). These
   functions take explicit keys so that they can be exercised independently of
   the group state machine. *)

let ( let* ) = Result.bind

open Framing

let framed_content_label = "FramedContentTBS"

(* Sign a FramedContent, producing AuthenticatedContent. *)
let sign c ~key ~wire_format ~group_context ~confirmation_tag
    (content : Framed_content.t) =
  let tbs = Framed_content.tbs ~wire_format ~group_context content in
  let signature =
    Crypto.sign_with_label c ~key ~label:framed_content_label tbs
  in
  let confirmation_tag =
    match content.Framed_content.content with
    | Content.Commit _ -> confirmation_tag
    | _ -> None
  in
  {
    Authenticated_content.wire_format;
    content;
    auth = { Auth_data.signature; confirmation_tag };
  }

let verify_signature c ~public_key ~group_context (ac : Authenticated_content.t)
    =
  let tbs =
    Framed_content.tbs ~wire_format:ac.Authenticated_content.wire_format
      ~group_context ac.Authenticated_content.content
  in
  if
    Crypto.verify_with_label c ~public_key ~label:framed_content_label
      ~signature:ac.Authenticated_content.auth.Auth_data.signature tbs
  then Ok ()
  else Error Error.Invalid_signature

let membership_tag c ~membership_key ~group_context
    (ac : Authenticated_content.t) =
  Crypto.mac c ~key:membership_key
    (Authenticated_content.tbm ~group_context:(Some group_context) ac)

(* PublicMessage *)

let protect_public c ~membership_key ~group_context
    (ac : Authenticated_content.t) =
  if ac.Authenticated_content.wire_format <> wire_format_public_message then
    Error (Error.Invalid_message "wire format is not mls_public_message")
  else
    match ac.Authenticated_content.content.Framed_content.content with
    | Content.Application _ ->
        Error
          (Error.Invalid_message
             "application data must not be sent as PublicMessage")
    | _ ->
        let membership_tag =
          match ac.Authenticated_content.content.Framed_content.sender with
          | Sender.Member _ ->
              Some (membership_tag c ~membership_key ~group_context ac)
          | _ -> None
        in
        Ok
          {
            Public_message.content = ac.Authenticated_content.content;
            auth = ac.Authenticated_content.auth;
            membership_tag;
          }

(* Check the membership tag of a PublicMessage from a member and return the
   AuthenticatedContent. The signature is verified separately once the sender's
   key is known. *)
let unprotect_public c ~membership_key ~group_context (pm : Public_message.t) =
  let ac =
    {
      Authenticated_content.wire_format = wire_format_public_message;
      content = pm.Public_message.content;
      auth = pm.Public_message.auth;
    }
  in
  match pm.Public_message.content.Framed_content.sender with
  | Sender.Member _ -> (
      match (membership_key, pm.Public_message.membership_tag) with
      | Some membership_key, Some tag ->
          if Eqaf.equal tag (membership_tag c ~membership_key ~group_context ac)
          then Ok ac
          else Error (Error.Invalid_message "membership tag mismatch")
      | None, _ -> Error (Error.Invalid_message "membership key required")
      | _, None -> Error (Error.Invalid_message "missing membership tag"))
  | _ -> (
      match pm.Public_message.content.Framed_content.content with
      | Content.Application _ ->
          Error (Error.Invalid_message "application data in PublicMessage")
      | _ -> Ok ac)

(* PrivateMessage *)

let secret_tree_content_type content_type =
  if content_type = content_type_application then Secret_tree.Application
  else Secret_tree.Handshake

let apply_reuse_guard nonce reuse_guard =
  let b = Bytes.of_string nonce in
  for i = 0 to 3 do
    Bytes.set b i
      (Char.chr (Char.code (Bytes.get b i) lxor Char.code reuse_guard.[i]))
  done;
  Bytes.to_string b

let protect_private c ~rng ~secret_tree ~sender_data_secret ~padding
    (ac : Authenticated_content.t) =
  if ac.Authenticated_content.wire_format <> wire_format_private_message then
    Error (Error.Invalid_message "wire format is not mls_private_message")
  else
    let content = ac.Authenticated_content.content in
    let* leaf_index =
      match content.Framed_content.sender with
      | Sender.Member i -> Ok i
      | _ ->
          Error (Error.Invalid_message "PrivateMessage sender must be a member")
    in
    let content_type = Framed_content.content_type content in
    let* (key, nonce, generation), secret_tree =
      Secret_tree.next_key secret_tree ~leaf:leaf_index
        (secret_tree_content_type content_type)
    in
    let reuse_guard = Crypto.random ~rng 4 in
    let nonce = apply_reuse_guard nonce reuse_guard in
    let pm_header =
      {
        Private_message.group_id = content.Framed_content.group_id;
        epoch = content.Framed_content.epoch;
        content_type;
        authenticated_data = content.Framed_content.authenticated_data;
        encrypted_sender_data = "";
        ciphertext = "";
      }
    in
    let plaintext =
      Private_message.encode_content ~padding
        (content.Framed_content.content, ac.Authenticated_content.auth)
    in
    let ciphertext =
      Crypto.aead_seal c ~key ~nonce
        ~aad:(Private_message.aad pm_header)
        plaintext
    in
    let sender_data =
      Tls.encode Private_message.encode_sender_data
        { Private_message.leaf_index; generation; reuse_guard }
    in
    let sd_key, sd_nonce =
      Key_schedule.sender_data_key_nonce c ~sender_data_secret ~ciphertext
    in
    let encrypted_sender_data =
      Crypto.aead_seal c ~key:sd_key ~nonce:sd_nonce
        ~aad:(Private_message.sender_data_aad pm_header)
        sender_data
    in
    Ok
      ( { pm_header with Private_message.encrypted_sender_data; ciphertext },
        secret_tree )

let unprotect_private ?own_leaf c ~secret_tree ~sender_data_secret
    (pm : Private_message.t) =
  let sd_key, sd_nonce =
    Key_schedule.sender_data_key_nonce c ~sender_data_secret
      ~ciphertext:pm.Private_message.ciphertext
  in
  let* sender_data =
    Crypto.aead_open c ~key:sd_key ~nonce:sd_nonce
      ~aad:(Private_message.sender_data_aad pm)
      pm.Private_message.encrypted_sender_data
  in
  let* { Private_message.leaf_index; generation; reuse_guard } =
    Error.of_decode (Tls.decode Private_message.decode_sender_data sender_data)
  in
  let* () =
    match own_leaf with
    | Some own when own = leaf_index ->
        Error (Error.Invalid_message "message from own leaf")
    | _ -> Ok ()
  in
  let content_type = pm.Private_message.content_type in
  let* (key, nonce), secret_tree =
    Secret_tree.key_for secret_tree ~leaf:leaf_index
      (secret_tree_content_type content_type)
      ~generation
  in
  let nonce = apply_reuse_guard nonce reuse_guard in
  let* plaintext =
    Crypto.aead_open c ~key ~nonce ~aad:(Private_message.aad pm)
      pm.Private_message.ciphertext
  in
  let* content, auth =
    Error.of_decode (Private_message.decode_content ~content_type plaintext)
  in
  let framed =
    {
      Framed_content.group_id = pm.Private_message.group_id;
      epoch = pm.Private_message.epoch;
      sender = Sender.Member leaf_index;
      authenticated_data = pm.Private_message.authenticated_data;
      content;
    }
  in
  Ok
    ( {
        Authenticated_content.wire_format = wire_format_private_message;
        content = framed;
        auth;
      },
      secret_tree )
