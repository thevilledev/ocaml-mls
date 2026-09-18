open Vectors
open Test_crypto
open Mls.Framing
module MP = Mls.Message_protection

let get = function
  | Ok v -> v
  | Error e -> Alcotest.fail (Mls.Error.to_string e)

let test_message_protection () =
  let rng = rng () in
  for_each_supported "message-protection.json" (fun c v ->
      let name =
        Format.asprintf "%a" Mls.Cipher_suite.pp (Mls.Crypto.suite c)
      in
      let gc =
        {
          Mls.Group_context.version = 1;
          cipher_suite = Mls.Crypto.suite c;
          group_id = hex_field v "group_id";
          epoch = int64_field v "epoch";
          tree_hash = hex_field v "tree_hash";
          confirmed_transcript_hash = hex_field v "confirmed_transcript_hash";
          extensions = [];
        }
      in
      let signature_priv =
        get (Mls.Crypto.signature_key_of_bytes c (hex_field v "signature_priv"))
      in
      let signature_pub = hex_field v "signature_pub" in
      let encryption_secret = hex_field v "encryption_secret" in
      let sender_data_secret = hex_field v "sender_data_secret" in
      let membership_key = hex_field v "membership_key" in
      let secret_tree () =
        Mls.Secret_tree.create c ~n_leaves:2 ~encryption_secret
      in
      let decode_msg k =
        match Mls.Mls_message.of_bytes (hex_field v k) with
        | Ok m -> m
        | Error e -> Alcotest.fail (k ^ ": " ^ Mls.Error.to_string e)
      in
      let framed content =
        {
          Framed_content.group_id = gc.group_id;
          epoch = gc.epoch;
          sender = Sender.Member 1;
          authenticated_data = "";
          content;
        }
      in
      let check_public k expected_content confirmation_tag =
        (* Verify the provided PublicMessage. *)
        (match decode_msg k with
        | Mls.Mls_message.Public_message pm ->
            let ac =
              get
                (MP.unprotect_public c ~membership_key:(Some membership_key)
                   ~group_context:gc pm)
            in
            get
              (MP.verify_signature c ~public_key:signature_pub
                 ~group_context:(Some gc) ac);
            check_bytes
              (name ^ " " ^ k ^ " content")
              (Mls.Tls.encode Content.encode_body expected_content)
              (Mls.Tls.encode Content.encode_body ac.content.content)
        | _ -> Alcotest.fail (k ^ ": not a public message"));
        (* Protect afresh and verify. *)
        let ac =
          MP.sign c ~key:signature_priv ~wire_format:wire_format_public_message
            ~group_context:(Some gc) ~confirmation_tag (framed expected_content)
        in
        let pm =
          get (MP.protect_public c ~membership_key ~group_context:gc ac)
        in
        let bytes =
          Mls.Mls_message.to_bytes (Mls.Mls_message.Public_message pm)
        in
        match get (Mls.Mls_message.of_bytes bytes) with
        | Mls.Mls_message.Public_message pm ->
            let ac =
              get
                (MP.unprotect_public c ~membership_key:(Some membership_key)
                   ~group_context:gc pm)
            in
            get
              (MP.verify_signature c ~public_key:signature_pub
                 ~group_context:(Some gc) ac)
        | _ -> Alcotest.fail "re-encoded message is not public"
      in
      let check_private k expected_content confirmation_tag =
        (match decode_msg k with
        | Mls.Mls_message.Private_message pm ->
            let ac, _ =
              get
                (MP.unprotect_private c ~secret_tree:(secret_tree ())
                   ~sender_data_secret pm)
            in
            get
              (MP.verify_signature c ~public_key:signature_pub
                 ~group_context:(Some gc) ac);
            Alcotest.(check bool)
              (name ^ " " ^ k ^ " sender")
              true
              (ac.content.sender = Sender.Member 1);
            check_bytes
              (name ^ " " ^ k ^ " content")
              (Mls.Tls.encode Content.encode_body expected_content)
              (Mls.Tls.encode Content.encode_body ac.content.content)
        | _ -> Alcotest.fail (k ^ ": not a private message"));
        let ac =
          MP.sign c ~key:signature_priv ~wire_format:wire_format_private_message
            ~group_context:(Some gc) ~confirmation_tag (framed expected_content)
        in
        let pm, _ =
          get
            (MP.protect_private c ~rng ~secret_tree:(secret_tree ())
               ~sender_data_secret ~padding:7 ac)
        in
        let bytes =
          Mls.Mls_message.to_bytes (Mls.Mls_message.Private_message pm)
        in
        match get (Mls.Mls_message.of_bytes bytes) with
        | Mls.Mls_message.Private_message pm ->
            let ac', _ =
              get
                (MP.unprotect_private c ~secret_tree:(secret_tree ())
                   ~sender_data_secret pm)
            in
            get
              (MP.verify_signature c ~public_key:signature_pub
                 ~group_context:(Some gc) ac');
            check_bytes
              (name ^ " " ^ k ^ " roundtrip content")
              (Mls.Tls.encode Content.encode_body expected_content)
              (Mls.Tls.encode Content.encode_body ac'.content.content)
        | _ -> Alcotest.fail "re-encoded message is not private"
      in
      let proposal =
        Mls.Tls.decode_exn Mls.Proposal.decode (hex_field v "proposal")
      in
      check_public "proposal_pub" (Content.Proposal proposal) None;
      check_private "proposal_priv" (Content.Proposal proposal) None;
      let commit =
        Mls.Tls.decode_exn Mls.Commit.decode (hex_field v "commit")
      in
      let commit_tag =
        match decode_msg "commit_pub" with
        | Mls.Mls_message.Public_message pm -> pm.auth.confirmation_tag
        | _ -> None
      in
      check_public "commit_pub" (Content.Commit commit) commit_tag;
      check_private "commit_priv" (Content.Commit commit) commit_tag;
      let application = hex_field v "application" in
      check_private "application_priv" (Content.Application application) None;
      (* Application data must not be protected as a PublicMessage. *)
      let ac =
        MP.sign c ~key:signature_priv ~wire_format:wire_format_public_message
          ~group_context:(Some gc) ~confirmation_tag:None
          (framed (Content.Application application))
      in
      Alcotest.(check bool)
        (name ^ " application as public rejected")
        true
        (Result.is_error
           (MP.protect_public c ~membership_key ~group_context:gc ac));
      (* Tampering is detected. *)
      match decode_msg "proposal_pub" with
      | Mls.Mls_message.Public_message pm ->
          let bad = { pm with membership_tag = Some (String.make 32 '\x00') } in
          Alcotest.(check bool)
            (name ^ " bad membership tag")
            true
            (Result.is_error
               (MP.unprotect_public c ~membership_key:(Some membership_key)
                  ~group_context:gc bad));
          let ac =
            get
              (MP.unprotect_public c ~membership_key:(Some membership_key)
                 ~group_context:gc pm)
          in
          let bad_gc = { gc with epoch = Int64.succ gc.epoch } in
          Alcotest.(check bool)
            (name ^ " wrong context") true
            (Result.is_error
               (MP.verify_signature c ~public_key:signature_pub
                  ~group_context:(Some bad_gc) ac))
      | _ -> ())

let tests =
  [
    Alcotest.test_case "message-protection.json" `Quick test_message_protection;
  ]
