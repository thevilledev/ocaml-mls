open Vectors
module Tls = Mls.Tls

let roundtrip name dec enc bytes =
  match Tls.decode dec bytes with
  | Error msg -> Alcotest.fail (name ^ ": " ^ msg)
  | Ok v -> check_bytes name bytes (Tls.encode enc v)

let test_messages () =
  List.iteri
    (fun i v ->
      let f k = hex_field v k in
      let n = Printf.sprintf "[%d] " i in
      let mls_message k =
        roundtrip (n ^ k) Mls.Mls_message.decode Mls.Mls_message.encode (f k)
      in
      mls_message "mls_welcome";
      mls_message "mls_group_info";
      mls_message "mls_key_package";
      roundtrip (n ^ "ratchet_tree") Mls.Node.decode_tree Mls.Node.encode_tree
        (f "ratchet_tree");
      roundtrip (n ^ "group_secrets") Mls.Welcome.Group_secrets.decode
        Mls.Welcome.Group_secrets.encode (f "group_secrets");
      let proposal k ty =
        roundtrip (n ^ k)
          (Mls.Proposal.decode_body ~proposal_type:ty)
          Mls.Proposal.encode_body (f k)
      in
      proposal "add_proposal" 1;
      proposal "update_proposal" 2;
      proposal "remove_proposal" 3;
      proposal "pre_shared_key_proposal" 4;
      proposal "re_init_proposal" 5;
      proposal "external_init_proposal" 6;
      proposal "group_context_extensions_proposal" 7;
      roundtrip (n ^ "commit") Mls.Commit.decode Mls.Commit.encode (f "commit");
      mls_message "public_message_application";
      mls_message "public_message_proposal";
      mls_message "public_message_commit";
      mls_message "private_message")
    (load "messages.json")

(* Decoding must fail closed on malformed input: corrupted or truncated messages
   yield [Error], never an exception. *)
let test_malformed () =
  let vectors = load "messages.json" in
  let rand = Random.State.make [| 9420 |] in
  let attempt name bytes =
    match Mls.Mls_message.of_bytes bytes with
    | Ok _ | Error _ -> ()
    | exception e ->
        Alcotest.fail
          (Printf.sprintf "%s raised %s" name (Printexc.to_string e))
  in
  List.iteri
    (fun i v ->
      if i < 40 then
        List.iter
          (fun k ->
            let bytes = hex_field v k in
            let n = String.length bytes in
            for _ = 1 to 25 do
              let b = Bytes.of_string bytes in
              let pos = Random.State.int rand n in
              Bytes.set b pos
                (Char.chr
                   (Char.code (Bytes.get b pos)
                   lxor (1 lsl Random.State.int rand 8)));
              attempt (k ^ " flipped") (Bytes.to_string b)
            done;
            for len = 0 to min n 64 do
              attempt (k ^ " truncated") (String.sub bytes 0 len)
            done;
            attempt (k ^ " extended") (bytes ^ "\x00");
            Alcotest.(check bool)
              (k ^ " truncated rejected")
              true
              (Result.is_error
                 (Mls.Mls_message.of_bytes (String.sub bytes 0 (n - 1)))))
          [
            "mls_welcome";
            "mls_group_info";
            "mls_key_package";
            "public_message_commit";
            "private_message";
          ])
    vectors;
  for _ = 1 to 2000 do
    let len = Random.State.int rand 64 in
    attempt "random"
      (String.init len (fun _ -> Char.chr (Random.State.int rand 256)))
  done

let tests =
  [
    Alcotest.test_case "messages.json" `Quick test_messages;
    Alcotest.test_case "malformed input" `Quick test_malformed;
  ]
