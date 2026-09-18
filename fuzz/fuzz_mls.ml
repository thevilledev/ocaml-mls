(* Crowbar fuzzing of the decoders: decoding arbitrary bytes must be total, and
   anything that decodes must re-encode to exactly the same bytes. Build with
   [dune build --profile fuzz fuzz/fuzz_mls.exe]. *)

open Crowbar

let pp_hex fmt s = Format.pp_print_string fmt (Mls.Hex.encode s)

let roundtrip name dec enc bytes =
  match Mls.Tls.decode dec bytes with
  | Error _ -> ()
  | Ok v -> check_eq ~pp:pp_hex ~eq:String.equal bytes (Mls.Tls.encode enc v)
  | exception e ->
      fail (Printf.sprintf "%s raised %s" name (Printexc.to_string e))

let total name f bytes =
  match f bytes with
  | Ok _ | Error _ -> ()
  | exception e ->
      fail (Printf.sprintf "%s raised %s" name (Printexc.to_string e))

let () =
  add_test ~name:"MLSMessage" [ bytes ] (fun b ->
      roundtrip "MLSMessage" Mls.Mls_message.decode Mls.Mls_message.encode b);
  add_test ~name:"AuthenticatedContent" [ bytes ] (fun b ->
      roundtrip "AuthenticatedContent" Mls.Framing.Authenticated_content.decode
        Mls.Framing.Authenticated_content.encode b);
  add_test ~name:"KeyPackage" [ bytes ] (fun b ->
      roundtrip "KeyPackage" Mls.Key_package.decode Mls.Key_package.encode b);
  add_test ~name:"GroupInfo" [ bytes ] (fun b ->
      roundtrip "GroupInfo" Mls.Group_info.decode Mls.Group_info.encode b);
  add_test ~name:"GroupSecrets" [ bytes ] (fun b ->
      roundtrip "GroupSecrets" Mls.Welcome.Group_secrets.decode
        Mls.Welcome.Group_secrets.encode b);
  add_test ~name:"Proposal" [ bytes ] (fun b ->
      roundtrip "Proposal" Mls.Proposal.decode Mls.Proposal.encode b);
  add_test ~name:"ratchet tree" [ bytes ] (fun b ->
      match Mls.Ratchet_tree.of_bytes b with
      | Error _ -> ()
      | Ok t ->
          check_eq ~pp:pp_hex ~eq:String.equal b (Mls.Ratchet_tree.to_bytes t)
      | exception e ->
          fail (Printf.sprintf "ratchet tree raised %s" (Printexc.to_string e)));
  add_test ~name:"PrivateMessageContent"
    [ range 3; bytes ]
    (fun ct b ->
      total "PrivateMessageContent"
        (Mls.Framing.Private_message.decode_content ~content_type:(ct + 1))
        b);
  add_test ~name:"varint"
    [ range (1 lsl 30) ]
    (fun n ->
      let e = Mls.Tls.Encoder.create () in
      Mls.Tls.Encoder.varint e n;
      check_eq (Ok n)
        (Mls.Tls.decode Mls.Tls.Decoder.varint (Mls.Tls.Encoder.contents e)))
