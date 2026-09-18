open Vectors
open Yojson.Safe.Util
open Test_crypto
module Crypto = Mls.Crypto
module KS = Mls.Key_schedule

let test_key_schedule () =
  for_each_supported "key-schedule.json" (fun c v ->
      let name = Format.asprintf "%a" Mls.Cipher_suite.pp (Crypto.suite c) in
      let group_id = hex_field v "group_id" in
      let init_secret = ref (hex_field v "initial_init_secret") in
      List.iteri
        (fun i ep ->
          let n k = Printf.sprintf "%s epoch %d %s" name i k in
          let gc =
            {
              Mls.Group_context.version = 1;
              cipher_suite = Crypto.suite c;
              group_id;
              epoch = Int64.of_int i;
              tree_hash = hex_field ep "tree_hash";
              confirmed_transcript_hash =
                hex_field ep "confirmed_transcript_hash";
              extensions = [];
            }
          in
          let group_context = Mls.Group_context.to_bytes gc in
          check_bytes (n "group_context")
            (hex_field ep "group_context")
            group_context;
          let s =
            ok
              (KS.derive c ~init_secret:!init_secret
                 ~commit_secret:(hex_field ep "commit_secret")
                 ~psk_secret:(hex_field ep "psk_secret")
                 ~group_context)
          in
          let chk k v = check_bytes (n k) (hex_field ep k) v in
          chk "joiner_secret" s.joiner_secret;
          chk "welcome_secret" s.welcome_secret;
          chk "init_secret" s.init_secret;
          chk "sender_data_secret" s.sender_data_secret;
          chk "encryption_secret" s.encryption_secret;
          chk "exporter_secret" s.exporter_secret;
          chk "epoch_authenticator" s.epoch_authenticator;
          chk "external_secret" s.external_secret;
          chk "confirmation_key" s.confirmation_key;
          chk "membership_key" s.membership_key;
          chk "resumption_psk" s.resumption_psk;
          (match KS.external_key_pair c ~external_secret:s.external_secret with
          | Ok (_, pub) -> chk "external_pub" (Hpke.Public_key.to_bytes pub)
          | Error e -> Alcotest.fail (Mls.Error.to_string e));
          let ex = member "exporter" ep in
          check_bytes (n "exporter") (hex_field ex "secret")
            (ok
               (KS.exporter c ~exporter_secret:s.exporter_secret
                  ~label:(string_field ex "label")
                  ~context:(hex_field ex "context") (int_field ex "length")));
          init_secret := s.init_secret)
        (member "epochs" v |> to_list))

let test_psk_secret () =
  for_each_supported "psk_secret.json" (fun c v ->
      let psks =
        member "psks" v |> to_list
        |> List.map (fun p ->
            ( {
                Mls.Psk.key = Mls.Psk.External (hex_field p "psk_id");
                psk_nonce = hex_field p "psk_nonce";
              },
              hex_field p "psk" ))
      in
      check_bytes "psk_secret" (hex_field v "psk_secret")
        (ok (Mls.Psk.psk_secret c psks)))

let test_transcript_hashes () =
  for_each_supported "transcript-hashes.json" (fun c v ->
      let ac =
        Mls.Tls.decode_exn Mls.Framing.Authenticated_content.decode
          (hex_field v "authenticated_content")
      in
      (match ac.content.content with
      | Mls.Framing.Content.Commit _ -> ()
      | _ -> Alcotest.fail "expected a commit");
      let confirmed =
        Mls.Transcript_hash.confirmed c
          ~interim_transcript_hash:
            (hex_field v "interim_transcript_hash_before")
          ac
      in
      check_bytes "confirmed_transcript_hash_after"
        (hex_field v "confirmed_transcript_hash_after")
        confirmed;
      let tag = Option.get ac.auth.confirmation_tag in
      check_bytes "confirmation_tag" tag
        (KS.confirmation_tag c
           ~confirmation_key:(hex_field v "confirmation_key")
           ~confirmed_transcript_hash:confirmed);
      check_bytes "interim_transcript_hash_after"
        (hex_field v "interim_transcript_hash_after")
        (Mls.Transcript_hash.interim c ~confirmed_transcript_hash:confirmed
           ~confirmation_tag:tag))

let test_secret_tree () =
  for_each_supported "secret-tree.json" (fun c v ->
      let sd = member "sender_data" v in
      let key, nonce =
        ok
          (KS.sender_data_key_nonce c
             ~sender_data_secret:(hex_field sd "sender_data_secret")
             ~ciphertext:(hex_field sd "ciphertext"))
      in
      check_bytes "sender_data key" (hex_field sd "key") key;
      check_bytes "sender_data nonce" (hex_field sd "nonce") nonce;
      let leaves = member "leaves" v |> to_list in
      let tree =
        Mls.Secret_tree.create c ~n_leaves:(List.length leaves)
          ~encryption_secret:(hex_field v "encryption_secret")
      in
      let _tree =
        List.fold_left
          (fun (tree, leaf) gens ->
            let tree =
              List.fold_left
                (fun tree g ->
                  let generation = int_field g "generation" in
                  let get tree ct =
                    match Mls.Secret_tree.key_for tree ~leaf ct ~generation with
                    | Ok v -> v
                    | Error e -> Alcotest.fail (Mls.Error.to_string e)
                  in
                  let (hk, hn), tree = get tree Mls.Secret_tree.Handshake in
                  let (ak, an), tree = get tree Mls.Secret_tree.Application in
                  let n k =
                    Printf.sprintf "leaf %d gen %d %s" leaf generation k
                  in
                  check_bytes (n "handshake_key")
                    (hex_field g "handshake_key")
                    hk;
                  check_bytes (n "handshake_nonce")
                    (hex_field g "handshake_nonce")
                    hn;
                  check_bytes (n "application_key")
                    (hex_field g "application_key")
                    ak;
                  check_bytes (n "application_nonce")
                    (hex_field g "application_nonce")
                    an;
                  tree)
                tree (to_list gens)
            in
            (tree, leaf + 1))
          (tree, 0) leaves
      in
      ())

let test_secret_tree_reuse () =
  let c = Crypto.create_exn 1 in
  let tree =
    Mls.Secret_tree.create c ~n_leaves:4 ~encryption_secret:(String.make 32 'k')
  in
  let ct = Mls.Secret_tree.Application in
  (* Sending advances the generation. *)
  let (k0, _, g0), tree =
    Result.get_ok (Mls.Secret_tree.next_key tree ~leaf:1 ct)
  in
  let (k1, _, g1), _tree =
    Result.get_ok (Mls.Secret_tree.next_key tree ~leaf:1 ct)
  in
  Alcotest.(check int) "gen 0" 0 g0;
  Alcotest.(check int) "gen 1" 1 g1;
  Alcotest.(check bool) "distinct keys" true (k0 <> k1);
  (* Receiving out of order retains skipped keys, each usable once. *)
  let rx =
    Mls.Secret_tree.create c ~n_leaves:4 ~encryption_secret:(String.make 32 'k')
  in
  let (rk1, _), rx =
    Result.get_ok (Mls.Secret_tree.key_for rx ~leaf:1 ct ~generation:1)
  in
  check_bytes "gen 1 matches" k1 rk1;
  let (rk0, _), rx =
    Result.get_ok (Mls.Secret_tree.key_for rx ~leaf:1 ct ~generation:0)
  in
  check_bytes "gen 0 matches" k0 rk0;
  Alcotest.(check bool)
    "gen 0 consumed" true
    (Result.is_error (Mls.Secret_tree.key_for rx ~leaf:1 ct ~generation:0));
  Alcotest.(check bool)
    "too far ahead" true
    (Result.is_error
       (Mls.Secret_tree.key_for rx ~leaf:1 ct ~generation:100_000));
  Alcotest.(check bool)
    "leaf out of range" true
    (Result.is_error (Mls.Secret_tree.key_for rx ~leaf:4 ct ~generation:0))

let tests =
  [
    Alcotest.test_case "key-schedule.json" `Quick test_key_schedule;
    Alcotest.test_case "psk_secret.json" `Quick test_psk_secret;
    Alcotest.test_case "transcript-hashes.json" `Quick test_transcript_hashes;
    Alcotest.test_case "secret-tree.json" `Quick test_secret_tree;
    Alcotest.test_case "secret tree reuse" `Quick test_secret_tree_reuse;
  ]
