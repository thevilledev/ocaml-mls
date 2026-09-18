open Vectors
open Yojson.Safe.Util
open Test_crypto
module G = Mls.Group

let get what = function
  | Ok v -> v
  | Error e -> Alcotest.fail (what ^ ": " ^ Mls.Error.to_string e)

let run_vector c v =
  let key_package =
    match
      get "key_package" (Mls.Mls_message.of_bytes (hex_field v "key_package"))
    with
    | Mls.Mls_message.Key_package kp -> kp
    | _ -> Alcotest.fail "key_package is not a KeyPackage message"
  in
  let init_key =
    get "init_priv" (Mls.Crypto.hpke_private_key c (hex_field v "init_priv"))
  in
  let encryption_key =
    get "encryption_priv"
      (Mls.Crypto.hpke_private_key c (hex_field v "encryption_priv"))
  in
  let signature_key =
    get "signature_priv"
      (Mls.Crypto.signature_key_of_bytes c (hex_field v "signature_priv"))
  in
  check_bytes "init key" key_package.init_key
    (Hpke.Public_key.to_bytes (Hpke.Private_key.public_key init_key));
  check_bytes "encryption key" key_package.leaf_node.encryption_key
    (Hpke.Public_key.to_bytes (Hpke.Private_key.public_key encryption_key));
  check_bytes "signature key" key_package.leaf_node.signature_key
    (Mls.Crypto.signature_public_key signature_key);
  let welcome =
    match get "welcome" (Mls.Mls_message.of_bytes (hex_field v "welcome")) with
    | Mls.Mls_message.Welcome w -> w
    | _ -> Alcotest.fail "welcome is not a Welcome message"
  in
  let tree =
    Option.map
      (fun b -> get "ratchet_tree" (Mls.Ratchet_tree.of_bytes b))
      (opt_hex_field v "ratchet_tree")
  in
  let external_psks =
    member "external_psks" v |> to_list
    |> List.map (fun p -> (hex_field p "psk_id", hex_field p "psk"))
  in
  let psks (id : Mls.Psk.id) =
    match id.key with
    | Mls.Psk.External psk_id -> List.assoc_opt psk_id external_psks
    | _ -> None
  in
  let g =
    get "join"
      (G.join ~psks ?tree c ~key_package ~init_key ~encryption_key
         ~signature_key welcome)
  in
  check_bytes "initial_epoch_authenticator"
    (hex_field v "initial_epoch_authenticator")
    (G.epoch_authenticator g);
  let _ =
    List.fold_left
      (fun (g, n) ep ->
        let g =
          List.fold_left
            (fun g p ->
              let msg =
                get "proposal message" (Mls.Mls_message.of_bytes (hex p))
              in
              match
                get
                  (Printf.sprintf "epoch %d proposal" n)
                  (G.process ~psks g msg)
              with
              | G.Proposal_received _, g -> g
              | _ -> Alcotest.fail "expected a proposal")
            g
            (member "proposals" ep |> to_list)
        in
        let msg =
          get "commit message"
            (Mls.Mls_message.of_bytes (hex_field ep "commit"))
        in
        let g =
          match
            get (Printf.sprintf "epoch %d commit" n) (G.process ~psks g msg)
          with
          | G.Commit_applied { removed_self = false; _ }, g -> g
          | _ -> Alcotest.fail "expected a commit"
        in
        check_bytes
          (Printf.sprintf "epoch %d epoch_authenticator" n)
          (hex_field ep "epoch_authenticator")
          (G.epoch_authenticator g);
        (g, n + 1))
      (g, 1)
      (member "epochs" v |> to_list)
  in
  ()

let test file () = for_each_supported file (fun c v -> run_vector c v)

let tests =
  [
    Alcotest.test_case "passive-client-welcome.json" `Quick
      (test "passive-client-welcome.json");
    Alcotest.test_case "passive-client-handling-commit.json" `Quick
      (test "passive-client-handling-commit.json");
    Alcotest.test_case "passive-client-random.json" `Slow
      (test "passive-client-random.json");
  ]
