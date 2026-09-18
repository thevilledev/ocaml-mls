open Vectors
open Yojson.Safe.Util
module Crypto = Mls.Crypto

let rng () =
  Mirage_crypto_rng_unix.use_default ();
  Mirage_crypto_rng.default_generator ()

(* Iterate over the supported cipher suites of a vector file. *)
let for_each_supported file f =
  List.iter
    (fun v ->
      let suite = int_field v "cipher_suite" in
      match Crypto.create suite with
      | Ok c -> f c v
      | Error _ -> assert (not (Mls.Cipher_suite.is_supported suite)))
    (load file)

let test_crypto_basics () =
  let rng = rng () in
  for_each_supported "crypto-basics.json" (fun c v ->
      let name = Format.asprintf "%a" Mls.Cipher_suite.pp (Crypto.suite c) in
      let rh = member "ref_hash" v in
      check_bytes (name ^ " ref_hash") (hex_field rh "out")
        (Crypto.ref_hash c ~label:(string_field rh "label")
           ~value:(hex_field rh "value"));
      let ewl = member "expand_with_label" v in
      check_bytes
        (name ^ " expand_with_label")
        (hex_field ewl "out")
        (Crypto.expand_with_label c ~secret:(hex_field ewl "secret")
           ~label:(string_field ewl "label") ~context:(hex_field ewl "context")
           (int_field ewl "length"));
      let ds = member "derive_secret" v in
      check_bytes (name ^ " derive_secret") (hex_field ds "out")
        (Crypto.derive_secret c ~secret:(hex_field ds "secret")
           ~label:(string_field ds "label"));
      let dts = member "derive_tree_secret" v in
      check_bytes
        (name ^ " derive_tree_secret")
        (hex_field dts "out")
        (Crypto.derive_tree_secret c ~secret:(hex_field dts "secret")
           ~label:(string_field dts "label")
           ~generation:(int_field dts "generation")
           (int_field dts "length"));
      let swl = member "sign_with_label" v in
      let pub = hex_field swl "pub" and label = string_field swl "label" in
      let content = hex_field swl "content" in
      Alcotest.(check bool)
        (name ^ " verify given signature")
        true
        (Crypto.verify_with_label c ~public_key:pub ~label
           ~signature:(hex_field swl "signature")
           content);
      let key =
        match Crypto.signature_key_of_bytes c (hex_field swl "priv") with
        | Ok k -> k
        | Error e -> Alcotest.fail (Mls.Error.to_string e)
      in
      check_bytes
        (name ^ " derived public key")
        pub
        (Crypto.signature_public_key key);
      let signature = Crypto.sign_with_label c ~key ~label content in
      Alcotest.(check bool)
        (name ^ " verify fresh signature")
        true
        (Crypto.verify_with_label c ~public_key:pub ~label ~signature content);
      Alcotest.(check bool)
        (name ^ " reject wrong label")
        false
        (Crypto.verify_with_label c ~public_key:pub ~label:"other" ~signature
           content);
      let ewl = member "encrypt_with_label" v in
      let priv =
        match Crypto.hpke_private_key c (hex_field ewl "priv") with
        | Ok k -> k
        | Error e -> Alcotest.fail (Mls.Error.to_string e)
      in
      let label = string_field ewl "label"
      and context = hex_field ewl "context" in
      let plaintext = hex_field ewl "plaintext" in
      check_bytes
        (name ^ " hpke public key")
        (hex_field ewl "pub")
        (Hpke.Public_key.to_bytes (Hpke.Private_key.public_key priv));
      (match
         Crypto.decrypt_with_label c ~private_key:priv ~label ~context
           ~kem_output:(hex_field ewl "kem_output")
           (hex_field ewl "ciphertext")
       with
      | Ok pt -> check_bytes (name ^ " decrypt_with_label") plaintext pt
      | Error e -> Alcotest.fail (Mls.Error.to_string e));
      match
        Crypto.encrypt_with_label c ~rng ~public_key:(hex_field ewl "pub")
          ~label ~context plaintext
      with
      | Error e -> Alcotest.fail (Mls.Error.to_string e)
      | Ok (kem_output, ciphertext) -> (
          match
            Crypto.decrypt_with_label c ~private_key:priv ~label ~context
              ~kem_output ciphertext
          with
          | Ok pt ->
              check_bytes (name ^ " encrypt/decrypt roundtrip") plaintext pt
          | Error e -> Alcotest.fail (Mls.Error.to_string e)))

let test_unsupported () =
  Alcotest.(check bool)
    "suite 4 unsupported" true
    (Result.is_error (Crypto.create 4));
  Alcotest.(check bool)
    "suite 6 unsupported" true
    (Result.is_error (Crypto.create 6));
  Alcotest.(check bool)
    "suite 0 unsupported" true
    (Result.is_error (Crypto.create 0))

let tests =
  [
    Alcotest.test_case "crypto-basics.json" `Quick test_crypto_basics;
    Alcotest.test_case "unsupported suites" `Quick test_unsupported;
  ]
