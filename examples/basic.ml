(* Two-member group example explained in doc/getting-started.md. *)

open Mls

let ( let* ) = Result.bind

let () =
  Mirage_crypto_rng_unix.use_default ();
  let rng = Mirage_crypto_rng.default_generator () in
  let c =
    Crypto.create_exn Cipher_suite.mls_128_dhkemx25519_aes128gcm_sha256_ed25519
  in
  let result =
    (* Each client has a signature key and publishes KeyPackages. *)
    let alice_key = Crypto.generate_signature_key c ~rng in
    let bob_key = Crypto.generate_signature_key c ~rng in
    let* alice_kp =
      Key_package.generate c ~rng ~signature_key:alice_key
        ~credential:(Credential.Basic "alice")
    in
    let* bob_kp =
      Key_package.generate c ~rng ~signature_key:bob_key
        ~credential:(Credential.Basic "bob")
    in
    (* Alice creates a group and adds Bob. *)
    let* alice =
      Group.create c ~rng ~group_id:(Crypto.random ~rng 32)
        ~signature_key:alice_key ~leaf_node:alice_kp.key_package.leaf_node
        ~leaf_key:alice_kp.encryption_key
    in
    let* r =
      Group.commit ~inline:[ Proposal.Add bob_kp.key_package ] alice ~rng
    in
    let alice = r.state in
    (* Bob joins from the Welcome, which carries the ratchet tree. *)
    let* welcome =
      match r.welcome with
      | Some (Mls_message.Welcome w) -> Ok w
      | _ -> Error (Error.Internal "no welcome")
    in
    let* bob =
      Group.join c ~key_package:bob_kp.key_package ~init_key:bob_kp.init_key
        ~encryption_key:bob_kp.encryption_key ~signature_key:bob_key welcome
    in
    (* Application messages are PrivateMessages. *)
    let* msg, _alice = Group.encrypt_application alice ~rng "hello bob" in
    let* event, _bob = Group.process bob msg in
    match event with
    | Group.Application_received { data; sender; _ } ->
        Printf.printf "leaf %d says %S\n" sender data;
        Ok ()
    | _ -> Error (Error.Internal "unexpected event")
  in
  match result with Ok () -> () | Error e -> prerr_endline (Error.to_string e)
