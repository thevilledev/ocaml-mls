(* End-to-end scenarios between simulated clients. *)

open Vectors
open Test_crypto
module G = Mls.Group
module KP = Mls.Key_package

let get what = function
  | Ok v -> v
  | Error e -> Alcotest.fail (what ^ ": " ^ Mls.Error.to_string e)

let expect_error what = function
  | Ok _ -> Alcotest.fail (what ^ ": expected an error")
  | Error _ -> ()

type client = {
  name : string;
  sig_key : Mls.Crypto.signature_key;
  kp : KP.generated;
}

let new_client c rng name =
  let sig_key = Mls.Crypto.generate_signature_key c ~rng in
  let kp =
    get (name ^ " key package")
      (KP.generate c ~rng ~signature_key:sig_key
         ~credential:(Mls.Credential.Basic name))
  in
  { name; sig_key; kp }

let same_epoch what groups =
  match groups with
  | [] -> ()
  | (_, g0) :: rest ->
      List.iter
        (fun (n, g) ->
          Alcotest.(check int64) (what ^ " epoch " ^ n) (G.epoch g0) (G.epoch g);
          check_bytes
            (what ^ " epoch_authenticator " ^ n)
            (G.epoch_authenticator g0) (G.epoch_authenticator g);
          check_bytes
            (what ^ " tree hash " ^ n)
            (G.context g0).tree_hash (G.context g).tree_hash;
          check_bytes
            (what ^ " exporter " ^ n)
            (ok (G.export g0 ~label:"test" ~context:"ctx" 32))
            (ok (G.export g ~label:"test" ~context:"ctx" 32)))
        rest

let process what ?psks g msg =
  match get what (G.process ?psks g msg) with
  | G.Commit_applied { removed_self = false; _ }, g -> g
  | G.Commit_applied { removed_self = true; _ }, _ ->
      Alcotest.fail (what ^ ": unexpectedly removed")
  | G.Proposal_received _, g -> g
  | G.Application_received _, g -> g

let process_proposal what g msg =
  match get what (G.process g msg) with
  | G.Proposal_received _, g -> g
  | _ -> Alcotest.fail (what ^ ": expected a proposal")

let decrypt what g msg =
  match get what (G.process g msg) with
  | G.Application_received { data; sender; _ }, g -> (data, sender, g)
  | _ -> Alcotest.fail (what ^ ": expected application data")

let scenario suite () =
  let rng = rng () in
  let c = Mls.Crypto.create_exn suite in
  let alice = new_client c rng "alice" and bob = new_client c rng "bob" in
  let charlie = new_client c rng "charlie" and dave = new_client c rng "dave" in
  let group_id = Mls.Crypto.random ~rng 32 in
  (* Alice creates the group and adds Bob and Charlie in one commit. *)
  let a =
    get "create"
      (G.create c ~rng ~group_id ~signature_key:alice.sig_key
         ~leaf_node:alice.kp.key_package.leaf_node
         ~leaf_key:alice.kp.encryption_key)
  in
  Alcotest.(check int) "creator index" 0 (G.own_index a);
  expect_error "oversized export" (G.export a ~label:"l" ~context:"" 1_000_000);
  let r =
    get "add commit"
      (G.commit
         ~inline:
           [
             Mls.Proposal.Add bob.kp.key_package;
             Mls.Proposal.Add charlie.kp.key_package;
           ]
         a ~rng)
  in
  let a = r.state in
  let welcome =
    match r.welcome with
    | Some (Mls.Mls_message.Welcome w) -> w
    | _ -> Alcotest.fail "no welcome"
  in
  let b =
    get "bob join"
      (G.join c ~key_package:bob.kp.key_package ~init_key:bob.kp.init_key
         ~encryption_key:bob.kp.encryption_key ~signature_key:bob.sig_key
         welcome)
  in
  (* Charlie joins with an externally provided tree. *)
  let ch =
    get "charlie join"
      (G.join ~tree:(G.tree a) c ~key_package:charlie.kp.key_package
         ~init_key:charlie.kp.init_key ~encryption_key:charlie.kp.encryption_key
         ~signature_key:charlie.sig_key welcome)
  in
  same_epoch "after add" [ ("alice", a); ("bob", b); ("charlie", ch) ];
  Alcotest.(check int) "three members" 3 (List.length (G.members a));
  Alcotest.(check int64) "epoch 1" 1L (G.epoch a);
  Alcotest.(check int) "bob index" 1 (G.own_index b);
  Alcotest.(check int) "charlie index" 2 (G.own_index ch);
  (* Welcome cannot be replayed by someone else. *)
  expect_error "dave cannot use welcome"
    (G.join c ~key_package:dave.kp.key_package ~init_key:dave.kp.init_key
       ~encryption_key:dave.kp.encryption_key ~signature_key:dave.sig_key
       welcome);
  (* Application messages, including out-of-order delivery. *)
  let m1, a =
    get "encrypt m1"
      (G.encrypt_application ~authenticated_data:"ad" a ~rng "hello from alice")
  in
  let m2, a = get "encrypt m2" (G.encrypt_application a ~rng "second") in
  expect_error "own private message" (G.process a m1);
  let d2, s2, b = decrypt "bob m2" b m2 in
  Alcotest.(check string) "m2 data" "second" d2;
  Alcotest.(check int) "m2 sender" 0 s2;
  let d1, _, b = decrypt "bob m1" b m1 in
  Alcotest.(check string) "m1 data" "hello from alice" d1;
  expect_error "replayed message" (G.process b m1);
  let d1c, _, ch = decrypt "charlie m1" ch m1 in
  Alcotest.(check string) "charlie m1" "hello from alice" d1c;
  let m3, b = get "bob encrypt" (G.encrypt_application b ~rng "hi alice") in
  let d3, s3, a = decrypt "alice m3" a m3 in
  Alcotest.(check string) "m3 data" "hi alice" d3;
  Alcotest.(check int) "m3 sender" 1 s3;
  (* Tampering with a private message is detected. *)
  (match m3 with
  | Mls.Mls_message.Private_message pm ->
      let ct = Bytes.of_string pm.ciphertext in
      Bytes.set ct 0 (Char.chr (Char.code (Bytes.get ct 0) lxor 1));
      expect_error "tampered ciphertext"
        (G.process ch
           (Mls.Mls_message.Private_message
              { pm with ciphertext = Bytes.to_string ct }))
  | _ -> Alcotest.fail "expected private message");
  let _, _, ch = decrypt "charlie m3" ch m3 in
  (* Bob proposes an update in public; Charlie commits it privately. *)
  let upd, b = get "bob update" (G.propose_update b ~rng) in
  let a = process_proposal "alice gets update" a upd in
  let ch = process_proposal "charlie gets update" ch upd in
  expect_error "app data with pending proposals"
    (G.encrypt_application a ~rng "blocked");
  let r = get "charlie commit" (G.commit ~wire:G.Private ch ~rng) in
  let ch = r.state in
  Alcotest.(check bool) "no welcome" true (r.welcome = None);
  let a = process "alice commit 2" a r.commit in
  let b = process "bob commit 2" b r.commit in
  same_epoch "after update" [ ("alice", a); ("bob", b); ("charlie", ch) ];
  Alcotest.(check int64) "epoch 2" 2L (G.epoch a);
  (* Bob's leaf was replaced by his update. *)
  check_bytes "bob's new leaf" (Option.get (G.own_leaf b)).encryption_key
    (Option.get (G.member a 1)).encryption_key;
  expect_error "stale epoch" (G.process a r.commit);
  (* Bob can still send after his own update was committed by Charlie. *)
  let m4, b =
    get "bob encrypt after update" (G.encrypt_application b ~rng "after update")
  in
  let d4, _, a = decrypt "alice m4" a m4 in
  Alcotest.(check string) "m4" "after update" d4;
  (* Alice removes Charlie by proposal + commit. *)
  let rm, a = get "propose remove" (G.propose_remove a ~rng 2) in
  let b = process_proposal "bob gets remove" b rm in
  let ch = process_proposal "charlie gets remove" ch rm in
  let r = get "remove commit" (G.commit a ~rng) in
  let a = r.state in
  let b = process "bob commit 3" b r.commit in
  (match G.process ch r.commit with
  | Ok (G.Commit_applied { removed_self = true; _ }, _) -> ()
  | Ok _ -> Alcotest.fail "charlie should be removed"
  | Error e -> Alcotest.fail ("charlie remove: " ^ Mls.Error.to_string e));
  same_epoch "after remove" [ ("alice", a); ("bob", b) ];
  Alcotest.(check int) "two members" 2 (List.length (G.members a));
  Alcotest.(check bool) "charlie's leaf blank" true (G.member a 2 = None);
  (* Dave joins with an external commit using a published GroupInfo. *)
  let gi = get "group info" (G.group_info a) in
  let ext_commit, d =
    get "external join"
      (G.external_join c ~rng ~group_info:gi ~signature_key:dave.sig_key
         ~leaf_node:dave.kp.key_package.leaf_node)
  in
  let a = process "alice ext commit" a ext_commit in
  let b = process "bob ext commit" b ext_commit in
  same_epoch "after external join" [ ("alice", a); ("bob", b); ("dave", d) ];
  Alcotest.(check int) "dave index" 2 (G.own_index d);
  let m5, d = get "dave encrypt" (G.encrypt_application d ~rng "dave here") in
  let d5, s5, a = decrypt "alice m5" a m5 in
  Alcotest.(check string) "m5" "dave here" d5;
  Alcotest.(check int) "m5 sender" 2 s5;
  let _, _, b = decrypt "bob m5" b m5 in
  (* External PSK and group context extensions in one commit. *)
  let psk = Mls.Crypto.random ~rng 32 in
  let psks (id : Mls.Psk.id) =
    match id.key with Mls.Psk.External "shared" -> Some psk | _ -> None
  in
  let psk_prop, b =
    get "propose psk" (G.propose_psk b ~rng (G.external_psk_id b ~rng "shared"))
  in
  let psk_ref =
    match get "alice psk" (G.process a psk_prop) with
    | G.Proposal_received { reference; _ }, _ -> reference
    | _ -> Alcotest.fail "expected proposal"
  in
  let a = process_proposal "alice psk" a psk_prop in
  let d = process_proposal "dave psk" d psk_prop in
  (* A stray Remove is proposed too, but the committer selects only the PSK. *)
  let stray, b = get "stray remove" (G.propose_remove b ~rng 2) in
  let a = process_proposal "alice stray" a stray in
  let d = process_proposal "dave stray" d stray in
  expect_error "unknown reference" (G.commit ~references:[ "nope" ] a ~rng);
  let rc =
    Mls.Group_extensions.make_required_capabilities
      {
        extension_types = [];
        proposal_types = [];
        credential_types = [ Mls.Credential.basic ];
      }
  in
  let r =
    get "psk commit"
      (G.commit ~psks ~references:[ psk_ref ]
         ~inline:[ Mls.Proposal.Group_context_extensions [ rc ] ]
         a ~rng)
  in
  let a = r.state in
  expect_error "bob without psk" (G.process b r.commit);
  let b = process "bob psk commit" ~psks b r.commit in
  let d = process "dave psk commit" ~psks d r.commit in
  same_epoch "after psk" [ ("alice", a); ("bob", b); ("dave", d) ];
  Alcotest.(check int) "dave still a member" 3 (List.length (G.members a));
  Alcotest.(check int) "extensions updated" 1 (List.length (G.extensions a));
  (* Resumption PSK from the previous epoch. *)
  let prev = Int64.pred (G.epoch a) in
  let r =
    get "resumption commit"
      (G.commit
         ~inline:
           [
             Mls.Proposal.Pre_shared_key
               (G.resumption_psk_id a ~rng ~group_id ~epoch:prev);
           ]
         a ~rng)
  in
  let a = r.state in
  let b = process "bob resumption" b r.commit in
  let d = process "dave resumption" d r.commit in
  same_epoch "after resumption psk" [ ("alice", a); ("bob", b); ("dave", d) ];
  (* Empty commit with a private handshake message and application data. *)
  let r = get "empty commit" (G.commit ~wire:G.Private d ~rng) in
  let d = r.state in
  let a = process "alice empty" a r.commit in
  let b = process "bob empty" b r.commit in
  same_epoch "after empty commit" [ ("alice", a); ("bob", b); ("dave", d) ];
  (* A commit from a different group is rejected. *)
  let other =
    get "other group"
      (G.create c ~rng
         ~group_id:(Mls.Crypto.random ~rng 32)
         ~signature_key:alice.sig_key ~leaf_node:alice.kp.key_package.leaf_node
         ~leaf_key:alice.kp.encryption_key)
  in
  let r = get "other commit" (G.commit ~force_path:true other ~rng) in
  expect_error "wrong group" (G.process a r.commit);
  (* Add Charlie back, this time with a tree-less Welcome plus the tree. *)
  let charlie2 = new_client c rng "charlie" in
  let r =
    get "re-add"
      (G.commit ~welcome_with_tree:false
         ~inline:[ Mls.Proposal.Add charlie2.kp.key_package ]
         b ~rng)
  in
  let b = r.state in
  let welcome =
    match r.welcome with
    | Some (Mls.Mls_message.Welcome w) -> w
    | _ -> Alcotest.fail "no welcome"
  in
  expect_error "welcome without tree"
    (G.join c ~key_package:charlie2.kp.key_package
       ~init_key:charlie2.kp.init_key ~encryption_key:charlie2.kp.encryption_key
       ~signature_key:charlie2.sig_key welcome);
  let ch =
    get "charlie rejoin"
      (G.join ~tree:(G.tree b) c ~key_package:charlie2.kp.key_package
         ~init_key:charlie2.kp.init_key
         ~encryption_key:charlie2.kp.encryption_key
         ~signature_key:charlie2.sig_key welcome)
  in
  let a = process "alice re-add" a r.commit in
  let d = process "dave re-add" d r.commit in
  same_epoch "after re-add"
    [ ("alice", a); ("bob", b); ("charlie", ch); ("dave", d) ];
  Alcotest.(check int) "four members" 4 (List.length (G.members a));
  (* Everyone can talk to the newcomer and vice versa. *)
  let m6, ch =
    get "charlie encrypt" (G.encrypt_application ch ~rng "back again")
  in
  List.iter
    (fun (n, g) ->
      let d6, _, _ = decrypt (n ^ " m6") g m6 in
      Alcotest.(check string) (n ^ " m6") "back again" d6)
    [ ("alice", a); ("bob", b); ("dave", d) ];
  let m7, _ =
    get "alice encrypt" (G.encrypt_application a ~rng "welcome back")
  in
  let d7, _, _ = decrypt "charlie m7" ch m7 in
  Alcotest.(check string) "m7" "welcome back" d7

let test_many_members () =
  (* A larger group exercises deeper trees and Welcome path secrets. *)
  let rng = rng () in
  let c = Mls.Crypto.create_exn 1 in
  let clients =
    List.init 9 (fun i -> new_client c rng (Printf.sprintf "member%d" i))
  in
  let creator = List.hd clients in
  let group_id = Mls.Crypto.random ~rng 32 in
  let g0 =
    get "create"
      (G.create c ~rng ~group_id ~signature_key:creator.sig_key
         ~leaf_node:creator.kp.key_package.leaf_node
         ~leaf_key:creator.kp.encryption_key)
  in
  let adds =
    List.map (fun cl -> Mls.Proposal.Add cl.kp.key_package) (List.tl clients)
  in
  let r = get "add all" (G.commit ~inline:adds g0 ~rng) in
  let welcome =
    match r.welcome with
    | Some (Mls.Mls_message.Welcome w) -> w
    | _ -> Alcotest.fail "no welcome"
  in
  let groups =
    (creator.name, r.state)
    :: List.map
         (fun cl ->
           ( cl.name,
             get (cl.name ^ " join")
               (G.join c ~key_package:cl.kp.key_package ~init_key:cl.kp.init_key
                  ~encryption_key:cl.kp.encryption_key ~signature_key:cl.sig_key
                  welcome) ))
         (List.tl clients)
  in
  same_epoch "nine members" groups;
  Alcotest.(check int)
    "nine members" 9
    (List.length (G.members (snd (List.hd groups))));
  (* Each member in turn commits an empty commit; everyone follows. *)
  let groups =
    List.fold_left
      (fun groups i ->
        let name, g = List.nth groups i in
        let r =
          get (name ^ " commit")
            (G.commit
               ~wire:(if i mod 2 = 0 then G.Public else G.Private)
               g ~rng)
        in
        let groups =
          List.mapi
            (fun j (n, g) ->
              if j = i then (n, r.state)
              else (n, process (n ^ " follows") g r.commit))
            groups
        in
        same_epoch (name ^ " committed") groups;
        groups)
      groups [ 0; 4; 8; 3; 7 ]
  in
  (* Remove several members at once, then add one back. *)
  let name, g = List.hd groups in
  let r =
    get "remove many"
      (G.commit
         ~inline:
           [
             Mls.Proposal.Remove 1; Mls.Proposal.Remove 5; Mls.Proposal.Remove 8;
           ]
         g ~rng)
  in
  let remaining =
    List.filter_map
      (fun (i, (n, g)) ->
        if n = name then Some (n, r.state)
        else if List.mem i [ 1; 5; 8 ] then None
        else Some (n, process (n ^ " after removes") g r.commit))
      (List.mapi (fun i x -> (i, x)) groups)
  in
  same_epoch "after removes" remaining;
  Alcotest.(check int)
    "six members" 6
    (List.length (G.members (snd (List.hd remaining))));
  let newcomer = new_client c rng "newcomer" in
  let name, g = List.nth remaining 2 in
  let r =
    get "add newcomer"
      (G.commit ~inline:[ Mls.Proposal.Add newcomer.kp.key_package ] g ~rng)
  in
  let welcome =
    match r.welcome with
    | Some (Mls.Mls_message.Welcome w) -> w
    | _ -> Alcotest.fail "no welcome"
  in
  let n =
    get "newcomer join"
      (G.join c ~key_package:newcomer.kp.key_package
         ~init_key:newcomer.kp.init_key
         ~encryption_key:newcomer.kp.encryption_key
         ~signature_key:newcomer.sig_key welcome)
  in
  Alcotest.(check int) "newcomer takes leaf 1" 1 (G.own_index n);
  let final =
    ("newcomer", n)
    :: List.map
         (fun (nm, g) ->
           if nm = name then (nm, r.state)
           else (nm, process (nm ^ " sees newcomer") g r.commit))
         remaining
  in
  same_epoch "after newcomer" final

let tests =
  List.map
    (fun suite ->
      Alcotest.test_case
        (Format.asprintf "%a" Mls.Cipher_suite.pp suite)
        `Quick (scenario suite))
    Mls.Cipher_suite.supported
  @ [ Alcotest.test_case "nine members" `Quick test_many_members ]
