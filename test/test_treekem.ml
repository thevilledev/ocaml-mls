open Vectors
open Yojson.Safe.Util
open Test_crypto
module RT = Mls.Ratchet_tree
module TK = Mls.Treekem

let get = function
  | Ok v -> v
  | Error e -> Alcotest.fail (Mls.Error.to_string e)

let test_treekem () =
  let rng = rng () in
  for_each_supported "treekem.json" (fun c v ->
      let tree = get (RT.of_bytes (hex_field v "ratchet_tree")) in
      let gc_template =
        {
          Mls.Group_context.version = 1;
          cipher_suite = Mls.Crypto.suite c;
          group_id = hex_field v "group_id";
          epoch = int64_field v "epoch";
          tree_hash = "";
          confirmed_transcript_hash = hex_field v "confirmed_transcript_hash";
          extensions = [];
        }
      in
      (* Private states. *)
      let privs =
        member "leaves_private" v |> to_list
        |> List.map (fun lp ->
            let index = int_field lp "index" in
            let leaf_key =
              get
                (Mls.Crypto.hpke_private_key c (hex_field lp "encryption_priv"))
            in
            let priv = TK.Private.create ~leaf_index:index ~leaf_key in
            let priv =
              List.fold_left
                (fun priv ps ->
                  let node = int_field ps "node" in
                  let path_secret = hex_field ps "path_secret" in
                  let k, _ = get (TK.node_key_pair c ~path_secret) in
                  TK.Private.set_private_key priv node k)
                priv
                (member "path_secrets" lp |> to_list)
            in
            get (TK.Private.check_consistency priv tree);
            let signature_key =
              get
                (Mls.Crypto.signature_key_of_bytes c
                   (hex_field lp "signature_priv"))
            in
            (index, priv, signature_key))
        |> List.sort compare
      in
      List.iter
        (fun up ->
          let sender = int_field up "sender" in
          let path =
            Mls.Tls.decode_exn Mls.Update_path.decode
              (hex_field up "update_path")
          in
          let expected_secrets =
            member "path_secrets" up |> to_list |> List.map opt_hex
          in
          let commit_secret = hex_field up "commit_secret" in
          (* Parent-hash validity and the merged tree hash. *)
          let merged = get (RT.apply_update_path c tree ~sender path) in
          check_bytes
            (Printf.sprintf "sender %d tree_hash_after" sender)
            (hex_field up "tree_hash_after")
            (RT.tree_hash c merged);
          get (RT.verify_parent_hashes c merged);
          (* Every other member decrypts the same commit secret. *)
          List.iter
            (fun (j, priv, _) ->
              if j <> sender then (
                let r =
                  get
                    (TK.process_update_path c ~tree ~priv ~sender ~path
                       ~group_context:gc_template ())
                in
                check_bytes
                  (Printf.sprintf "sender %d receiver %d commit_secret" sender j)
                  commit_secret r.commit_secret;
                check_bytes "receiver tree hash"
                  (hex_field up "tree_hash_after")
                  (RT.tree_hash c r.tree);
                get (TK.Private.check_consistency r.priv r.tree);
                (* The decrypted path secret is the one for the common
                   ancestor. *)
                match List.nth expected_secrets j with
                | Some ps ->
                    let n = RT.n_leaves tree in
                    let ca =
                      Mls.Tree_math.common_ancestor
                        (Mls.Tree_math.node_of_leaf j)
                        (Mls.Tree_math.node_of_leaf sender)
                        n
                    in
                    (* Walk up to the first node of the sender's filtered
                       path. *)
                    let fdp = RT.filtered_direct_path r.tree sender in
                    let rec up x =
                      if List.mem x fdp then x
                      else up (Mls.Tree_math.parent x n)
                    in
                    let node = up ca in
                    let k, _ = get (TK.node_key_pair c ~path_secret:ps) in
                    check_bytes
                      (Printf.sprintf "path secret for %d" j)
                      (Hpke.Private_key.to_bytes k)
                      (Hpke.Private_key.to_bytes
                         (Option.get (TK.Private.private_key r.priv node)))
                | None -> ()))
            privs;
          (* Create a fresh path from the sender and have everyone process
             it. *)
          let _, sender_priv, signature_key =
            List.find (fun (i, _, _) -> i = sender) privs
          in
          let created =
            get
              (TK.create_update_path c ~rng ~tree ~priv:sender_priv
                 ~signature_key ~group_context:gc_template ())
          in
          get (RT.verify_parent_hashes c created.tree);
          get (TK.Private.check_consistency created.priv created.tree);
          get
            (RT.verify_leaf_signatures c created.tree
               ~group_id:gc_template.group_id);
          List.iter
            (fun (j, priv, _) ->
              if j <> sender then (
                let r =
                  get
                    (TK.process_update_path c ~tree ~priv ~sender
                       ~path:created.update_path ~group_context:gc_template ())
                in
                check_bytes
                  (Printf.sprintf "fresh path receiver %d" j)
                  created.commit_secret r.commit_secret;
                check_bytes "fresh path tree hash"
                  created.group_context.tree_hash (RT.tree_hash c r.tree)))
            privs)
        (member "update_paths" v |> to_list))

let tests = [ Alcotest.test_case "treekem.json" `Quick test_treekem ]
