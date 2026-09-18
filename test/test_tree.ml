open Vectors
open Yojson.Safe.Util
open Test_crypto
module RT = Mls.Ratchet_tree

let tree_of_hex c v =
  ignore c;
  match RT.of_bytes (hex_field v "tree") with
  | Ok t -> t
  | Error e -> Alcotest.fail (Mls.Error.to_string e)

let test_tree_validation () =
  for_each_supported "tree-validation.json" (fun c v ->
      let t = tree_of_hex c v in
      let group_id = hex_field v "group_id" in
      let resolutions =
        member "resolutions" v |> to_list
        |> List.map (fun l -> to_list l |> List.map to_int)
      in
      let hashes = member "tree_hashes" v |> to_list |> List.map hex in
      Alcotest.(check int) "node count" (List.length resolutions) (RT.width t);
      List.iteri
        (fun x expected ->
          Alcotest.(check (list int))
            (Printf.sprintf "resolution of %d" x)
            expected (RT.resolution t x))
        resolutions;
      List.iteri
        (fun x expected ->
          check_bytes
            (Printf.sprintf "tree hash of %d" x)
            expected (RT.tree_hash_at c t x))
        hashes;
      (match RT.verify_parent_hashes c t with
      | Ok () -> ()
      | Error e -> Alcotest.fail (Mls.Error.to_string e));
      (match RT.verify_leaf_signatures c t ~group_id with
      | Ok () -> ()
      | Error e -> Alcotest.fail (Mls.Error.to_string e));
      (* Round trip through the wire encoding. *)
      check_bytes "tree re-encoding" (hex_field v "tree") (RT.to_bytes t))

let test_tree_operations () =
  for_each_supported "tree-operations.json" (fun c v ->
      let before =
        match RT.of_bytes (hex_field v "tree_before") with
        | Ok t -> t
        | Error e -> Alcotest.fail (Mls.Error.to_string e)
      in
      check_bytes "tree_hash_before"
        (hex_field v "tree_hash_before")
        (RT.tree_hash c before);
      let proposal =
        Mls.Tls.decode_exn Mls.Proposal.decode (hex_field v "proposal")
      in
      let sender = int_field v "proposal_sender" in
      let after =
        match proposal with
        | Mls.Proposal.Add kp ->
            fst (RT.add_leaf before kp.Mls.Key_package.leaf_node)
        | Mls.Proposal.Update ln -> RT.update_leaf before sender ln
        | Mls.Proposal.Remove i -> RT.remove_leaf before i
        | _ -> Alcotest.fail "unexpected proposal type"
      in
      check_bytes "tree_after" (hex_field v "tree_after") (RT.to_bytes after);
      check_bytes "tree_hash_after"
        (hex_field v "tree_hash_after")
        (RT.tree_hash c after))

let test_structure () =
  Alcotest.(check int) "empty tree has one leaf" 1 (RT.n_leaves RT.empty);
  let t = RT.extend RT.empty in
  Alcotest.(check int) "extended tree" 2 (RT.n_leaves t);
  let t = RT.extend t in
  Alcotest.(check int) "extended twice" 4 (RT.n_leaves t);
  Alcotest.(check int) "truncate all-blank" 1 (RT.n_leaves (RT.truncate t));
  Alcotest.(check bool)
    "of_nodes rejects trailing blank" true
    (Result.is_error (RT.of_nodes [ None; None ]));
  Alcotest.(check bool)
    "of_nodes rejects empty" true
    (Result.is_error (RT.of_nodes []))

let tests =
  [
    Alcotest.test_case "tree-validation.json" `Quick test_tree_validation;
    Alcotest.test_case "tree-operations.json" `Quick test_tree_operations;
    Alcotest.test_case "structure" `Quick test_structure;
  ]
