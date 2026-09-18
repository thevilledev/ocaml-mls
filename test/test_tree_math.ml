open Vectors
open Yojson.Safe.Util
module T = Mls.Tree_math

let attempt f = try Some (f ()) with Invalid_argument _ -> None

let test_vectors () =
  List.iter
    (fun v ->
      let n = int_field v "n_leaves" in
      let width = T.node_width n in
      Alcotest.(check int) "n_nodes" (int_field v "n_nodes") width;
      Alcotest.(check int) "root" (int_field v "root") (T.root n);
      let arr k = member k v |> to_list |> List.map opt_int |> Array.of_list in
      let left = arr "left" and right = arr "right" in
      let parent = arr "parent" and sibling = arr "sibling" in
      for x = 0 to width - 1 do
        Alcotest.(check (option int))
          (Printf.sprintf "left n=%d x=%d" n x)
          left.(x)
          (attempt (fun () -> T.left x));
        Alcotest.(check (option int))
          (Printf.sprintf "right n=%d x=%d" n x)
          right.(x)
          (attempt (fun () -> T.right x));
        Alcotest.(check (option int))
          (Printf.sprintf "parent n=%d x=%d" n x)
          parent.(x)
          (attempt (fun () -> T.parent x n));
        Alcotest.(check (option int))
          (Printf.sprintf "sibling n=%d x=%d" n x)
          sibling.(x)
          (attempt (fun () -> T.sibling x n))
      done)
    (load "tree-math.json")

let test_paths () =
  (* Figure from RFC 9420 Appendix C: 8 leaves, node 7 is the root. *)
  Alcotest.(check (list int)) "direct path of 0" [ 1; 3; 7 ] (T.direct_path 0 8);
  Alcotest.(check (list int)) "copath of 0" [ 2; 5; 11 ] (T.copath 0 8);
  Alcotest.(check (list int))
    "direct path of 12" [ 13; 11; 7 ] (T.direct_path 12 8);
  Alcotest.(check (list int)) "copath of 12" [ 14; 9; 3 ] (T.copath 12 8);
  Alcotest.(check (list int)) "direct path of root" [] (T.direct_path 7 8);
  Alcotest.(check int) "common ancestor 0,4" 3 (T.common_ancestor 0 4 8);
  Alcotest.(check int) "common ancestor 2,12" 7 (T.common_ancestor 2 12 8);
  Alcotest.(check int) "common ancestor 8,10" 9 (T.common_ancestor 8 10 8);
  Alcotest.(check bool) "in subtree" true (T.is_in_subtree 4 3);
  Alcotest.(check bool) "not in subtree" false (T.is_in_subtree 8 3);
  Alcotest.(check int) "leaf count of width" 5 (T.leaf_count_of_width 9)

let tests =
  [
    Alcotest.test_case "tree-math.json" `Quick test_vectors;
    Alcotest.test_case "paths" `Quick test_paths;
  ]
