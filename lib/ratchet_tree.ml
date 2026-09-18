(* Public ratchet tree state (RFC 9420 Section 7). The tree is a complete binary
   tree with 2^d leaves stored in the array representation of Appendix C. Values
   are immutable; operations return new trees. *)

let ( let* ) = Result.bind

type t = { nodes : Node.t option array }

let width t = Array.length t.nodes
let n_leaves t = Tree_math.leaf_count_of_width (width t)
let root t = Tree_math.root (n_leaves t)
let empty = { nodes = [| None |] }
let node t x = if x < 0 || x >= width t then None else t.nodes.(x)

let leaf t i =
  match node t (Tree_math.node_of_leaf i) with
  | Some (Node.Leaf ln) -> Some ln
  | _ -> None

let parent_node t x =
  match node t x with Some (Node.Parent pn) -> Some pn | _ -> None

let is_blank t x = node t x = None

let leaves t =
  List.init (n_leaves t) (fun i -> (i, leaf t i))
  |> List.filter_map (fun (i, l) -> Option.map (fun l -> (i, l)) l)

let non_blank_leaf_count t = List.length (leaves t)

let rec next_power_of_two n =
  if n <= 1 then 1 else 2 * next_power_of_two ((n + 1) / 2)

(* Decode the ratchet_tree extension representation. *)
let of_nodes nodes =
  match List.rev nodes with
  | [] -> Error (Error.Invalid_tree "empty tree")
  | None :: _ -> Error (Error.Invalid_tree "trailing blank node")
  | _ -> (
      let l = List.length nodes in
      let n = next_power_of_two ((l / 2) + 1) in
      let arr = Array.make (Tree_math.node_width n) None in
      let bad = ref None in
      List.iteri
        (fun i nd ->
          (match (nd, Tree_math.is_leaf i) with
          | Some (Node.Leaf _), false ->
              bad := Some "leaf node at parent position"
          | Some (Node.Parent _), true ->
              bad := Some "parent node at leaf position"
          | _ -> ());
          arr.(i) <- nd)
        nodes;
      match !bad with
      | Some msg -> Error (Error.Invalid_tree msg)
      | None -> Ok { nodes = arr })

let to_nodes t =
  let last = ref (-1) in
  Array.iteri (fun i n -> if n <> None then last := i) t.nodes;
  Array.to_list (Array.sub t.nodes 0 (!last + 1))

let of_bytes bytes =
  let* nodes = Error.of_decode (Tls.decode Node.decode_tree bytes) in
  of_nodes nodes

let to_bytes t = Tls.encode Node.encode_tree (to_nodes t)

(* Resolution of a node (Section 7.2), as node indices. *)
let rec resolution t x =
  match node t x with
  | Some (Node.Leaf _) -> [ x ]
  | Some (Node.Parent pn) ->
      x :: List.map Tree_math.node_of_leaf pn.unmerged_leaves
  | None ->
      if Tree_math.is_leaf x then []
      else resolution t (Tree_math.left x) @ resolution t (Tree_math.right x)

(* Direct path of a leaf's node with nodes removed whose copath child has an
   empty resolution. Returns (direct path node, copath child) pairs. *)
let filtered_direct_path_with_copath t leaf_index =
  let n = n_leaves t in
  let x = Tree_math.node_of_leaf leaf_index in
  let dp = Tree_math.direct_path x n in
  let cp = Tree_math.copath x n in
  List.combine dp cp |> List.filter (fun (_, c) -> resolution t c <> [])

let filtered_direct_path t leaf_index =
  List.map fst (filtered_direct_path_with_copath t leaf_index)

(* Tree hashes (Section 7.8). [exclude] lists leaf indices to treat as blank and
   to drop from unmerged_leaves, for original_sibling_tree_hash. *)
let rec tree_hash_at ?(exclude = []) c t x =
  if Tree_math.is_leaf x then
    let li = Tree_math.leaf_of_node x in
    let ln = if List.mem li exclude then None else leaf t li in
    Crypto.hash c
      (Tls.encode
         (fun e () ->
           Tls.Encoder.u8 e Node.node_type_leaf;
           Tls.Encoder.u32 e li;
           Tls.Encoder.optional e Leaf_node.encode ln)
         ())
  else
    let pn =
      match parent_node t x with
      | Some pn when exclude <> [] ->
          Some
            {
              pn with
              Parent_node.unmerged_leaves =
                List.filter
                  (fun l -> not (List.mem l exclude))
                  pn.Parent_node.unmerged_leaves;
            }
      | pn -> pn
    in
    let left_hash = tree_hash_at ~exclude c t (Tree_math.left x) in
    let right_hash = tree_hash_at ~exclude c t (Tree_math.right x) in
    Crypto.hash c
      (Tls.encode
         (fun e () ->
           Tls.Encoder.u8 e Node.node_type_parent;
           Tls.Encoder.optional e Parent_node.encode pn;
           Tls.Encoder.opaque e left_hash;
           Tls.Encoder.opaque e right_hash)
         ())

let tree_hash c t = tree_hash_at c t (root t)

(* Parent hash of parent node [p] with copath child [sibling] (Section 7.9). *)
let parent_hash_input ~encryption_key ~parent_hash ~original_sibling_tree_hash =
  Tls.encode
    (fun e () ->
      Tls.Encoder.opaque e encryption_key;
      Tls.Encoder.opaque e parent_hash;
      Tls.Encoder.opaque e original_sibling_tree_hash)
    ()

let parent_hash c t ~p ~sibling =
  match parent_node t p with
  | None -> Error (Error.Invalid_tree "parent hash of a blank node")
  | Some pn ->
      let original_sibling_tree_hash =
        tree_hash_at ~exclude:pn.Parent_node.unmerged_leaves c t sibling
      in
      Ok
        (Crypto.hash c
           (parent_hash_input ~encryption_key:pn.Parent_node.encryption_key
              ~parent_hash:pn.Parent_node.parent_hash
              ~original_sibling_tree_hash))

let node_parent_hash t x =
  match node t x with
  | Some (Node.Leaf ln) -> Leaf_node.parent_hash ln
  | Some (Node.Parent pn) -> Some pn.Parent_node.parent_hash
  | None -> None

(* Whether the parent hash of node [d] is valid with respect to parent [p]
   (Section 7.9.2). *)
let parent_hash_valid c t ~d ~p =
  let n = n_leaves t in
  let c_child = if d < p then Tree_math.left p else Tree_math.right p in
  let sibling = if d < p then Tree_math.right p else Tree_math.left p in
  ignore n;
  match (node_parent_hash t d, parent_node t p) with
  | Some ph, Some pn -> (
      match parent_hash c t ~p ~sibling with
      | Error _ -> false
      | Ok expected ->
          String.equal ph expected
          &&
          let res = resolution t c_child in
          List.mem d res
          &&
          let unmerged_in_c =
            List.filter_map
              (fun l ->
                let x = Tree_math.node_of_leaf l in
                if Tree_math.is_in_subtree x c_child then Some x else None)
              pn.Parent_node.unmerged_leaves
          in
          let res_minus_d = List.filter (fun x -> x <> d) res in
          List.sort compare unmerged_in_c = List.sort compare res_minus_d)
  | _ -> false

(* Verify that every non-blank parent node is parent-hash valid by chaining up
   from each leaf and checking that each parent is covered exactly once. *)
let verify_parent_hashes c t =
  let n = n_leaves t in
  let covered = Hashtbl.create 16 in
  let error = ref None in
  List.iter
    (fun (li, _) ->
      let x = Tree_math.node_of_leaf li in
      let rec climb d = function
        | [] -> ()
        | p :: rest ->
            if is_blank t p then climb d rest
            else if parent_hash_valid c t ~d ~p then (
              if Hashtbl.mem covered p then
                error :=
                  Some (Printf.sprintf "parent node %d covered by two chains" p)
              else Hashtbl.replace covered p ();
              climb p rest)
            else ()
      in
      climb x (Tree_math.direct_path x n))
    (leaves t);
  match !error with
  | Some msg -> Error (Error.Invalid_tree msg)
  | None -> (
      let missing = ref None in
      Array.iteri
        (fun x nd ->
          match nd with
          | Some (Node.Parent _) when not (Hashtbl.mem covered x) ->
              if !missing = None then missing := Some x
          | _ -> ())
        t.nodes;
      match !missing with
      | Some x ->
          Error
            (Error.Invalid_tree
               (Printf.sprintf "parent node %d is not parent-hash valid" x))
      | None -> Ok ())

let verify_leaf_signature c ~group_id ~leaf_index (ln : Leaf_node.t) =
  let tbs = Leaf_node.tbs ~group_id ~leaf_index ln in
  if
    Crypto.verify_with_label c ~public_key:ln.Leaf_node.signature_key
      ~label:Leaf_node.signature_label ~signature:ln.Leaf_node.signature tbs
  then Ok ()
  else Error Error.Invalid_signature

let verify_leaf_signatures c t ~group_id =
  List.fold_left
    (fun acc (li, ln) ->
      let* () = acc in
      match verify_leaf_signature c ~group_id ~leaf_index:li ln with
      | Ok () -> Ok ()
      | Error _ ->
          Error
            (Error.Invalid_leaf_node
               (Printf.sprintf "invalid signature on leaf %d" li)))
    (Ok ()) (leaves t)

(* Structural modifications *)

let set t x nd =
  let nodes = Array.copy t.nodes in
  nodes.(x) <- nd;
  { nodes }

let blank_direct_path t x =
  let nodes = Array.copy t.nodes in
  List.iter (fun p -> nodes.(p) <- None) (Tree_math.direct_path x (n_leaves t));
  { nodes }

let extend t =
  let w = width t in
  let nodes = Array.make ((2 * w) + 1) None in
  Array.blit t.nodes 0 nodes 0 w;
  { nodes }

let rec truncate t =
  let w = width t in
  if w <= 1 then t
  else
    let r = root t in
    let right_blank = ref true in
    for x = r + 1 to w - 1 do
      if t.nodes.(x) <> None then right_blank := false
    done;
    if !right_blank then truncate { nodes = Array.sub t.nodes 0 r } else t

let first_blank_leaf t =
  let n = n_leaves t in
  let rec go i =
    if i >= n then None else if leaf t i = None then Some i else go (i + 1)
  in
  go 0

let insert_sorted x xs =
  let rec go = function
    | [] -> [ x ]
    | y :: rest as l ->
        if x < y then x :: l else if x = y then l else y :: go rest
  in
  go xs

(* Add a leaf (Section 12.1.1). Returns the tree and the new leaf index. *)
let add_leaf t (ln : Leaf_node.t) =
  let t, i =
    match first_blank_leaf t with
    | Some i -> (t, i)
    | None ->
        let i = n_leaves t in
        (extend t, i)
  in
  let x = Tree_math.node_of_leaf i in
  let nodes = Array.copy t.nodes in
  nodes.(x) <- Some (Node.Leaf ln);
  List.iter
    (fun p ->
      match nodes.(p) with
      | Some (Node.Parent pn) ->
          nodes.(p) <-
            Some
              (Node.Parent
                 {
                   pn with
                   Parent_node.unmerged_leaves =
                     insert_sorted i pn.Parent_node.unmerged_leaves;
                 })
      | _ -> ())
    (Tree_math.direct_path x (n_leaves t));
  ({ nodes }, i)

(* Update a leaf (Section 12.1.2). *)
let update_leaf t i (ln : Leaf_node.t) =
  let x = Tree_math.node_of_leaf i in
  blank_direct_path (set t x (Some (Node.Leaf ln))) x

(* Remove a leaf (Section 12.1.3). *)
let remove_leaf t i =
  let x = Tree_math.node_of_leaf i in
  truncate (blank_direct_path (set t x None) x)

let find_leaf t pred =
  List.find_opt (fun (_, ln) -> pred ln) (leaves t) |> Option.map fst

(* Set the public keys of the sender's filtered direct path from [keys]
   (root-most last), blanking the rest of the direct path, and compute parent
   hashes from the root down. Returns the tree and the parent hash for the
   sender's leaf. *)
let merge_path_keys c t ~sender ~keys =
  let x = Tree_math.node_of_leaf sender in
  let fdp = filtered_direct_path t sender in
  if List.length fdp <> List.length keys then
    Error
      (Error.Invalid_commit
         (Printf.sprintf "update path has %d nodes, filtered direct path has %d"
            (List.length keys) (List.length fdp)))
  else
    let t = blank_direct_path t x in
    let rec assign t ~above = function
      | [] -> Ok (t, above)
      | (p, encryption_key) :: rest ->
          let pn =
            {
              Parent_node.encryption_key;
              parent_hash = above;
              unmerged_leaves = [];
            }
          in
          let t = set t p (Some (Node.Parent pn)) in
          (* The sender's leaf is in the left subtree of p iff x < p. *)
          let sib = if x < p then Tree_math.right p else Tree_math.left p in
          let* ph = parent_hash c t ~p ~sibling:sib in
          assign t ~above:ph rest
    in
    assign t ~above:"" (List.rev (List.combine fdp keys))

(* Apply the public parts of an UpdatePath (Section 7.5) and verify the leaf
   node's parent hash. *)
let apply_update_path c t ~sender (path : Update_path.t) =
  let keys =
    List.map
      (fun (n : Update_path.node) -> n.Update_path.encryption_key)
      path.Update_path.nodes
  in
  let* t, leaf_parent_hash = merge_path_keys c t ~sender ~keys in
  let ln = path.Update_path.leaf_node in
  match Leaf_node.parent_hash ln with
  | Some ph when String.equal ph leaf_parent_hash ->
      Ok (set t (Tree_math.node_of_leaf sender) (Some (Node.Leaf ln)))
  | Some _ -> Error (Error.Invalid_commit "leaf node parent hash mismatch")
  | None ->
      Error
        (Error.Invalid_commit "update path leaf node must have source commit")
