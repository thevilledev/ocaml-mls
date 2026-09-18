(* Array-based binary tree arithmetic (RFC 9420 Appendix C). Nodes are numbered
   left to right; leaves have even node indices and leaf index [i] corresponds
   to node index [2 * i]. *)

type node_index = int
type leaf_index = int

let log2 x =
  if x <= 0 then 0
  else
    let rec go k = if x lsr k = 0 then k - 1 else go (k + 1) in
    go 1

(* Level of a node: number of trailing one bits in its index. *)
let level x =
  if x land 1 = 0 then 0
  else
    let rec go k = if (x lsr k) land 1 = 1 then go (k + 1) else k in
    go 0

let node_width n_leaves = if n_leaves = 0 then 0 else (2 * (n_leaves - 1)) + 1
let root n_leaves = (1 lsl log2 (node_width n_leaves)) - 1
let is_leaf x = x land 1 = 0
let node_of_leaf i = 2 * i

let leaf_of_node x =
  if not (is_leaf x) then invalid_arg "Tree_math.leaf_of_node: not a leaf";
  x / 2

let left x =
  let k = level x in
  if k = 0 then invalid_arg "Tree_math.left: leaf node has no children";
  x lxor (1 lsl (k - 1))

let right x =
  let k = level x in
  if k = 0 then invalid_arg "Tree_math.right: leaf node has no children";
  x lxor (3 lsl (k - 1))

let parent x n_leaves =
  if x = root n_leaves then invalid_arg "Tree_math.parent: root has no parent";
  let k = level x in
  let b = (x lsr (k + 1)) land 1 in
  x lor (1 lsl k) lxor (b lsl (k + 1))

let sibling x n_leaves =
  let p = parent x n_leaves in
  if x < p then right p else left p

(* Direct path from [x] (exclusive) to the root (inclusive). *)
let direct_path x n_leaves =
  let r = root n_leaves in
  let rec go x acc =
    if x = r then List.rev acc
    else
      let p = parent x n_leaves in
      go p (p :: acc)
  in
  if x = r then [] else go x []

(* Copath: siblings of [x] and of every node on its direct path except root. *)
let copath x n_leaves =
  let r = root n_leaves in
  if x = r then []
  else
    let path = x :: direct_path x n_leaves in
    let path = List.filter (fun y -> y <> r) path in
    List.map (fun y -> sibling y n_leaves) path

(* Lowest common ancestor of two nodes in a tree with [n_leaves] leaves. *)
let common_ancestor x y n_leaves =
  let r = root n_leaves in
  let ancestors z = z :: direct_path z n_leaves in
  let ax = ancestors x in
  let ay = ancestors y in
  let rec find = function
    | [] -> r
    | a :: rest -> if List.mem a ay then a else find rest
  in
  find ax

(* Number of leaves in a tree with the given node width. *)
let leaf_count_of_width w = if w = 0 then 0 else (w / 2) + 1

(* Whether node [x] lies in the subtree rooted at [a]. *)
let is_in_subtree x a =
  let k = level a in
  let lo = a - (1 lsl k) + 1 and hi = a + (1 lsl k) - 1 in
  x >= lo && x <= hi
