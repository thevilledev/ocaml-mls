(** Array-based binary tree arithmetic (RFC 9420 Appendix C). Nodes are numbered
    left to right in in-order traversal; leaf [i] is node [2 * i]. *)

type node_index = int
type leaf_index = int

val log2 : int -> int
val level : node_index -> int

val node_width : int -> int
(** Number of nodes in a tree with the given number of leaves. *)

val root : int -> node_index
val is_leaf : node_index -> bool
val node_of_leaf : leaf_index -> node_index

val leaf_of_node : node_index -> leaf_index
(** Raises [Invalid_argument] on a parent node index. *)

val left : node_index -> node_index

val right : node_index -> node_index
(** Raises [Invalid_argument] on a leaf node index. *)

val parent : node_index -> int -> node_index
(** [parent x n_leaves]; raises [Invalid_argument] on the root. *)

val sibling : node_index -> int -> node_index

val direct_path : node_index -> int -> node_index list
(** Ancestors of [x] from its parent up to and including the root. *)

val copath : node_index -> int -> node_index list
val common_ancestor : node_index -> node_index -> int -> node_index
val leaf_count_of_width : int -> int

val is_in_subtree : node_index -> node_index -> bool
(** [is_in_subtree x a] holds when [x] is [a] or a descendant of [a]. *)
