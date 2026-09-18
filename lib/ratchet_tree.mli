(** Public ratchet tree (RFC 9420 Section 7): a complete binary tree with [2^d]
    leaves in the array representation of Appendix C. Values are immutable;
    operations return new trees. *)

type t = { nodes : Node.t option array }
(** Read-only; use the functions below. *)

val empty : t
(** A tree with a single blank leaf. *)

val width : t -> int
val n_leaves : t -> int
val root : t -> int
val node : t -> int -> Node.t option
val leaf : t -> int -> Leaf_node.t option
val parent_node : t -> int -> Parent_node.t option
val is_blank : t -> int -> bool
val leaves : t -> (int * Leaf_node.t) list
val non_blank_leaf_count : t -> int
val find_leaf : t -> (Leaf_node.t -> bool) -> int option

(** {1 Wire representation (Section 12.4.3.3)} *)

val of_nodes : Node.t option list -> (t, Error.t) result
val to_nodes : t -> Node.t option list
val of_bytes : string -> (t, Error.t) result
val to_bytes : t -> string

(** {1 Structure} *)

val resolution : t -> int -> int list
val filtered_direct_path : t -> int -> int list

val filtered_direct_path_with_copath : t -> int -> (int * int) list
(** Filtered direct path nodes of a leaf paired with their copath children. *)

(** {1 Hashes (Sections 7.8 and 7.9)} *)

val tree_hash_at : ?exclude:int list -> Crypto.t -> t -> int -> string
val tree_hash : Crypto.t -> t -> string

val parent_hash :
  Crypto.t -> t -> p:int -> sibling:int -> (string, Error.t) result

val node_parent_hash : t -> int -> string option
val parent_hash_valid : Crypto.t -> t -> d:int -> p:int -> bool
val verify_parent_hashes : Crypto.t -> t -> (unit, Error.t) result

val verify_leaf_signature :
  Crypto.t ->
  group_id:string ->
  leaf_index:int ->
  Leaf_node.t ->
  (unit, Error.t) result

val verify_leaf_signatures :
  Crypto.t -> t -> group_id:string -> (unit, Error.t) result

(** {1 Modifications} *)

val set : t -> int -> Node.t option -> t
val blank_direct_path : t -> int -> t
val extend : t -> t
val truncate : t -> t
val first_blank_leaf : t -> int option
val add_leaf : t -> Leaf_node.t -> t * int
val update_leaf : t -> int -> Leaf_node.t -> t
val remove_leaf : t -> int -> t

val merge_path_keys :
  Crypto.t ->
  t ->
  sender:int ->
  keys:string list ->
  (t * string, Error.t) result
(** Set the sender's filtered direct path keys and recompute parent hashes,
    returning the parent hash for the sender's leaf. *)

val apply_update_path :
  Crypto.t -> t -> sender:int -> Update_path.t -> (t, Error.t) result
