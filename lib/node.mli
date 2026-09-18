(** Ratchet tree nodes (RFC 9420 Section 12.4.3.3). *)

type t = Leaf of Leaf_node.t | Parent of Parent_node.t

val node_type_leaf : int
val node_type_parent : int
val encode : Tls.Encoder.t -> t -> unit
val decode : Tls.Decoder.t -> t
val encryption_key : t -> string

val encode_tree : Tls.Encoder.t -> t option list -> unit
(** [optional<Node> ratchet_tree<V>] *)

val decode_tree : Tls.Decoder.t -> t option list
