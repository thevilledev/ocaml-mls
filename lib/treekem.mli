(** TreeKEM: private tree state and UpdatePath generation and processing (RFC
    9420 Sections 7.4 to 7.6). *)

module Int_map : Map.S with type key = int

(** A member's private view of the tree: HPKE private keys for its leaf and for
    nodes on its direct path. *)
module Private : sig
  type t

  val create : leaf_index:int -> leaf_key:Hpke.Private_key.t -> t
  val leaf_index : t -> int
  val private_key : t -> int -> Hpke.Private_key.t option
  val set_private_key : t -> int -> Hpke.Private_key.t -> t
  val nodes : t -> int list

  val prune : t -> Ratchet_tree.t -> t
  (** Drop keys for nodes that are blank or carry a different public key. *)

  val check_consistency : t -> Ratchet_tree.t -> (unit, Error.t) result
end

val node_key_pair :
  Crypto.t ->
  path_secret:string ->
  (Hpke.Private_key.t * Hpke.Public_key.t, Error.t) result

val derive_path :
  Crypto.t ->
  nodes:int list ->
  path_secret:string ->
  ( (int * string * Hpke.Private_key.t * Hpke.Public_key.t) list * string,
    Error.t )
  result
(** Derive path secrets and key pairs along [nodes], returning them together
    with the commit secret. *)

val set_path_secret :
  Crypto.t ->
  Private.t ->
  Ratchet_tree.t ->
  node:int ->
  path_secret:string ->
  (Private.t, Error.t) result
(** Install keys derived from [path_secret] at [node] and above it on the leaf's
    filtered direct path, as when joining via Welcome. *)

type created = {
  tree : Ratchet_tree.t;
  priv : Private.t;
  update_path : Update_path.t;
  commit_secret : string;
  path_secrets : string Int_map.t;  (** node index to path secret *)
  group_context : Group_context.t;
      (** provisional context with the new tree hash *)
}

val create_update_path :
  ?update_leaf:(Leaf_node.t -> Leaf_node.t) ->
  ?exclude:int list ->
  Crypto.t ->
  rng:Mirage_crypto_rng.g ->
  tree:Ratchet_tree.t ->
  priv:Private.t ->
  signature_key:Crypto.signature_key ->
  group_context:Group_context.t ->
  unit ->
  (created, Error.t) result
(** Generate a fresh UpdatePath for the member owning [priv]. [exclude] lists
    leaves added in the same commit; [group_context]'s tree hash is replaced. *)

type processed = {
  tree : Ratchet_tree.t;
  priv : Private.t;
  commit_secret : string;
  group_context : Group_context.t;
}

val process_update_path :
  ?exclude:int list ->
  Crypto.t ->
  tree:Ratchet_tree.t ->
  priv:Private.t ->
  sender:int ->
  path:Update_path.t ->
  group_context:Group_context.t ->
  unit ->
  (processed, Error.t) result
(** Merge an UpdatePath from [sender] and decrypt our path secret. *)

val path_secret_for_joiner : created -> joiner:int -> (int * string) option
(** The [(node, path_secret)] a new member at [joiner] needs in its Welcome. *)
