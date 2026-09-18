(* Ratchet tree node (RFC 9420 Section 12.4.3.3). *)

type t = Leaf of Leaf_node.t | Parent of Parent_node.t

let node_type_leaf = 1
let node_type_parent = 2

let encode e = function
  | Leaf ln ->
      Tls.Encoder.u8 e node_type_leaf;
      Leaf_node.encode e ln
  | Parent pn ->
      Tls.Encoder.u8 e node_type_parent;
      Parent_node.encode e pn

let decode d =
  match Tls.Decoder.u8 d with
  | 1 -> Leaf (Leaf_node.decode d)
  | 2 -> Parent (Parent_node.decode d)
  | n -> Tls.fail "unknown node type %d" n

let encryption_key = function
  | Leaf ln -> ln.Leaf_node.encryption_key
  | Parent pn -> pn.Parent_node.encryption_key

(* optional<Node> ratchet_tree<V> *)
let encode_tree e nodes =
  Tls.Encoder.vector e (fun e n -> Tls.Encoder.optional e encode n) nodes

let decode_tree d =
  Tls.Decoder.vector d (fun d -> Tls.Decoder.optional d decode)
