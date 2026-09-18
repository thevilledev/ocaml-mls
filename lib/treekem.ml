(* TreeKEM: private tree state, UpdatePath generation and processing (RFC 9420
   Sections 7.4 to 7.6). *)

let ( let* ) = Result.bind

module Int_map = Map.Make (Int)

let update_path_node_label = "UpdatePathNode"

(* A member's private view of the tree: HPKE private keys for its leaf and for
   nodes on its direct path. *)
module Private = struct
  type t = { leaf_index : int; keys : Hpke.Private_key.t Int_map.t }

  let create ~leaf_index ~leaf_key =
    {
      leaf_index;
      keys = Int_map.singleton (Tree_math.node_of_leaf leaf_index) leaf_key;
    }

  let leaf_index t = t.leaf_index
  let private_key t x = Int_map.find_opt x t.keys
  let set_private_key t x k = { t with keys = Int_map.add x k t.keys }
  let nodes t = Int_map.bindings t.keys |> List.map fst

  (* Drop keys for nodes that are blank or carry a different public key. *)
  let prune t tree =
    let keys =
      Int_map.filter
        (fun x k ->
          match Ratchet_tree.node tree x with
          | Some nd ->
              String.equal (Node.encryption_key nd)
                (Hpke.Public_key.to_bytes (Hpke.Private_key.public_key k))
          | None -> false)
        t.keys
    in
    { t with keys }

  (* Every private key must correspond to a non-blank node in [tree] with the
     matching public key. *)
  let check_consistency t tree =
    Int_map.fold
      (fun x k acc ->
        let* () = acc in
        match Ratchet_tree.node tree x with
        | None ->
            Error
              (Error.Invalid_tree
                 (Printf.sprintf "private key for blank node %d" x))
        | Some nd ->
            if
              String.equal (Node.encryption_key nd)
                (Hpke.Public_key.to_bytes (Hpke.Private_key.public_key k))
            then Ok ()
            else
              Error
                (Error.Invalid_tree
                   (Printf.sprintf "private key mismatch at node %d" x)))
      t.keys (Ok ())
end

let next_path_secret c secret = Crypto.derive_secret c ~secret ~label:"path"

let node_key_pair c ~path_secret =
  let node_secret = Crypto.derive_secret c ~secret:path_secret ~label:"node" in
  Crypto.derive_key_pair c ~ikm:node_secret

(* Derive path secrets and key pairs along [nodes] (a suffix of a filtered
   direct path, ending at the root), starting with [path_secret] at the first
   node. Returns [(node, path_secret, private, public)] and the commit secret,
   which is the path secret following the root's. *)
let derive_path c ~nodes ~path_secret =
  let rec go secret acc = function
    | [] -> Ok (List.rev acc, secret)
    | n :: rest ->
        let* priv, pub = node_key_pair c ~path_secret:secret in
        go (next_path_secret c secret) ((n, secret, priv, pub) :: acc) rest
  in
  match nodes with [] -> Ok ([], path_secret) | _ -> go path_secret [] nodes

let ancestors_from tree ~leaf_index ~node =
  (* Nodes of the leaf's filtered direct path from [node] (inclusive) upward. *)
  let fdp = Ratchet_tree.filtered_direct_path tree leaf_index in
  let rec drop = function
    | [] -> []
    | n :: rest as l -> if n = node then l else drop rest
  in
  drop fdp

(* Set private keys derived from [path_secret] at [node] and at every node above
   it on the leaf's filtered direct path (used when joining via Welcome). *)
let set_path_secret c (priv : Private.t) tree ~node ~path_secret =
  let nodes = ancestors_from tree ~leaf_index:priv.Private.leaf_index ~node in
  if nodes = [] then
    Error (Error.Invalid_welcome "path secret node is not on the direct path")
  else
    let* derived, _ = derive_path c ~nodes ~path_secret in
    let* () =
      List.fold_left
        (fun acc (n, _, _, pub) ->
          let* () = acc in
          match Ratchet_tree.node tree n with
          | Some nd
            when String.equal (Node.encryption_key nd)
                   (Hpke.Public_key.to_bytes pub) ->
              Ok ()
          | _ ->
              Error
                (Error.Invalid_welcome
                   (Printf.sprintf "derived key mismatch at node %d" n)))
        (Ok ()) derived
    in
    Ok
      (List.fold_left
         (fun p (n, _, k, _) -> Private.set_private_key p n k)
         priv derived)

let sign_leaf c ~key ~group_id ~leaf_index (ln : Leaf_node.t) =
  Leaf_node.sign c ~key ~group_id ~leaf_index ln

type created = {
  tree : Ratchet_tree.t;
  priv : Private.t;
  update_path : Update_path.t;
  commit_secret : string;
  path_secrets : string Int_map.t; (* node index -> path secret, for Welcome *)
  group_context : Group_context.t; (* provisional, with the new tree hash *)
}

let public_key_of_node tree x =
  match Ratchet_tree.node tree x with
  | Some nd -> Ok (Node.encryption_key nd)
  | None ->
      Error
        (Error.Invalid_tree (Printf.sprintf "resolution node %d is blank" x))

(* Generate a fresh UpdatePath for the member at [priv.leaf_index]. [exclude]
   lists leaf indices of members added in the same commit, whose keys must not
   receive path secrets. [group_context] is the provisional context whose
   tree_hash is replaced with that of the updated tree. [update_leaf] may
   further modify the new leaf node before it is signed. *)
let create_update_path ?(update_leaf = fun ln -> ln) ?(exclude = []) c ~rng
    ~tree ~(priv : Private.t) ~signature_key ~group_context () =
  let li = priv.Private.leaf_index in
  let x = Tree_math.node_of_leaf li in
  let* old_leaf =
    match Ratchet_tree.leaf tree li with
    | Some ln -> Ok ln
    | None -> Error (Error.Invalid_tree "sender leaf is blank")
  in
  let* leaf_priv, leaf_pub = Crypto.generate_key_pair c ~rng in
  let fdp_pairs = Ratchet_tree.filtered_direct_path_with_copath tree li in
  let fdp = List.map fst fdp_pairs in
  let path_secret0 = Crypto.random ~rng (Crypto.hash_size c) in
  let* derived, commit_secret =
    derive_path c ~nodes:fdp ~path_secret:path_secret0
  in
  let keys =
    List.map (fun (_, _, _, pub) -> Hpke.Public_key.to_bytes pub) derived
  in
  let* tree, leaf_parent_hash =
    Ratchet_tree.merge_path_keys c tree ~sender:li ~keys
  in
  let new_leaf =
    update_leaf
      {
        old_leaf with
        Leaf_node.encryption_key = Hpke.Public_key.to_bytes leaf_pub;
        leaf_node_source = Leaf_node.Commit leaf_parent_hash;
      }
  in
  let group_id = group_context.Group_context.group_id in
  let new_leaf =
    sign_leaf c ~key:signature_key ~group_id ~leaf_index:li new_leaf
  in
  let tree = Ratchet_tree.set tree x (Some (Node.Leaf new_leaf)) in
  let group_context =
    {
      group_context with
      Group_context.tree_hash = Ratchet_tree.tree_hash c tree;
    }
  in
  let context = Group_context.to_bytes group_context in
  let excluded = List.map Tree_math.node_of_leaf exclude in
  let* nodes =
    List.fold_right
      (fun ((_, copath_child), (_, secret, _, pub)) acc ->
        let* acc = acc in
        let res =
          Ratchet_tree.resolution tree copath_child
          |> List.filter (fun r -> not (List.mem r excluded))
        in
        let* cts =
          List.fold_right
            (fun r acc ->
              let* acc = acc in
              let* public_key = public_key_of_node tree r in
              let* kem_output, ciphertext =
                Crypto.encrypt_with_label c ~rng ~public_key
                  ~label:update_path_node_label ~context secret
              in
              Ok ({ Hpke_ciphertext.kem_output; ciphertext } :: acc))
            res (Ok [])
        in
        Ok
          ({
             Update_path.encryption_key = Hpke.Public_key.to_bytes pub;
             encrypted_path_secret = cts;
           }
          :: acc))
      (List.combine fdp_pairs derived)
      (Ok [])
  in
  let update_path = { Update_path.leaf_node = new_leaf; nodes } in
  let priv =
    List.fold_left
      (fun p (n, _, k, _) -> Private.set_private_key p n k)
      (Private.create ~leaf_index:li ~leaf_key:leaf_priv)
      derived
  in
  let path_secrets =
    List.fold_left
      (fun m (n, s, _, _) -> Int_map.add n s m)
      Int_map.empty derived
  in
  Ok { tree; priv; update_path; commit_secret; path_secrets; group_context }

type processed = {
  tree : Ratchet_tree.t;
  priv : Private.t;
  commit_secret : string;
  group_context : Group_context.t;
}

let rec find_index p i = function
  | [] -> None
  | x :: rest -> if p x then Some (i, x) else find_index p (i + 1) rest

(* Process an UpdatePath from [sender], updating the public tree and decrypting
   the path secret for the lowest node in the sender's filtered direct path
   above our leaf. *)
let process_update_path ?(exclude = []) c ~tree ~(priv : Private.t) ~sender
    ~(path : Update_path.t) ~group_context () =
  let li = priv.Private.leaf_index in
  if sender = li then
    Error (Error.Invalid_commit "cannot process own update path")
  else
    let* tree = Ratchet_tree.apply_update_path c tree ~sender path in
    let group_context =
      {
        group_context with
        Group_context.tree_hash = Ratchet_tree.tree_hash c tree;
      }
    in
    let context = Group_context.to_bytes group_context in
    let my_node = Tree_math.node_of_leaf li in
    let fdp_pairs = Ratchet_tree.filtered_direct_path_with_copath tree sender in
    let entries = List.combine fdp_pairs path.Update_path.nodes in
    (* Entries of the filtered direct path from the lowest node above us. *)
    let rec find = function
      | [] -> []
      | ((_, copath_child), _) :: _ as l
        when Tree_math.is_in_subtree my_node copath_child ->
          l
      | _ :: rest -> find rest
    in
    match find entries with
    | [] ->
        Error
          (Error.Invalid_commit "receiver is not below any update path node")
    | ((_, copath_child), (upn : Update_path.node)) :: _ as remaining -> (
        let excluded = List.map Tree_math.node_of_leaf exclude in
        let res =
          Ratchet_tree.resolution tree copath_child
          |> List.filter (fun r -> not (List.mem r excluded))
        in
        if List.length res <> List.length upn.Update_path.encrypted_path_secret
        then
          Error (Error.Invalid_commit "wrong number of encrypted path secrets")
        else
          match
            find_index (fun r -> Private.private_key priv r <> None) 0 res
          with
          | None ->
              Error
                (Error.Invalid_commit "no private key for any resolution node")
          | Some (idx, r) ->
              let private_key = Option.get (Private.private_key priv r) in
              let ct = List.nth upn.Update_path.encrypted_path_secret idx in
              let* path_secret =
                Crypto.decrypt_with_label c ~private_key
                  ~label:update_path_node_label ~context
                  ~kem_output:ct.Hpke_ciphertext.kem_output
                  ct.Hpke_ciphertext.ciphertext
              in
              let nodes = List.map (fun ((p, _), _) -> p) remaining in
              let* derived, commit_secret = derive_path c ~nodes ~path_secret in
              let* () =
                List.fold_left
                  (fun acc ((n, _, _, pub), (_, (upn : Update_path.node))) ->
                    let* () = acc in
                    if
                      String.equal
                        (Hpke.Public_key.to_bytes pub)
                        upn.Update_path.encryption_key
                    then Ok ()
                    else
                      Error
                        (Error.Invalid_commit
                           (Printf.sprintf
                              "derived public key mismatch at node %d" n)))
                  (Ok ())
                  (List.combine derived remaining)
              in
              let sender_path =
                Tree_math.direct_path
                  (Tree_math.node_of_leaf sender)
                  (Ratchet_tree.n_leaves tree)
              in
              let keys =
                List.fold_left
                  (fun m n -> Int_map.remove n m)
                  priv.Private.keys sender_path
              in
              let keys =
                List.fold_left
                  (fun m (n, _, k, _) -> Int_map.add n k m)
                  keys derived
              in
              Ok
                {
                  tree;
                  priv = { priv with Private.keys };
                  commit_secret;
                  group_context;
                })

(* The path secret a new member at [joiner] needs from a path created by
   [sender]: the one for their lowest common ancestor in the filtered path. *)
let path_secret_for_joiner (created : created) ~joiner =
  let tree = created.tree in
  let n = Ratchet_tree.n_leaves tree in
  let sender = created.priv.Private.leaf_index in
  let ca =
    Tree_math.common_ancestor
      (Tree_math.node_of_leaf joiner)
      (Tree_math.node_of_leaf sender)
      n
  in
  (* The common ancestor may have been filtered out; walk up to the first node
     that carries a path secret. *)
  let rec up x =
    match Int_map.find_opt x created.path_secrets with
    | Some s -> Some (x, s)
    | None -> if x = Tree_math.root n then None else up (Tree_math.parent x n)
  in
  up ca
