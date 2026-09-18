(* Group state machine (RFC 9420 Sections 11 and 12): creation, joining via
   Welcome, and processing of proposals, commits and application messages. The
   state is immutable; every operation returns the updated group. *)

let ( let* ) = Result.bind

module String_map = Map.Make (String)
module Int64_map = Map.Make (Int64)
open Framing

type psk_lookup = Psk.id -> string option

let no_external_psks _ = None

type t = {
  crypto : Crypto.t;
  context : Group_context.t;
  tree : Ratchet_tree.t;
  priv : Treekem.Private.t;
  signature_key : Crypto.signature_key;
  secrets : Key_schedule.epoch_secrets;
  secret_tree : Secret_tree.t;
  interim_transcript_hash : string;
  confirmation_tag : string;
  pending : (Proposal.t * Sender.t) String_map.t;
  own_leaf_keys : Hpke.Private_key.t list;
  resumption_psks : string Int64_map.t;
}

type event =
  | Proposal_received of {
      proposal : Proposal.t;
      sender : Sender.t;
      reference : string;
    }
  | Commit_applied of {
      removed_self : bool;
      committer : int option;
      reinit : Proposal.re_init option;
    }
  | Application_received of {
      data : string;
      sender : int;
      authenticated_data : string;
    }

let max_resumption_epochs = 256L
let group_info_label = "GroupInfoTBS"
let welcome_label = "Welcome"
let external_init_label = "MLS 1.0 external init secret"

(* Accessors *)

let crypto t = t.crypto
let cipher_suite t = t.context.Group_context.cipher_suite
let group_id t = t.context.Group_context.group_id
let epoch t = t.context.Group_context.epoch
let context t = t.context
let extensions t = t.context.Group_context.extensions
let tree t = t.tree
let own_index t = Treekem.Private.leaf_index t.priv
let members t = Ratchet_tree.leaves t.tree
let member t i = Ratchet_tree.leaf t.tree i
let own_leaf t = Ratchet_tree.leaf t.tree (own_index t)
let epoch_authenticator t = t.secrets.Key_schedule.epoch_authenticator
let resumption_psk t = t.secrets.Key_schedule.resumption_psk
let confirmation_tag t = t.confirmation_tag
let signature_key t = t.signature_key
let pending_proposals t = String_map.bindings t.pending

let export t ~label ~context length =
  Key_schedule.exporter t.crypto
    ~exporter_secret:t.secrets.Key_schedule.exporter_secret ~label ~context
    length

(* Leaf node and key package validation (Sections 7.3 and 10.1) *)

type leaf_expectation = For_key_package | For_update | For_commit | For_any

let supports_extension_type (caps : Capabilities.t) ty =
  Extension.is_default_type ty || List.mem ty caps.Capabilities.extensions

let supports_proposal_type (caps : Capabilities.t) ty =
  List.mem ty Proposal.default_types || List.mem ty caps.Capabilities.proposals

let check_required_capabilities (rc : Group_extensions.required_capabilities)
    (caps : Capabilities.t) =
  List.for_all
    (supports_extension_type caps)
    rc.Group_extensions.extension_types
  && List.for_all
       (supports_proposal_type caps)
       rc.Group_extensions.proposal_types
  && List.for_all
       (fun ty -> List.mem ty caps.Capabilities.credentials)
       rc.Group_extensions.credential_types

let fail_leaf msg = Error (Error.Invalid_leaf_node msg)

let validate_leaf_node c ~group_id ~cipher_suite ~tree ~extensions ~expected
    ~leaf_index (ln : Leaf_node.t) =
  let caps = ln.Leaf_node.capabilities in
  let* () =
    match (ln.Leaf_node.leaf_node_source, expected) with
    | Leaf_node.Key_package _, (For_key_package | For_any)
    | Leaf_node.Update, (For_update | For_any)
    | Leaf_node.Commit _, (For_commit | For_any) ->
        Ok ()
    | _ -> fail_leaf "unexpected leaf_node_source"
  in
  let* () =
    match Ratchet_tree.verify_leaf_signature c ~group_id ~leaf_index ln with
    | Ok () -> Ok ()
    | Error _ -> fail_leaf "invalid signature"
  in
  let* () =
    if
      List.mem cipher_suite caps.Capabilities.cipher_suites
      && List.mem Framing.protocol_version_mls10 caps.Capabilities.versions
    then Ok ()
    else fail_leaf "cipher suite or protocol version not supported by leaf"
  in
  let* () =
    if
      List.for_all
        (fun (e : Extension.t) ->
          supports_extension_type caps e.Extension.extension_type)
        ln.Leaf_node.extensions
    then Ok ()
    else fail_leaf "leaf extension not listed in capabilities"
  in
  let cred_type = Credential.credential_type ln.Leaf_node.credential in
  let* () =
    if List.mem cred_type caps.Capabilities.credentials then Ok ()
    else fail_leaf "credential type not listed in capabilities"
  in
  let* rc = Group_extensions.required_capabilities extensions in
  let* () =
    match rc with
    | Some rc when not (check_required_capabilities rc caps) ->
        fail_leaf "required capabilities not supported"
    | _ -> Ok ()
  in
  let others =
    List.filter (fun (i, _) -> i <> leaf_index) (Ratchet_tree.leaves tree)
  in
  let* () =
    if
      List.for_all
        (fun (_, (other : Leaf_node.t)) ->
          List.mem cred_type
            other.Leaf_node.capabilities.Capabilities.credentials
          && List.mem
               (Credential.credential_type other.Leaf_node.credential)
               caps.Capabilities.credentials)
        others
    then Ok ()
    else fail_leaf "credential type not supported by all members"
  in
  if
    List.exists
      (fun (_, (other : Leaf_node.t)) ->
        String.equal other.Leaf_node.signature_key ln.Leaf_node.signature_key
        || String.equal other.Leaf_node.encryption_key
             ln.Leaf_node.encryption_key)
      others
  then fail_leaf "signature or encryption key already in use"
  else Ok ()

let validate_key_package c ~group_id ~cipher_suite ~tree ~extensions
    (kp : Key_package.t) =
  let fail msg = Error (Error.Invalid_key_package msg) in
  let* () =
    if kp.Key_package.version <> Framing.protocol_version_mls10 then
      fail "unsupported version"
    else Ok ()
  in
  let* () =
    if kp.Key_package.cipher_suite <> cipher_suite then
      fail "cipher suite mismatch"
    else Ok ()
  in
  let* () =
    if
      Crypto.verify_with_label c
        ~public_key:kp.Key_package.leaf_node.Leaf_node.signature_key
        ~label:Key_package.signature_label ~signature:kp.Key_package.signature
        (Key_package.tbs kp)
    then Ok ()
    else fail "invalid signature"
  in
  let* () =
    validate_leaf_node c ~group_id ~cipher_suite ~tree ~extensions
      ~expected:For_key_package ~leaf_index:(-1) kp.Key_package.leaf_node
  in
  if
    String.equal kp.Key_package.init_key
      kp.Key_package.leaf_node.Leaf_node.encryption_key
  then fail "init_key equals leaf encryption_key"
  else Ok ()

(* Every encryption key in the tree must be unique (Section 12.4.3.1). *)
let check_tree_keys_unique tree =
  let seen = Hashtbl.create 64 in
  let dup = ref false in
  Ratchet_tree.iteri
    (fun _ -> function
      | Some nd ->
          let k = Node.encryption_key nd in
          if Hashtbl.mem seen k then dup := true else Hashtbl.replace seen k ()
      | None -> ())
    tree;
  if !dup then Error (Error.Invalid_tree "duplicate encryption key") else Ok ()

(* Unmerged leaves must be non-blank descendants, listed in every non-blank
   intermediate node between the leaf and the parent. *)
let check_unmerged_leaves tree =
  let n = Ratchet_tree.n_leaves tree in
  let ok = ref true in
  Ratchet_tree.iteri
    (fun x nd ->
      match nd with
      | Some (Node.Parent pn) ->
          List.iter
            (fun l ->
              let lx = Tree_math.node_of_leaf l in
              if
                (not (Tree_math.is_in_subtree lx x))
                || Ratchet_tree.leaf tree l = None
              then ok := false
              else
                List.iter
                  (fun y ->
                    if y <> x && Tree_math.is_in_subtree y x then
                      match Ratchet_tree.parent_node tree y with
                      | Some p
                        when not (List.mem l p.Parent_node.unmerged_leaves) ->
                          ok := false
                      | _ -> ())
                  (Tree_math.direct_path lx n))
            pn.Parent_node.unmerged_leaves
      | _ -> ())
    tree;
  if !ok then Ok () else Error (Error.Invalid_tree "invalid unmerged_leaves")

let validate_tree c ~group_id ~cipher_suite ~extensions tree =
  let* () = Ratchet_tree.verify_parent_hashes c tree in
  let* () =
    List.fold_left
      (fun acc (i, ln) ->
        let* () = acc in
        validate_leaf_node c ~group_id ~cipher_suite ~tree ~extensions
          ~expected:For_any ~leaf_index:i ln)
      (Ok ()) (Ratchet_tree.leaves tree)
  in
  let* () = check_unmerged_leaves tree in
  check_tree_keys_unique tree

(* Group creation (Section 11) *)

let create ?(extensions = []) c ~rng ~group_id ~signature_key ~leaf_node
    ~leaf_key =
  let* () =
    if
      Crypto.signature_key_matches c ~key:signature_key
        ~public_key:leaf_node.Leaf_node.signature_key
    then Ok ()
    else Error (Error.Invalid_key "signature key does not match leaf node")
  in
  let* () =
    if
      String.equal
        (Hpke.Public_key.to_bytes (Hpke.Private_key.public_key leaf_key))
        leaf_node.Leaf_node.encryption_key
    then Ok ()
    else Error (Error.Invalid_key "encryption key does not match leaf node")
  in
  let tree =
    Ratchet_tree.set Ratchet_tree.empty 0 (Some (Node.Leaf leaf_node))
  in
  let* () =
    validate_tree c ~group_id ~cipher_suite:(Crypto.suite c) ~extensions tree
  in
  let context =
    {
      Group_context.version = Framing.protocol_version_mls10;
      cipher_suite = Crypto.suite c;
      group_id;
      epoch = 0L;
      tree_hash = Ratchet_tree.tree_hash c tree;
      confirmed_transcript_hash = "";
      extensions;
    }
  in
  let epoch_secret = Crypto.random ~rng (Crypto.hash_size c) in
  let* secrets = Key_schedule.from_epoch_secret c ~epoch_secret in
  let confirmation_tag =
    Key_schedule.confirmation_tag c
      ~confirmation_key:secrets.Key_schedule.confirmation_key
      ~confirmed_transcript_hash:""
  in
  let interim_transcript_hash =
    Transcript_hash.interim c ~confirmed_transcript_hash:"" ~confirmation_tag
  in
  Ok
    {
      crypto = c;
      context;
      tree;
      priv = Treekem.Private.create ~leaf_index:0 ~leaf_key;
      signature_key;
      secrets;
      secret_tree =
        Secret_tree.create c ~n_leaves:1
          ~encryption_secret:secrets.Key_schedule.encryption_secret;
      interim_transcript_hash;
      confirmation_tag;
      pending = String_map.empty;
      own_leaf_keys = [];
      resumption_psks = Int64_map.empty;
    }

(* Pre-shared keys *)

let resolve_psks ~lookup ~group_id ~current_epoch ~current_psk ~history ids =
  List.fold_right
    (fun (id : Psk.id) acc ->
      let* acc = acc in
      let secret =
        match id.Psk.key with
        | Psk.Resumption { psk_group_id; psk_epoch; _ }
          when String.equal psk_group_id group_id ->
            if Int64.equal psk_epoch current_epoch then Some current_psk
            else Int64_map.find_opt psk_epoch history
        | _ -> lookup id
      in
      match secret with
      | Some s -> Ok ((id, s) :: acc)
      | None ->
          Error (Error.Unknown_psk (Hex.encode (Tls.encode Psk.encode_id id))))
    ids (Ok [])

(* Joining via Welcome (Section 12.4.3.1) *)

let join ?(psks = no_external_psks) ?tree c ~(key_package : Key_package.t)
    ~init_key ~encryption_key ~signature_key (welcome : Welcome.t) =
  let fail msg = Error (Error.Invalid_welcome msg) in
  let suite = Crypto.suite c in
  let* () =
    if
      welcome.Welcome.cipher_suite <> suite
      || key_package.Key_package.cipher_suite <> suite
    then fail "cipher suite mismatch"
    else Ok ()
  in
  let kp_ref = Crypto.key_package_ref c (Key_package.to_bytes key_package) in
  let* egs =
    match
      List.find_opt
        (fun s -> String.equal s.Welcome.new_member kp_ref)
        welcome.Welcome.secrets
    with
    | Some s -> Ok s
    | None -> fail "no secrets for this key package"
  in
  let* gs_bytes =
    Crypto.decrypt_with_label c ~private_key:init_key ~label:welcome_label
      ~context:welcome.Welcome.encrypted_group_info
      ~kem_output:egs.Welcome.encrypted_group_secrets.Hpke_ciphertext.kem_output
      egs.Welcome.encrypted_group_secrets.Hpke_ciphertext.ciphertext
  in
  let* gs = Welcome.Group_secrets.of_bytes gs_bytes in
  let* psk_pairs =
    resolve_psks ~lookup:psks ~group_id:"" ~current_epoch:(-1L) ~current_psk:""
      ~history:Int64_map.empty gs.Welcome.Group_secrets.psks
  in
  let* psk_secret = Psk.psk_secret c psk_pairs in
  let joiner_secret = gs.Welcome.Group_secrets.joiner_secret in
  let* welcome_secret =
    Key_schedule.welcome_secret c ~joiner_secret ~psk_secret
  in
  let* key, nonce = Key_schedule.welcome_key_nonce c ~welcome_secret in
  let* gi_bytes =
    Crypto.aead_open c ~key ~nonce ~aad:"" welcome.Welcome.encrypted_group_info
  in
  let* gi = Error.of_decode (Tls.decode Group_info.decode gi_bytes) in
  let context = gi.Group_info.group_context in
  let* () =
    if
      context.Group_context.cipher_suite <> suite
      || context.Group_context.version <> Framing.protocol_version_mls10
    then fail "group info cipher suite or version mismatch"
    else Ok ()
  in
  let* tree =
    match tree with
    | Some t -> Ok t
    | None -> (
        let* ext = Group_extensions.ratchet_tree gi.Group_info.extensions in
        match ext with
        | Some t -> Ok t
        | None -> fail "no ratchet tree available")
  in
  let* signer =
    match Ratchet_tree.leaf tree gi.Group_info.signer with
    | Some ln -> Ok ln
    | None -> fail "signer leaf is blank"
  in
  let* () =
    if
      Crypto.verify_with_label c ~public_key:signer.Leaf_node.signature_key
        ~label:group_info_label ~signature:gi.Group_info.signature
        (Group_info.tbs gi)
    then Ok ()
    else fail "invalid group info signature"
  in
  let group_id = context.Group_context.group_id in
  let* () =
    if
      String.equal
        (Ratchet_tree.tree_hash c tree)
        context.Group_context.tree_hash
    then Ok ()
    else fail "tree hash mismatch"
  in
  let* () =
    validate_tree c ~group_id ~cipher_suite:suite
      ~extensions:context.Group_context.extensions tree
  in
  let my_leaf_bytes = Leaf_node.to_bytes key_package.Key_package.leaf_node in
  let* my_index =
    match
      Ratchet_tree.find_leaf tree (fun ln ->
          String.equal (Leaf_node.to_bytes ln) my_leaf_bytes)
    with
    | Some i -> Ok i
    | None -> fail "own leaf not found in tree"
  in
  let* () =
    if
      String.equal
        (Hpke.Public_key.to_bytes (Hpke.Private_key.public_key encryption_key))
        key_package.Key_package.leaf_node.Leaf_node.encryption_key
      && Crypto.signature_key_matches c ~key:signature_key
           ~public_key:key_package.Key_package.leaf_node.Leaf_node.signature_key
    then Ok ()
    else Error (Error.Invalid_key "private keys do not match the key package")
  in
  let priv =
    Treekem.Private.create ~leaf_index:my_index ~leaf_key:encryption_key
  in
  let* priv =
    match gs.Welcome.Group_secrets.path_secret with
    | None -> Ok priv
    | Some path_secret ->
        let n = Ratchet_tree.n_leaves tree in
        let ca =
          Tree_math.common_ancestor
            (Tree_math.node_of_leaf my_index)
            (Tree_math.node_of_leaf gi.Group_info.signer)
            n
        in
        Treekem.set_path_secret c priv tree ~node:ca ~path_secret
  in
  let* () = Treekem.Private.check_consistency priv tree in
  let context_bytes = Group_context.to_bytes context in
  let* secrets =
    Key_schedule.from_joiner_secret c ~joiner_secret ~psk_secret
      ~group_context:context_bytes
  in
  let confirmed_transcript_hash =
    context.Group_context.confirmed_transcript_hash
  in
  let confirmation_tag =
    Key_schedule.confirmation_tag c
      ~confirmation_key:secrets.Key_schedule.confirmation_key
      ~confirmed_transcript_hash
  in
  let* () =
    if Eqaf.equal confirmation_tag gi.Group_info.confirmation_tag then Ok ()
    else fail "confirmation tag mismatch"
  in
  let interim_transcript_hash =
    Transcript_hash.interim c ~confirmed_transcript_hash ~confirmation_tag
  in
  Ok
    {
      crypto = c;
      context;
      tree;
      priv;
      signature_key;
      secrets;
      secret_tree =
        Secret_tree.create c
          ~n_leaves:(Ratchet_tree.n_leaves tree)
          ~encryption_secret:secrets.Key_schedule.encryption_secret;
      interim_transcript_hash;
      confirmation_tag;
      pending = String_map.empty;
      own_leaf_keys = [];
      resumption_psks = Int64_map.empty;
    }

(* Proposal validation (Sections 12.1 and 12.2) *)

let fail_proposal msg = Error (Error.Invalid_proposal msg)

let validate_proposal t ~tree ~extensions ~sender (p : Proposal.t) =
  let c = t.crypto in
  let group_id = group_id t and cipher_suite = cipher_suite t in
  let* () =
    match (sender, p) with
    | ( Sender.External _,
        ( Proposal.Add _ | Proposal.Remove _ | Proposal.Pre_shared_key _
        | Proposal.Re_init _ | Proposal.Group_context_extensions _ ) ) ->
        Ok ()
    | Sender.External _, _ ->
        fail_proposal "proposal type not allowed from external senders"
    | Sender.New_member_proposal, Proposal.Add _ -> Ok ()
    | Sender.New_member_proposal, _ ->
        fail_proposal "new members may only propose Add"
    | ( Sender.New_member_commit,
        ( Proposal.External_init _ | Proposal.Remove _
        | Proposal.Pre_shared_key _ ) ) ->
        Ok ()
    | Sender.New_member_commit, _ ->
        fail_proposal "proposal type not allowed in external commits"
    | Sender.Member _, Proposal.External_init _ ->
        fail_proposal "ExternalInit is only valid in external commits"
    | Sender.Member _, _ -> Ok ()
  in
  match p with
  | Proposal.Add kp ->
      validate_key_package c ~group_id ~cipher_suite ~tree ~extensions kp
  | Proposal.Update ln -> (
      match sender with
      | Sender.Member i -> (
          match Ratchet_tree.leaf tree i with
          | None -> fail_proposal "update from a blank leaf"
          | Some old ->
              let* () =
                validate_leaf_node c ~group_id ~cipher_suite ~tree ~extensions
                  ~expected:For_update ~leaf_index:i ln
              in
              if
                String.equal old.Leaf_node.encryption_key
                  ln.Leaf_node.encryption_key
              then fail_proposal "update must change the encryption key"
              else Ok ())
      | _ -> fail_proposal "update from a non-member")
  | Proposal.Remove i ->
      if Ratchet_tree.leaf tree i = None then
        fail_proposal "removed leaf is blank"
      else Ok ()
  | Proposal.Pre_shared_key id -> (
      let* () =
        if String.length id.Psk.psk_nonce <> Crypto.hash_size c then
          fail_proposal "psk_nonce has the wrong length"
        else Ok ()
      in
      match id.Psk.key with
      | Psk.External _ | Psk.Resumption { usage = Psk.Application; _ } -> Ok ()
      | Psk.Resumption _ ->
          fail_proposal
            "reinit and branch PSKs are only valid during resumption")
  | Proposal.Re_init r ->
      if r.Proposal.version <> Framing.protocol_version_mls10 then
        fail_proposal "unsupported version in ReInit"
      else Ok ()
  | Proposal.External_init _ -> Ok ()
  | Proposal.Group_context_extensions exts -> (
      let* rc = Group_extensions.required_capabilities exts in
      match rc with
      | None -> Ok ()
      | Some rc ->
          if
            List.for_all
              (fun (_, (ln : Leaf_node.t)) ->
                check_required_capabilities rc ln.Leaf_node.capabilities)
              (Ratchet_tree.leaves tree)
          then Ok ()
          else
            fail_proposal "required capabilities not supported by all members")

let rec has_duplicates = function
  | [] -> false
  | x :: rest -> List.mem x rest || has_duplicates rest

let fail_commit msg = Error (Error.Invalid_commit msg)

let validate_proposal_list t ~committer ~is_external proposals =
  if is_external then
    let n_ei =
      List.length
        (List.filter
           (function Proposal.External_init _, _ -> true | _ -> false)
           proposals)
    in
    let n_rm =
      List.length
        (List.filter
           (function Proposal.Remove _, _ -> true | _ -> false)
           proposals)
    in
    let others =
      List.exists
        (function
          | ( ( Proposal.External_init _ | Proposal.Remove _
              | Proposal.Pre_shared_key _ ),
              _ ) ->
              false
          | _ -> true)
        proposals
    in
    if n_ei <> 1 || n_rm > 1 || others then
      fail_commit "invalid proposal list for external commit"
    else
      List.fold_left
        (fun acc (p, sender) ->
          let* () = acc in
          validate_proposal t ~tree:t.tree ~extensions:(extensions t) ~sender p)
        (Ok ()) proposals
  else
    let* () =
      List.fold_left
        (fun acc (p, sender) ->
          let* () = acc in
          validate_proposal t ~tree:t.tree ~extensions:(extensions t) ~sender p)
        (Ok ()) proposals
    in
    let* () =
      if
        List.exists
          (function Proposal.Update _, s -> s = committer | _ -> false)
          proposals
      then fail_commit "commit includes an update from the committer"
      else Ok ()
    in
    let removed =
      List.filter_map
        (function Proposal.Remove i, _ -> Some i | _ -> None)
        proposals
    in
    let* () =
      match committer with
      | Sender.Member i when List.mem i removed ->
          fail_commit "commit removes the committer"
      | _ -> Ok ()
    in
    let touched =
      List.filter_map
        (function
          | Proposal.Update _, Sender.Member i -> Some i
          | Proposal.Remove i, _ -> Some i
          | _ -> None)
        proposals
    in
    let* () =
      if has_duplicates touched then
        fail_commit "multiple updates or removes for the same leaf"
      else Ok ()
    in
    let added_keys =
      List.filter_map
        (function
          | Proposal.Add kp, _ ->
              Some kp.Key_package.leaf_node.Leaf_node.signature_key
          | _ -> None)
        proposals
    in
    let* () =
      if has_duplicates added_keys then
        fail_commit "multiple adds for the same client"
      else Ok ()
    in
    let* () =
      let existing =
        List.filter (fun (i, _) -> not (List.mem i removed)) (members t)
        |> List.map (fun (_, (ln : Leaf_node.t)) -> ln.Leaf_node.signature_key)
      in
      if List.exists (fun k -> List.mem k existing) added_keys then
        fail_commit "add of an existing member"
      else Ok ()
    in
    let psk_ids =
      List.filter_map
        (function
          | Proposal.Pre_shared_key id, _ -> Some (Tls.encode Psk.encode_id id)
          | _ -> None)
        proposals
    in
    let* () =
      if has_duplicates psk_ids then
        fail_commit "duplicate PreSharedKey proposals"
      else Ok ()
    in
    let n_gce =
      List.length
        (List.filter
           (function
             | Proposal.Group_context_extensions _, _ -> true | _ -> false)
           proposals)
    in
    let* () =
      if n_gce > 1 then fail_commit "multiple GroupContextExtensions proposals"
      else Ok ()
    in
    let n_reinit =
      List.length
        (List.filter
           (function Proposal.Re_init _, _ -> true | _ -> false)
           proposals)
    in
    let* () =
      if n_reinit > 0 && List.length proposals > 1 then
        fail_commit "ReInit must be the only proposal"
      else Ok ()
    in
    if
      List.exists
        (function Proposal.External_init _, _ -> true | _ -> false)
        proposals
    then fail_commit "ExternalInit in a regular commit"
    else Ok ()

(* Applying a proposal list (Section 12.3) *)

type applied = {
  tree : Ratchet_tree.t;
  extensions : Extension.t list;
  added : int list;
  removed : int list;
  psk_ids : Psk.id list;
  external_init : string option;
  reinit : Proposal.re_init option;
  updated_self : Leaf_node.t option;
}

let apply_proposals (t : t) proposals =
  let own = own_index t in
  let extensions =
    match
      List.find_map
        (function
          | Proposal.Group_context_extensions e, _ -> Some e | _ -> None)
        proposals
    with
    | Some e -> e
    | None -> extensions t
  in
  let tree, updated_self =
    List.fold_left
      (fun (tree, us) (p, sender) ->
        match (p, sender) with
        | Proposal.Update ln, Sender.Member i ->
            (Ratchet_tree.update_leaf tree i ln, if i = own then Some ln else us)
        | _ -> (tree, us))
      (t.tree, None) proposals
  in
  let removed =
    List.filter_map
      (function Proposal.Remove i, _ -> Some i | _ -> None)
      proposals
  in
  let tree = List.fold_left Ratchet_tree.remove_leaf tree removed in
  let tree, added =
    List.fold_left
      (fun (tree, added) (p, _) ->
        match p with
        | Proposal.Add kp ->
            let tree, i = Ratchet_tree.add_leaf tree kp.Key_package.leaf_node in
            (tree, i :: added)
        | _ -> (tree, added))
      (tree, []) proposals
  in
  {
    tree;
    extensions;
    added = List.rev added;
    removed;
    psk_ids =
      List.filter_map
        (function Proposal.Pre_shared_key id, _ -> Some id | _ -> None)
        proposals;
    external_init =
      List.find_map
        (function Proposal.External_init k, _ -> Some k | _ -> None)
        proposals;
    reinit =
      List.find_map
        (function Proposal.Re_init r, _ -> Some r | _ -> None)
        proposals;
    updated_self;
  }

let path_required proposals =
  proposals = []
  || List.exists
       (function
         | ( ( Proposal.Update _ | Proposal.Remove _ | Proposal.External_init _
             | Proposal.Group_context_extensions _ ),
             _ ) ->
             true
         | _ -> false)
       proposals

let resolve_proposals (t : t) ~committer ~is_external (commit : Commit.t) =
  List.fold_right
    (fun por acc ->
      let* acc = acc in
      match por with
      | Commit.Proposal p -> Ok ((p, committer) :: acc)
      | Commit.Reference r -> (
          if is_external then
            fail_commit "external commit references a proposal"
          else
            match String_map.find_opt r t.pending with
            | Some ps -> Ok (ps :: acc)
            | None -> fail_commit "unknown proposal reference"))
    commit.Commit.proposals (Ok [])

let external_init_secret c ~external_secret ~kem_output =
  let* private_key, _ = Crypto.derive_key_pair c ~ikm:external_secret in
  Crypto.hpke_export_receiver c ~private_key ~encapsulated_key:kem_output
    ~info:"" ~context:external_init_label ~length:(Crypto.hash_size c)

let remember_resumption_psk (t : t) =
  let m = Int64_map.add (epoch t) (resumption_psk t) t.resumption_psks in
  let cutoff = Int64.sub (epoch t) max_resumption_epochs in
  Int64_map.filter (fun e _ -> Int64.compare e cutoff >= 0) m

(* Finish an epoch transition once the new tree, private state, commit secret
   and provisional context are known. Shared by commit processing and commit
   creation. *)
let advance_epoch ~psks (t : t) ~(ac : Authenticated_content.t) ~tree ~priv
    ~commit_secret ~provisional ~psk_ids ~external_init ~confirmation_tag_check
    =
  let c = t.crypto in
  let* () = check_tree_keys_unique tree in
  let confirmed_transcript_hash =
    Transcript_hash.confirmed c
      ~interim_transcript_hash:t.interim_transcript_hash ac
  in
  let context = { provisional with Group_context.confirmed_transcript_hash } in
  let context_bytes = Group_context.to_bytes context in
  let* psk_pairs =
    resolve_psks ~lookup:psks ~group_id:(group_id t) ~current_epoch:(epoch t)
      ~current_psk:(resumption_psk t) ~history:t.resumption_psks psk_ids
  in
  let* psk_secret = Psk.psk_secret c psk_pairs in
  let* init_secret =
    match external_init with
    | None -> Ok t.secrets.Key_schedule.init_secret
    | Some kem_output ->
        external_init_secret c
          ~external_secret:t.secrets.Key_schedule.external_secret ~kem_output
  in
  let* secrets =
    Key_schedule.derive c ~init_secret ~commit_secret ~psk_secret
      ~group_context:context_bytes
  in
  let confirmation_tag =
    Key_schedule.confirmation_tag c
      ~confirmation_key:secrets.Key_schedule.confirmation_key
      ~confirmed_transcript_hash
  in
  let* () = confirmation_tag_check confirmation_tag in
  let interim_transcript_hash =
    Transcript_hash.interim c ~confirmed_transcript_hash ~confirmation_tag
  in
  Ok
    ( {
        t with
        context;
        tree;
        priv;
        secrets;
        secret_tree =
          Secret_tree.create c
            ~n_leaves:(Ratchet_tree.n_leaves tree)
            ~encryption_secret:secrets.Key_schedule.encryption_secret;
        interim_transcript_hash;
        confirmation_tag;
        pending = String_map.empty;
        own_leaf_keys = [];
        resumption_psks = remember_resumption_psk t;
      },
      psk_pairs )

let apply_commit ~psks (t : t) (ac : Authenticated_content.t)
    (commit : Commit.t) =
  let c = t.crypto in
  let committer = ac.Authenticated_content.content.Framed_content.sender in
  let is_external = committer = Sender.New_member_commit in
  let* () =
    match committer with
    | Sender.Member _ | Sender.New_member_commit -> Ok ()
    | _ -> fail_commit "commits must be sent by members or new members"
  in
  let* proposals = resolve_proposals t ~committer ~is_external commit in
  let* () = validate_proposal_list t ~committer ~is_external proposals in
  let* () =
    if (path_required proposals || is_external) && commit.Commit.path = None
    then fail_commit "path required"
    else Ok ()
  in
  let applied = apply_proposals t proposals in
  let own = own_index t in
  if List.mem own applied.removed then
    Ok
      ( Commit_applied
          { removed_self = true; committer = None; reinit = applied.reinit },
        t )
  else
    let* priv =
      match applied.updated_self with
      | None -> Ok t.priv
      | Some ln -> (
          match
            List.find_opt
              (fun k ->
                String.equal
                  (Hpke.Public_key.to_bytes (Hpke.Private_key.public_key k))
                  ln.Leaf_node.encryption_key)
              t.own_leaf_keys
          with
          | Some k -> Ok (Treekem.Private.create ~leaf_index:own ~leaf_key:k)
          | None ->
              Error (Error.Internal "no private key for own update proposal"))
    in
    let priv = Treekem.Private.prune priv applied.tree in
    let provisional =
      {
        t.context with
        Group_context.epoch = Int64.succ (epoch t);
        extensions = applied.extensions;
      }
    in
    let* tree, priv, commit_secret, provisional, sender_index =
      match commit.Commit.path with
      | None ->
          let sender_index =
            match committer with Sender.Member i -> i | _ -> -1
          in
          Ok
            ( applied.tree,
              priv,
              Crypto.zeros c,
              {
                provisional with
                Group_context.tree_hash = Ratchet_tree.tree_hash c applied.tree;
              },
              sender_index )
      | Some path ->
          let* tree, sender_index =
            match committer with
            | Sender.Member i -> Ok (applied.tree, i)
            | _ ->
                Ok
                  (Ratchet_tree.add_leaf applied.tree path.Update_path.leaf_node)
          in
          let* () =
            validate_leaf_node c ~group_id:(group_id t)
              ~cipher_suite:(cipher_suite t) ~tree
              ~extensions:applied.extensions ~expected:For_commit
              ~leaf_index:sender_index path.Update_path.leaf_node
          in
          let* () =
            match committer with
            | Sender.Member i -> (
                match Ratchet_tree.leaf t.tree i with
                | Some old
                  when String.equal old.Leaf_node.encryption_key
                         path.Update_path.leaf_node.Leaf_node.encryption_key ->
                    fail_commit "committer's encryption key is unchanged"
                | _ -> Ok ())
            | _ -> Ok ()
          in
          let path_keys =
            List.map
              (fun (n : Update_path.node) -> n.Update_path.encryption_key)
              path.Update_path.nodes
          in
          let* () =
            if
              Array.exists
                (function
                  | Some nd -> List.mem (Node.encryption_key nd) path_keys
                  | None -> false)
                (Ratchet_tree.nodes tree)
            then fail_commit "update path key already present in the tree"
            else Ok ()
          in
          let* r =
            Treekem.process_update_path ~exclude:applied.added c ~tree ~priv
              ~sender:sender_index ~path ~group_context:provisional ()
          in
          Ok
            ( r.Treekem.tree,
              r.Treekem.priv,
              r.Treekem.commit_secret,
              r.Treekem.group_context,
              sender_index )
    in
    let confirmation_tag_check tag =
      match ac.Authenticated_content.auth.Auth_data.confirmation_tag with
      | Some given when Eqaf.equal given tag -> Ok ()
      | Some _ -> fail_commit "confirmation tag mismatch"
      | None -> fail_commit "missing confirmation tag"
    in
    let* t, _ =
      advance_epoch ~psks t ~ac ~tree ~priv ~commit_secret ~provisional
        ~psk_ids:applied.psk_ids ~external_init:applied.external_init
        ~confirmation_tag_check
    in
    Ok
      ( Commit_applied
          {
            removed_self = false;
            committer = Some sender_index;
            reinit = applied.reinit;
          },
        t )

(* Receiving messages *)

let check_group_and_epoch (t : t) ~group_id ~epoch =
  if not (String.equal group_id Group_context.(t.context.group_id)) then
    Error (Error.Wrong_group (Hex.encode group_id))
  else if not (Int64.equal epoch Group_context.(t.context.epoch)) then
    Error
      (Error.Wrong_epoch
         { expected = Group_context.(t.context.epoch); actual = epoch })
  else Ok ()

let unprotect (t : t) (msg : Mls_message.t) =
  let c = t.crypto in
  match msg with
  | Mls_message.Public_message pm ->
      let content = pm.Public_message.content in
      let* () =
        check_group_and_epoch t ~group_id:content.Framed_content.group_id
          ~epoch:content.Framed_content.epoch
      in
      let* ac =
        Message_protection.unprotect_public c
          ~membership_key:(Some t.secrets.Key_schedule.membership_key)
          ~group_context:t.context pm
      in
      Ok (ac, t)
  | Mls_message.Private_message pm ->
      let* () =
        check_group_and_epoch t ~group_id:pm.Private_message.group_id
          ~epoch:pm.Private_message.epoch
      in
      let* ac, secret_tree =
        Message_protection.unprotect_private ~own_leaf:(own_index t) c
          ~secret_tree:t.secret_tree
          ~sender_data_secret:t.secrets.Key_schedule.sender_data_secret pm
      in
      Ok (ac, { t with secret_tree })
  | _ ->
      Error (Error.Invalid_message "expected a PublicMessage or PrivateMessage")

let sender_signature_key (t : t) (ac : Authenticated_content.t) =
  let content = ac.Authenticated_content.content in
  match content.Framed_content.sender with
  | Sender.Member i -> (
      match Ratchet_tree.leaf t.tree i with
      | Some ln -> Ok ln.Leaf_node.signature_key
      | None -> Error (Error.Invalid_message "sender leaf is blank"))
  | Sender.External i -> (
      let* senders = Group_extensions.external_senders (extensions t) in
      match List.nth_opt senders i with
      | Some es -> Ok es.Group_extensions.signature_key
      | None -> Error (Error.Invalid_message "unknown external sender"))
  | Sender.New_member_proposal -> (
      match content.Framed_content.content with
      | Content.Proposal (Proposal.Add kp) ->
          Ok kp.Key_package.leaf_node.Leaf_node.signature_key
      | _ ->
          Error (Error.Invalid_message "new_member_proposal must carry an Add"))
  | Sender.New_member_commit -> (
      match content.Framed_content.content with
      | Content.Commit { Commit.path = Some p; _ } ->
          Ok p.Update_path.leaf_node.Leaf_node.signature_key
      | _ -> Error (Error.Invalid_message "external commit requires a path"))

let proposal_reference (t : t) (ac : Authenticated_content.t) =
  Crypto.proposal_ref t.crypto (Tls.encode Authenticated_content.encode ac)

let process ?(psks = no_external_psks) (t : t) msg =
  let* ac, t = unprotect t msg in
  let* public_key = sender_signature_key t ac in
  let* () =
    Message_protection.verify_signature t.crypto ~public_key
      ~group_context:(Some t.context) ac
  in
  let content = ac.Authenticated_content.content in
  match content.Framed_content.content with
  | Content.Application data -> (
      match content.Framed_content.sender with
      | Sender.Member sender ->
          Ok
            ( Application_received
                {
                  data;
                  sender;
                  authenticated_data = content.Framed_content.authenticated_data;
                },
              t )
      | _ -> Error (Error.Invalid_message "application data from a non-member"))
  | Content.Proposal proposal ->
      let sender = content.Framed_content.sender in
      let* () =
        validate_proposal t ~tree:t.tree ~extensions:(extensions t) ~sender
          proposal
      in
      let reference = proposal_reference t ac in
      Ok
        ( Proposal_received { proposal; sender; reference },
          {
            t with
            pending = String_map.add reference (proposal, sender) t.pending;
          } )
  | Content.Commit commit -> apply_commit ~psks t ac commit

(* Sending messages *)

type wire = Public | Private

let wire_format_of = function
  | Public -> Framing.wire_format_public_message
  | Private -> Framing.wire_format_private_message

let frame (t : t) ~authenticated_data content =
  {
    Framed_content.group_id = group_id t;
    epoch = epoch t;
    sender = Sender.Member (own_index t);
    authenticated_data;
    content;
  }

let sign_content (t : t) ~wire ~confirmation_tag framed =
  Message_protection.sign t.crypto ~key:t.signature_key
    ~wire_format:(wire_format_of wire) ~group_context:(Some t.context)
    ~confirmation_tag framed

let protect_content (t : t) ~rng ~wire ~padding (ac : Authenticated_content.t) =
  match wire with
  | Public ->
      let* pm =
        Message_protection.protect_public t.crypto
          ~membership_key:t.secrets.Key_schedule.membership_key
          ~group_context:t.context ac
      in
      Ok (Mls_message.Public_message pm, t)
  | Private ->
      let* pm, secret_tree =
        Message_protection.protect_private t.crypto ~rng
          ~secret_tree:t.secret_tree
          ~sender_data_secret:t.secrets.Key_schedule.sender_data_secret ~padding
          ac
      in
      Ok (Mls_message.Private_message pm, { t with secret_tree })

let propose ?(authenticated_data = "") ?(wire = Public) (t : t) ~rng proposal =
  let sender = Sender.Member (own_index t) in
  let* () =
    validate_proposal t ~tree:t.tree ~extensions:(extensions t) ~sender proposal
  in
  let ac =
    sign_content t ~wire ~confirmation_tag:None
      (frame t ~authenticated_data (Content.Proposal proposal))
  in
  let* msg, t = protect_content t ~rng ~wire ~padding:0 ac in
  let reference = proposal_reference t ac in
  Ok
    ( msg,
      { t with pending = String_map.add reference (proposal, sender) t.pending }
    )

let propose_add ?authenticated_data ?wire t ~rng key_package =
  propose ?authenticated_data ?wire t ~rng (Proposal.Add key_package)

let propose_remove ?authenticated_data ?wire t ~rng leaf_index =
  propose ?authenticated_data ?wire t ~rng (Proposal.Remove leaf_index)

let propose_psk ?authenticated_data ?wire t ~rng psk_id =
  propose ?authenticated_data ?wire t ~rng (Proposal.Pre_shared_key psk_id)

let propose_group_context_extensions ?authenticated_data ?wire t ~rng exts =
  propose ?authenticated_data ?wire t ~rng
    (Proposal.Group_context_extensions exts)

(* A fresh PreSharedKeyID for an external PSK. *)
let external_psk_id (t : t) ~rng psk_id =
  {
    Psk.key = Psk.External psk_id;
    psk_nonce = Crypto.random ~rng (Crypto.hash_size t.crypto);
  }

let resumption_psk_id ?(usage = Psk.Application) (t : t) ~rng ~group_id ~epoch =
  {
    Psk.key =
      Psk.Resumption { usage; psk_group_id = group_id; psk_epoch = epoch };
    psk_nonce = Crypto.random ~rng (Crypto.hash_size t.crypto);
  }

(* Propose replacing our own leaf node with fresh keys. [update_leaf] may change
   other leaf contents such as capabilities or extensions. *)
let propose_update ?authenticated_data ?wire ?(update_leaf = fun ln -> ln)
    (t : t) ~rng =
  let own = own_index t in
  let* old =
    match own_leaf t with
    | Some ln -> Ok ln
    | None -> Error (Error.Internal "own leaf is blank")
  in
  let* leaf_key, leaf_pub = Crypto.generate_key_pair t.crypto ~rng in
  let ln =
    update_leaf
      {
        old with
        Leaf_node.encryption_key = Hpke.Public_key.to_bytes leaf_pub;
        leaf_node_source = Leaf_node.Update;
      }
  in
  let ln =
    Leaf_node.sign t.crypto ~key:t.signature_key ~group_id:(group_id t)
      ~leaf_index:own ln
  in
  let t = { t with own_leaf_keys = leaf_key :: t.own_leaf_keys } in
  propose ?authenticated_data ?wire t ~rng (Proposal.Update ln)

let make_group_info (t : t) ~extensions =
  let gi =
    {
      Group_info.group_context = t.context;
      extensions;
      confirmation_tag = t.confirmation_tag;
      signer = own_index t;
      signature = "";
    }
  in
  {
    gi with
    Group_info.signature =
      Crypto.sign_with_label t.crypto ~key:t.signature_key
        ~label:group_info_label (Group_info.tbs gi);
  }

(* A signed GroupInfo for the current epoch, by default carrying the ratchet
   tree and the external public key so that it can be used for external
   joins. *)
let group_info ?(with_tree = true) ?(with_external_pub = true)
    ?(extensions = []) (t : t) =
  let* ext_pub =
    if with_external_pub then
      let* _, pub =
        Key_schedule.external_key_pair t.crypto
          ~external_secret:t.secrets.Key_schedule.external_secret
      in
      Ok [ Group_extensions.make_external_pub (Hpke.Public_key.to_bytes pub) ]
    else Ok []
  in
  let tree_ext =
    if with_tree then [ Group_extensions.make_ratchet_tree t.tree ] else []
  in
  Ok (make_group_info t ~extensions:(tree_ext @ ext_pub @ extensions))

type commit_result = {
  commit : Mls_message.t;
  welcome : Mls_message.t option;
  group_info : Group_info.t;
  state : t;
}

let make_welcome (t : t) ~rng ~group_info ~added ~psk_ids =
  let c = t.crypto in
  let* encrypted_group_info =
    let* key, nonce =
      Key_schedule.welcome_key_nonce c
        ~welcome_secret:t.secrets.Key_schedule.welcome_secret
    in
    Crypto.aead_seal c ~key ~nonce ~aad:"" (Group_info.to_bytes group_info)
  in
  let* secrets =
    List.fold_right
      (fun ((kp : Key_package.t), path_secret) acc ->
        let* acc = acc in
        let gs =
          {
            Welcome.Group_secrets.joiner_secret =
              t.secrets.Key_schedule.joiner_secret;
            path_secret;
            psks = psk_ids;
          }
        in
        let* kem_output, ciphertext =
          Crypto.encrypt_with_label c ~rng ~public_key:kp.Key_package.init_key
            ~label:welcome_label ~context:encrypted_group_info
            (Welcome.Group_secrets.to_bytes gs)
        in
        Ok
          ({
             Welcome.new_member =
               Crypto.key_package_ref c (Key_package.to_bytes kp);
             encrypted_group_secrets =
               { Hpke_ciphertext.kem_output; ciphertext };
           }
          :: acc))
      added (Ok [])
  in
  Ok
    (Mls_message.Welcome
       { Welcome.cipher_suite = cipher_suite t; secrets; encrypted_group_info })

(* Create a Commit covering all pending proposals (by reference) and [inline]
   proposals (by value), and a Welcome for any added members. The returned state
   is the committer's view of the new epoch; the caller should only adopt it
   once the Delivery Service has accepted the Commit. *)
let commit ?(authenticated_data = "") ?(wire = Public) ?(inline = [])
    ?references ?(force_path = false) ?(psks = no_external_psks)
    ?(welcome_with_tree = true) ?(group_info_extensions = []) (t : t) ~rng =
  let c = t.crypto in
  let own = own_index t in
  let committer = Sender.Member own in
  let* refs =
    match references with
    | None ->
        Ok
          (String_map.bindings t.pending
          |> List.filter (fun (_, (p, s)) ->
              match p with Proposal.Update _ -> s <> committer | _ -> true))
    | Some rs ->
        List.fold_right
          (fun r acc ->
            let* acc = acc in
            match String_map.find_opt r t.pending with
            | Some ps -> Ok ((r, ps) :: acc)
            | None -> fail_commit "unknown proposal reference")
          rs (Ok [])
  in
  let proposals =
    List.map snd refs @ List.map (fun p -> (p, committer)) inline
  in
  let* () = validate_proposal_list t ~committer ~is_external:false proposals in
  let applied = apply_proposals t proposals in
  let priv = Treekem.Private.prune t.priv applied.tree in
  let provisional =
    {
      t.context with
      Group_context.epoch = Int64.succ (epoch t);
      extensions = applied.extensions;
    }
  in
  let* tree, priv, commit_secret, provisional, path, created =
    if force_path || path_required proposals then
      let* r =
        Treekem.create_update_path ~exclude:applied.added c ~rng
          ~tree:applied.tree ~priv ~signature_key:t.signature_key
          ~group_context:provisional ()
      in
      Ok
        ( r.Treekem.tree,
          r.Treekem.priv,
          r.Treekem.commit_secret,
          r.Treekem.group_context,
          Some r.Treekem.update_path,
          Some r )
    else
      Ok
        ( applied.tree,
          priv,
          Crypto.zeros c,
          {
            provisional with
            Group_context.tree_hash = Ratchet_tree.tree_hash c applied.tree;
          },
          None,
          None )
  in
  let commit =
    {
      Commit.proposals =
        List.map (fun (r, _) -> Commit.Reference r) refs
        @ List.map (fun p -> Commit.Proposal p) inline;
      path;
    }
  in
  let ac =
    sign_content t ~wire ~confirmation_tag:(Some "")
      (frame t ~authenticated_data (Content.Commit commit))
  in
  let* state, _ =
    advance_epoch ~psks t ~ac ~tree ~priv ~commit_secret ~provisional
      ~psk_ids:applied.psk_ids ~external_init:None
      ~confirmation_tag_check:(fun _ -> Ok ())
  in
  let ac =
    {
      ac with
      Authenticated_content.auth =
        {
          ac.Authenticated_content.auth with
          Auth_data.confirmation_tag = Some state.confirmation_tag;
        };
    }
  in
  let* commit_msg, _ = protect_content t ~rng ~wire ~padding:0 ac in
  let* ext_pub =
    let* _, pub =
      Key_schedule.external_key_pair c
        ~external_secret:state.secrets.Key_schedule.external_secret
    in
    Ok (Group_extensions.make_external_pub (Hpke.Public_key.to_bytes pub))
  in
  let gi_exts =
    (if welcome_with_tree then [ Group_extensions.make_ratchet_tree state.tree ]
     else [])
    @ [ ext_pub ] @ group_info_extensions
  in
  let group_info = make_group_info state ~extensions:gi_exts in
  let* welcome =
    if applied.added = [] then Ok None
    else
      let kps =
        List.filter_map
          (function Proposal.Add kp, _ -> Some kp | _ -> None)
          proposals
      in
      let added =
        List.map2
          (fun kp i ->
            let path_secret =
              match created with
              | Some r ->
                  Option.map snd (Treekem.path_secret_for_joiner r ~joiner:i)
              | None -> None
            in
            (kp, path_secret))
          kps applied.added
      in
      let* w =
        make_welcome state ~rng ~group_info ~added ~psk_ids:applied.psk_ids
      in
      Ok (Some w)
  in
  Ok { commit = commit_msg; welcome; group_info; state }

(* Encrypt application data as a PrivateMessage. *)
let encrypt_application ?(authenticated_data = "") ?(padding = 0) (t : t) ~rng
    data =
  if not (String_map.is_empty t.pending) then
    Error
      (Error.Invalid_message
         "pending proposals must be committed before sending application data")
  else
    let ac =
      sign_content t ~wire:Private ~confirmation_tag:None
        (frame t ~authenticated_data (Content.Application data))
    in
    protect_content t ~rng ~wire:Private ~padding ac

(* Joining via an external Commit (Section 12.4.3.2). [leaf_node] provides the
   joiner's credential, capabilities and extensions; its keys are replaced.
   [remove_old] removes a previous appearance of the joiner. *)
let external_join ?(psks = no_external_psks) ?(authenticated_data = "") ?tree
    ?remove_old ?(psk_ids = []) c ~rng ~(group_info : Group_info.t)
    ~signature_key ~(leaf_node : Leaf_node.t) =
  let fail msg = Error (Error.Invalid_group_info msg) in
  let context = group_info.Group_info.group_context in
  let suite = Crypto.suite c in
  let* () =
    if
      context.Group_context.cipher_suite <> suite
      || context.Group_context.version <> Framing.protocol_version_mls10
    then fail "cipher suite or version mismatch"
    else Ok ()
  in
  let* tree =
    match tree with
    | Some t -> Ok t
    | None -> (
        let* ext =
          Group_extensions.ratchet_tree group_info.Group_info.extensions
        in
        match ext with
        | Some t -> Ok t
        | None -> fail "no ratchet tree available")
  in
  let* signer =
    match Ratchet_tree.leaf tree group_info.Group_info.signer with
    | Some ln -> Ok ln
    | None -> fail "signer leaf is blank"
  in
  let* () =
    if
      Crypto.verify_with_label c ~public_key:signer.Leaf_node.signature_key
        ~label:group_info_label ~signature:group_info.Group_info.signature
        (Group_info.tbs group_info)
    then Ok ()
    else fail "invalid signature"
  in
  let group_id = context.Group_context.group_id in
  let* () =
    if
      String.equal
        (Ratchet_tree.tree_hash c tree)
        context.Group_context.tree_hash
    then Ok ()
    else fail "tree hash mismatch"
  in
  let* () =
    validate_tree c ~group_id ~cipher_suite:suite
      ~extensions:context.Group_context.extensions tree
  in
  let* external_pub =
    let* ext = Group_extensions.external_pub group_info.Group_info.extensions in
    match ext with
    | Some pub -> Ok pub
    | None -> fail "no external_pub extension"
  in
  let* kem_output, init_secret =
    Crypto.hpke_export_sender c ~rng ~public_key:external_pub ~info:""
      ~context:external_init_label ~length:(Crypto.hash_size c)
  in
  let* () =
    if
      Crypto.signature_key_matches c ~key:signature_key
        ~public_key:leaf_node.Leaf_node.signature_key
    then Ok ()
    else Error (Error.Invalid_key "signature key does not match leaf node")
  in
  let removes =
    match remove_old with Some i -> [ Proposal.Remove i ] | None -> []
  in
  let* () =
    match remove_old with
    | Some i when Ratchet_tree.leaf tree i = None ->
        fail "removed leaf is blank"
    | _ -> Ok ()
  in
  let proposals =
    (Proposal.External_init kem_output :: removes)
    @ List.map (fun id -> Proposal.Pre_shared_key id) psk_ids
  in
  let tree_after =
    List.fold_left Ratchet_tree.remove_leaf tree
      (match remove_old with Some i -> [ i ] | None -> [])
  in
  let* placeholder_key, _ = Crypto.generate_key_pair c ~rng in
  let tree_after, my_index = Ratchet_tree.add_leaf tree_after leaf_node in
  let provisional =
    {
      context with
      Group_context.epoch = Int64.succ context.Group_context.epoch;
    }
  in
  let* r =
    Treekem.create_update_path c ~rng ~tree:tree_after
      ~priv:
        (Treekem.Private.create ~leaf_index:my_index ~leaf_key:placeholder_key)
      ~signature_key ~group_context:provisional ()
  in
  let commit =
    {
      Commit.proposals = List.map (fun p -> Commit.Proposal p) proposals;
      path = Some r.Treekem.update_path;
    }
  in
  let framed =
    {
      Framed_content.group_id;
      epoch = context.Group_context.epoch;
      sender = Sender.New_member_commit;
      authenticated_data;
      content = Content.Commit commit;
    }
  in
  let ac =
    Message_protection.sign c ~key:signature_key
      ~wire_format:Framing.wire_format_public_message
      ~group_context:(Some context) ~confirmation_tag:(Some "") framed
  in
  let interim =
    Transcript_hash.interim c
      ~confirmed_transcript_hash:context.Group_context.confirmed_transcript_hash
      ~confirmation_tag:group_info.Group_info.confirmation_tag
  in
  let confirmed_transcript_hash =
    Transcript_hash.confirmed c ~interim_transcript_hash:interim ac
  in
  let new_context =
    { r.Treekem.group_context with Group_context.confirmed_transcript_hash }
  in
  let* psk_pairs =
    resolve_psks ~lookup:psks ~group_id:"" ~current_epoch:(-1L) ~current_psk:""
      ~history:Int64_map.empty psk_ids
  in
  let* psk_secret = Psk.psk_secret c psk_pairs in
  let* secrets =
    Key_schedule.derive c ~init_secret ~commit_secret:r.Treekem.commit_secret
      ~psk_secret
      ~group_context:(Group_context.to_bytes new_context)
  in
  let confirmation_tag =
    Key_schedule.confirmation_tag c
      ~confirmation_key:secrets.Key_schedule.confirmation_key
      ~confirmed_transcript_hash
  in
  let ac =
    {
      ac with
      Authenticated_content.auth =
        {
          ac.Authenticated_content.auth with
          Auth_data.confirmation_tag = Some confirmation_tag;
        };
    }
  in
  let* pm =
    Message_protection.protect_public c ~membership_key:""
      ~group_context:context ac
  in
  let* () = check_tree_keys_unique r.Treekem.tree in
  Ok
    ( Mls_message.Public_message pm,
      {
        crypto = c;
        context = new_context;
        tree = r.Treekem.tree;
        priv = r.Treekem.priv;
        signature_key;
        secrets;
        secret_tree =
          Secret_tree.create c
            ~n_leaves:(Ratchet_tree.n_leaves r.Treekem.tree)
            ~encryption_secret:secrets.Key_schedule.encryption_secret;
        interim_transcript_hash =
          Transcript_hash.interim c ~confirmed_transcript_hash ~confirmation_tag;
        confirmation_tag;
        pending = String_map.empty;
        own_leaf_keys = [];
        resumption_psks = Int64_map.empty;
      } )
