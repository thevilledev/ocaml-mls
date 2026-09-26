(* An MLS interop client: a gRPC server implementing the MLSClient service of
   the mlswg/mls-implementations test harness (interop/proto/mls_client.proto)
   on top of the mls library. The test runner drives it over plaintext HTTP/2.

   Every identifier the runner sees (state, transaction, reinit and signer ids)
   comes from one counter, so that StorePSK can be given either kind. *)

open Mls
module G = Group

let rng =
  lazy
    (Mirage_crypto_rng_unix.use_default ();
     Mirage_crypto_rng.default_generator ())

let rng () = Lazy.force rng
let ok = function Ok v -> v | Error e -> failwith (Error.to_string e)

(* Retain two past epochs so that application messages sent before a Commit
   can still be read after it. *)
let policy = Policy.make ~max_past_epochs:2 ()

(* Tables *)

type state = {
  mutable group : G.t;
  encrypt : bool;
  identity : string;
  mutable pending : G.commit_result option;
  sent : (string, string) Hashtbl.t;
      (* Proposal messages this state sent, to their references: a member
         cannot decrypt its own PrivateMessages when they come back. *)
}

type transaction = {
  crypto : Crypto.t;
  signature_key : Crypto.signature_key;
  generated : Key_package.generated;
}

type reinit = {
  old : state;
  next : transaction;  (** The member's KeyPackage in the new cipher suite. *)
}

type signer = { signer_crypto : Crypto.t; signer_key : Crypto.signature_key }

let next_id = ref 0

let fresh_id () =
  incr next_id;
  !next_id

let states : (int, state) Hashtbl.t = Hashtbl.create 64
let transactions : (int, transaction) Hashtbl.t = Hashtbl.create 64
let reinits : (int, reinit) Hashtbl.t = Hashtbl.create 16
let signers : (int, signer) Hashtbl.t = Hashtbl.create 16
let psks : (string, string) Hashtbl.t = Hashtbl.create 16

let find table what id =
  match Hashtbl.find_opt table id with
  | Some v -> v
  | None -> failwith (Printf.sprintf "unknown %s %d" what id)

let add_state ?(encrypt = false) ?(identity = "") group =
  let id = fresh_id () in
  Hashtbl.replace states id
    { group; encrypt; identity; pending = None; sent = Hashtbl.create 8 };
  id

let psk_lookup (id : Psk.id) =
  match id.Psk.key with
  | Psk.External psk_id -> Hashtbl.find_opt psks psk_id
  | Psk.Resumption _ -> None

(* Wire formats *)

let message bytes = ok (Mls_message.of_bytes bytes)

let key_package_of_bytes bytes =
  match Mls_message.of_bytes bytes with
  | Ok (Mls_message.Key_package kp) -> kp
  | _ -> ok (Key_package.of_bytes bytes)

let welcome_of_bytes bytes =
  match message bytes with
  | Mls_message.Welcome w -> w
  | _ -> failwith "expected a Welcome"

let group_info_of_bytes bytes =
  match Mls_message.of_bytes bytes with
  | Ok (Mls_message.Group_info gi) -> gi
  | _ -> ok (Error.of_decode (Tls.decode Group_info.decode bytes))

let tree_of_bytes = function
  | "" -> None
  | bytes -> Some (ok (Ratchet_tree.of_bytes bytes))

let tree_bytes ~external_tree tree =
  if external_tree then Ratchet_tree.to_bytes tree else ""

let extensions_of fields n =
  List.map
    (fun f ->
      {
        Extension.extension_type = Pb.int f 1;
        extension_data = Pb.bytes f 2;
      })
    (Pb.repeated_messages fields n)

let wire st = if st.encrypt then G.Private else G.Public
let epoch_authenticator st = G.epoch_authenticator st.group

let new_transaction ?signature_key c identity =
  let signature_key =
    match signature_key with
    | Some k -> k
    | None -> Crypto.generate_signature_key c ~rng:(rng ())
  in
  let generated =
    ok
      (Key_package.generate c ~rng:(rng ()) ~signature_key
         ~credential:(Credential.Basic identity))
  in
  { crypto = c; signature_key; generated }

let key_package_bytes tx =
  Mls_message.to_bytes (Mls_message.Key_package tx.generated.key_package)

let leaf_of_identity tree identity =
  match
    Ratchet_tree.find_leaf tree (fun ln ->
        ln.Leaf_node.credential = Credential.Basic identity)
  with
  | Some i -> i
  | None -> failwith ("no member " ^ identity)

(* A proposal described by a ProposalDescription, in a group with the given
   cipher suite, tree and ID. *)
let proposal_of_description ~c ~tree ~group_id d =
  let nonce () = Crypto.random ~rng:(rng ()) (Crypto.hash_size c) in
  match Pb.bytes d 1 with
  | "add" -> Proposal.Add (key_package_of_bytes (Pb.bytes d 2))
  | "remove" -> Proposal.Remove (leaf_of_identity tree (Pb.bytes d 3))
  | "externalPSK" ->
      Proposal.Pre_shared_key
        { Psk.key = Psk.External (Pb.bytes d 4); psk_nonce = nonce () }
  | "resumptionPSK" ->
      Proposal.Pre_shared_key
        {
          Psk.key =
            Psk.Resumption
              {
                usage = Psk.Application;
                psk_group_id = group_id;
                psk_epoch = Int64.of_int (Pb.int d 5);
              };
          psk_nonce = nonce ();
        }
  | "groupContextExtensions" ->
      Proposal.Group_context_extensions (extensions_of d 6)
  | "reinit" ->
      Proposal.Re_init
        {
          Proposal.group_id = Pb.bytes d 7;
          version = Framing.protocol_version_mls10;
          cipher_suite = Pb.int d 8;
          extensions = extensions_of d 6;
        }
  | other -> failwith ("unknown proposal type " ^ other)

(* Proposals *)

(* Send a proposal from [st] and remember its reference. *)
let propose st send =
  let before = List.map fst (G.pending_proposals st.group) in
  let msg, group = ok (send st.group) in
  let reference =
    match
      List.find_opt
        (fun (r, _) -> not (List.mem r before))
        (G.pending_proposals group)
    with
    | Some (r, _) -> r
    | None -> failwith "proposal already pending"
  in
  let bytes = Mls_message.to_bytes msg in
  st.group <- group;
  Hashtbl.replace st.sent bytes reference;
  Pb.encode (fun b -> Pb.Writer.bytes b 1 bytes)

let propose_value st proposal =
  propose st (fun g -> G.propose ~wire:(wire st) g ~rng:(rng ()) proposal)

(* The reference of a proposal message, processing it unless [st] sent it. *)
let reference_of st bytes =
  match Hashtbl.find_opt st.sent bytes with
  | Some r -> r
  | None -> (
      match ok (G.process ~psks:psk_lookup st.group (message bytes)) with
      | G.Proposal_received { reference; _ }, group ->
          st.group <- group;
          reference
      | _ -> failwith "expected a proposal")

(* Commits *)

let commit_response ~external_tree (r : G.commit_result) =
  Pb.encode (fun b ->
      Pb.Writer.bytes b 1 (Mls_message.to_bytes r.commit);
      Pb.Writer.bytes b 2
        (match r.welcome with Some w -> Mls_message.to_bytes w | None -> "");
      Pb.Writer.bytes b 3 (tree_bytes ~external_tree (G.tree r.state)))

let commit req =
  let st = find states "state" (Pb.int req 1) in
  let references = List.map (reference_of st) (Pb.repeated_bytes req 2) in
  let g = st.group in
  let inline =
    List.map
      (proposal_of_description ~c:(G.crypto g) ~tree:(G.tree g)
         ~group_id:(G.group_id g))
      (Pb.repeated_messages req 3)
  in
  let external_tree = Pb.bool req 5 in
  let r =
    ok
      (G.commit ~wire:(wire st) ~inline ~references ~force_path:(Pb.bool req 4)
         ~psks:psk_lookup ~welcome_with_tree:(not external_tree) st.group
         ~rng:(rng ()))
  in
  st.pending <- Some r;
  commit_response ~external_tree r

let apply_pending st =
  match st.pending with
  | None -> failwith "no pending commit"
  | Some r ->
      st.group <- r.state;
      st.pending <- None;
      Hashtbl.reset st.sent

let handle_commit st req =
  List.iter (fun p -> ignore (reference_of st p)) (Pb.repeated_bytes req 2);
  match ok (G.process ~psks:psk_lookup st.group (message (Pb.bytes req 3))) with
  | G.Commit_applied _, group ->
      st.group <- group;
      Hashtbl.reset st.sent
  | _ -> failwith "expected a commit"

let state_response id st =
  Pb.encode (fun b ->
      Pb.Writer.int b 1 id;
      Pb.Writer.bytes b 2 (epoch_authenticator st))

(* ReInit: after the Commit, each member makes a KeyPackage for the new group. *)
let reinit_response st =
  let r =
    match G.reinitialized st.group with
    | Some r -> r
    | None -> failwith "the commit did not reinitialize the group"
  in
  let next =
    new_transaction (Crypto.create_exn r.Proposal.cipher_suite) st.identity
  in
  let id = fresh_id () in
  Hashtbl.replace reinits id { old = st; next };
  Pb.encode (fun b ->
      Pb.Writer.int b 1 id;
      Pb.Writer.bytes b 2 (key_package_bytes next);
      Pb.Writer.bytes b 3 (epoch_authenticator st))

let subgroup_response ~external_tree ~encrypt ~identity (r : G.commit_result) =
  let id = add_state ~encrypt ~identity r.state in
  Pb.encode (fun b ->
      Pb.Writer.int b 1 id;
      Pb.Writer.bytes b 2
        (match r.welcome with Some w -> Mls_message.to_bytes w | None -> "");
      Pb.Writer.bytes b 3 (tree_bytes ~external_tree (G.tree r.state));
      Pb.Writer.bytes b 4 (G.epoch_authenticator r.state))

(* Messages from non-members, signed without the group context. *)
let external_proposal c ~key ~(context : Group_context.t) ~sender proposal =
  let framed =
    {
      Framing.Framed_content.group_id = context.group_id;
      epoch = context.epoch;
      sender;
      authenticated_data = "";
      content = Framing.Content.Proposal proposal;
    }
  in
  let ac =
    Message_protection.sign c ~key
      ~wire_format:Framing.wire_format_public_message ~group_context:None
      ~confirmation_tag:None framed
  in
  let pm =
    ok (Message_protection.protect_public c ~membership_key:"" ~group_context:context ac)
  in
  Mls_message.to_bytes (Mls_message.Public_message pm)

(* Handlers, one per RPC, from the decoded request to the encoded response. *)

let handlers : (string * (Pb.fields -> string)) list =
  [
    ("Name", fun _ -> Pb.encode (fun b -> Pb.Writer.bytes b 1 "ocaml-mls"));
    ( "SupportedCiphersuites",
      fun _ ->
        Pb.encode (fun b -> Pb.Writer.packed_ints b 1 Cipher_suite.supported) );
    ( "CreateGroup",
      fun req ->
        let c = Crypto.create_exn (Pb.int req 2) in
        let identity = Pb.bytes req 4 in
        let tx = new_transaction c identity in
        let group =
          ok
            (G.create ~policy c ~rng:(rng ()) ~group_id:(Pb.bytes req 1)
               ~signature_key:tx.signature_key
               ~leaf_node:tx.generated.key_package.leaf_node
               ~leaf_key:tx.generated.encryption_key)
        in
        let id = add_state ~encrypt:(Pb.bool req 3) ~identity group in
        Pb.encode (fun b -> Pb.Writer.int b 1 id) );
    ( "CreateKeyPackage",
      fun req ->
        let tx =
          new_transaction (Crypto.create_exn (Pb.int req 1)) (Pb.bytes req 2)
        in
        let id = fresh_id () in
        Hashtbl.replace transactions id tx;
        Pb.encode (fun b ->
            Pb.Writer.int b 1 id;
            Pb.Writer.bytes b 2 (key_package_bytes tx);
            Pb.Writer.bytes b 3
              (Hpke.Private_key.to_bytes tx.generated.init_key);
            Pb.Writer.bytes b 4
              (Hpke.Private_key.to_bytes tx.generated.encryption_key);
            Pb.Writer.bytes b 5 (Crypto.signature_key_to_bytes tx.signature_key))
    );
    ( "JoinGroup",
      fun req ->
        let tx = find transactions "transaction" (Pb.int req 1) in
        let group =
          ok
            (G.join ~psks:psk_lookup ~policy
               ?tree:(tree_of_bytes (Pb.bytes req 5))
               tx.crypto ~key_package:tx.generated.key_package
               ~init_key:tx.generated.init_key
               ~encryption_key:tx.generated.encryption_key
               ~signature_key:tx.signature_key
               (welcome_of_bytes (Pb.bytes req 2)))
        in
        let id =
          add_state ~encrypt:(Pb.bool req 3) ~identity:(Pb.bytes req 4) group
        in
        state_response id (find states "state" id) );
    ( "ExternalJoin",
      fun req ->
        let gi = group_info_of_bytes (Pb.bytes req 1) in
        let context = gi.Group_info.group_context in
        let c = Crypto.create_exn context.Group_context.cipher_suite in
        let identity = Pb.bytes req 4 in
        let tree = tree_of_bytes (Pb.bytes req 2) in
        let psk_ids =
          List.map
            (fun p ->
              let psk_id = Pb.bytes p 1 in
              Hashtbl.replace psks psk_id (Pb.bytes p 2);
              {
                Psk.key = Psk.External psk_id;
                psk_nonce = Crypto.random ~rng:(rng ()) (Crypto.hash_size c);
              })
            (Pb.repeated_messages req 6)
        in
        let remove_old =
          if Pb.bool req 5 then
            let tree =
              match tree with
              | Some t -> t
              | None -> (
                  match
                    ok (Group_extensions.ratchet_tree gi.Group_info.extensions)
                  with
                  | Some t -> t
                  | None -> failwith "no ratchet tree")
            in
            Some (leaf_of_identity tree identity)
          else None
        in
        let tx = new_transaction c identity in
        let msg, group =
          ok
            (G.external_join ~psks:psk_lookup ~policy ?tree ?remove_old
               ~psk_ids c ~rng:(rng ()) ~group_info:gi
               ~signature_key:tx.signature_key
               ~leaf_node:tx.generated.key_package.leaf_node)
        in
        let id = add_state ~encrypt:(Pb.bool req 3) ~identity group in
        Pb.encode (fun b ->
            Pb.Writer.int b 1 id;
            Pb.Writer.bytes b 2 (Mls_message.to_bytes msg);
            Pb.Writer.bytes b 3 (G.epoch_authenticator group)) );
    ( "GroupInfo",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        let external_tree = Pb.bool req 2 in
        let gi = ok (G.group_info ~with_tree:(not external_tree) st.group) in
        Pb.encode (fun b ->
            Pb.Writer.bytes b 1
              (Mls_message.to_bytes (Mls_message.Group_info gi));
            Pb.Writer.bytes b 2 (tree_bytes ~external_tree (G.tree st.group)))
    );
    ( "StateAuth",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        Pb.encode (fun b -> Pb.Writer.bytes b 1 (epoch_authenticator st)) );
    ( "Export",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        let secret =
          ok
            (G.export st.group ~label:(Pb.bytes req 2) ~context:(Pb.bytes req 3)
               (Pb.int req 4))
        in
        Pb.encode (fun b -> Pb.Writer.bytes b 1 secret) );
    ( "Protect",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        let msg, group =
          ok
            (G.encrypt_application ~authenticated_data:(Pb.bytes req 2)
               st.group ~rng:(rng ()) (Pb.bytes req 3))
        in
        st.group <- group;
        Pb.encode (fun b -> Pb.Writer.bytes b 1 (Mls_message.to_bytes msg)) );
    ( "Unprotect",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        match ok (G.process st.group (message (Pb.bytes req 2))) with
        | G.Application_received { data; authenticated_data; _ }, group ->
            st.group <- group;
            Pb.encode (fun b ->
                Pb.Writer.bytes b 1 authenticated_data;
                Pb.Writer.bytes b 2 data)
        | _ -> failwith "expected application data" );
    ( "StorePSK",
      fun req ->
        Hashtbl.replace psks (Pb.bytes req 2) (Pb.bytes req 3);
        "" );
    ( "AddProposal",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        propose_value st (Proposal.Add (key_package_of_bytes (Pb.bytes req 2)))
    );
    ( "UpdateProposal",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        propose st (fun g -> G.propose_update ~wire:(wire st) g ~rng:(rng ()))
    );
    ( "RemoveProposal",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        propose_value st
          (Proposal.Remove (leaf_of_identity (G.tree st.group) (Pb.bytes req 2)))
    );
    ( "ExternalPSKProposal",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        propose_value st
          (Proposal.Pre_shared_key
             (G.external_psk_id st.group ~rng:(rng ()) (Pb.bytes req 2))) );
    ( "ResumptionPSKProposal",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        propose_value st
          (Proposal.Pre_shared_key
             (G.resumption_psk_id st.group ~rng:(rng ())
                ~group_id:(G.group_id st.group)
                ~epoch:(Int64.of_int (Pb.int req 2)))) );
    ( "GroupContextExtensionsProposal",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        propose_value st
          (Proposal.Group_context_extensions (extensions_of req 2)) );
    ("Commit", commit);
    ( "HandleCommit",
      fun req ->
        let id = Pb.int req 1 in
        let st = find states "state" id in
        handle_commit st req;
        state_response id st );
    ( "HandlePendingCommit",
      fun req ->
        let id = Pb.int req 1 in
        let st = find states "state" id in
        apply_pending st;
        state_response id st );
    ( "ReInitProposal",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        propose_value st
          (Proposal.Re_init
             {
               Proposal.group_id = Pb.bytes req 3;
               version = Framing.protocol_version_mls10;
               cipher_suite = Pb.int req 2;
               extensions = extensions_of req 4;
             }) );
    ("ReInitCommit", commit);
    ( "HandlePendingReInitCommit",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        apply_pending st;
        reinit_response st );
    ( "HandleReInitCommit",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        handle_commit st req;
        reinit_response st );
    ( "ReInitWelcome",
      fun req ->
        let ri = find reinits "reinit" (Pb.int req 1) in
        let external_tree = Pb.bool req 4 in
        let key_packages =
          List.map key_package_of_bytes (Pb.repeated_bytes req 2)
        in
        let r =
          ok
            (G.reinit ~force_path:(Pb.bool req 3)
               ~welcome_with_tree:(not external_tree) ri.old.group
               ri.next.crypto ~rng:(rng ())
               ~signature_key:ri.next.signature_key
               ~leaf_node:ri.next.generated.key_package.leaf_node
               ~leaf_key:ri.next.generated.encryption_key key_packages)
        in
        subgroup_response ~external_tree ~encrypt:ri.old.encrypt
          ~identity:ri.old.identity r );
    ( "HandleReInitWelcome",
      fun req ->
        let ri = find reinits "reinit" (Pb.int req 1) in
        let group =
          ok
            (G.join_reinit ~psks:psk_lookup
               ?tree:(tree_of_bytes (Pb.bytes req 3))
               ri.old.group ri.next.crypto
               ~key_package:ri.next.generated.key_package
               ~init_key:ri.next.generated.init_key
               ~encryption_key:ri.next.generated.encryption_key
               ~signature_key:ri.next.signature_key
               (welcome_of_bytes (Pb.bytes req 2)))
        in
        let id =
          add_state ~encrypt:ri.old.encrypt ~identity:ri.old.identity group
        in
        state_response id (find states "state" id) );
    ( "CreateBranch",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        let external_tree = Pb.bool req 6 in
        let own =
          new_transaction ~signature_key:(G.signature_key st.group)
            (G.crypto st.group) st.identity
        in
        let r =
          ok
            (G.branch ~force_path:(Pb.bool req 5)
               ~welcome_with_tree:(not external_tree)
               ~extensions:(extensions_of req 3) st.group ~rng:(rng ())
               ~group_id:(Pb.bytes req 2)
               ~leaf_node:own.generated.key_package.leaf_node
               ~leaf_key:own.generated.encryption_key
               (List.map key_package_of_bytes (Pb.repeated_bytes req 4)))
        in
        subgroup_response ~external_tree ~encrypt:st.encrypt
          ~identity:st.identity r );
    ( "HandleBranch",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        let tx = find transactions "transaction" (Pb.int req 2) in
        let group =
          ok
            (G.join_branch ~psks:psk_lookup
               ?tree:(tree_of_bytes (Pb.bytes req 4))
               ~signature_key:tx.signature_key st.group
               ~key_package:tx.generated.key_package
               ~init_key:tx.generated.init_key
               ~encryption_key:tx.generated.encryption_key
               (welcome_of_bytes (Pb.bytes req 3)))
        in
        let id = add_state ~encrypt:st.encrypt ~identity:st.identity group in
        state_response id (find states "state" id) );
    ( "NewMemberAddProposal",
      fun req ->
        let gi = group_info_of_bytes (Pb.bytes req 1) in
        let context = gi.Group_info.group_context in
        let c = Crypto.create_exn context.Group_context.cipher_suite in
        let tx = new_transaction c (Pb.bytes req 2) in
        let id = fresh_id () in
        Hashtbl.replace transactions id tx;
        let proposal =
          external_proposal c ~key:tx.signature_key ~context
            ~sender:Framing.Sender.New_member_proposal
            (Proposal.Add tx.generated.key_package)
        in
        Pb.encode (fun b ->
            Pb.Writer.int b 1 id;
            Pb.Writer.bytes b 2 proposal;
            Pb.Writer.bytes b 3
              (Hpke.Private_key.to_bytes tx.generated.init_key);
            Pb.Writer.bytes b 4
              (Hpke.Private_key.to_bytes tx.generated.encryption_key);
            Pb.Writer.bytes b 5 (Crypto.signature_key_to_bytes tx.signature_key))
    );
    ( "CreateExternalSigner",
      fun req ->
        let c = Crypto.create_exn (Pb.int req 1) in
        let key = Crypto.generate_signature_key c ~rng:(rng ()) in
        let sender =
          {
            Group_extensions.signature_key = Crypto.signature_public_key key;
            credential = Credential.Basic (Pb.bytes req 2);
          }
        in
        let id = fresh_id () in
        Hashtbl.replace signers id { signer_crypto = c; signer_key = key };
        Pb.encode (fun b ->
            Pb.Writer.int b 1 id;
            Pb.Writer.bytes b 2
              (Tls.encode Group_extensions.encode_external_sender sender)) );
    ( "AddExternalSigner",
      fun req ->
        let st = find states "state" (Pb.int req 1) in
        let sender =
          Tls.decode_exn Group_extensions.decode_external_sender
            (Pb.bytes req 2)
        in
        let exts = G.extensions st.group in
        let current = ok (Group_extensions.external_senders exts) in
        let others =
          List.filter
            (fun (e : Extension.t) ->
              e.Extension.extension_type <> Extension.external_senders)
            exts
        in
        propose_value st
          (Proposal.Group_context_extensions
             (others
             @ [ Group_extensions.make_external_senders (current @ [ sender ]) ]
             )) );
    ( "ExternalSignerProposal",
      fun req ->
        let signer = find signers "signer" (Pb.int req 1) in
        let c = signer.signer_crypto in
        let gi = group_info_of_bytes (Pb.bytes req 3) in
        let context = gi.Group_info.group_context in
        let tree =
          match tree_of_bytes (Pb.bytes req 4) with
          | Some t -> t
          | None -> (
              match
                ok (Group_extensions.ratchet_tree gi.Group_info.extensions)
              with
              | Some t -> t
              | None -> failwith "no ratchet tree")
        in
        let own = Crypto.signature_public_key signer.signer_key in
        let senders =
          ok (Group_extensions.external_senders context.Group_context.extensions)
        in
        let index =
          let rec go i = function
            | [] -> Pb.int req 2
            | (s : Group_extensions.external_sender) :: rest ->
                if String.equal s.Group_extensions.signature_key own then i
                else go (i + 1) rest
          in
          go 0 senders
        in
        let description =
          match Pb.message req 5 with
          | Some d -> d
          | None -> failwith "missing description"
        in
        let proposal =
          proposal_of_description ~c ~tree
            ~group_id:context.Group_context.group_id description
        in
        let bytes =
          external_proposal c ~key:signer.signer_key ~context
            ~sender:(Framing.Sender.External index) proposal
        in
        Pb.encode (fun b -> Pb.Writer.bytes b 1 bytes) );
    ( "Free",
      fun req ->
        Hashtbl.remove states (Pb.int req 1);
        "" );
  ]

(* gRPC *)

let unary name f request =
  match f (Pb.decode request) with
  | response -> Lwt.return (Grpc.Status.v Grpc.Status.OK, Some response)
  | exception e ->
      let message = Printexc.to_string e in
      Printf.eprintf "%s failed: %s\n%!" name message;
      Lwt.return (Grpc.Status.v ~message Grpc.Status.Internal, None)

let service =
  List.fold_left
    (fun service (name, f) ->
      Grpc_lwt.Server.Service.add_rpc ~name
        ~rpc:(Grpc_lwt.Server.Rpc.Unary (unary name f))
        service)
    (Grpc_lwt.Server.Service.v ())
    handlers
  |> Grpc_lwt.Server.Service.handle_request

let server =
  Grpc_lwt.Server.(
    v () |> add_service ~name:"mls_client.MLSClient" ~service)

let () =
  let port = ref 50051 in
  Arg.parse
    [ ("-port", Arg.Set_int port, "PORT  listen on this port (default 50051)") ]
    (fun _ -> ())
    "mls_interop [-port PORT]";
  ignore (rng ());
  let listen_address = Unix.(ADDR_INET (inet_addr_loopback, !port)) in
  let handler =
    H2_lwt_unix.Server.create_connection_handler ?config:None
      ~request_handler:(fun _ reqd -> Grpc_lwt.Server.handle_request server reqd)
      ~error_handler:(fun _ ?request:_ _ _ ->
        prerr_endline "HTTP/2 error")
  in
  Lwt_main.run
    (let open Lwt.Syntax in
     let* _server =
       Lwt_io.establish_server_with_client_socket listen_address handler
     in
     Printf.printf "mls_interop listening on port %d\n%!" !port;
     fst (Lwt.wait ()))
