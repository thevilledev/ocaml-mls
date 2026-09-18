(** Group state machine (RFC 9420 Sections 11 and 12). A value of type [t] is
    one member's view of a group in one epoch. All operations are pure: they
    return the updated state instead of mutating it, so a caller can discard a
    state (for example a commit the Delivery Service rejected). *)

type t

type psk_lookup = Psk.id -> string option
(** Resolves external pre-shared keys, and resumption PSKs of other groups. *)

val no_external_psks : psk_lookup

type event =
  | Proposal_received of {
      proposal : Proposal.t;
      sender : Framing.Sender.t;
      reference : string;
    }
  | Commit_applied of {
      removed_self : bool;
      committer : int option;
      reinit : Proposal.re_init option;
    }
      (** When [removed_self] is set the returned state is unchanged and the
          group should no longer be used. *)
  | Application_received of {
      data : string;
      sender : int;
      authenticated_data : string;
    }

type wire = Public | Private  (** Wire format for handshake messages. *)

type commit_result = {
  commit : Mls_message.t;
  welcome : Mls_message.t option;  (** Present when members were added. *)
  group_info : Group_info.t;  (** Signed GroupInfo for the new epoch. *)
  state : t;  (** The committer's view of the new epoch. *)
}

(** {1 Creating and joining} *)

val create :
  ?extensions:Extension.t list ->
  Crypto.t ->
  rng:Mirage_crypto_rng.g ->
  group_id:string ->
  signature_key:Crypto.signature_key ->
  leaf_node:Leaf_node.t ->
  leaf_key:Hpke.Private_key.t ->
  (t, Error.t) result
(** Create a one-member group from the creator's leaf node (typically the one in
    a freshly generated {!Key_package}) and its HPKE private key. *)

val join :
  ?psks:psk_lookup ->
  ?tree:Ratchet_tree.t ->
  Crypto.t ->
  key_package:Key_package.t ->
  init_key:Hpke.Private_key.t ->
  encryption_key:Hpke.Private_key.t ->
  signature_key:Crypto.signature_key ->
  Welcome.t ->
  (t, Error.t) result
(** Join via a Welcome addressed to [key_package]. The ratchet tree is taken
    from the [ratchet_tree] GroupInfo extension unless [tree] is given. *)

val external_join :
  ?psks:psk_lookup ->
  ?authenticated_data:string ->
  ?tree:Ratchet_tree.t ->
  ?remove_old:int ->
  ?psk_ids:Psk.id list ->
  Crypto.t ->
  rng:Mirage_crypto_rng.g ->
  group_info:Group_info.t ->
  signature_key:Crypto.signature_key ->
  leaf_node:Leaf_node.t ->
  (Mls_message.t * t, Error.t) result
(** Join via an external Commit using a GroupInfo carrying an [external_pub]
    extension. [leaf_node] supplies the credential and capabilities; its keys
    are replaced. Returns the Commit to broadcast and the joiner's state. *)

(** {1 Accessors} *)

val crypto : t -> Crypto.t
val cipher_suite : t -> Cipher_suite.t
val group_id : t -> string
val epoch : t -> int64
val context : t -> Group_context.t
val extensions : t -> Extension.t list
val tree : t -> Ratchet_tree.t
val own_index : t -> int
val members : t -> (int * Leaf_node.t) list
val member : t -> int -> Leaf_node.t option
val own_leaf : t -> Leaf_node.t option
val epoch_authenticator : t -> string
val resumption_psk : t -> string
val confirmation_tag : t -> string
val signature_key : t -> Crypto.signature_key
val pending_proposals : t -> (string * (Proposal.t * Framing.Sender.t)) list

val export : t -> label:string -> context:string -> int -> string
(** [MLS-Exporter] (Section 8.5). *)

(** {1 Receiving} *)

val process :
  ?psks:psk_lookup -> t -> Mls_message.t -> (event * t, Error.t) result
(** Process a PublicMessage or PrivateMessage for the current epoch. *)

(** {1 Sending} *)

val propose :
  ?authenticated_data:string ->
  ?wire:wire ->
  t ->
  rng:Mirage_crypto_rng.g ->
  Proposal.t ->
  (Mls_message.t * t, Error.t) result
(** Send a proposal; it is remembered so that a later {!val-commit} references
    it. *)

val propose_add :
  ?authenticated_data:string ->
  ?wire:wire ->
  t ->
  rng:Mirage_crypto_rng.g ->
  Key_package.t ->
  (Mls_message.t * t, Error.t) result

val propose_remove :
  ?authenticated_data:string ->
  ?wire:wire ->
  t ->
  rng:Mirage_crypto_rng.g ->
  int ->
  (Mls_message.t * t, Error.t) result

val propose_psk :
  ?authenticated_data:string ->
  ?wire:wire ->
  t ->
  rng:Mirage_crypto_rng.g ->
  Psk.id ->
  (Mls_message.t * t, Error.t) result

val propose_group_context_extensions :
  ?authenticated_data:string ->
  ?wire:wire ->
  t ->
  rng:Mirage_crypto_rng.g ->
  Extension.t list ->
  (Mls_message.t * t, Error.t) result

val propose_update :
  ?authenticated_data:string ->
  ?wire:wire ->
  ?update_leaf:(Leaf_node.t -> Leaf_node.t) ->
  t ->
  rng:Mirage_crypto_rng.g ->
  (Mls_message.t * t, Error.t) result
(** Propose replacing our leaf with fresh keys. *)

val external_psk_id : t -> rng:Mirage_crypto_rng.g -> string -> Psk.id

val resumption_psk_id :
  ?usage:Psk.resumption_usage ->
  t ->
  rng:Mirage_crypto_rng.g ->
  group_id:string ->
  epoch:int64 ->
  Psk.id

val commit :
  ?authenticated_data:string ->
  ?wire:wire ->
  ?inline:Proposal.t list ->
  ?references:string list ->
  ?force_path:bool ->
  ?psks:psk_lookup ->
  ?welcome_with_tree:bool ->
  ?group_info_extensions:Extension.t list ->
  t ->
  rng:Mirage_crypto_rng.g ->
  (commit_result, Error.t) result
(** Commit pending proposals by reference, all of them unless [references]
    selects a subset, plus [inline] proposals by value. An UpdatePath is
    included when required or when [force_path] is set. The Welcome carries the
    ratchet tree unless [welcome_with_tree] is false. *)

val encrypt_application :
  ?authenticated_data:string ->
  ?padding:int ->
  t ->
  rng:Mirage_crypto_rng.g ->
  string ->
  (Mls_message.t * t, Error.t) result
(** Encrypt application data as a PrivateMessage. Fails while proposals are
    pending, since they must be committed first (Section 12.4). *)

val group_info :
  ?with_tree:bool ->
  ?with_external_pub:bool ->
  ?extensions:Extension.t list ->
  t ->
  (Group_info.t, Error.t) result
(** A signed GroupInfo for the current epoch, usable for external joins. *)

(** {1 Validation} *)

val validate_key_package :
  Crypto.t ->
  group_id:string ->
  cipher_suite:Cipher_suite.t ->
  tree:Ratchet_tree.t ->
  extensions:Extension.t list ->
  Key_package.t ->
  (unit, Error.t) result
(** KeyPackage validation (Section 10.1) against a group's parameters. *)
