(** Application policy (RFC 9420 Sections 5.3.1, 7.3 and 9.2).

    MLS leaves some checks to the application: the current time, against which a
    KeyPackage's lifetime is checked, the longest lifetime the application
    accepts, and the Authentication Service that validates credentials. A
    {!Group.t} carries a policy and applies it to every KeyPackage and
    credential it validates, whether it adds a member itself or learns of one
    from a proposal, a commit, or the group it joins. The policy also sets how
    many past epochs' secrets a group keeps for late application messages.

    Lifetimes are only checked for KeyPackages being added. Leaf nodes already
    in a ratchet tree are not checked: a member that has not updated since it
    joined still carries its KeyPackage's lifetime, and RFC 9420 makes the check
    optional for received leaf nodes. *)

(** Why a credential is being introduced to the group (Section 5.3.1). *)
type credential_event =
  | Add
      (** A new member: a KeyPackage in an Add proposal, sent or received, or
          the joiner in an external Commit. *)
  | Join
      (** A member of the group this client is joining, via Welcome or external
          Commit. *)
  | Replace of { credential : Credential.t; signature_key : string }
      (** A member replacing its credential or signature key in an Update
          proposal or a Commit's UpdatePath. The payload is the replaced
          credential and key; the validator must also decide whether the new
          identity is a valid successor to the old one. *)
  | External_sender
      (** An entry of an [external_senders] extension being added to the group.
      *)

type credential_validator =
  credential_event ->
  credential:Credential.t ->
  signature_key:string ->
  (unit, string) result
(** Validates a credential with the application's Authentication Service: that
    the credential's identities are bound to [signature_key] and acceptable for
    this group. An [Error] message is returned as [Invalid_credential]. *)

type t = {
  clock : (unit -> int64) option;
      (** The current time in seconds since the Unix epoch. When set, a
          KeyPackage is rejected unless [not_before <= now <= not_after]. *)
  max_lifetime : int64 option;
      (** The longest acceptable [not_after - not_before], in seconds. RFC 9420
          requires applications to define one. *)
  validate_credential : credential_validator option;
      (** RFC 9420 requires every new credential to be validated. Without a
          validator the library accepts any credential whose leaf node is
          otherwise valid. *)
  max_past_epochs : int;
      (** How many past epochs a group keeps secret trees for, so that
          application messages sent before a Commit but delivered after it can
          still be decrypted. Only application messages are accepted from past
          epochs, and each key is still used at most once. Retained secrets
          weaken forward secrecy for as long as they are kept (Section 9.2), so
          the default is [0]. *)
}

val default : t
(** No clock, no maximum, no credential validator and no past epochs. *)

val make :
  ?clock:(unit -> int64) ->
  ?max_lifetime:int64 ->
  ?validate_credential:credential_validator ->
  ?max_past_epochs:int ->
  unit ->
  t

val check_lifetime : t -> Leaf_node.lifetime -> (unit, Error.t) result
(** Fails with [Invalid_key_package] for a lifetime that ends before it starts,
    exceeds [max_lifetime], or does not contain the current time. Checks nothing
    under {!default}. *)

val check_leaf_node : t -> Leaf_node.t -> (unit, Error.t) result
(** {!check_lifetime} for a leaf node whose source is a KeyPackage; other leaf
    nodes carry no lifetime and always pass. *)

val check_credential :
  t ->
  credential_event ->
  credential:Credential.t ->
  signature_key:string ->
  (unit, Error.t) result
(** Run the credential validator, if any. *)
