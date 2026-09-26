(** Application validation policy (RFC 9420 Section 7.3).

    MLS leaves some checks to the application: the current time, against which a
    KeyPackage's lifetime is checked, and the longest lifetime the application
    accepts. A {!Group.t} carries a policy and applies it to every KeyPackage it
    validates, whether the KeyPackage is added by the group itself or arrives in
    a proposal or commit from another member.

    Lifetimes are only checked for KeyPackages being added. Leaf nodes already
    in a ratchet tree are not checked: a member that has not updated since it
    joined still carries its KeyPackage's lifetime, and RFC 9420 makes the check
    optional for received leaf nodes. *)

type t = {
  clock : (unit -> int64) option;
      (** The current time in seconds since the Unix epoch. When set, a
          KeyPackage is rejected unless [not_before <= now <= not_after]. *)
  max_lifetime : int64 option;
      (** The longest acceptable [not_after - not_before], in seconds. RFC 9420
          requires applications to define one. *)
}

val default : t
(** No clock and no maximum: lifetimes are not checked. *)

val make : ?clock:(unit -> int64) -> ?max_lifetime:int64 -> unit -> t

val check_lifetime : t -> Leaf_node.lifetime -> (unit, Error.t) result
(** Fails with [Invalid_key_package] for a lifetime that ends before it starts,
    exceeds [max_lifetime], or does not contain the current time. Checks nothing
    under {!default}. *)

val check_leaf_node : t -> Leaf_node.t -> (unit, Error.t) result
(** {!check_lifetime} for a leaf node whose source is a KeyPackage; other leaf
    nodes carry no lifetime and always pass. *)
