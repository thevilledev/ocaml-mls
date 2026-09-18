(** Secret tree and hash ratchets (RFC 9420 Section 9). Values are immutable;
    each operation returns the updated tree. *)

type content_type = Handshake | Application
type t

val create : Crypto.t -> n_leaves:int -> encryption_secret:string -> t
val n_leaves : t -> int

val next_key :
  t -> leaf:int -> content_type -> ((string * string * int) * t, Error.t) result
(** The next [(key, nonce, generation)] for sending from [leaf]. *)

val key_for :
  t ->
  leaf:int ->
  content_type ->
  generation:int ->
  ((string * string) * t, Error.t) result
(** The [(key, nonce)] for receiving a message from [leaf] at [generation]. Keys
    for skipped generations are retained within a bounded window so that
    reordered messages can be decrypted; every key is returned at most once. *)
