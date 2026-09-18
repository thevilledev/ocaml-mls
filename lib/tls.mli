(** TLS presentation-language codec (RFC 8446 Section 3, profiled by RFC 9420
    Section 2.1). Integers are big-endian; variable-length vectors use the
    minimal QUIC-style variable-length header of RFC 9420 Section 2.1.2. *)

exception Decode_error of string
(** Raised by {!Decoder} functions on malformed input. *)

val fail : ('a, unit, string, 'b) format4 -> 'a
(** [fail fmt ...] raises {!Decode_error} with a formatted message. *)

module Encoder : sig
  type t

  val create : unit -> t
  val contents : t -> string
  val raw : t -> string -> unit
  val u8 : t -> int -> unit
  val u16 : t -> int -> unit
  val u32 : t -> int -> unit
  val u64 : t -> int64 -> unit
  val varint : t -> int -> unit

  val opaque : t -> string -> unit
  (** [opaque<V>]: a variable-length byte string. *)

  val nested : t -> (t -> unit) -> unit
  (** Encode the output of the callback as a length-prefixed structure. *)

  val vector : t -> (t -> 'a -> unit) -> 'a list -> unit
  (** [T list<V>]: a length-prefixed sequence of elements. *)

  val optional : t -> (t -> 'a -> unit) -> 'a option -> unit
  (** [optional<T>]: a presence byte followed by the value. *)

  val fixed : t -> int -> string -> unit
  (** [fixed t n s] writes the exactly [n]-byte string [s]. *)
end

module Decoder : sig
  type t

  val of_string : ?pos:int -> ?len:int -> string -> t
  val remaining : t -> int
  val at_end : t -> bool
  val u8 : t -> int
  val u16 : t -> int
  val u32 : t -> int
  val u64 : t -> int64
  val raw : t -> int -> string

  val varint : t -> int
  (** Rejects non-minimal encodings and the reserved prefix. *)

  val opaque : t -> string
  val sub : t -> int -> t
  val nested : t -> (t -> 'a) -> 'a
  val vector : t -> (t -> 'a) -> 'a list
  val optional : t -> (t -> 'a) -> 'a option

  val with_slice : t -> (t -> 'a) -> 'a * string
  (** Run a decoder and also return the bytes it consumed. *)
end

val encode : (Encoder.t -> 'a -> unit) -> 'a -> string

val decode : (Decoder.t -> 'a) -> string -> ('a, string) result
(** Decode a complete value; trailing bytes are an error. *)

val decode_exn : (Decoder.t -> 'a) -> string -> 'a
