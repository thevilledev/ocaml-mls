(** Extensions (RFC 9420 Sections 5.3.1 and 12.4.3). *)

type extension_type = int

val application_id : extension_type
val ratchet_tree : extension_type
val required_capabilities : extension_type
val external_pub : extension_type
val external_senders : extension_type

type t = { extension_type : extension_type; extension_data : string }

val encode : Tls.Encoder.t -> t -> unit
val decode : Tls.Decoder.t -> t
val encode_list : Tls.Encoder.t -> t list -> unit
val decode_list : Tls.Decoder.t -> t list
val find : extension_type -> t list -> t option

val is_default_type : extension_type -> bool
(** Default extension types are implicitly supported and must not be listed in
    capabilities (Section 7.2). *)

val default_types : extension_type list
