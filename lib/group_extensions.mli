(** GroupContext and GroupInfo extension payloads (RFC 9420 Sections 11.1,
    12.1.8.1, 12.4.3.2 and 12.4.3.3). *)

type external_sender = { signature_key : string; credential : Credential.t }

val encode_external_sender : Tls.Encoder.t -> external_sender -> unit
val decode_external_sender : Tls.Decoder.t -> external_sender
val encode_external_senders : Tls.Encoder.t -> external_sender list -> unit
val decode_external_senders : Tls.Decoder.t -> external_sender list

type required_capabilities = {
  extension_types : int list;
  proposal_types : int list;
  credential_types : int list;
}

val encode_required_capabilities :
  Tls.Encoder.t -> required_capabilities -> unit

val decode_required_capabilities : Tls.Decoder.t -> required_capabilities

(** {1 Lookup in extension lists} *)

val external_senders :
  Extension.t list -> (external_sender list, Error.t) result

val required_capabilities :
  Extension.t list -> (required_capabilities option, Error.t) result

val external_pub : Extension.t list -> (string option, Error.t) result
val ratchet_tree : Extension.t list -> (Ratchet_tree.t option, Error.t) result

(** {1 Construction} *)

val make_external_senders : external_sender list -> Extension.t
val make_required_capabilities : required_capabilities -> Extension.t
val make_external_pub : string -> Extension.t
val make_ratchet_tree : Ratchet_tree.t -> Extension.t
