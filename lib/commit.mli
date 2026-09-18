(** Commit (RFC 9420 Section 12.4). *)

type proposal_or_ref = Proposal of Proposal.t | Reference of string
type t = { proposals : proposal_or_ref list; path : Update_path.t option }

val encode_proposal_or_ref : Tls.Encoder.t -> proposal_or_ref -> unit
val decode_proposal_or_ref : Tls.Decoder.t -> proposal_or_ref
val encode : Tls.Encoder.t -> t -> unit
val decode : Tls.Decoder.t -> t
