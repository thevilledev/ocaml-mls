(* Commit (RFC 9420 Section 12.4). *)

type proposal_or_ref = Proposal of Proposal.t | Reference of string
type t = { proposals : proposal_or_ref list; path : Update_path.t option }

let encode_proposal_or_ref e = function
  | Proposal p ->
      Tls.Encoder.u8 e 1;
      Proposal.encode e p
  | Reference r ->
      Tls.Encoder.u8 e 2;
      Tls.Encoder.opaque e r

let decode_proposal_or_ref d =
  match Tls.Decoder.u8 d with
  | 1 -> Proposal (Proposal.decode d)
  | 2 -> Reference (Tls.Decoder.opaque d)
  | n -> Tls.fail "unknown ProposalOrRef type %d" n

let encode e t =
  Tls.Encoder.vector e encode_proposal_or_ref t.proposals;
  Tls.Encoder.optional e Update_path.encode t.path

let decode d =
  let proposals = Tls.Decoder.vector d decode_proposal_or_ref in
  let path = Tls.Decoder.optional d Update_path.decode in
  { proposals; path }
