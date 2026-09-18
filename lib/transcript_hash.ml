(* Transcript hashes (RFC 9420 Section 8.2). *)

let confirmed c ~interim_transcript_hash (ac : Framing.Authenticated_content.t)
    =
  Crypto.hash c
    (interim_transcript_hash
    ^ Framing.Authenticated_content.confirmed_transcript_hash_input ac)

let interim c ~confirmed_transcript_hash ~confirmation_tag =
  Crypto.hash c
    (confirmed_transcript_hash ^ Tls.encode Tls.Encoder.opaque confirmation_tag)
