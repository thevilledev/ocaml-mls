(** Transcript hashes (RFC 9420 Section 8.2). *)

val confirmed :
  Crypto.t ->
  interim_transcript_hash:string ->
  Framing.Authenticated_content.t ->
  string

val interim :
  Crypto.t ->
  confirmed_transcript_hash:string ->
  confirmation_tag:string ->
  string
