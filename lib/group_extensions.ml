(* GroupContext and GroupInfo extension payloads (RFC 9420 Sections 11.1,
   12.1.8.1, 12.4.3.2, 12.4.3.3). *)

type external_sender = { signature_key : string; credential : Credential.t }

let encode_external_sender e (x : external_sender) =
  Tls.Encoder.opaque e x.signature_key;
  Credential.encode e x.credential

let decode_external_sender d =
  let signature_key = Tls.Decoder.opaque d in
  let credential = Credential.decode d in
  { signature_key; credential }

let encode_external_senders e xs =
  Tls.Encoder.vector e encode_external_sender xs

let decode_external_senders d = Tls.Decoder.vector d decode_external_sender

type required_capabilities = {
  extension_types : int list;
  proposal_types : int list;
  credential_types : int list;
}

let encode_required_capabilities e (r : required_capabilities) =
  Tls.Encoder.vector e Tls.Encoder.u16 r.extension_types;
  Tls.Encoder.vector e Tls.Encoder.u16 r.proposal_types;
  Tls.Encoder.vector e Tls.Encoder.u16 r.credential_types

let decode_required_capabilities d =
  let extension_types = Tls.Decoder.vector d Tls.Decoder.u16 in
  let proposal_types = Tls.Decoder.vector d Tls.Decoder.u16 in
  let credential_types = Tls.Decoder.vector d Tls.Decoder.u16 in
  { extension_types; proposal_types; credential_types }

let external_senders exts =
  match Extension.find Extension.external_senders exts with
  | None -> Ok []
  | Some e ->
      Error.of_decode
        (Tls.decode decode_external_senders e.Extension.extension_data)

let required_capabilities exts =
  match Extension.find Extension.required_capabilities exts with
  | None -> Ok None
  | Some e ->
      Result.map Option.some
        (Error.of_decode
           (Tls.decode decode_required_capabilities e.Extension.extension_data))

let external_pub exts =
  match Extension.find Extension.external_pub exts with
  | None -> Ok None
  | Some e ->
      Result.map Option.some
        (Error.of_decode
           (Tls.decode Tls.Decoder.opaque e.Extension.extension_data))

let ratchet_tree exts =
  match Extension.find Extension.ratchet_tree exts with
  | None -> Ok None
  | Some e ->
      Result.map Option.some (Ratchet_tree.of_bytes e.Extension.extension_data)

let make_external_senders xs =
  {
    Extension.extension_type = Extension.external_senders;
    extension_data = Tls.encode encode_external_senders xs;
  }

let make_required_capabilities r =
  {
    Extension.extension_type = Extension.required_capabilities;
    extension_data = Tls.encode encode_required_capabilities r;
  }

let make_external_pub pub =
  {
    Extension.extension_type = Extension.external_pub;
    extension_data = Tls.encode Tls.Encoder.opaque pub;
  }

let make_ratchet_tree tree =
  {
    Extension.extension_type = Extension.ratchet_tree;
    extension_data = Ratchet_tree.to_bytes tree;
  }
