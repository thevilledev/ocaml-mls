(* Capabilities advertised in a LeafNode (RFC 9420 Section 7.2). All list
   elements are uint16 registry values. *)

type t = {
  versions : int list;
  cipher_suites : int list;
  extensions : int list;
  proposals : int list;
  credentials : int list;
}

let protocol_version_mls10 = 0x0001

let encode e t =
  let u16s = Tls.Encoder.vector e Tls.Encoder.u16 in
  u16s t.versions;
  u16s t.cipher_suites;
  u16s t.extensions;
  u16s t.proposals;
  u16s t.credentials

let decode d =
  let u16s () = Tls.Decoder.vector d Tls.Decoder.u16 in
  let versions = u16s () in
  let cipher_suites = u16s () in
  let extensions = u16s () in
  let proposals = u16s () in
  let credentials = u16s () in
  { versions; cipher_suites; extensions; proposals; credentials }

let default ~cipher_suite =
  {
    versions = [ protocol_version_mls10 ];
    cipher_suites = [ cipher_suite ];
    extensions = [];
    proposals = [];
    credentials = [ Credential.basic ];
  }

let supports_extension t ty =
  Extension.is_default_type ty || List.mem ty t.extensions

let supports_credential t ty = List.mem ty t.credentials
