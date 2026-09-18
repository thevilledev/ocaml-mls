(* Leaf nodes (RFC 9420 Section 7.2). *)

type lifetime = { not_before : int64; not_after : int64 }
type source = Key_package of lifetime | Update | Commit of string

type t = {
  encryption_key : string;
  signature_key : string;
  credential : Credential.t;
  capabilities : Capabilities.t;
  leaf_node_source : source;
  extensions : Extension.t list;
  signature : string;
}

let source_key_package = 1
let source_update = 2
let source_commit = 3

let encode_lifetime e l =
  Tls.Encoder.u64 e l.not_before;
  Tls.Encoder.u64 e l.not_after

let decode_lifetime d =
  let not_before = Tls.Decoder.u64 d in
  let not_after = Tls.Decoder.u64 d in
  { not_before; not_after }

let encode_source e = function
  | Key_package lifetime ->
      Tls.Encoder.u8 e source_key_package;
      encode_lifetime e lifetime
  | Update -> Tls.Encoder.u8 e source_update
  | Commit parent_hash ->
      Tls.Encoder.u8 e source_commit;
      Tls.Encoder.opaque e parent_hash

let decode_source d =
  match Tls.Decoder.u8 d with
  | 1 -> Key_package (decode_lifetime d)
  | 2 -> Update
  | 3 -> Commit (Tls.Decoder.opaque d)
  | n -> Tls.fail "unknown leaf node source %d" n

let encode_body e t =
  Tls.Encoder.opaque e t.encryption_key;
  Tls.Encoder.opaque e t.signature_key;
  Credential.encode e t.credential;
  Capabilities.encode e t.capabilities;
  encode_source e t.leaf_node_source;
  Extension.encode_list e t.extensions

let encode e t =
  encode_body e t;
  Tls.Encoder.opaque e t.signature

let decode d =
  let encryption_key = Tls.Decoder.opaque d in
  let signature_key = Tls.Decoder.opaque d in
  let credential = Credential.decode d in
  let capabilities = Capabilities.decode d in
  let leaf_node_source = decode_source d in
  let extensions = Extension.decode_list d in
  let signature = Tls.Decoder.opaque d in
  {
    encryption_key;
    signature_key;
    credential;
    capabilities;
    leaf_node_source;
    extensions;
    signature;
  }

(* LeafNodeTBS. [group_id] and [leaf_index] are required for the update and
   commit sources and ignored for key packages. *)
let encode_tbs e ~group_id ~leaf_index t =
  encode_body e t;
  match t.leaf_node_source with
  | Key_package _ -> ()
  | Update | Commit _ ->
      Tls.Encoder.opaque e group_id;
      Tls.Encoder.u32 e leaf_index

let tbs ~group_id ~leaf_index t =
  Tls.encode (fun e t -> encode_tbs e ~group_id ~leaf_index t) t

let to_bytes t = Tls.encode encode t
let of_bytes s = Error.of_decode (Tls.decode decode s)

let parent_hash t =
  match t.leaf_node_source with Commit ph -> Some ph | _ -> None

let signature_label = "LeafNodeTBS"
let unbounded_lifetime = { not_before = 0L; not_after = -1L }

let sign c ~key ~group_id ~leaf_index t =
  {
    t with
    signature =
      Crypto.sign_with_label c ~key ~label:signature_label
        (tbs ~group_id ~leaf_index t);
  }

(* Generate a fresh leaf node for a KeyPackage, returning it with the HPKE
   private key for its encryption_key. *)
let generate ?(lifetime = unbounded_lifetime) ?(extensions = []) ?capabilities c
    ~rng ~signature_key ~credential =
  match Crypto.generate_key_pair c ~rng with
  | Error e -> Error e
  | Ok (encryption_priv, encryption_pub) ->
      let capabilities =
        match capabilities with
        | Some caps -> caps
        | None -> Capabilities.default ~cipher_suite:(Crypto.suite c)
      in
      let ln =
        {
          encryption_key = Hpke.Public_key.to_bytes encryption_pub;
          signature_key = Crypto.signature_public_key signature_key;
          credential;
          capabilities;
          leaf_node_source = Key_package lifetime;
          extensions;
          signature = "";
        }
      in
      Ok
        ( sign c ~key:signature_key ~group_id:"" ~leaf_index:0 ln,
          encryption_priv )
