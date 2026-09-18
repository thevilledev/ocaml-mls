(* Key packages (RFC 9420 Section 10). *)

type t = {
  version : int;
  cipher_suite : Cipher_suite.t;
  init_key : string;
  leaf_node : Leaf_node.t;
  extensions : Extension.t list;
  signature : string;
}

let encode_tbs e t =
  Tls.Encoder.u16 e t.version;
  Tls.Encoder.u16 e t.cipher_suite;
  Tls.Encoder.opaque e t.init_key;
  Leaf_node.encode e t.leaf_node;
  Extension.encode_list e t.extensions

let encode e t =
  encode_tbs e t;
  Tls.Encoder.opaque e t.signature

let decode d =
  let version = Tls.Decoder.u16 d in
  let cipher_suite = Tls.Decoder.u16 d in
  let init_key = Tls.Decoder.opaque d in
  let leaf_node = Leaf_node.decode d in
  let extensions = Extension.decode_list d in
  let signature = Tls.Decoder.opaque d in
  { version; cipher_suite; init_key; leaf_node; extensions; signature }

let tbs t = Tls.encode encode_tbs t
let to_bytes t = Tls.encode encode t
let of_bytes s = Error.of_decode (Tls.decode decode s)
let signature_label = "KeyPackageTBS"

type generated = {
  key_package : t;
  init_key : Hpke.Private_key.t;
  encryption_key : Hpke.Private_key.t;
}

let sign c ~key t =
  {
    t with
    signature = Crypto.sign_with_label c ~key ~label:signature_label (tbs t);
  }

(* Generate a KeyPackage and the private keys it commits to. *)
let generate ?lifetime ?leaf_extensions ?capabilities ?(extensions = []) c ~rng
    ~signature_key ~credential =
  match
    Leaf_node.generate ?lifetime ?extensions:leaf_extensions ?capabilities c
      ~rng ~signature_key ~credential
  with
  | Error e -> Error e
  | Ok (leaf_node, encryption_key) -> (
      match Crypto.generate_key_pair c ~rng with
      | Error e -> Error e
      | Ok (init_key, init_pub) ->
          let kp =
            {
              version = 1;
              cipher_suite = Crypto.suite c;
              init_key = Hpke.Public_key.to_bytes init_pub;
              leaf_node;
              extensions;
              signature = "";
            }
          in
          Ok
            {
              key_package = sign c ~key:signature_key kp;
              init_key;
              encryption_key;
            })
