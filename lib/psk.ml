(* Pre-shared key identifiers (RFC 9420 Section 8.4). *)

type resumption_usage = Application | Reinit | Branch

type key =
  | External of string
  | Resumption of {
      usage : resumption_usage;
      psk_group_id : string;
      psk_epoch : int64;
    }

type id = { key : key; psk_nonce : string }

let usage_to_int = function Application -> 1 | Reinit -> 2 | Branch -> 3

let usage_of_int = function
  | 1 -> Application
  | 2 -> Reinit
  | 3 -> Branch
  | n -> Tls.fail "unknown resumption PSK usage %d" n

let encode_id e t =
  (match t.key with
  | External psk_id ->
      Tls.Encoder.u8 e 1;
      Tls.Encoder.opaque e psk_id
  | Resumption { usage; psk_group_id; psk_epoch } ->
      Tls.Encoder.u8 e 2;
      Tls.Encoder.u8 e (usage_to_int usage);
      Tls.Encoder.opaque e psk_group_id;
      Tls.Encoder.u64 e psk_epoch);
  Tls.Encoder.opaque e t.psk_nonce

let decode_id d =
  let key =
    match Tls.Decoder.u8 d with
    | 1 -> External (Tls.Decoder.opaque d)
    | 2 ->
        let usage = usage_of_int (Tls.Decoder.u8 d) in
        let psk_group_id = Tls.Decoder.opaque d in
        let psk_epoch = Tls.Decoder.u64 d in
        Resumption { usage; psk_group_id; psk_epoch }
    | n -> Tls.fail "unknown PSK type %d" n
  in
  let psk_nonce = Tls.Decoder.opaque d in
  { key; psk_nonce }

(* PSKLabel *)
let encode_label e (id, index, count) =
  encode_id e id;
  Tls.Encoder.u16 e index;
  Tls.Encoder.u16 e count

(* psk_secret derivation (RFC 9420 Section 8.4). [psks] pairs each
   PreSharedKeyID with its secret value, in proposal order. *)
let psk_secret c psks =
  let nh = Crypto.hash_size c in
  let zero = Crypto.zeros c in
  let count = List.length psks in
  let rec go acc index = function
    | [] -> Ok acc
    | (id, psk) :: rest -> (
        let psk_extracted = Crypto.hkdf_extract c ~salt:zero ~ikm:psk in
        let label = Tls.encode encode_label (id, index, count) in
        match
          Crypto.expand_with_label c ~secret:psk_extracted ~label:"derived psk"
            ~context:label nh
        with
        | Error e -> Error e
        | Ok psk_input ->
            go (Crypto.hkdf_extract c ~salt:psk_input ~ikm:acc) (index + 1) rest
        )
  in
  go zero 0 psks
