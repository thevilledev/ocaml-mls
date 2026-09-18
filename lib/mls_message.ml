(* MLSMessage (RFC 9420 Section 6). *)

type t =
  | Public_message of Framing.Public_message.t
  | Private_message of Framing.Private_message.t
  | Welcome of Welcome.t
  | Group_info of Group_info.t
  | Key_package of Key_package.t

let wire_format = function
  | Public_message _ -> Framing.wire_format_public_message
  | Private_message _ -> Framing.wire_format_private_message
  | Welcome _ -> Framing.wire_format_welcome
  | Group_info _ -> Framing.wire_format_group_info
  | Key_package _ -> Framing.wire_format_key_package

let encode e t =
  Tls.Encoder.u16 e Framing.protocol_version_mls10;
  Tls.Encoder.u16 e (wire_format t);
  match t with
  | Public_message m -> Framing.Public_message.encode e m
  | Private_message m -> Framing.Private_message.encode e m
  | Welcome w -> Welcome.encode e w
  | Group_info gi -> Group_info.encode e gi
  | Key_package kp -> Key_package.encode e kp

let decode d =
  let version = Tls.Decoder.u16 d in
  if version <> Framing.protocol_version_mls10 then
    Tls.fail "unsupported protocol version %d" version;
  match Tls.Decoder.u16 d with
  | 1 -> Public_message (Framing.Public_message.decode d)
  | 2 -> Private_message (Framing.Private_message.decode d)
  | 3 -> Welcome (Welcome.decode d)
  | 4 -> Group_info (Group_info.decode d)
  | 5 -> Key_package (Key_package.decode d)
  | n -> Tls.fail "unknown wire format %d" n

let to_bytes t = Tls.encode encode t
let of_bytes s = Error.of_decode (Tls.decode decode s)
