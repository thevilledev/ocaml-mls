(* TLS presentation-language codec (RFC 8446 Section 3, as profiled by RFC 9420
   Section 2.1). Multi-byte integers are big-endian. Variable-length vectors use
   the QUIC-style variable-length integer header with the minimum-size encoding
   requirement of RFC 9420 Section 2.1.2. *)

exception Decode_error of string

let fail fmt = Printf.ksprintf (fun s -> raise (Decode_error s)) fmt

module Encoder = struct
  type t = Buffer.t

  let create () = Buffer.create 256
  let contents = Buffer.contents
  let raw t s = Buffer.add_string t s

  let u8 t v =
    if v < 0 || v > 0xff then invalid_arg "Tls.Encoder.u8";
    Buffer.add_char t (Char.unsafe_chr v)

  let u16 t v =
    if v < 0 || v > 0xffff then invalid_arg "Tls.Encoder.u16";
    Buffer.add_uint16_be t v

  let u32 t v =
    if v < 0 || v > 0xffff_ffff then invalid_arg "Tls.Encoder.u32";
    Buffer.add_int32_be t (Int32.of_int v)

  let u64 t v = Buffer.add_int64_be t v

  let varint t n =
    if n < 0 then invalid_arg "Tls.Encoder.varint"
    else if n < 0x40 then u8 t n
    else if n < 0x4000 then u16 t (0x4000 lor n)
    else if n < 0x4000_0000 then u32 t (0x8000_0000 lor n)
    else invalid_arg "Tls.Encoder.varint: value exceeds 2^30 - 1"

  let opaque t s =
    varint t (String.length s);
    raw t s

  let nested t f =
    let inner = create () in
    f inner;
    opaque t (contents inner)

  let vector t f xs = nested t (fun inner -> List.iter (f inner) xs)

  let optional t f = function
    | None -> u8 t 0
    | Some x ->
        u8 t 1;
        f t x

  let fixed t n s =
    if String.length s <> n then
      invalid_arg (Printf.sprintf "Tls.Encoder.fixed: expected %d bytes" n);
    raw t s
end

module Decoder = struct
  type t = { s : string; mutable pos : int; limit : int }

  let of_string ?(pos = 0) ?len s =
    let len = match len with None -> String.length s - pos | Some l -> l in
    if pos < 0 || len < 0 || pos + len > String.length s then
      invalid_arg "Tls.Decoder.of_string";
    { s; pos; limit = pos + len }

  let remaining t = t.limit - t.pos
  let at_end t = t.pos >= t.limit

  let need t n =
    if remaining t < n then
      fail "unexpected end of input: need %d bytes, have %d" n (remaining t)

  let u8 t =
    need t 1;
    let v = Char.code (String.unsafe_get t.s t.pos) in
    t.pos <- t.pos + 1;
    v

  let u16 t =
    need t 2;
    let v = String.get_uint16_be t.s t.pos in
    t.pos <- t.pos + 2;
    v

  let u32 t =
    need t 4;
    let v = String.get_int32_be t.s t.pos in
    t.pos <- t.pos + 4;
    Int32.to_int v land 0xffff_ffff

  let u64 t =
    need t 8;
    let v = String.get_int64_be t.s t.pos in
    t.pos <- t.pos + 8;
    v

  let raw t n =
    need t n;
    let v = String.sub t.s t.pos n in
    t.pos <- t.pos + n;
    v

  let varint t =
    let b0 = u8 t in
    match b0 lsr 6 with
    | 0 -> b0 land 0x3f
    | 1 ->
        let b1 = u8 t in
        let v = ((b0 land 0x3f) lsl 8) lor b1 in
        if v < 0x40 then fail "non-minimal varint encoding";
        v
    | 2 ->
        let b1 = u8 t in
        let b2 = u8 t in
        let b3 = u8 t in
        let v = ((b0 land 0x3f) lsl 24) lor (b1 lsl 16) lor (b2 lsl 8) lor b3 in
        if v < 0x4000 then fail "non-minimal varint encoding";
        v
    | _ -> fail "invalid varint prefix (0b11 is reserved)"

  let opaque t =
    let n = varint t in
    raw t n

  let sub t n =
    need t n;
    let d = { s = t.s; pos = t.pos; limit = t.pos + n } in
    t.pos <- t.pos + n;
    d

  let nested t f =
    let n = varint t in
    let d = sub t n in
    let v = f d in
    if not (at_end d) then
      fail "trailing bytes inside length-prefixed structure";
    v

  let vector t f =
    nested t (fun d ->
        let rec loop acc =
          if at_end d then List.rev acc
          else
            let x = f d in
            loop (x :: acc)
        in
        loop [])

  let optional t f =
    match u8 t with
    | 0 -> None
    | 1 -> Some (f t)
    | n -> fail "invalid optional tag %d" n

  (* Run [f] on the remaining input and return the bytes it consumed. *)
  let with_slice t f =
    let start = t.pos in
    let v = f t in
    (v, String.sub t.s start (t.pos - start))
end

let encode f v =
  let e = Encoder.create () in
  f e v;
  Encoder.contents e

let decode f s =
  let d = Decoder.of_string s in
  match f d with
  | v ->
      if Decoder.at_end d then Ok v
      else
        Error
          (Printf.sprintf "trailing bytes after structure: %d"
             (Decoder.remaining d))
  | exception Decode_error msg -> Error msg

let decode_exn f s =
  match decode f s with Ok v -> v | Error msg -> raise (Decode_error msg)
