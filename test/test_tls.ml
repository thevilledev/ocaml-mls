open Vectors
module Tls = Mls.Tls

let test_deserialization () =
  List.iter
    (fun v ->
      let header = hex_field v "vlbytes_header" in
      let expected = int_field v "length" in
      let d = Tls.Decoder.of_string header in
      Alcotest.(check int)
        ("varint " ^ Mls.Hex.encode header)
        expected (Tls.Decoder.varint d);
      Alcotest.(check bool) "consumed header" true (Tls.Decoder.at_end d);
      (* Re-encoding must produce the minimal header. *)
      let e = Tls.Encoder.create () in
      Tls.Encoder.varint e expected;
      check_bytes "re-encoded varint" header (Tls.Encoder.contents e))
    (load "deserialization.json")

let test_varint_minimal () =
  (* Non-minimal encodings must be rejected (RFC 9420 Section 2.1.2). *)
  let rejects s =
    match Tls.decode Tls.Decoder.varint s with Ok _ -> false | Error _ -> true
  in
  Alcotest.(check bool) "two-byte encoding of 1" true (rejects "\x40\x01");
  Alcotest.(check bool)
    "four-byte encoding of 300" true
    (rejects "\x80\x00\x01\x2c");
  Alcotest.(check bool)
    "reserved prefix" true
    (rejects "\xc0\x00\x00\x00\x00\x00\x00\x00");
  Alcotest.(check bool) "truncated" true (rejects "\x40")

let test_roundtrip () =
  let open Tls in
  let enc e (a, b, c, d, xs, o) =
    Encoder.u8 e a;
    Encoder.u16 e b;
    Encoder.u32 e c;
    Encoder.u64 e d;
    Encoder.vector e Encoder.opaque xs;
    Encoder.optional e Encoder.u32 o
  in
  let dec d =
    let a = Decoder.u8 d in
    let b = Decoder.u16 d in
    let c = Decoder.u32 d in
    let x = Decoder.u64 d in
    let xs = Decoder.vector d Decoder.opaque in
    let o = Decoder.optional d Decoder.u32 in
    (a, b, c, x, xs, o)
  in
  let v =
    ( 0xff,
      0xabcd,
      0xdead_beef,
      0xffff_ffff_ffff_ffffL,
      [ "a"; ""; String.make 70 'x' ],
      Some 7 )
  in
  let bytes = encode enc v in
  match decode dec bytes with
  | Ok v' -> Alcotest.(check bool) "roundtrip" true (v = v')
  | Error msg -> Alcotest.fail msg

let tests =
  [
    Alcotest.test_case "deserialization.json" `Quick test_deserialization;
    Alcotest.test_case "minimal varint" `Quick test_varint_minimal;
    Alcotest.test_case "roundtrip" `Quick test_roundtrip;
  ]
