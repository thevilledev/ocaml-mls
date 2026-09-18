(* Helpers for the mlswg/mls-implementations JSON test vectors. *)

open Yojson.Safe.Util

let load name : Yojson.Safe.t list =
  Yojson.Safe.from_file (Filename.concat "vectors" name) |> to_list

let hex json = Mls.Hex.decode_exn (to_string json)
let hex_field j k = hex (member k j)
let int_field j k = to_int (member k j)
let string_field j k = to_string (member k j)

let opt_hex_field j k =
  match member k j with `Null -> None | v -> Some (hex v)

let int64_field j k =
  match member k j with
  | `Int i -> Int64.of_int i
  | `Intlit s -> Int64.of_string s
  | _ -> failwith ("expected integer field " ^ k)

let check_bytes name expected actual =
  Alcotest.(check string) name (Mls.Hex.encode expected) (Mls.Hex.encode actual)

let opt_int json = match json with `Null -> None | v -> Some (to_int v)
let opt_hex json = match json with `Null -> None | v -> Some (hex v)
let ok = function Ok v -> v | Error e -> Alcotest.fail (Mls.Error.to_string e)
