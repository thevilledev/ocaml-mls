(* The subset of the protocol buffers (proto3) wire format that
   mls_client.proto needs: varint fields (uint32, uint64, bool), length-delimited
   fields (bytes, string, nested messages, packed repeated varints), and
   repeated fields. Unknown fields and fixed-width wire types are skipped. *)

exception Malformed of string

type value = Varint of int | Bytes of string

(* Decoding *)

type fields = (int * value) list

let decode s : fields =
  let n = String.length s in
  let pos = ref 0 in
  let byte () =
    if !pos >= n then raise (Malformed "truncated");
    let b = Char.code s.[!pos] in
    incr pos;
    b
  in
  let varint () =
    let rec go acc shift =
      if shift > 63 then raise (Malformed "varint too long");
      let b = byte () in
      let acc = acc lor ((b land 0x7f) lsl shift) in
      if b land 0x80 = 0 then acc else go acc (shift + 7)
    in
    go 0 0
  in
  let skip k =
    if !pos + k > n then raise (Malformed "truncated");
    pos := !pos + k
  in
  let rec fields acc =
    if !pos >= n then List.rev acc
    else
      let key = varint () in
      let field = key lsr 3 in
      match key land 7 with
      | 0 -> fields ((field, Varint (varint ())) :: acc)
      | 2 ->
          let len = varint () in
          if len < 0 || !pos + len > n then raise (Malformed "truncated");
          let v = String.sub s !pos len in
          pos := !pos + len;
          fields ((field, Bytes v) :: acc)
      | 1 ->
          skip 8;
          fields acc
      | 5 ->
          skip 4;
          fields acc
      | t -> raise (Malformed (Printf.sprintf "wire type %d" t))
  in
  fields []

let all fs n = List.filter_map (fun (f, v) -> if f = n then Some v else None) fs

let last fs n =
  match List.rev (all fs n) with v :: _ -> Some v | [] -> None

let bytes fs n =
  match last fs n with
  | Some (Bytes s) -> s
  | Some (Varint _) -> raise (Malformed "expected bytes")
  | None -> ""

let int fs n =
  match last fs n with
  | Some (Varint v) -> v
  | Some (Bytes _) -> raise (Malformed "expected a varint")
  | None -> 0

let bool fs n = int fs n <> 0

let message fs n =
  match last fs n with Some (Bytes s) -> Some (decode s) | _ -> None

let repeated_bytes fs n =
  List.map
    (function Bytes s -> s | Varint _ -> raise (Malformed "expected bytes"))
    (all fs n)

let repeated_messages fs n = List.map decode (repeated_bytes fs n)

(* Encoding *)

module Writer = struct
  type t = Buffer.t

  let create () = Buffer.create 64
  let contents = Buffer.contents

  let varint b v =
    let rec go v =
      if v land lnot 0x7f = 0 then Buffer.add_char b (Char.chr v)
      else (
        Buffer.add_char b (Char.chr (v land 0x7f lor 0x80));
        go (v lsr 7))
    in
    go v

  let key b n wire = varint b ((n lsl 3) lor wire)

  (* proto3 omits fields that hold their default value. *)
  let int b n v =
    if v <> 0 then (
      key b n 0;
      varint b v)

  let bool b n v = int b n (if v then 1 else 0)

  let bytes b n s =
    if s <> "" then (
      key b n 2;
      varint b (String.length s);
      Buffer.add_string b s)

  let message b n s =
    key b n 2;
    varint b (String.length s);
    Buffer.add_string b s

  let packed_ints b n l =
    if l <> [] then (
      let inner = create () in
      List.iter (varint inner) l;
      bytes b n (contents inner))
end

let encode f =
  let b = Writer.create () in
  f b;
  Writer.contents b
