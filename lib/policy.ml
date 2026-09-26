(* Application validation policy (RFC 9420 Section 7.3). The library cannot read
   a clock or know the application's limits, so the application supplies them
   here and each group applies them to the leaf nodes it validates. *)

type t = { clock : (unit -> int64) option; max_lifetime : int64 option }

let default = { clock = None; max_lifetime = None }
let make ?clock ?max_lifetime () = { clock; max_lifetime }

(* Lifetimes are uint64 seconds since the Unix epoch, so every comparison is
   unsigned: [Leaf_node.unbounded_lifetime] ends at 2^64 - 1. *)
let le a b = Int64.unsigned_compare a b <= 0

let check_lifetime t (l : Leaf_node.lifetime) =
  let fail msg = Error (Error.Invalid_key_package msg) in
  let { Leaf_node.not_before; not_after } = l in
  let checked = Option.is_some t.clock || Option.is_some t.max_lifetime in
  let within_max =
    match t.max_lifetime with
    | Some max -> le (Int64.sub not_after not_before) max
    | None -> true
  in
  if not checked then Ok ()
  else if not (le not_before not_after) then
    fail "lifetime ends before it starts"
  else if not within_max then fail "lifetime exceeds the maximum"
  else
    match Option.map (fun now -> now ()) t.clock with
    | Some now when not (le not_before now) -> fail "lifetime not yet valid"
    | Some now when not (le now not_after) -> fail "lifetime expired"
    | _ -> Ok ()

let check_leaf_node t (ln : Leaf_node.t) =
  match ln.Leaf_node.leaf_node_source with
  | Leaf_node.Key_package l -> check_lifetime t l
  | Leaf_node.Update | Leaf_node.Commit _ -> Ok ()
