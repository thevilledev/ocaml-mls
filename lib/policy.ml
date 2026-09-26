(* Application policy (RFC 9420 Sections 5.3.1, 7.3 and 9.2). The library cannot
   read a clock, know the application's limits, or authenticate identities, so
   the application supplies them here and each group applies them to the leaf
   nodes and credentials it validates. The policy also sets how long a group
   keeps the secrets of past epochs. *)

type credential_event =
  | Add
  | Join
  | Replace of { credential : Credential.t; signature_key : string }
  | External_sender

type credential_validator =
  credential_event ->
  credential:Credential.t ->
  signature_key:string ->
  (unit, string) result

type t = {
  clock : (unit -> int64) option;
  max_lifetime : int64 option;
  validate_credential : credential_validator option;
  max_past_epochs : int;
}

let default =
  {
    clock = None;
    max_lifetime = None;
    validate_credential = None;
    max_past_epochs = 0;
  }

let make ?clock ?max_lifetime ?validate_credential ?(max_past_epochs = 0) () =
  { clock; max_lifetime; validate_credential; max_past_epochs }

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

let check_credential t event ~credential ~signature_key =
  match t.validate_credential with
  | None -> Ok ()
  | Some validate -> (
      match validate event ~credential ~signature_key with
      | Ok () -> Ok ()
      | Error msg -> Error (Error.Invalid_credential msg))
