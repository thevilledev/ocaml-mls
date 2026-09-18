(* Secret tree and hash ratchets (RFC 9420 Section 9). The state is immutable:
   every operation returns the updated tree. Node secrets are derived lazily and
   deleted once their children or ratchets exist. *)

module Int_map = Map.Make (Int)

module Skipped_key = struct
  type t = int * int * int (* leaf, content type, generation *)

  let compare = compare
end

module Skipped_map = Map.Make (Skipped_key)

type content_type = Handshake | Application

let content_type_index = function Handshake -> 0 | Application -> 1

type ratchet = { secret : string; generation : int }

type t = {
  crypto : Crypto.t;
  n_leaves : int;
  nodes : string Int_map.t;
  handshake : ratchet Int_map.t;
  application : ratchet Int_map.t;
  skipped : (string * string) Skipped_map.t;
}

let max_forward_distance = 2000
let max_skipped_keys = 2000
let max_generation = 0xffff_ffff

let create crypto ~n_leaves ~encryption_secret =
  {
    crypto;
    n_leaves;
    nodes = Int_map.singleton (Tree_math.root n_leaves) encryption_secret;
    handshake = Int_map.empty;
    application = Int_map.empty;
    skipped = Skipped_map.empty;
  }

let n_leaves t = t.n_leaves

let rec expand_to t node =
  if Int_map.mem node t.nodes then t
  else
    let parent = Tree_math.parent node t.n_leaves in
    let t = expand_to t parent in
    let ps = Int_map.find parent t.nodes in
    let nh = Crypto.hash_size t.crypto in
    let derive context =
      Crypto.expand_with_label t.crypto ~secret:ps ~label:"tree" ~context nh
    in
    let nodes =
      t.nodes |> Int_map.remove parent
      |> Int_map.add (Tree_math.left parent) (derive "left")
      |> Int_map.add (Tree_math.right parent) (derive "right")
    in
    { t with nodes }

let init_leaf t leaf =
  if Int_map.mem leaf t.handshake then t
  else
    let node = Tree_math.node_of_leaf leaf in
    let t = expand_to t node in
    let secret = Int_map.find node t.nodes in
    let nh = Crypto.hash_size t.crypto in
    let derive label =
      {
        secret = Crypto.expand_with_label t.crypto ~secret ~label ~context:"" nh;
        generation = 0;
      }
    in
    {
      t with
      nodes = Int_map.remove node t.nodes;
      handshake = Int_map.add leaf (derive "handshake") t.handshake;
      application = Int_map.add leaf (derive "application") t.application;
    }

let ratchet_key_nonce t r =
  let key =
    Crypto.derive_tree_secret t.crypto ~secret:r.secret ~label:"key"
      ~generation:r.generation
      (Crypto.aead_key_size t.crypto)
  in
  let nonce =
    Crypto.derive_tree_secret t.crypto ~secret:r.secret ~label:"nonce"
      ~generation:r.generation
      (Crypto.aead_nonce_size t.crypto)
  in
  (key, nonce)

let advance t r =
  {
    secret =
      Crypto.derive_tree_secret t.crypto ~secret:r.secret ~label:"secret"
        ~generation:r.generation
        (Crypto.hash_size t.crypto);
    generation = r.generation + 1;
  }

let get_ratchet t leaf ct =
  match ct with
  | Handshake -> Int_map.find leaf t.handshake
  | Application -> Int_map.find leaf t.application

let set_ratchet t leaf ct r =
  match ct with
  | Handshake -> { t with handshake = Int_map.add leaf r t.handshake }
  | Application -> { t with application = Int_map.add leaf r t.application }

let check_leaf t leaf =
  if leaf < 0 || leaf >= t.n_leaves then
    Error
      (Error.Invalid_message (Printf.sprintf "leaf index %d out of range" leaf))
  else Ok ()

(* Next key for sending from [leaf]. *)
let next_key t ~leaf ct =
  match check_leaf t leaf with
  | Error e -> Error e
  | Ok () ->
      let t = init_leaf t leaf in
      let r = get_ratchet t leaf ct in
      if r.generation >= max_generation then Error Error.Ratchet_exhausted
      else
        let key, nonce = ratchet_key_nonce t r in
        let t = set_ratchet t leaf ct (advance t r) in
        Ok ((key, nonce, r.generation), t)

(* Key for receiving a message from [leaf] at [generation]. Keys for skipped
   generations are retained (bounded) so that reordered messages can still be
   decrypted; each key can be obtained only once. *)
let key_for t ~leaf ct ~generation =
  match check_leaf t leaf with
  | Error e -> Error e
  | Ok () ->
      let t = init_leaf t leaf in
      let r = get_ratchet t leaf ct in
      let sk = (leaf, content_type_index ct, generation) in
      if generation < r.generation then
        match Skipped_map.find_opt sk t.skipped with
        | Some kn ->
            Ok (kn, { t with skipped = Skipped_map.remove sk t.skipped })
        | None -> Error (Error.Generation_out_of_range generation)
      else if generation - r.generation > max_forward_distance then
        Error (Error.Generation_out_of_range generation)
      else if
        Skipped_map.cardinal t.skipped + (generation - r.generation)
        > max_skipped_keys
      then Error (Error.Generation_out_of_range generation)
      else
        let rec go t r =
          if r.generation = generation then
            let kn = ratchet_key_nonce t r in
            Ok (kn, set_ratchet t leaf ct (advance t r))
          else
            let kn = ratchet_key_nonce t r in
            let t =
              {
                t with
                skipped =
                  Skipped_map.add
                    (leaf, content_type_index ct, r.generation)
                    kn t.skipped;
              }
            in
            go t (advance t r)
        in
        go t r
