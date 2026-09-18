(* QCheck property tests. *)

open QCheck2
module Tls = Mls.Tls
module T = Mls.Tree_math

let varint_roundtrip =
  Test.make ~name:"varint round trip" ~count:2000
    (Gen.int_bound ((1 lsl 30) - 1))
    (fun n ->
      let e = Tls.Encoder.create () in
      Tls.Encoder.varint e n;
      Tls.decode Tls.Decoder.varint (Tls.Encoder.contents e) = Ok n)

let vector_roundtrip =
  Test.make ~name:"opaque vector round trip" ~count:500
    (Gen.list_size (Gen.int_bound 20) (Gen.string_size (Gen.int_bound 100)))
    (fun xs ->
      let enc e xs = Tls.Encoder.vector e Tls.Encoder.opaque xs in
      Tls.decode
        (fun d -> Tls.Decoder.vector d Tls.Decoder.opaque)
        (Tls.encode enc xs)
      = Ok xs)

let decode_total =
  Test.make ~name:"MLSMessage decoding never raises" ~count:2000
    (Gen.string_size (Gen.int_bound 300))
    (fun s -> match Mls.Mls_message.of_bytes s with Ok _ | Error _ -> true)

let tree_decode_total =
  Test.make ~name:"ratchet tree decoding never raises" ~count:1000
    (Gen.string_size (Gen.int_bound 300))
    (fun s -> match Mls.Ratchet_tree.of_bytes s with Ok _ | Error _ -> true)

let tree_math_invariants =
  Test.make ~name:"tree math invariants" ~count:1000
    (Gen.pair (Gen.int_range 1 2048) (Gen.int_bound 4096))
    (fun (n, x) ->
      let w = T.node_width n in
      let x = x mod w in
      let r = T.root n in
      let children_ok =
        T.is_leaf x
        || T.parent (T.left x) n = x
           && T.parent (T.right x) n = x
           && T.sibling (T.left x) n = T.right x
      in
      let parent_ok =
        x = r
        ||
        let p = T.parent x n in
        (T.left p = x || T.right p = x)
        && T.sibling (T.sibling x n) n = x
        && T.is_in_subtree x p
      in
      let dp = T.direct_path x n in
      let path_ok =
        (x = r && dp = []) || List.nth dp (List.length dp - 1) = r
      in
      children_ok && parent_ok && path_ok
      && List.length (T.copath x n) = List.length dp
      && T.common_ancestor x r n = r
      && T.common_ancestor x x n = x)

let secret_tree_distinct =
  Test.make ~name:"secret tree keys are distinct" ~count:30
    (Gen.pair (Gen.int_range 1 16) (Gen.int_range 1 6))
    (fun (n, gens) ->
      let c = Mls.Crypto.create_exn 1 in
      let tree =
        ref
          (Mls.Secret_tree.create c ~n_leaves:n
             ~encryption_secret:(String.make 32 'x'))
      in
      let keys = ref [] in
      for leaf = 0 to n - 1 do
        for _ = 1 to gens do
          List.iter
            (fun ct ->
              match Mls.Secret_tree.next_key !tree ~leaf ct with
              | Ok ((k, nonce, _), t) ->
                  keys := (k ^ nonce) :: !keys;
                  tree := t
              | Error _ -> ())
            [ Mls.Secret_tree.Handshake; Mls.Secret_tree.Application ]
        done
      done;
      List.length (List.sort_uniq compare !keys) = List.length !keys)

let hex_roundtrip =
  Test.make ~name:"hex round trip" ~count:500
    (Gen.string_size (Gen.int_bound 64))
    (fun s -> Mls.Hex.decode (Mls.Hex.encode s) = Ok s)

let tests =
  List.map
    (QCheck_alcotest.to_alcotest ~speed_level:`Quick)
    [
      varint_roundtrip;
      vector_roundtrip;
      decode_total;
      tree_decode_total;
      tree_math_invariants;
      secret_tree_distinct;
      hex_roundtrip;
    ]
