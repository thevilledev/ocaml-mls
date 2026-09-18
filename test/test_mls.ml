let () =
  Alcotest.run "mls"
    [
      ("tree_math", Test_tree_math.tests);
      ("tls", Test_tls.tests);
      ("crypto", Test_crypto.tests);
      ("messages", Test_messages.tests);
      ("key_schedule", Test_key_schedule.tests);
      ("tree", Test_tree.tests);
      ("message_protection", Test_message_protection.tests);
      ("treekem", Test_treekem.tests);
      ("passive", Test_passive.tests);
      ("group", Test_group.tests);
    ]
