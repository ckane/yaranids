rule slashdot_rule {
 strings:
  $slashdot = "\x08slashdot" nocase

 condition:
  any of them
}
