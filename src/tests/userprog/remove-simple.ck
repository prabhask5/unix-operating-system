# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(remove-simple) begin
(remove-simple) remove() correctly returned TRUE
(remove-simple) fd is -1, should be -1
(remove-simple) remove() correctly returned FALSE
(remove-simple) end
remove-simple: exit(0)
EOF
pass;