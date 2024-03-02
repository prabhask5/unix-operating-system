# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(seek-simple) begin
(seek-simple) end
seek-simple: exit(0)
EOF
pass;
