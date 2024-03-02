# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(tell-simple) begin
(tell-simple) tell(fd) = 0
(tell-simple) tell(fd) = 3
(tell-simple) end
tell-simple: exit(0)
EOF
pass;
