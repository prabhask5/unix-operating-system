# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(coalesce-write) begin
(coalesce-write) create "cache_test"
(coalesce-write) open "cache_test"
(coalesce-write) close "cache_test"
(coalesce-write) open "cache_test"
(coalesce-write) close "cache_test"
(coalesce-write) coalesces write acceptably
(coalesce-write) end


EOF
pass;
