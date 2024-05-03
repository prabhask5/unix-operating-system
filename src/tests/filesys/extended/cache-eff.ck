# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(cache-eff) begin
(cache-eff) create "cache_test"
(cache-eff) open "cache_test"
(cache-eff) write "cache_test"
(cache-eff) close "cache_test"
(cache-eff) open "cache_test"
(cache-eff) close "cache_test"
(cache-eff) cold hit rate is "0"
(cache-eff) open "cache_test"
(cache-eff) close "cache_test"
(cache-eff) hot hit rate is "100"
(cache-eff) Hot cache hit rate is higher than cold cache hit rate
(cache-eff) end

EOF
pass;
