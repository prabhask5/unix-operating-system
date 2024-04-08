# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(alarm-priority-donation) begin
(alarm-priority-donation) Recipient thread acquired lock a.
(alarm-priority-donation) Recipient thread sleeping.
(alarm-priority-donation) Donor thread started.
(alarm-priority-donation) Recipient thread woke up.
(alarm-priority-donation) Donor thread acquired lock a.
(alarm-priority-donation) Donor thread finished.
(alarm-priority-donation) Sleeping thread 0 woke up.
(alarm-priority-donation) Sleeping thread 1 woke up.
(alarm-priority-donation) Sleeping thread 2 woke up.
(alarm-priority-donation) Sleeping thread 3 woke up.
(alarm-priority-donation) Sleeping thread 4 woke up.
(alarm-priority-donation) Sleeping thread 5 woke up.
(alarm-priority-donation) Sleeping thread 6 woke up.
(alarm-priority-donation) Sleeping thread 7 woke up.
(alarm-priority-donation) Sleeping thread 8 woke up.
(alarm-priority-donation) Sleeping thread 9 woke up.
(alarm-priority-donation) end
EOF
pass;
