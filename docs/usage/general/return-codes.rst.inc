Return codes
~~~~~~~~~~~~

Borg can exit with the following return codes (rc):

=========== =======
Return code Meaning
=========== =======
0           success (logged as INFO)
1           warning (operation reached its normal end, but there were warnings --
            you should check the log, logged as WARNING)
2           error (like a fatal error, a local or remote exception, the operation
            did not reach its normal end, logged as ERROR)
128+N       killed by signal N (e.g. 137 == kill -9)
=========== =======

If you use ``--show-rc``, the return code is also logged at the indicated
level as the last log entry.
