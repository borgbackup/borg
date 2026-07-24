Return codes
~~~~~~~~~~~~

Borg can exit with the following return codes (rc):

=========== =======
Return code Meaning
=========== =======
0           success (logged as INFO)
1           generic warning (operation reached its normal end, but there
            were warnings - you should check the log; logged as WARNING)
2           generic error (such as a fatal error or a local/remote exception;
            the operation did not reach its normal end; logged as ERROR)
3..99       specific error (see below; logged as ERROR)
100..127    specific warning (see below; logged as WARNING)
128+N       terminated by signal N (e.g. 130 == SIGINT, Ctrl+C, or kill -2;
            logged as ERROR)
=========== =======

If you use ``--show-rc``, the return code is also logged at the indicated
level as the last log entry.

Borg categorizes return codes into groups and exits with the more severe
group: signals (rc 128+N) are more severe than errors (rc 2 and 3..99),
which take precedence over warnings (rc 1 and 100..127), and lastly
success (rc 0).

Within the signal and error groups, the first signal or error determines
the final return code. Within the warning group, Borg returns the specific
warning code (rc 100..127) if there were one or more warnings of the same
kind. If warnings of different kinds occurred, Borg returns the generic
warning code (rc 1) instead. All errors and warnings are still logged
individually.

Borg 2 exits with specific error (rc 3..99) and warning (rc 100..127) codes
by default. If you want Borg 2 to always exit with the generic error (rc 2)
or generic warning (rc 1) code instead (like Borg 1 did), set the
``BORG_EXIT_CODES=legacy`` environment variable.

For a list of all specific error and warning codes, see :ref:`msgid`.
