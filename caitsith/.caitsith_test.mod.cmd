savedcmd_caitsith_test.mod := printf '%s\n'   test.o probe.o | awk '!x[$$0]++ { print("./"$$0) }' > caitsith_test.mod
