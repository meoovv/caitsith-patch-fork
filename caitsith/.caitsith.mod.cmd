savedcmd_caitsith.mod := printf '%s\n'   permission.o gc.o policy_io.o realpath.o probe.o lsm.o | awk '!x[$$0]++ { print("./"$$0) }' > caitsith.mod
