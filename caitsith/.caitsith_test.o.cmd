savedcmd_caitsith_test.o := ld -m elf_x86_64 -z noexecstack --no-warn-rwx-segments   -r -o caitsith_test.o @caitsith_test.mod  ; /usr/src/linux-headers-7.1.5-0-stable/tools/objtool/objtool --hacks=jump_label --hacks=noinstr --hacks=skylake --ibt --orc --retpoline --rethunk --static-call --uaccess --prefix=16  --link  --module caitsith_test.o

caitsith_test.o: $(wildcard /usr/src/linux-headers-7.1.5-0-stable/tools/objtool/objtool)
