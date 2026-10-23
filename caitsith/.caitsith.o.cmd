savedcmd_caitsith.o := ld -m elf_x86_64 -z noexecstack --no-warn-rwx-segments   -r -o caitsith.o @caitsith.mod  ; /usr/src/linux-headers-7.1.5-0-stable/tools/objtool/objtool --hacks=jump_label --hacks=noinstr --hacks=skylake --ibt --orc --retpoline --rethunk --static-call --uaccess --prefix=16  --link  --module caitsith.o

caitsith.o: $(wildcard /usr/src/linux-headers-7.1.5-0-stable/tools/objtool/objtool)
