caitsith-objs := permission.o gc.o policy_io.o realpath.o probe.o lsm.o
caitsith_test-objs := test.o probe.o
obj-m += caitsith_test.o caitsith.o

$(obj)/policy/policy.conf:
	@mkdir -p $(obj)/policy/
	@echo Creating an empty policy/policy.conf
	@touch $@

$(obj)/builtin-policy.h: $(obj)/policy/policy.conf
	@echo Generating built-in policy for CaitSith 0.2.
	@echo "static char cs_builtin_policy[] __initdata =" > $@.tmp
	@sed -e 's/\\/\\134/g' -e 's/"/\\"/g' -e 's/\(.*\)/"\1\\n"/' < $(obj)/policy/policy.conf >> $@.tmp
	@echo "\"\";" >> $@.tmp
	@mv $@.tmp $@

$(obj)/policy_io.o: $(obj)/builtin-policy.h $(obj)/config.h

$(obj)/check_umode_t.h:
	@echo Checking whether umode_t is used by include/linux/security.h or not.
	@grep -q umode_t $(srctree)/include/linux/security.h && echo "#define USE_UMODE_T" > $@.tmp || echo "" > $@.tmp
	@mv $@.tmp $@

$(obj)/check_security_file_ioctl_compat.h: $(srctree)/include/linux/security.h
	@echo Checking whether security_file_ioctl_compat is defined in include/linux/security.h or not.
	@grep -q security_file_ioctl_compat $(srctree)/include/linux/security.h && echo "#define HAVE_SECURITY_FILE_IOCTL_COMPAT" > $@.tmp || echo "" > $@.tmp
	@mv $@.tmp $@

$(obj)/lsm.o: $(obj)/check_umode_t.h $(obj)/check_security_file_ioctl_compat.h $(obj)/config.h

.o: $(obj)/config.h
