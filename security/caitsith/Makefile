caitsith-objs := permission.o gc.o memory.o policy_io.o realpath.o

obj-y += load_policy.o
ifdef CONFIG_CAITSITH_LKM
obj-m += caitsith.o
else
obj-y += caitsith.o
endif

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

$(obj)/policy_io.o: $(obj)/builtin-policy.h

$(obj)/check_security_file_ioctl_compat.h: $(srctree)/include/linux/security.h
	@echo Checking whether security_file_ioctl_compat is defined in include/linux/security.h or not.
	@grep -q security_file_ioctl_compat $(srctree)/include/linux/security.h && echo "#define HAVE_SECURITY_FILE_IOCTL_COMPAT" > $@.tmp || echo "" > $@.tmp
	@mv $@.tmp $@

$(obj)/load_policy.o: $(obj)/check_security_file_ioctl_compat.h
