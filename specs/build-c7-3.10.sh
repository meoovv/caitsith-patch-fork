#! /bin/sh
#
# This is a kernel build script for CentOS 7's 3.10 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-3.10.0-1160.118.1.el7.src.rpm ]
then
    wget https://vault.centos.org/centos/7/updates/Source/SPackages/kernel-3.10.0-1160.118.1.el7.src.rpm || die "Can't download source package."
fi
LANG=C rpm --checksig kernel-3.10.0-1160.118.1.el7.src.rpm | grep -F ': rsa sha1 (md5) pgp md5 OK' || die "Can't verify signature."
rpm -ivh kernel-3.10.0-1160.118.1.el7.src.rpm || die "Can't install source package."

cd ~/rpmbuild/SOURCES/ || die "Can't chdir to ~/rpmbuild/SOURCES/ ."
if [ ! -r caitsith-patch-0.2-20260928.tar.gz ]
then
    wget https://sourceforge.net/projects/tomoyo/files/caitsith-patch/0.2/caitsith-patch-0.2-20260928.tar.gz || die "Can't download patch."
fi

cd ~/rpmbuild/SPECS/ || die "Can't chdir to ~/rpmbuild/SPECS/ ."
cp -p kernel.spec cs-kernel.spec || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- cs-kernel.spec
+++ cs-kernel.spec
@@ -5,7 +5,7 @@
 
 %define dist .el7
 
-# % define buildid .local
+%define buildid _caitsith_0.2.16
 
 # If there's no unversioned python, select version explicitly,
 # so it's possible to at least do rh-srpm.
@@ -331,7 +331,7 @@
 AutoProv: yes\
 %{nil}
 
-Name: kernel%{?variant}
+Name: cs-kernel%{?variant}
 Group: System Environment/Kernel
 License: GPLv2
 URL: http://www.kernel.org/
@@ -690,13 +690,13 @@
 %package %{?1:%{1}-}devel\
 Summary: Development package for building kernel modules to match the %{?2:%{2} }kernel\
 Group: System Environment/Kernel\
-Provides: kernel%{?1:-%{1}}-devel-%{_target_cpu} = %{version}-%{release}\
-Provides: kernel-devel-%{_target_cpu} = %{version}-%{release}%{?1:.%{1}}\
-Provides: kernel-devel-uname-r = %{KVRA}%{?1:.%{1}}\
+Provides: cs-kernel%{?1:-%{1}}-devel-%{_target_cpu} = %{version}-%{release}\
+Provides: cs-kernel-devel-%{_target_cpu} = %{version}-%{release}%{?1:.%{1}}\
+Provides: cs-kernel-devel-uname-r = %{KVRA}%{?1:.%{1}}\
 AutoReqProv: no\
 Requires(pre): /usr/bin/find\
 Requires: perl\
-%description -n kernel%{?variant}%{?1:-%{1}}-devel\
+%description -n cs-kernel%{?variant}%{?1:-%{1}}-devel\
 This package provides kernel headers and makefiles sufficient to build modules\
 against the %{?2:%{2} }kernel package.\
 %{nil}
@@ -808,6 +808,10 @@
 ApplyOptionalPatch debrand-rh_taint.patch
 ApplyOptionalPatch debrand-rh-i686-cpu.patch
 
+# CaitSith
+tar -zxf %_sourcedir/caitsith-patch-0.2-20260928.tar.gz
+sed -i -e 's/CCSECURITY/CAITSITH/g' -e 's/ccsecurity/caitsith/g' -e 's/ccs_domain_info/cs_domain_info/g' -e 's/ccs_flags/cs_flags/g' patches/ccs-patch-*.diff
+patch -sp1 < patches/ccs-patch-3.10-centos-7.diff
 # Any further pre-build tree manipulations happen here.
 
 chmod +x scripts/checkpatch.pl
@@ -846,6 +850,17 @@
 for i in *.config
 do
   mv $i .config
+  # TOMOYO Linux 2.5
+  sed -i -e 's/# CONFIG_SECURITY_PATH is not set/CONFIG_SECURITY_PATH=y/' -- .config
+  sed -i -e 's/# CONFIG_SECURITY_TOMOYO is not set/CONFIG_SECURITY_TOMOYO=y/' -- .config
+  echo 'CONFIG_SECURITY_TOMOYO_MAX_ACCEPT_ENTRY=2048' >> .config
+  echo 'CONFIG_SECURITY_TOMOYO_MAX_AUDIT_LOG=1024' >> .config
+  echo '# CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER is not set' >> .config
+  echo 'CONFIG_SECURITY_TOMOYO_POLICY_LOADER="/sbin/tomoyo-init"' >> .config
+  echo 'CONFIG_SECURITY_TOMOYO_ACTIVATION_TRIGGER="/usr/lib/systemd/systemd"' >> .config
+  echo '# CONFIG_DEFAULT_SECURITY_TOMOYO is not set' >> .config
+  # CaitSith
+  sed -e 's@/sbin/init@/usr/lib/systemd/systemd@' -- config.caitsith >> .config
   Arch=`head -1 .config | cut -b 3-`
   make %{?cross_opts} ARCH=$Arch listnewconfig | grep -E '^CONFIG_' >.newoptions || true
 %if %{listnewconfig_fail}
EOF
echo ""
echo ""
echo ""
echo "Edit ~/rpmbuild/SPECS/cs-kernel.spec if needed, and run"
echo "rpmbuild -bb ~/rpmbuild/SPECS/cs-kernel.spec"
echo "to build kernel rpm packages."
echo ""
ARCH=`uname -m`
echo "I'll start 'rpmbuild -bb --target $ARCH --with baseonly --without debug --without debuginfo ~/rpmbuild/SPECS/cs-kernel.spec' in 30 seconds. Press Ctrl-C to stop."
sleep 30
exec rpmbuild -bb --target $ARCH --with baseonly --without debug --without debuginfo ~/rpmbuild/SPECS/cs-kernel.spec
exit 0
