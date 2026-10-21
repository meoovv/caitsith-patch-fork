#! /bin/sh
#
# This is a kernel build script for VineLinux 6's 4.4 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-4.4.110-2vl6.src.rpm ]
then
    wget http://updates.vinelinux.org/Vine-6.5/updates/SRPMS/kernel-4.4.110-2vl6.src.rpm || die "Can't download source package."
fi
LANG=C rpm --checksig kernel-4.4.110-2vl6.src.rpm | grep -F ': (sha1) dsa sha1 md5 gpg OK' || die "Can't verify signature."
rpm -ivh kernel-4.4.110-2vl6.src.rpm || die "Can't install source package."

cd ~/rpm/SOURCES/ || die "Can't chdir to ~/rpm/SOURCES/ ."
if [ ! -r caitsith-patch-0.2-20260928.tar.gz ]
then
    wget https://sourceforge.net/projects/tomoyo/files/caitsith-patch/0.2/caitsith-patch-0.2-20260928.tar.gz || die "Can't download patch."
fi

cd /tmp/ || die "Can't chdir to /tmp/ ."
cp -p ~/rpm/SPECS/kernel44-vl.spec . || die "Can't copy spec file."
patch << "EOF" || die "Can't patch spec file."
--- kernel44-vl.spec
+++ kernel44-vl.spec
@@ -34,7 +34,7 @@
 %define patchlevel 110
 %define kversion 4.%{sublevel}
 %define rpmversion 4.%{sublevel}.%{patchlevel}
-%define release 2%{?_dist_release}
+%define release 2%{?_dist_release}_caitsith_0.2.16
 
 %define make_target bzImage
 %define hdrarch %_target_cpu
@@ -126,6 +126,9 @@
 # to versions below the minimum
 #
 
+
+%define signmodules 0
+
 #
 # First the general kernel 2.6 required versions as per
 # Documentation/Changes
@@ -158,7 +161,7 @@
 #
 %define kernel_prereq  fileutils, %{kmod}, initscripts >= 8.80, mkinitrd >= 6.0.93, linux-firmware >= 20110601-1
 
-Name: kernel
+Name: cs-kernel
 Group: System Environment/Kernel
 License: GPLv2
 Version: %{rpmversion}
@@ -670,6 +673,10 @@
 
 # END OF PATCH APPLICATIONS
 
+# CaitSith
+tar -zxf %_sourcedir/caitsith-patch-0.2-20260928.tar.gz
+sed -i -e 's/CCSECURITY/CAITSITH/g' -e 's/ccsecurity/caitsith/g' -e 's/ccs_domain_info/cs_domain_info/g' -e 's/ccs_flags/cs_flags/g' patches/ccs-patch-*.diff
+patch -sp1 < patches/ccs-patch-4.4-vine-linux-6.diff
 cp %{SOURCE10} Documentation/
 
 # put Vine logo
@@ -688,6 +695,9 @@
 for i in *.config
 do 
 	mv $i .config 
+	# CaitSith
+	cat config.caitsith >> .config
+	sed -i -e "s/^CONFIG_DEBUG_INFO=.*/# CONFIG_DEBUG_INFO is not set/" -- .config
 	Arch=`head -1 .config | cut -b 3-`
 	make ARCH=$Arch oldnoconfig
 	echo "# $Arch" > configs/$i
EOF
mv kernel44-vl.spec cs-kernel.spec || die "Can't rename spec file."
echo ""
echo ""
echo ""
echo "Edit /tmp/cs-kernel.spec if needed, and run"
echo "rpmbuild -bb /tmp/cs-kernel.spec"
echo "to build kernel rpm packages."
echo ""
ARCH=`uname -m`
echo "I'll start 'rpmbuild -bb --target $ARCH /tmp/cs-kernel.spec' in 30 seconds. Press Ctrl-C to stop."
sleep 30
exec rpmbuild -bb --target $ARCH /tmp/cs-kernel.spec
exit 0
