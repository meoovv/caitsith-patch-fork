#! /bin/sh
#
# This is a kernel build script for CentOS Stream 8's 4.18 kernel.
#

die () {
    echo $1
    exit 1
}

cd /tmp/ || die "Can't chdir to /tmp/ ."

if [ ! -r kernel-4.18.0-448.el8.src.rpm ]
then
    wget https://vault.centos.org/centos/8-stream/BaseOS/Source/SPackages/kernel-4.18.0-448.el8.src.rpm || die "Can't download source package."
fi
LANG=C rpm --checksig kernel-4.18.0-448.el8.src.rpm | grep -F ': digests signatures OK' || die "Can't verify signature."
rpm -ivh kernel-4.18.0-448.el8.src.rpm || die "Can't install source package."

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
@@ -35,7 +35,7 @@
 %global zipsed -e 's/\.ko$/\.ko.xz/'
 %endif
 
-# define buildid .local
+%define buildid _caitsith_0.2.16
 
 %define rpmversion 4.18.0
 %define pkgrelease 448.el8
@@ -1085,6 +1085,10 @@
 
 # END OF PATCH APPLICATIONS
 
+# CaitSith
+tar -zxf %_sourcedir/caitsith-patch-0.2-20260928.tar.gz
+sed -i -e 's/CCSECURITY/CAITSITH/g' -e 's/ccsecurity/caitsith/g' -e 's/ccs_domain_info/cs_domain_info/g' -e 's/ccs_flags/cs_flags/g' patches/ccs-patch-*.diff
+patch -sp1 < patches/ccs-patch-4.18-centos-8.diff
 # Any further pre-build tree manipulations happen here.
 
 %if %{with_realtime}
@@ -1212,6 +1216,9 @@
     cp %{SOURCE9} certs/.
     %endif
 
+    # CaitSith
+    sed -e 's@/sbin/init@/usr/lib/systemd/systemd@' -- config.caitsith >> .config
+
     Arch=`head -1 .config | cut -b 3-`
     echo USING ARCH=$Arch
 
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
