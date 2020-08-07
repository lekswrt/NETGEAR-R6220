# SC_BUILD
include ../../../sc_trunk/Rules.mak

ifeq ($(SMB_4_6_4_LIBINTMP),1)
SMB_LIB_PATH_IN_FS=/lib/smblibforcp/
else
SMB_LIB_PATH_IN_FS=/lib/
endif

all:
	cd python && make
	cd keyutils && make
	cd krb5 && make
	cd samba && make

install_python:
	# python
	cp -a $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/idle $(TARGET_DIR)/usr/sbin/
	cp -a $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/python2.7 $(TARGET_DIR)/usr/sbin/
	cp -a $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/python2 $(TARGET_DIR)/usr/sbin/
	cp -a $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/python $(TARGET_DIR)/usr/sbin/
	cp -a $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/python2-config $(TARGET_DIR)/usr/sbin/
	cp -a $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/python-config $(TARGET_DIR)/usr/sbin/
	cp -a $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/python2.7-config $(TARGET_DIR)/usr/sbin/
	cp -a $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/smtpd.py $(TARGET_DIR)/usr/sbin/
	cp -af $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/libffi.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/libpython2.7.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/python2.7/* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/pkgconfig/ $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/lib/libutil-0.9.33.2.so $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)/libutil.so.0
	mkdir -p $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)/python2.7/config/
	cp -af $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/python2.7/config/* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)/python2.7/config/

romfs:
	mkdir -p $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	# it seem not need python when run smbd/nmbd/smbpassword in device so that not install for save space.
	#make install_python
	# keyuti
	cp -af keyutils/keyutils-1.5.9/libkeyutils.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	# krb
	#cp -af krb5/krb5-1.9/qqq/lib/* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	# samba
	#make install_samba_all
	make install_samba_min
	# strip the lib
	$(STRIP) $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)/*so*; 
	#cp -a $(MTK_DIR_USER)/samba-3.0.2/etc/* $(TARGET_DIR)/usr/etc/
	cp -af etc/* $(TARGET_DIR)/usr/etc/
	echo -n $(HOME)/qqq/ > $(TARGET_DIR)/usr/etc/smb_home_dir_string
 
install_samba_all:
	cp -af $(HOME)/qqq/lib/* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -a $(HOME)/qqq/bin/* $(TARGET_DIR)/usr/sbin/
	cp -a $(HOME)/qqq/sbin/* $(TARGET_DIR)/usr/sbin/

install_samba_min:
	cp -a $(HOME)/qqq/sbin/* $(TARGET_DIR)/usr/sbin/
	cp -a $(HOME)/qqq/bin/smbpasswd $(TARGET_DIR)/usr/sbin/
	cp -a $(HOME)/qqq/bin/testparm $(TARGET_DIR)/usr/sbin/
	cp -a $(HOME)/qqq/bin/smbstatus $(TARGET_DIR)/usr/sbin/
	cp -a $(HOME)/qqq/bin/smbclient $(TARGET_DIR)/usr/sbin/
	cp -a $(HOME)/qqq/bin/nmblookup $(TARGET_DIR)/usr/sbin/
	cp -a $(HOME)/qqq/bin/tdbdump $(TARGET_DIR)/usr/sbin/
	cp -af $(HOME)/qqq/lib/libnetapi.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/libsamdb.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libprinting-migrate-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libmessages-dgm-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libwinbind-client-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libsmbd-conn-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/libwbclient.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/libndr-krb5pac.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libtdb-wrap-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/liblibcli-lsa3-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libasn1util-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libldbsamba-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libauthkrb5-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libflag-mapping-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libmsghdr-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libutil-setid-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libutil-reg-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libgensec-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libndr-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libtrusts-util-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libldb.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libsmb-transport-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libcli-spoolss-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libsamdb-common-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libdbwrap-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libauth-sam-reply-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/liblibcli-netlogon3-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libkrb5samba-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libtalloc-report-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libcli-ldap-common-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libiov-buf-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libads-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libinterfaces-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libnpa-tstream-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libsamba-modules-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libmessages-util-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/libdcerpc-binding.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libtime-basic-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libreplace-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libpopt-samba3-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libsmbd-base-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libpopt-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libsamba-debug-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libgenrand-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libtalloc.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libsocket-blocking-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libtevent.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libndr-samba-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libsys-rw-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libutil-tdb-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libauth-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libmsrpc3-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libsmbd-shim-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libcli-smb-common-samba4.so*  $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libsamba-security-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/liblibsmb-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libsamba-sockets-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libdcerpc-samba-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libsecrets3-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libserver-id-db-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libtdb.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libcli-cldap-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libserver-role-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libsamba3-util-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libCHARSET3-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libcli-nbt-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libutil-cmdline-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libsamba-cluster-support-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libgse-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libcliauth-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/private/libaddns-samba4.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/libsamba-util.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/libtevent-util.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/libsamba-hostconfig.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/libndr-standard.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/libndr.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/libsamba-passdb.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/libsmbconf.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/libndr-nbt.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/libsamba-credentials.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)
	cp -af $(HOME)/qqq/lib/libsamba-errors.so* $(TARGET_DIR)/$(SMB_LIB_PATH_IN_FS)



clean:
	echo done
	
