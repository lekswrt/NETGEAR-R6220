
SAMBA_DIRECTORY=samba-4.6.4
 
all:
	if [ ! -d $(SAMBA_DIRECTORY) ]; then \
           echo untar the source code; \
           tar xzf $(SAMBA_DIRECTORY).tar.gz; \
        fi
	make patch_samba
	if [ ! -f $(SAMBA_DIRECTORY)/sc_configured ]; then \
           echo not configured yet, do config; \
           make configure_samba; \
        fi
	if [ -e $(SAMBA_DIRECTORY)/bin/smbd ]; then \
           echo already build; \
        else                    \
           make build_samba;     \
        fi

build_samba:
	cd $(SAMBA_DIRECTORY) && make
	mv $(HOME)/qqq $(HOME)/qqq_bk_`date +%s`; pwd
	cd $(SAMBA_DIRECTORY) && make install

patch_samba:
	cp -af patch/vfs.c $(SAMBA_DIRECTORY)/source3/smbd/
	cp -af patch/gse.c $(SAMBA_DIRECTORY)/source3/librpc/crypto/gse.c
	cp -af patch/wscript_configure_system_mitkrb5 $(SAMBA_DIRECTORY)/wscript_configure_system_mitkrb5
	cp -af patch/wscript $(SAMBA_DIRECTORY)/third_party/wscript
	@echo patch done

configure_samba:
	cd $(SAMBA_DIRECTORY) && echo > sc_configured
	cp -af qqq_new.txt $(SAMBA_DIRECTORY)
	cd $(SAMBA_DIRECTORY) && ./configure --host=mips-linux CC=$(CROSS)gcc --cross-compile --cross-answers=qqq_new.txt --prefix=$(HOME)/qqq --with-libiconv=$(LIBS_DIR)/public/libiconv.1.8/ \
--without-gettext --disable-gnutls --without-gpgme --without-winbind \
  --without-ads \
  --without-ldap \
  --without-pam \
  --without-quotas \
  --with-sendfile-support \
  --with-utmp \
  --enable-pthreadpool \
  --disable-avahi \
  --with-iconv \
  --without-dnsupdate  \
  --with-syslog \
  --without-automount  \
  --without-dmapi \
  --without-fam \
  --without-profiling-data \
  --without-libarchive \
  --without-cluster-support \
  --without-regedit \
  --without-fake-kaserver \
  --disable-glusterfs \
  --disable-cephfs \
  --disable-spotlight \
  --disable-fault-handling \
  --without-systemd \
  --without-lttng \
  --without-ntvfs-fileserver \
 --without-acl-support \
 --without-ads --disable-cups --without-ldap --disable-iprint \
 --disable-glusterfs --without-gettext --without-dnsupdate \
 --without-ad-dc \
  --with-system-mitkrb5
#  --with-acl-support 
	
