include ../../../../Rules.mak

DESTLIB = $(ROOT)/target/lib
DESTBIN = $(ROOT)/target/usr/sbin
#SOURCELIB = $(ROOT)/rtl819x/toolchain/rsdk-1.3.6-5281-EB-2.6.30-0.9.30/lib
SUBDIR_NTFS_3G = ntfs-3g_ntfsprogs-2012.1.15

all: config
	cd ntfs-3g_ntfsprogs-2012.1.15 && make
	cd ntfs-3g_ntfsprogs-2012.1.15 && make -C ntfsprogs
config:
	@(if test -f h_config; then \
		echo "has configuration" ;   \
        else \
		make configure; \
		touch h_config; \
	fi)

configure:
	cd ./$(SUBDIR_NTFS_3G) && ./configure --enable-shared --enable-static --disable-ntfsprogs --with-fuse=external FUSE_MODULE_CFLAGS="-I$(LIBS_DIR)/public/fuse.2.7.4/include" FUSE_MODULE_LIBS="-L$(LIBS_DIR)/public/fuse.2.7.4/lib -lfuse"   --host=mips-linux CC=$(CROSS)gcc

install:
	$(STRIP) ./$(SUBDIR_NTFS_3G)/src/.libs/ntfs-3g
	$(STRIP) ./$(SUBDIR_NTFS_3G)/src/.libs/ntfs-3g.probe
	$(STRIP) ./$(SUBDIR_NTFS_3G)/libntfs-3g/.libs/libntfs-3g.so.83.0.0
	rm -f $(DESTLIB)/libntfs-3g.so
	rm -f $(DESTLIB)/libntfs-3g.so.83
	rm -f $(DESTLIB)/libntfs-3g.so.83.0.0
	cp -p ./$(SUBDIR_NTFS_3G)/libntfs-3g/.libs/libntfs-3g.so.83.0.0 $(DESTLIB)/libntfs-3g.so.83.0.0
	ln -s libntfs-3g.so.83.0.0 $(DESTLIB)/libntfs-3g.so
	ln -s libntfs-3g.so.83.0.0 $(DESTLIB)/libntfs-3g.so.83
	cp -a ./$(SUBDIR_NTFS_3G)/src/.libs/ntfs-3g $(DESTBIN)
	cp -a ./$(SUBDIR_NTFS_3G)/src/.libs/ntfs-3g.probe $(DESTBIN)
	cp -a ./$(SUBDIR_NTFS_3G)/ntfsprogs/ntfslabel $(DESTBIN)

clean:
	cd ntfs-3g_ntfsprogs-2012.1.15 && make clean
