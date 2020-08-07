


KEYUTILS_DIRECTORY=keyutils-1.5.9

all:
	if [ ! -d $(KEYUTILS_DIRECTORY) ]; then \
	   tar jxf $(KEYUTILS_DIRECTORY).tar.bz2; \
        fi
	cd $(KEYUTILS_DIRECTORY) && make
	echo install in toolchain so that later build krb ok
	sudo cp -a $(KEYUTILS_DIRECTORY)/libkeyutils.so* $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/lib/
	sudo cp -a $(KEYUTILS_DIRECTORY)/libkeyutils.so* $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/lib/
	sudo cp -a $(KEYUTILS_DIRECTORY)/keyutils.h $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/include/

