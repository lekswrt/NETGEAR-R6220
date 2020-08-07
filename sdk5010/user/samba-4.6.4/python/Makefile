PYTHON_PACKAGE_TOOLCHAIN_ADDON=python_package_toolchain_addon

#make toolchain support python:
#1. in fact, if current toolchain already support python, you don't need this directory, just comment the python line in the up directory.
#	but if current toolchain not support python and you want update the toolchain with python support, 
#	just enable the python in the buildroot then replace the current toolchain. you don't need this directory, just comment the python line in the up directory.
#2. but, sometimes we don't want update toolchain just for one function, so that' we may:
#	first, build one toolchain which is built by buildroot source code that enable python support.
#	then, run the "make python_from_toolchain", it will generate the python_package_for_toolchain.tgz.
#	differnert buildroot may build toochain with python support, compare the toolchain then update the python_from_toolchain
#3. here is for mt7621, with toolchain buildroot-gcc463_NPTLSHAREDLIBGCC. Then we build new toolchain buildroot-gcc463_NPTLSHAREDLIBGCCPYTHNEW from buildroot. You can find the build root config also the need library by buildroot
all:
	if [ -f sc_python_done ]; then \
            echo already install python addon; \
	else					\
		echo need install python addon;	\
		if [ -f $(PYTHON_PACKAGE_TOOLCHAIN_ADDON).tgz ]; then \
		    echo update toolchain $(TOOLCHAIN_DECOMP_PATH) support python; \
        	    sudo tar xzf $(PYTHON_PACKAGE_TOOLCHAIN_ADDON).tgz -C $(CROSS_TOOLCHAIN_LOCATION); \
		    sudo tar xzf $(PYTHON_PACKAGE_TOOLCHAIN_ADDON)_toolchain.tgz -C /; \
		else 									\
		    echo need $(PYTHON_PACKAGE_TOOLCHAIN_ADDON).tgz first; \
		    exit 1; 							\
	        fi;								\
		cp -af $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/libpython2.7.so* $(MTK_DIR_USER)/../uClibc-0.9.33.2/lib/; \
		echo > sc_python_done;																\
	fi 

CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION=/opt/buildroot-gcc463_NPTLSHAREDLIBGCCPYTHNEW/
CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION_NOSLASH=opt/buildroot-gcc463_NPTLSHAREDLIBGCCPYTHNEW/
python_from_toolchain:
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/include/expat_external.h .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/include/zconf.h .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/include/expat.h .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/include/python2.7/* .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/include/zlib.h .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/python2.7/* .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/libz.so .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/libexpat.la .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/libexpat.so .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/libz.so.1 .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/libz.so.1.2.7 .
	cp -af --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/libpython2.7.so.1.0 .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/libexpat.so.1.6.0 .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/libpython2.7.so .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/pkgconfig .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/pkgconfig/python2.pc .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/pkgconfig/python-2.7.pc .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/pkgconfig/zlib.pc .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/pkgconfig/expat.pc .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/pkgconfig/python.pc .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/libexpat.so.1 .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/lib/libz.a .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/bin/idle .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/bin/python2.7 .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/bin/python2 .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/bin/python .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/bin/pydoc .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/bin/python2-config .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/bin/2to3 .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/bin/python-config .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/bin/python2.7-config .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/bin/xmlwf .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/bin/smtpd.py .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/include/python2.7/* .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/include/ffi.h .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/include/ffitarget.h .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/libffi.so.6 .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/libffi.la .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/python2.7/* .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/libffi-3.0.11 .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/libffi-3.0.11/include .
	cp -af --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/libpython2.7.so.1.0 .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/libffi.so.6.0.0 .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/libpython2.7.so .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/pkgconfig/python2.pc .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/pkgconfig/python-2.7.pc .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/pkgconfig/libffi.pc .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/pkgconfig/python.pc .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/libffi.so .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/lib/libffi.a .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/idle .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/python2.7 .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/python2 .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/python .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/python2-config .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/python-config .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/python2.7-config .
	cp -a --parents $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/bin/smtpd.py .
	cd $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION_NOSLASH) && tar czf $(PYTHON_PACKAGE_TOOLCHAIN_ADDON).tgz usr/
	mv $(CROSS_TOOLCHAIN_WITH_PYTHON_LOCATION_NOSLASH)/$(PYTHON_PACKAGE_TOOLCHAIN_ADDON).tgz .
	tar czf $(PYTHON_PACKAGE_TOOLCHAIN_ADDON)_toolchain.tgz opt/


