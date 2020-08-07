KRB5_DIRECTORY=krb5-1.9
HOST_KRB5_VERSION=$(shell krb5-config --version)

all:
	@echo host krb5 version $(HOST_KRB5_VERSION), if it not large than 1.9, 
	@echo first need build host krb5 by configure/make/makesinatll for the host. if not, configure samba will have error.
	@echo also need manually update the krb5 host binary after make install like the test target
	@echo if it already large than 1.9, just comment out the following make host krb5 ok
	if [ "$(HOST_KRB5_VERSION)" != "Kerberos 5 release 1.9" ]; then \
           echo host krb5 not expected; \
           exit 1; 			\
	else				\
	   echo host krb5 ok;		\
        fi
	if [ ! -d $(KRB5_DIRECTORY) ]; then \
	   echo untar the source code; \
           tar xzf $(KRB5_DIRECTORY).tar.gz; \
        fi
	if [ -d $(KRB5_DIRECTORY)/qqq/bin/ ]; then \
           echo already build; \
	else			\
	   make build_krb5;	\
        fi

build_krb5:
	cd $(KRB5_DIRECTORY)/src/ && echo krb5_cv_attr_constructor_destructor=yes > linux-cache
	cd $(KRB5_DIRECTORY)/src/ && echo ac_cv_func_regcomp=yes >> linux-cache
	cd $(KRB5_DIRECTORY)/src/ && echo ac_cv_printf_positional=yes >> linux-cache
	cd $(KRB5_DIRECTORY)/src/ && echo ac_cv_file__etc_environment=yes >> linux-cache
	cd $(KRB5_DIRECTORY)/src/ && echo ac_cv_file__etc_TIMEZONE=yes >> linux-cache
	cd $(KRB5_DIRECTORY)/src/ && echo ac_cv_lib_resolv_res_search=yes >> linux-cache
	make keyutils_patch
	cd $(KRB5_DIRECTORY)/src/ && ./configure --host=mips-linux CC=$(CROSS)gcc --prefix=`pwd`/../qqq --cache-file=linux-cache
	cd $(KRB5_DIRECTORY)/src/ && make
	cd $(KRB5_DIRECTORY)/src/ && make install
	echo install krb5 to toolchain for later compile pass
	sudo cp -a $(KRB5_DIRECTORY)/qqq/lib/* $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/lib/
	sudo cp -a $(KRB5_DIRECTORY)/qqq/lib/* $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/lib/
	sudo cp -a $(KRB5_DIRECTORY)/qqq/include/* $(CROSS_TOOLCHAIN_LOCATION)/usr/mipsel-buildroot-linux-uclibc/sysroot/usr/include/
	cp -af $(KRB5_DIRECTORY)/qqq/include/* $(MTK_DIR_USER)/../uClibc-0.9.33.2/app_headers/include/
	cp -af $(KRB5_DIRECTORY)/qqq/lib/* $(MTK_DIR_USER)/../uClibc-0.9.33.2/lib/

keyutils_patch:
	cd $(KRB5_DIRECTORY)/src/ && cp ../../k5-platform.h include/


test:
	echo not used in makefile, just show how update host krb5 after host build krb5 done
	mv /usr/kerberos /usr/kerberos_q
	mkdir -p /usr/kerberos/bin/
	cp /usr/local/bin/k* /usr/kerberos/bin/
	cp /usr/local/bin/sclient /usr/kerberos/bin/
 
