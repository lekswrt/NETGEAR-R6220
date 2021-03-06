#!/bin/bash
build_dir=build_sc
cp afppasswd ../target/usr/bin
cd $build_dir
CC=$1 CFLAGS="-I`pwd`/../../target/usr/include -I`pwd`/../../../nvram" LDFLAGS="-L`pwd`/../../target/usr/lib -L`pwd`/../../../nvram -lscnvram" ../configure --target=mipsel-linux-uclibc --host=mipsel-linux-uclibc --build=i486-linux-gnu prefix=/usr --disable-afs --enable-hfs --disable-debugging --enable-shell-check --disable-timelord --disable-a2boot --disable-cups  --disable-tcp-wrappers --enable-admin-group --disable-srvloc --with-bdb=`pwd`/../../target/usr --with-pkgconfdir=/etc/netatalk --with-ssl-dir=`pwd`/../../target --with-shadow=no --with-libgcrypt-dir=`pwd`/../../target/usr

