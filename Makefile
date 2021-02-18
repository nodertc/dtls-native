# Source
ARCHIVE_GNUTLS=https://www.gnupg.org/ftp/gcrypt/gnutls/v3.6/gnutls-3.6.15.tar.xz
ARCHIVE_LIBTASN=https://ftp.gnu.org/gnu/libtasn1/libtasn1-4.16.0.tar.gz
ARCHIVE_NETTLE=https://ftp.gnu.org/gnu/nettle/nettle-3.7.tar.gz
ARCHIVE_GMPLIB=https://gmplib.org/download/gmp/gmp-6.2.1.tar.xz

# Build
ROOT_DIR=${PWD}
MAKE=make
CFLAGS="-O3 -fPIC"
CONFIGURE=./configure CFLAGS=${CFLAGS} --prefix=${ROOT_DIR}/dependencies
CURL=curl -s
EXTRACT_XZ=tar -xJ
EXTRACT_GZ=tar -xz

all: gnutls

clean:
	rm -rf gnutls-3.6.15 gmp-6.2.1 nettle-3.7 libtasn1-4.16.0 dependencies

# gmp

gmp-6.2.1/configure:
	${CURL} ${ARCHIVE_GMPLIB} | ${EXTRACT_XZ}

gmp-6.2.1/Makefile: gmp-6.2.1/configure
	cd gmp-6.2.1 && \
	${CONFIGURE} \
		--prefix=${ROOT_DIR}/dependencies && \
	cd -

dependencies/lib/libgmp.a: gmp-6.2.1/Makefile
	cd gmp-6.2.1 && ${MAKE} install && cd -

gmp: dependencies/lib/libgmp.a

# libtasn1

libtasn1-4.16.0/configure:
	${CURL} ${ARCHIVE_LIBTASN} | ${EXTRACT_GZ}

libtasn1-4.16.0/Makefile: libtasn1-4.16.0/configure
	cd libtasn1-4.16.0 && \
	${CONFIGURE} \
		--disable-doc \
		--disable-valgrind-tests \
		--prefix=${ROOT_DIR}/dependencies && \
	cd -

dependencies/lib/libtasn1.a: libtasn1-4.16.0/Makefile
	cd libtasn1-4.16.0 && ${MAKE} install && cd -

asn1: dependencies/lib/libtasn1.a

# nettle

nettle-3.7/configure:
	${CURL} ${ARCHIVE_NETTLE} | ${EXTRACT_GZ}

nettle-3.7/Makefile: nettle-3.7/configure dependencies/lib/libgmp.a
	cd nettle-3.7 && \
	${CONFIGURE} \
		LDFLAGS="-L${ROOT_DIR}/dependencies/lib" \
		LIBS="-lgmp" \
		--disable-documentation \
		--enable-x86-aesni \
		--enable-public-key \
		&& cd -

dependencies/lib/libnettle.a: nettle-3.7/Makefile
	cd nettle-3.7 && ${MAKE} install && cd -

nettle: dependencies/lib/libnettle.a

# gnutls

gnutls-3.6.15/configure:
	${CURL} ${ARCHIVE_GNUTLS} | ${EXTRACT_XZ}

gnutls-3.6.15/Makefile: gnutls-3.6.15/configure dependencies/lib/libnettle.a dependencies/lib/libtasn1.a dependencies/lib/libgmp.a
	cd gnutls-3.6.15 && \
	${CONFIGURE} \
		NETTLE_CFLAGS="-I${ROOT_DIR}/dependencies/include" \
		NETTLE_LIBS="-L${ROOT_DIR}/dependencies/lib -lnettle" \
		HOGWEED_CFLAGS="-I${ROOT_DIR}/dependencies/include" \
		HOGWEED_LIBS="-L${ROOT_DIR}/dependencies/lib -lhogweed -lgmp" \
		GMP_CFLAGS="-I${ROOT_DIR}/dependencies/include" \
		GMP_LIBS="-L${ROOT_DIR}/dependencies/lib -lgmp" \
		LIBTASN1_CFLAGS="-I${ROOT_DIR}/dependencies/include" \
		LIBTASN1_LIBS="-L${ROOT_DIR}/dependencies/lib -ltasn1" \
		LDFLAGS="-L${ROOT_DIR}/dependencies/lib" \
		--disable-maintainer-mode \
		--disable-doc \
		--disable-tools \
		--disable-cxx \
		--disable-ssl3-support \
		--disable-ssl2-support \
		--disable-tests \
		--disable-valgrind-tests \
		--disable-full-test-suite \
		--disable-rpath \
		--disable-libtool-lock \
		--disable-libdane \
		--with-included-unistring \
		--without-zlib \
		--without-libz-prefix \
		--without-idn \
		--without-libidn2 \
		--without-tpm \
		--without-p11-kit \
		&& cd -

dependencies/lib/libgnutls.a: gnutls-3.6.15/Makefile
	cd gnutls-3.6.15 && ${MAKE} install && cd -

gnutls: dependencies/lib/libgnutls.a
