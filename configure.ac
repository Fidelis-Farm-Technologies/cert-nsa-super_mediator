dnl Copyright 2012-2023 Carnegie Mellon University
dnl See license information in LICENSE.txt.

dnl Process this file with autoconf to produce a configure script
dnl ------------------------------------------------------------------------
dnl configure.ac
dnl  autotools build system for super_mediator
dnl ------------------------------------------------------------------------
dnl Authors: CERT Network Situational Awareness
dnl ------------------------------------------------------------------------
dnl @DISTRIBUTION_STATEMENT_BEGIN@
dnl Super Mediator 2.0.0
dnl
dnl Copyright 2023 Carnegie Mellon University.
dnl
dnl NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
dnl INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
dnl UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
dnl AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
dnl PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
dnl THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
dnl ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
dnl INFRINGEMENT.
dnl
dnl Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
dnl contact permission@sei.cmu.edu for full terms.
dnl
dnl [DISTRIBUTION STATEMENT A] This material has been approved for public
dnl release and unlimited distribution.  Please see Copyright notice for
dnl non-US Government use and distribution.
dnl
dnl GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
dnl Contract No.: FA8702-15-D-0002
dnl Contractor Name: Carnegie Mellon University
dnl Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
dnl
dnl The Government's rights to use, modify, reproduce, release, perform,
dnl display, or disclose this software are restricted by paragraph (b)(2) of
dnl the Rights in Noncommercial Computer Software and Noncommercial Computer
dnl Software Documentation clause contained in the above identified
dnl contract. No restrictions apply after the expiration date shown
dnl above. Any reproduction of the software or portions thereof marked with
dnl this legend must also reproduce the markings.
dnl
dnl This Software includes and/or makes use of Third-Party Software each
dnl subject to its own license.
dnl
dnl DM23-2321
dnl @DISTRIBUTION_STATEMENT_END@
dnl ------------------------------------------------------------------------

AC_PREREQ(2.59)
AC_INIT([super_mediator], [2.0.0.alpha3], [netsa-help@cert.org], [super_mediator], [https://tools.netsa.cert.org/super_mediator/])
AC_CONFIG_SRCDIR([src/mediator_main.c])
AC_CONFIG_HEADERS([src/mediator_autohdr.h])
AH_TOP([/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  autoheader generated header file
 *  ------------------------------------------------------------------------
 *  @DISTRIBUTION_STATEMENT_BEGIN@
 *  Super Mediator 2.0.0
 *
 *  Copyright 2023 Carnegie Mellon University.
 *
 *  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 *  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
 *  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
 *  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
 *  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
 *  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 *  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
 *  INFRINGEMENT.
 *
 *  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
 *  contact permission@sei.cmu.edu for full terms.
 *
 *  [DISTRIBUTION STATEMENT A] This material has been approved for public
 *  release and unlimited distribution.  Please see Copyright notice for
 *  non-US Government use and distribution.
 *
 *  GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
 *  Contract No.: FA8702-15-D-0002
 *  Contractor Name: Carnegie Mellon University
 *  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
 *
 *  The Government's rights to use, modify, reproduce, release, perform,
 *  display, or disclose this software are restricted by paragraph (b)(2) of
 *  the Rights in Noncommercial Computer Software and Noncommercial Computer
 *  Software Documentation clause contained in the above identified
 *  contract. No restrictions apply after the expiration date shown
 *  above. Any reproduction of the software or portions thereof marked with
 *  this legend must also reproduce the markings.
 *
 *  This Software includes and/or makes use of Third-Party Software each
 *  subject to its own license.
 *
 *  DM23-2321
 *  @DISTRIBUTION_STATEMENT_END@
 *  ------------------------------------------------------------------------
 */])

AC_COPYRIGHT([Copyright (C) 2012-2023 by Carnegie Mellon University
GNU General Public License (GPL) Rights pursuant to Version 2, June 1991])
AC_CONFIG_AUX_DIR([autoconf])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.9 foreign check-news subdir-objects])
AM_EXTRA_RECURSIVE_TARGETS([docs])

AC_REQUIRE_AUX_FILE([tap-driver.sh])

AC_LANG([C])
AC_PROG_CC
AM_PROG_CC_C_O
AX_ENABLE_WARNINGS

AM_PROG_LEX
AC_PROG_YACC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
# Despite super_mediator not building a library, include LT_INIT to
# help super_mediator find other libraries (such as fixbuf) on Linux.
LT_INIT

AC_SUBST(AM_CPPFLAGS)
AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_LDFLAGS)

RPM_CONFIG_FLAGS=""

AC_CHECK_HEADERS([glob.h errno.h pthread.h stdarg.h stdint.h stddef.h stdio.h stdlib.h string.h])
dnl ----------------------------------------------------------------------
dnl for some reason prefix doesn't get set here - so this is a nice hack
dnl ----------------------------------------------------------------------

if test "x$prefix" = "xNONE"; then
   prefix=/usr/local
fi

dnl ----------------------------------------------------------------------
dnl Modify PKG_CONFIG_PATH based on prefix
dnl ----------------------------------------------------------------------

if test "x$PKG_CONFIG_PATH" != "x"; then
    PKG_CONFIG_PATH="$PKG_CONFIG_PATH:$prefix/lib/pkgconfig"
    export PKG_CONFIG_PATH
else
    PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
    export PKG_CONFIG_PATH
fi

dnl ----------------------------------------------------------------------
dnl Check for a suitable glib
dnl ----------------------------------------------------------------------

GLIB_PRESENT=NO
GLIB_LDADD=

AM_PATH_GLIB_2_0([2.18.0],[GLIB_PRESENT=YES], [GLIB_PRESENT=NO], [gthread])

AC_ARG_WITH(glib-static,
AS_HELP_STRING([--with-glib-static=prefix],[use static glib tree (prefix is REQUIRED)]),[
GLIB_STATIC_LIBGLIB2_A="${withval}/lib/libglib-2.0.a"
GLIB_STATIC_INCLUDE="${withval}/include/glib-2.0"
GLIB_STATIC_LIBINCLUDE="${withval}/lib/glib-2.0/include"
if test -f ${GLIB_STATIC_LIBGLIB2_A}; then
   if test -f "${GLIB_STATIC_INCLUDE}/glib.h"; then
        GLIB_LDADD=${GLIB_STATIC_LIBGLIB2_A}
        GLIB_CFLAGS="-I${GLIB_STATIC_INCLUDE} -I${GLIB_STATIC_LIBINCLUDE}"
        AC_SUBST(GLIB_LIBS)
        AC_SUBST(GLIB_CFLAGS)
        GLIB_PRESENT=YES
        AC_MSG_NOTICE([assuming static glib in ${withval} is good...])
    fi
fi
])

if test x"$GLIB_PRESENT" != "xYES"; then
  AC_MSG_ERROR([Cannot find a suitable glib2 (>= 2.12.0)])
fi

AC_SUBST(GLIB_LDADD)

AC_DEFUN([YF_PKGCONFIG_VERSION],[
        AC_REQUIRE([PKG_PROG_PKG_CONFIG])
        yfpkg_ver=`$PKG_CONFIG --modversion $1`
])

AC_DEFUN([YF_PKGCONFIG_LPATH],[
        AC_REQUIRE([PKG_PROG_PKG_CONFIG])
        yfpkg_lpath=`$PKG_CONFIG --libs-only-L $1 | cut -d' ' -f 1`
])

AC_DEFUN([YF_LIBSTR_STRIP],[
#       _resultString=[`echo $1 | sed 's/-L\([^ ]*\).*/\1/pg'`]
#       yf_libstr=${_resultString}
        yf_libstr=$1
])

dnl ----------------------------------------------------------------------
dnl Check for libfixbuf
dnl when changing the version number required, do both the subst, and
dnl package lines!
dnl ----------------------------------------------------------------------
yaf_req_fixbuf_ver=2.99.0
AC_SUBST(YAF_REQ_FIXBUF_VER, [${yaf_req_fixbuf_ver}])
PKG_CHECK_MODULES(libfixbuf, [libfixbuf >= ${yaf_req_fixbuf_ver} libfixbuf < 4.0.0],
                  [
                    YF_PKGCONFIG_VERSION(libfixbuf)
                    YF_PKGCONFIG_LPATH(libfixbuf)
                  ],
                  [AC_MSG_ERROR([Cannot find a suitable libfixbuf (>= ${yaf_req_fixbuf_ver}) (Try setting PKG_CONFIG_PATH): $libfixbuf_PKG_ERRORS])
])

YF_PKGCONFIG_VERSION(libfixbuf)
fixbuf_install_loc=`$PKG_CONFIG --variable=prefix libfixbuf`
AC_MSG_NOTICE([libfixbuf version: $yfpkg_ver])
AC_MSG_NOTICE([Using libfixbuf installed in: $fixbuf_install_loc])
AC_DEFINE_UNQUOTED([FIXBUF_VERSION], ["$yfpkg_ver"], [fixbuf version])

dnl---------------------------------------------------------------------
dnl Check fo MySQL support
dnl --------------------------------------------------------------------
AX_LIB_MYSQL([5.0])

dnl--------------------------------------------------------------------
dnl Check for OpenSSL support
dnl--------------------------------------------------------------------
AC_ARG_WITH(openssl,
AS_HELP_STRING([--with-openssl=prefix], [Use OpenSSL for Hashing support]),[
if test -d ${withval}; then
    LDFLAGS="-L${withval}/lib ${LDFLAGS}"
    CFLAGS="-I${withval}/include ${CFLAGS}"
    RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-openssl=${withval}"
else
    RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-openssl"
fi


dnl look for libssl
    AC_CHECK_LIB(crypto,MD5,[
    AC_DEFINE(HAVE_OPENSSL, 1, [Define to 1 to enable OpenSSL support])
        LIBS="-lssl -lcrypto ${LIBS}"
    ],[
        AC_MSG_ERROR([--with-openssl given but cannot find MD5()])
    ])

    AC_CHECK_LIB(crypto,SHA1,[
    AC_DEFINE(HAVE_OPENSSL, 1, [Define to 1 to enable OpenSSL support])
    ],[
        AC_MSG_ERROR([--with-openssl given but cannot find SHA1()])
    ])

    AC_CHECK_HEADERS(openssl/sha.h openssl/md5.h,[],
    [
       AC_MSG_ERROR([--with-openssl given but cannot find sha, md5 headers.])
    ])

])


AC_SUBST(RPM_CONFIG_FLAGS)

dnl get the size of long, long long, and time_t
AC_CHECK_SIZEOF([long])
AC_CHECK_SIZEOF([long long])
AC_CHECK_SIZEOF([time_t])

AC_SUBST([abs_top_srcdir])
AC_SUBST([abs_top_builddir])

dnl----------------------------------------------------------------------
dnl Check for silk-ipset library
dnl----------------------------------------------------------------------

AX_LIB_SKIPSET([3.0])

dnl ----------------------------------------------------------------------
dnl Check for Unix vs. Linux privdrop (EWW EWW HACK EWW)
dnl ----------------------------------------------------------------------
if test "x$target_os" = "xlinux" -o \
        "x$target_os" = "xlinux-gnu"; then
    AC_MSG_NOTICE([Enabling Linux privilege drop hack])
    AC_DEFINE([LINUX_PRIVHACK], 1,
              [Define to 1 on Linux for privilege drop hack])
else
    AC_MSG_NOTICE([Normal privilege drop (target os is $target_os)])
fi

dnl ----------------------------------------------------------------------
dnl Check for script to update the distribution statement
dnl ----------------------------------------------------------------------
update_markings='doc/update-document-marking.pl'
update_markings_file=`eval "echo ${srcdir}/${update_markings}"`
AC_CHECK_FILE([${update_markings_file}], [
    AC_SUBST([UPDATE_MARKINGS], ['${top_srcdir}'/${update_markings}])
])
AM_CONDITIONAL([HAVE_UPDATE_MARKINGS], [test -n "${UPDATE_MARKINGS}"])

dnl ----------------------------------------------------------------------
dnl Set up pod2man
dnl ----------------------------------------------------------------------
AC_ARG_VAR([POD2MAN], [Perl POD markup language to man page tool])
AC_CHECK_PROGS([POD2MAN], [pod2man], [true])

SM_POD2MAN_ARGS="--center='ipfix mediator' --release='"${PACKAGE_VERSION}"' --date='"`date +"%v"`"'"

AC_SUBST(SM_POD2MAN_ARGS)

dnl ----------------------------------------------------------------------
dnl Set up pod2html
dnl ----------------------------------------------------------------------
AC_ARG_VAR([POD2HTML], [Perl POD markup language to HTML tool])
AM_MISSING_PROG([POD2HTML], [pod2html])


dnl ---------------------------------------------------------------------
dnl Check for decompression support
dnl ---------------------------------------------------------------------
AX_CHECK_LIBZ

dnl ----------------------------------------------------------------------
dnl Check for pandoc
dnl ----------------------------------------------------------------------
AC_ARG_VAR([PANDOC], [Pandoc: A universal document converter])
AM_MISSING_PROG([PANDOC], [pandoc])


dnl ----------------------------------------------------------------------
dnl Determine infomodel information
dnl ----------------------------------------------------------------------
AM_MISSING_PROG([XSLTPROC], [xsltproc])
INFOMODEL_AC_COLLECT_REGISTRIES([src/infomodel])
AC_PATH_PROG([PERL], [perl])

SM_AC_WRITE_SUMMARY

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/infomodel/Makefile
    etc/Makefile
    doc/Makefile
    etc/init.d/super_mediator
    super_mediator.spec
])

dnl ----------------------------------------------------------------------
dnl Do output
dnl ----------------------------------------------------------------------

AC_OUTPUT
