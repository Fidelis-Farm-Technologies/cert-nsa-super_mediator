dnl Copyright 2014-2023 Carnegie Mellon University
dnl See license information in LICENSE.txt.

dnl ------------------------------------------------------------------------
dnl smsummary.m4
dnl write summary of configure to a file (stolen from SiLK)
dnl ------------------------------------------------------------------------
dnl Authors: Emily Sarneso
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

AC_DEFUN([SM_AC_WRITE_SUMMARY],[
    AC_SUBST(SM_SUMMARY_FILE)
    SM_SUMMARY_FILE=sm-summary.txt

    SM_FINAL_MSG="
    * Configured package:           ${PACKAGE_STRING}
    * pkg-config path:              ${PKG_CONFIG_PATH}
    * Host type:                    ${build}
    * Source files (\$top_srcdir):   $srcdir
    * Install directory:            $prefix"

    YF_LIBSTR_STRIP($GLIB_LIBS)
    SM_FINAL_MSG="$SM_FINAL_MSG
    * GLIB:                         $yf_libstr"

    YF_PKGCONFIG_VERSION(libfixbuf)
    YF_PKGCONFIG_LPATH(libfixbuf)
    yf_msg_ldflags=`echo "$yfpkg_lpath" | sed 's/^ *//' | sed 's/ *$//'`
    SM_BUILD_CONF="$SM_BUILD_CONF
    * Libfixbuf version:            ${yfpkg_ver}"

    if test "$found_mysql" = "yes"
    then
	SM_BUILD_CONF="$SM_BUILD_CONF
    * MySQL Support:                YES (v. $MYSQL_VERSION)"
    else
        SM_BUILD_CONF="$SM_BUILD_CONF
    * MySQL Support:		    NO"
    fi

    if test "x$ENABLE_SKIPSET" = "x1"
    then
	SM_BUILD_CONF="$SM_BUILD_CONF
    * SiLK IPset Support:           YES"
    else
        SM_BUILD_CONF="$SM_BUILD_CONF
    * SiLK IPset Support:           NO"
    fi

    # Remove leading whitespace
    yf_msg_cflags="$CPPFLAGS $CFLAGS"
    yf_msg_cflags=`echo "$yf_msg_cflags" | sed 's/^ *//' | sed 's/  */ /g'`

    yf_msg_ldflags="$SM_LDFLAGS $LDFLAGS"
    yf_msg_ldflags=`echo "$yf_msg_ldflags" | sed 's/^ *//' | sed 's/  */ /g'`

    yf_msg_libs="$LIBS"
    yf_msg_libs=`echo "$yf_msg_libs" | sed 's/^ *//' | sed 's/  */ /g'`

    SM_FINAL_MSG="$SM_FINAL_MSG $SM_BUILD_CONF
    * Compiler (CC):                $CC
    * Compiler flags (CFLAGS):      $yf_msg_cflags
    * Linker flags (LDFLAGS):       $yf_msg_ldflags
    * Libraries (LIBS):             $yf_msg_libs
"

    echo "$SM_FINAL_MSG" > $SM_SUMMARY_FILE

    AC_CONFIG_COMMANDS([sm_summary],[
        if test -f $SM_SUMMARY_FILE
        then
            cat $SM_SUMMARY_FILE
        fi],[SM_SUMMARY_FILE=$SM_SUMMARY_FILE])
])
