dnl Copyright (C) 2004-2023 by Carnegie Mellon University.
dnl See license information in LICENSE.txt.

dnl ------------------------------------------------------------------------
dnl ax_lib_skipset.m4
dnl autotools build system for super_mediator
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


# ---------------------------------------------------------------------------
# AX_LIB_SKIPSET
#
#    Determine how to use skipset.
#    Output variables: SKIPSET_LDFLAGS, SKIPSET_CFLAGS
#    Output definition: HAVE_SKIPSET
#
AC_DEFUN([AX_LIB_SKIPSET],[
	AC_SUBST(SKIPSET_LDFLAGS)
	AC_SUBST(SKIPSET_CFLAGS)

	silk_header_names="silk/skipset.h silk-ipset/silk-ipset.h"
	silk_library_names="silk skipset"	

	AC_ARG_WITH([skipset],[AS_HELP_STRING([--with-skipset=SKIPSET_DIR],
	[specify location of SiLK or SiLK IPSet Library; find "silk-ipset/skipset.h" or "silk/silk.h" in SKIPSET_DIR/include/; find "libskipset.so" or "libsilk.so" in SKIPSET_DIR/lib/
	])],[
	   if test "x$withval" != "xyes"
           then 
	      skipset_dir="$withval"
              skipset_includes="$skipset_dir/include"
	      skipset_libs="$skipset_dir/lib"
           fi
        ])


	ENABLE_SKIPSET=0;


	if test "x$skipset_dir" != "xno"
	then
	    skip_save_LDFLAGS="$LDFLAGS"
	    skip_save_LIBS="$LIBS"
	    skip_save_CFLAGS="$CFLAGS"
	    skip_save_CPPFLAGS="$CPPFLAGS"

	    if test "x$skipset_libs" != "x"
	    then
	      SKIPSET_LDFLAGS="-L$skipset_libs"
	      LDFLAGS="$SKIPSET_LDFLAGS $skip_save_LDFLAGS"
	    fi

	    if test "x$skipset_includes" != "x"
  	    then
		SKIPSET_CFLAGS="-I$skipset_includes"
		CPPFLAGS="$SKIPSET_CFLAGS $skip_save_CPPFLAGS"
	    fi
	    
	    for sk_ip_hdr in $silk_header_names
	    do
		AC_CHECK_HEADER([$sk_ip_hdr], [
		    sk_ip_hdr="<$sk_ip_hdr>"
		    ENABLE_SKIPSET=1
		    break])
	    done	    

	    if test "x$ENABLE_SKIPSET" = "x1"
	    then
	        AC_CHECK_HEADERS([silk/skipaddr.h silk/utils.h])

	    	AC_SEARCH_LIBS([skIPSetLoad],[$silk_library_names],[ENABLE_SKIPSET=1],[ENABLE_SKIPSET=0])

	    	if test "x$ENABLE_SKIPSET" = "x1"
	    	then
			case "(X$ac_cv_search_skIPSetLoad" in *X-l*)
		     	SKIPSET_LDFLAGS="$SKIPSET_LDFLAGS $ac_cv_search_skIPSetLoad" ;;
			esac
            	fi
	    fi
	    		
	     # Restore cached values		                     
             LDFLAGS="$skip_save_LDFLAGS"
             LIBS="$skip_save_LIBS"
             CFLAGS="$skip_save_CFLAGS"
             CPPFLAGS="$skip_save_CPPFLAGS"	    

	fi
    
        if test "x$ENABLE_SKIPSET" != "x1"
	   then
	       AC_MSG_NOTICE([Not building IPSET support due to missing skipset headers or libraries])
	       SKIPSET_LDFLAGS=
               SKIPSET_CLAGS=
           else
	      AC_DEFINE_UNQUOTED([SKIPSET_HEADER_NAME],[$sk_ip_hdr],
	          [When ENABLE_SKIPSET is set, this is the path to the skipset.h header file])
	fi

	AM_CONDITIONAL(HAVE_SKIPSET, [test "x$ENABLE_SKIPSET" = "x1"])
	if test "x$ENABLE_SKIPSET" = "x1"
	then
	    AC_DEFINE(ENABLE_SKIPSET, [1],	
                      [Define to 1 if SiLK IPSet libraries are available])
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-skipset"
	    AC_SUBST(SM_REQ_SKIPSET, [1])
	fi
])
