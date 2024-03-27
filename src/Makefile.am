##  Copyright 2012-2023 Carnegie Mellon University
##  See license information in LICENSE.txt.

##  Process this file with automake to produce Makefile.in
##  ------------------------------------------------------------------------
##  Makefile.am (source)
##  autotools build system for super_mediator
##  ------------------------------------------------------------------------
##  Authors: Emily Sarneso
##  ------------------------------------------------------------------------
##  @DISTRIBUTION_STATEMENT_BEGIN@
##  Super Mediator 2.0.0
##
##  Copyright 2023 Carnegie Mellon University.
##
##  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
##  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
##  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
##  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
##  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
##  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
##  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
##  INFRINGEMENT.
##
##  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
##  contact permission@sei.cmu.edu for full terms.
##
##  [DISTRIBUTION STATEMENT A] This material has been approved for public
##  release and unlimited distribution.  Please see Copyright notice for
##  non-US Government use and distribution.
##
##  GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
##  Contract No.: FA8702-15-D-0002
##  Contractor Name: Carnegie Mellon University
##  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
##
##  The Government's rights to use, modify, reproduce, release, perform,
##  display, or disclose this software are restricted by paragraph (b)(2) of
##  the Rights in Noncommercial Computer Software and Noncommercial Computer
##  Software Documentation clause contained in the above identified
##  contract. No restrictions apply after the expiration date shown
##  above. Any reproduction of the software or portions thereof marked with
##  this legend must also reproduce the markings.
##
##  This Software includes and/or makes use of Third-Party Software each
##  subject to its own license.
##
##  DM23-2321
##  @DISTRIBUTION_STATEMENT_END@
##  ------------------------------------------------------------------------

SUBDIRS = infomodel

bin_PROGRAMS = super_mediator

if MYSQLENABLE
bin_PROGRAMS += super_table_creator
endif

AM_CFLAGS = $(WARN_CFLAGS) $(GLIB_CFLAGS) $(libfixbuf_CFLAGS) \
    $(MYSQL_CFLAGS) $(SKIPSET_CFLAGS)
LDADD = $(libfixbuf_LIBS) $(GLIB_LIBS) $(MYSQL_LDFLAGS) $(SKIPSET_LDFLAGS)

# When adding a PODFILE, update man1_MANS here and the POD_SOURCE and
# POD_HTML variables in ../doc
PODFILES = super_mediator.pod super_mediator.conf.pod super_table_creator.pod
man1_MANS = super_mediator.1 super_mediator.conf.1
if MYSQLENABLE
man1_MANS += super_table_creator.1
else
noinst_man1_MANS = super_table_creator.1
endif

.pod.1:
	$(POD2MAN) $(SM_POD2MAN_ARGS) --section=1 $< $@

CLEANFILES = $(man1_MANS)

EXTRA_DIST = $(PODFILES) lookup3.c

super_mediator_SOURCES = mediator_core.c mediator_util.c mediator_open.c \
	mediator_export.c mediator_filter.c mediator_json.c mediator_log.c \
	mediator_main.c mediator_dns.c mediator_print.c mediator_specs.c \
	mediator_ssl.c mediator_stat.c mediator_dedup.c \
	mediator_config_lex.l mediator_config_parse.y

super_table_creator_SOURCES = mediator_mysql.c

noinst_HEADERS = mediator_config.h mediator_core.h \
	mediator_dedup.h mediator_dns.h mediator_filter.h mediator_inf.h \
	mediator_json.h mediator_log.h mediator_main.h mediator_print.h \
	mediator_ssl.h mediator_stat.h mediator_structs.h mediator_util.h \
	specs.h templates.h

AM_YFLAGS = -d
mediator_config_lex.$(OBJEXT) mediator_config_lex.lo: mediator_config_parse.h

BUILT_SOURCES = infomodel.c infomodel.h
nodist_super_mediator_SOURCES = infomodel.c infomodel.h
CLEANFILES += infomodel.c infomodel.h
EXTRA_DIST += xml2fixbuf.xslt make-infomodel

RUN_MAKE_INFOMODEL = $(AM_V_GEN) \
 srcdir='' ; \
 test -f ./make-infomodel || srcdir=$(srcdir)/ ; \
 $(PERL) $${srcdir}make-infomodel --package $(PACKAGE) $(INFOMODEL_REGISTRY_PREFIXES)

infomodel.c : infomodel.h
infomodel.h : make-infomodel Makefile
	$(RUN_MAKE_INFOMODEL)


TEST_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
                       $(top_srcdir)/autoconf/tap-driver.sh
#TEST_LOG_DRIVER_FLAGS = --merge --comments
TEST_LOG_DRIVER_FLAGS = --merge
TESTS = \
	tests/cmdline-nodata-good.test \
	tests/cmdline-nodata-bad.test \
	tests/config-nodata-good.test \
	tests/config-nodata-bad.test \
	tests/config-nodata-filterfail.test \
	tests/config-nodata-ipset.test \
	tests/flow-only.test \
	tests/passthrough.test \
	tests/data-ipset.test \
	tests/dns-rr.test \
	tests/dns-dedup.test \
	tests/ssl-dedup.test \
	tests/general-dedup.test

EXTRA_DIST += $(TESTS) tests/emptyset.set tests/setup.sh
