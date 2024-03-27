##  Copyright 2012-2023 Carnegie Mellon University
##  See license information in LICENSE.txt.

##  Process this file with automake to produce Makefile.in
##  ------------------------------------------------------------------------
##  Makefile.am (toplevel)
##  autotools build system for super_mediator
##  ------------------------------------------------------------------------
##  Authors: CERT Network Situational Awareness
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


ACLOCAL_AMFLAGS = -I m4

# Avoid picking up MacOS X resource forks in "make dist"
am__tar = COPY_EXTENDED_ATTRIBUTES_DISABLE=1 COPYFILE_DISABLE=1 ${AMTAR} chof - "$$tardir"

SUBDIRS = src etc doc

UPDATE_DOC_MARKINGS = \
  if test -f "$(UPDATE_MARKINGS)" ; then \
    find $(distdir) \
      -name html -prune -o \
      -name libltld -prune -o \
      -type f -print0 \
    | xargs -0 $(PERL) $(UPDATE_MARKINGS) ; \
  fi

if HAVE_UPDATE_MARKINGS
update-doc-markings:
	$(UPDATE_DOC_MARKINGS)
else
update-doc-markings:
endif

#  This reads its standard input and assures its length is at least
#  16k. It is used by a dist-hook to check the length of the tar
#  output in hopes of catching times where tar fails due to a the UID
#  being too large.
check_tar_len = \
  $(PERL) -e ' \
    binmode STDIN; \
    die "\n\t\tERROR: tar output appears too short\n" \
        if read(STDIN, $$_, 0xffff) < 0xffff;'

dist-hook: update-doc-markings
	$(AMTAR) cof - $(distdir) | $(check_tar_len)


FCCX_PCAP_DIR = 
MERGECAP = mergecap
YAF = yaf
YAF_ARGS = --max-payload=65500 --applabel
YAF3_ARGS = --dpi
YAF2_ARGS = --plugin-name=dpacketplugin.la

MAKE_TEST_IPFIX = \
  dest="$@.new" ; \
  if test -z "$(FCCX_PCAP_DIR)" ; then \
    { echo "Set FCCX_PCAP_DIR to the location of the Flaming Cupcake Challenge data" 1>&2 ; exit 1; } ; \
  fi ; \
  if test ! -d "$(FCCX_PCAP_DIR)" ; then \
    { echo "FCCX_PCAP_DIR location ($(FCCX_PCAP_DIR)) is not a directory" 1>&2 ; exit 1; } ; \
  fi ; \
  if ! $(MERGECAP) -h >/dev/null 2>&1 ; then \
    { echo "Unable to run $(MERGECAP) -h" 1>&2 ; exit 1; } ; \
  fi ; \
  if ! $(YAF) --help-all >/dev/null ; then \
    { echo "Unable to run $(YAF) --help-all" 1>&2 ; exit 1; } ; \
  fi ; \
  if $(YAF) --help-all | grep -e --dpi >/dev/null 2>&1 ; then \
      YAF_CMD="$(YAF) $(YAF_ARGS) $(YAF3_ARGS)" ; \
  elif $(YAF) --help-all | grep -e --metadata-export >/dev/null 2>&1 ; then \
      YAF_CMD="$(YAF) $(YAF_ARGS) $(YAF2_ARGS) --metadata-export" ; \
  elif $(YAF) --help-all | grep -e --template-info >/dev/null 2>&1 ; then \
      YAF_CMD="$(YAF) $(YAF_ARGS) $(YAF2_ARGS) --template-info" ; \
  else \
      YAF_CMD="$(YAF) $(YAF_ARGS) $(YAF2_ARGS)" ; \
  fi ; \
  pcap_files='"$(FCCX_PCAP_DIR)/gatewaySensor-2.pcap" "$(FCCX_PCAP_DIR)/gatewaySensor-3.pcap" "$(FCCX_PCAP_DIR)/marSensor.pcap" "$(FCCX_PCAP_DIR)/intel2Sensor.pcap"' ; \
  echo "$(MERGECAP) -w - $${pcap_files} | $${YAF_CMD} --out=$${dest}" ; \
  { $(MERGECAP) -w - \
    "$(FCCX_PCAP_DIR)/gatewaySensor-2.pcap" \
    "$(FCCX_PCAP_DIR)/gatewaySensor-3.pcap" \
    "$(FCCX_PCAP_DIR)/marSensor.pcap" \
    "$(FCCX_PCAP_DIR)/intel2Sensor.pcap" \
  | $${YAF_CMD} --out="$${dest}" ; } \
  && mv "$${dest}" "$@"


FCCX-reduced.ipfix:
	@$(MAKE_TEST_IPFIX)

DISTCLEANFILES = $(SM_SUMMARY_FILE)

EXTRA_DIST = \
	LICENSE.txt \
	README
