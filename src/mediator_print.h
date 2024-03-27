/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_print.h
 *
 *  header file for mediator_print.c
 *
 *  ------------------------------------------------------------------------
 *  Authors: Emily Sarneso
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
 */

#ifndef _MEDIATOR_PRINT_H
#define _MEDIATOR_PRINT_H

#include <stdint.h>
#include <stdlib.h>
#include <glib.h>
#include "templates.h"

gboolean
mdPrintDecimal(
    GString  *buf,
    char      delimiter,
    int       decimal);

gboolean
mdPrintFieldEntry(
    mdFullFlow_t    *flow,
    mdExporter_t    *exporter,
    GString         *buf,
    mdFieldEntry_t  *field,
    gboolean         json);

void
mdPrintBasicHeader(
    mdExporter_t  *exporter,
    GString  *rstr);

gboolean
mdPrintDPIRecord(
    mdExporter_t       *exporter,
    const fbRecord_t   *rec,
    const GString      *prefixString,
    GString            *buf,
    char                delimiter,
    gboolean            escape,
    gboolean            json);

/**
 * mdPrintStats
 *
 * print a YAF stats message to the given exporter
 *
 */
size_t
mdPrintStats(
    yafStatsV2Rec_t  *stats,
    const char       *name,
    FILE             *lfp,
    char              delim,
    gboolean          allYafStatsAllowed,
    gboolean          statsOnlySpecified,
    GError          **err);

int
mdPrintDNSDedupRecord(
    FILE            *fp,
    GString         *buf,
    char             delimiter,
    mdGenericRec_t  *mdRec,
    gboolean         base64,
    gboolean         print_last,
    gboolean         escape_chars,
    GError         **err);

int
mdPrintDNSRRRecord(
    GString         *buf,
    FILE            *fp,
    char             delimiter,
    mdGenericRec_t  *mdRec,
    gboolean         base64,
    gboolean         escape_chars,
    GError         **err);

gboolean
mdPrintEscapeChars(
    GString        *mdbuf,
    const uint8_t  *data,
    size_t          datalen,
    char            delimiter,
    gboolean        json);

gboolean
mdPrintDPIBasicList(
    mdExporter_t         *exporter,
    GString              *buf,
    const GString        *prefixString,
    const fbBasicList_t  *bl,
    char                  delimiter,
    gboolean              escape);

gboolean
mdPrintVariableLength(
    GString        *mdbuf,
    const uint8_t  *data,
    size_t          datalen,
    char            delimiter,
    gboolean        hex,
    gboolean        escape,
    gboolean        json);

int
mdPrintDedupRecord(
    FILE        *fp,
    GString     *buf,
    md_dedup_t  *rec,
    char         delimiter,
    GError     **err);

int
mdPrintSSLDedupRecord(
    FILE            *fp,
    GString         *buf,
    mdGenericRec_t  *mdRec,
    char             delimiter,
    GError         **err);

void
mdPrintEscapeStrChars(
    GString        *str,
    const uint8_t  *data,
    size_t          datalen,
    char            delimiter);

gboolean
mdExporterTextNewSSLPrint(
    mdExporter_t  *exporter,
    fbRecord_t    *subrec,
    const GString *prefixString);

gboolean
mdExporterTextNewSSLCertPrint(
    mdExporter_t           *exporter,
    const yafSSLDPICert_t  *cert,
    const GString          *index_str,
    uint8_t                 cert_no);

gboolean
mdExporterTextRewrittenSSLCertPrint(
    mdExporter_t          *exporter,
    md_ssl_certificate_t  *cert,
    const GString         *index_str,
    uint8_t                cert_no);

#endif  /* _MEDIATOR_PRINT_H */
