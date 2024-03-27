/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_core.h
 *
 *  Yaf mediator for filtering, DNS deduplication, and other mediator-like
 *  things
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

#ifndef _MEDIATOR_CORE_H
#define _MEDIATOR_CORE_H

#include "templates.h"
#include "mediator_inf.h"
#include "mediator_structs.h"
#include "mediator_util.h"

//typedef fbSession_t *(*md_sess_init_fn)(fbSession_t *,GError **, uint8_t, gboolean);

fbInfoModel_t *
mdInfoModel(
    void);

//fbSession_t *mdInitExporterSession(
//    fbSession_t  *session,
//    GError       **err,
//    uint8_t      stats,
//    gboolean     metadata_export);
//
//fbSession_t *mdInitExporterSessionDNSDedupOnly(
//    fbSession_t  *session,
//    GError       **err,
//    uint8_t      stats,
//    gboolean     metadata_export);
//
//fbSession_t *mdInitExporterSessionDedupOnly(
//    fbSession_t  *session,
//    GError       **err,
//    uint8_t      stats,
//    gboolean     metadata_export);
//
//fbSession_t *mdInitExporterSessionDNSRROnly(
//    fbSession_t  *session,
//    GError       **err,
//    uint8_t      stats,
//    gboolean     metadata_export);
//
//fbSession_t *mdInitExporterSessionFlowOnly(
//    fbSession_t  *session,
//    GError       **err,
//    uint8_t      stats,
//    gboolean     metadata_export);
//
//fbSession_t *mdInitExporterSessionSSLDedupOnly(
//    fbSession_t     *session,
//    GError           **err,
//    uint8_t          stats,
//    gboolean     metadata_export);
//
//void mdAllocAndInitCollectorSession(
//    mdCollector_t      *collector);
//
//fbSession_t *mdInitCollectorSession(
//    mdCollector_t      *collectorNode,
//    GError            **err);

void
mdCollectorTemplateCallback(
    fbSession_t            *session,
    uint16_t                extTid,
    fbTemplate_t           *extTmpl,
    void                   *app_ctx, /* mdCollector_t */
    void                  **tmpl_ctx,
    fbTemplateCtxFree_fn   *fn);

//gboolean mdSetExportTemplate(
//    fBuf_t *fbuf,
//    uint16_t tid,
//    GError **err);
//
//void mdPrintIP4Address(
//    char           *ipaddr_buf,
//    uint32_t       ip);
//
//gboolean mdOptionsCheck(
//    fBuf_t         **fbuf,
//    uint16_t       *tid,
//    fbTemplate_t   **tmpl,
//    GError         **err);
//
//gboolean mdForwardOptions(
//    mdContext_t       *ctx,
//    mdCollector_t     *collector,
//    fbRecord_t         *record,
//    GError            **err,
//    uint16_t          tid);

gboolean
mdProcessTombstone(
    mdContext_t        *ctx,
    mdCollector_t      *collector,
    mdGenericRec_t     *mdRec,
    GError            **err);

gboolean
mdProcessYafStats(
    mdContext_t        *ctx,
    mdCollector_t      *collector,
    mdGenericRec_t     *genRec,
    GError            **err);

gboolean
mdProcessDNSRR(
    mdContext_t *ctx,
    mdGenericRec_t *mdRec,
    GError      **err);

//gboolean mdForwardDedup(
//    mdContext_t *ctx,
//    fbRecord_t     *record,
//    GError      **err);

gboolean
mdProcessDNSDedup(
    mdContext_t    *ctx,
    mdGenericRec_t *genRec,
    GError        **err);

gboolean
mdProcessGeneralDedup(
    mdContext_t                *ctx,
    mdGeneralDedupTmplCtx_t    *tctx,
    mdGenericRec_t             *mdRec,
    GError                    **err);

gboolean
mdProcessSSLDedup(
    mdContext_t    *ctx,
    mdGenericRec_t *genRec,
    GError        **err);

gboolean
mdProcessSSLCert(
    mdContext_t    *ctx,
    mdGenericRec_t *mdRec,
    GError        **err);

gboolean
mdProcessFlow(
    mdContext_t    *ctx,
    mdFullFlow_t   *flow,
    uint8_t         yafVersion,
    GError        **err);

//void mdDecodeAndClear(
//    mdContext_t    *ctx,
//    mdFullFlow_t   *flow);
//
//gboolean mdFlowAlignOrigDPI(
//    mdContext_t   *ctx,
//    mdFullFlow_t  *flow);
//
//void mdCleanUP(
//    mdFullFlow_t  *flow);
//
//void mdCleanUpSSLCert(
//    yafSSLDPICert_t *cert);

mdFieldEntry_t *
mdMakeFieldEntryFromName(
    const char  *field,
    gboolean     onlyFetchOne,
    GError     **err);

mdFieldEntry_t *
mdCreateBasicFlowList(
    gboolean payload,
    gboolean obdomain);

mdFieldEntry_t *
mdCreateIndexFlowList(
    void);

void
attachHeadToDLL(
    mdDLL_t **head,
    mdDLL_t **tail,
    mdDLL_t *newEntry);

void
detachThisEntryOfDLL(
    mdDLL_t **head,
    mdDLL_t **tail,
    mdDLL_t  *entryToDetach);

void
detachHeadOfSLL(
    mdSLL_t **head,
    mdSLL_t **toRemove);

void
attachHeadToSLL(
    mdSLL_t **head,
    mdSLL_t  *newEntry);

#endif  /* _MEDIATOR_CORE_H */
