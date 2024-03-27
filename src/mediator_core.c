/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_core.c
 *
 *  Yaf mediator for filtering, DNS deduplication, and other mediator-like
 *  things
 *
 *  ------------------------------------------------------------------------
 *  Authors: Emily Sarneso, Matt Coates
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

#include "templates.h"
#include "mediator_core.h"
#include "mediator_filter.h"
#include "mediator_util.h"
#include "mediator_structs.h"
#include "specs.h"
#include "mediator_stat.h"
#include "mediator_dns.h"
#include "mediator_dedup.h"
#include "mediator_print.h"
#include "mediator_ssl.h"
#include "infomodel.h"

#ifdef ENABLE_SKIPSET
#include SKIPSET_HEADER_NAME
#ifdef HAVE_SILK_SKIPADDR_H
#include <silk/skipaddr.h>
#endif
#endif


#ifdef ENABLE_SKIPSET
static fbInfoElementSpec_t md_ipset_added_to_flows[] = {
    { "smIPSetMatchesSource",                1, 0 },
    { "smIPSetMatchesDestination",           1, 0 },
    FB_IESPEC_NULL
};
#endif  /* ENABLE_SKIPSET */

/**
 * mdInfoModel
 *
 * create an appropriate info model
 * ================================
 * alloc the default (with IANA elements pre-populated) via fbInfoModelAlloc
 * add in the CERT/NetSA added elements using infomodelAddGlobalElements
 *
 */
fbInfoModel_t *
mdInfoModel(
    void)
{
    static fbInfoModel_t *md_info_model = NULL;

    if (!md_info_model) {
        md_info_model = fbInfoModelAlloc();
        infomodelAddGlobalElements(md_info_model);
        if (user_elements) {
            fbInfoModelAddElementArray(md_info_model, user_elements);
        }
    }

    return md_info_model;
}

/* spec mdEmSpecYafStatsV1; struct yafStatsV1Rec_t; no defined TID since not
 * added to session */
fbTemplate_t   *yafStatsV1Tmpl;

/* spec mdEmSpecYafStatsV2; struct yafStatsV2Rec_t; no defined TID since not
 * added to session */
fbTemplate_t   *yafStatsV2Tmpl;

/* spec mdEmSpecTombstoneMainV1; struct tombstoneMainV1Rec_t; no defined TID
 * since not added to session */
fbTemplate_t   *tombstoneMainV1Tmpl;

/* spec mdEmSpecTombstoneMainV2; struct tombstoneMainV2Rec_t; no defined TID
 * since not added to session */
fbTemplate_t   *tombstoneMainV2Tmpl;

/* spec mdEmSpecTombstoneAccessV1; struct tombstoneAccessV1Rec_t; no defined
 * TID since not added to session */
fbTemplate_t   *tombstoneAccessV1Tmpl;

/* spec mdEmSpecTombstoneAccessV2; struct tombstoneAccessV2Rec_t; no defined
 * TID since not added to session */
fbTemplate_t   *tombstoneAccessV2Tmpl;

//||fbTemplate_t   *dnsDedupArecTmpl;
//||fbTemplate_t   *dnsDedupOrecTmpl;
//||fbTemplate_t   *dnsDedupLastSeenArecTmpl;
//||fbTemplate_t   *dnsDedupLastSeenOrecTmpl;
fbTemplate_t   *sslDedupTmpl;
fbTemplate_t   *yafDnsQRTmplV2;
fbTemplate_t   *yafDnsQRTmplV3;

fbTemplate_t   *yafV2SSLLevel1Tmpl;
fbTemplate_t   *yafV2SSLLevel2Tmpl;

fbTemplate_t   *yafV3SSLLevel1Tmpl;
fbTemplate_t   *yafV3SSLLevel1TmplCertList;
fbTemplate_t   *yafV3SSLLevel2Tmpl;

fbTemplate_t   *yafSSLLevel3Tmpl;
fbTemplate_t   *mdSSLRWCertLevel2Tmpl;

#define MAKE_TMPL_FROM_SPEC(_tmpl_, _spec_)             \
    MAKE_TMPL_FROM_SPEC_FLAGS(_tmpl_, _spec_, ~0)

#define MAKE_TMPL_FROM_SPEC_FLAGS(_tmpl_, _spec_, _flags_)      \
    do {                                                        \
        _tmpl_ = fbTemplateAlloc(model);                        \
        mdTemplateAppendSpecArray(_tmpl_, _spec_, _flags_);     \
    } while(0)


/* setup anything needed by "core". As of now, it's just creating templates
 * of known record types to use to compare for exact matches.
 * This helps mediator_util label templates, and know whether we can use a
 * struct when processing data
 */

gboolean
mdCoreInit(
    GError    **error)
{
    fbInfoModel_t  *model;

    MD_UNUSED_PARAM(error);

    model = mdInfoModel();

    MAKE_TMPL_FROM_SPEC(yafStatsV1Tmpl,
                        mdEmSpecYafStatsV1);
    fbTemplateSetOptionsScope(yafStatsV1Tmpl, 2);

    MAKE_TMPL_FROM_SPEC(yafStatsV2Tmpl,
                        mdEmSpecYafStatsV2);
    fbTemplateSetOptionsScope(yafStatsV2Tmpl, 3);

    MAKE_TMPL_FROM_SPEC(tombstoneMainV1Tmpl,
                        mdEmSpecTombstoneMainV1);
    MAKE_TMPL_FROM_SPEC(tombstoneAccessV1Tmpl,
                        mdEmSpecTombstoneAccessV1);
    fbTemplateSetOptionsScope(tombstoneMainV1Tmpl, 2);

    MAKE_TMPL_FROM_SPEC(tombstoneMainV2Tmpl,
                        mdEmSpecTombstoneMainV2);
    fbTemplateSetOptionsScope(tombstoneMainV2Tmpl, MD_TOMBSTONE_MAIN_SCOPE);

    MAKE_TMPL_FROM_SPEC(tombstoneAccessV2Tmpl,
                        mdEmSpecTombstoneAccessV2);

    MAKE_TMPL_FROM_SPEC_FLAGS(yafDnsQRTmplV2,
                              mdEmSpecYafDnsQR,
                              YAF_2_IE);

    MAKE_TMPL_FROM_SPEC_FLAGS(yafDnsQRTmplV3,
                              mdEmSpecYafDnsQR,
                              YAF_3_IE);

    MAKE_TMPL_FROM_SPEC(mdSSLRWCertLevel2Tmpl,
                        mdSSLRWCertLevel2Spec);

    MAKE_TMPL_FROM_SPEC(sslDedupTmpl,
                        mdSSLDedupSpec);

    MAKE_TMPL_FROM_SPEC(yafV2SSLLevel1Tmpl,
                        mdEmSpecYafV2SSLLevel1);

    /* make the default level 1 yaf 3 template be without binary cert list */
    MAKE_TMPL_FROM_SPEC_FLAGS(yafV3SSLLevel1Tmpl,
                              mdEmSpecYafV3SSLLevel1,
                              0);

    MAKE_TMPL_FROM_SPEC_FLAGS(yafV3SSLLevel1TmplCertList,
                              mdEmSpecYafV3SSLLevel1,
                              YAF_SSL_CERT_EXPORT_FLAG);

    MAKE_TMPL_FROM_SPEC_FLAGS(yafV2SSLLevel2Tmpl,
                              mdEmSpecYafSSLLevel2,
                              YAF_2_IE);

    MAKE_TMPL_FROM_SPEC_FLAGS(yafV3SSLLevel2Tmpl,
                              mdEmSpecYafSSLLevel2,
                              YAF_3_IE);

    MAKE_TMPL_FROM_SPEC(yafSSLLevel3Tmpl,
                        mdEmSpecYafSSLLevel3);

    return TRUE;
}



/**
 *  Makes an exact copy of `origTmpl`, stores it in the referent of `newTmpl`,
 *  and adds `newTmpl` as an internal template to `session` with template ID
 *  `origTid`, storing the result in the referent of `newTid`.
 *
 *  Exits the application on error, using `msgPref` to prefix the error
 *  messages.
 */
static void
copyTemplateAddToSesssion(
    fbSession_t        *session,
    fbTemplate_t      **newTmpl,
    uint16_t           *newTid,
    const fbTemplate_t *origTmpl,
    uint16_t            origTid,
    const GString      *msgPref)
{
    *newTmpl = fbTemplateCopy(origTmpl, 0);
    if (!*newTmpl) {
        g_error("%s Could not copy template %#06x", msgPref->str, origTid);
    }
    *newTid = mdSessionAddTemplate(session, TRUE, origTid, *newTmpl, NULL);
}


static void
mdSetupTemplateCtxPair(
    mdDefaultTmplCtx_t        *extCtx,
    mdDefaultTmplCtx_t        *intCtx,
    uint16_t                   extTid,
    uint16_t                   intTid,
    mdUtilTemplateType_t       templateType,
    mdUtilTemplateContents_t   templateContents,
    mdTmplCtxType_t            contextType)
{
    extCtx->templateType        = templateType;
    extCtx->templateContents    = templateContents;
    extCtx->associatedIntTid    = intTid;
    extCtx->contextType         = contextType;

    intCtx->templateType        = templateType;
    intCtx->templateContents    = templateContents;
    intCtx->associatedExtTid    = extTid;
    intCtx->contextType         = contextType;
}


static void
handleCtxListType(
    const fbTemplate_t       *tmpl,
    fbInfoElementDataType_t   dataType,
    uint16_t                **offsets,
    uint16_t                 *count)
{
    const fbTemplateField_t    *field;
    uint16_t                    position;
    uint16_t                    i;

    position = 0;
    *count = 0;
    while ((field = fbTemplateFindFieldByDataType(tmpl, dataType,
                                                  &position, 0)))
    {
        ++position;
        ++*count;
    }

    if (0 == *count) {
        *offsets = NULL;
        return;
    }

    *offsets = g_new(uint16_t, *count);
    position = 0;
    i = 0;
    while ((field = fbTemplateFindFieldByDataType(tmpl, dataType,
                                                  &position, 0)))
    {
        ++position;
        (*offsets)[i] = field->offset;
        ++i;
    }
}


void
mdTemplateContextSetListOffsets(
    mdDefaultTmplCtx_t *tmplCtx,
    const fbTemplate_t *tmpl)
{
    if (tmplCtx && tmpl) {
        handleCtxListType(tmpl, FB_BASIC_LIST,
                          &(tmplCtx->blOffsets), &(tmplCtx->blCount));
        handleCtxListType(tmpl, FB_SUB_TMPL_LIST,
                          &(tmplCtx->stlOffsets), &(tmplCtx->stlCount));
        handleCtxListType(tmpl, FB_SUB_TMPL_MULTI_LIST,
                          &(tmplCtx->stmlOffsets), &(tmplCtx->stmlCount));
    }
}


/* only called in callback within a lock/unlock block */
#define CALLBACK_GET_CTX_FIELD(_tmpl_, _tid_, _ent_, _num_, _ctxIE_)    \
    do {                                                                \
        if (!(_ctxIE_ = fbTemplateFindFieldByIdent(                     \
                  _tmpl_, _ent_, _num_, NULL, 0)))                      \
        {                                                               \
            g_warning("no IE %d %d in flow tmpl %#x",                   \
                      _ent_, _num_, _tid_);                             \
        }                                                               \
    } while(0)



/*
 *  **********************************************************************
 *
 *  Helper functions for mdCollectorTemplateCallback(), alphabetically.
 *
 */


/*
 *  Handles TC_DNS_DEDUP records for mdCollectorTemplateCallback().
 */
static fbTemplate_t *
mdCollectorTemplateCallbackDnsDedup(
    mdCollector_t              *collector,
    fbSession_t                *session,
    fbTemplate_t              **newIntTmpl,
    uint16_t                   *newIntTid,
    const fbTemplate_t         *extTmpl,
    uint16_t                    extTid,
    const GString              *msgPref,
    mdUtilTemplateType_t        templateType,
    mdUtilTemplateContents_t    templateContents,
    fbTemplate_t              **exporterExportTmpl,
    fbTemplate_t              **origIntTmpl,
    void                      **tmpl_ctx,
    fbTemplateCtxFree_fn       *fn)
{
    mdDefaultTmplCtx_t         *defExtTmplCtx   = NULL;
    mdDefaultTmplCtx_t         *defIntTmplCtx   = NULL;

    fbTemplate_t *intTmpl = NULL;
    uint16_t intTid;

    MD_UNUSED_PARAM(origIntTmpl);
    g_assert(TC_DNS_DEDUP == templateContents.general);

    /*
     * DNS Dedup is generated by super_mediator, so assume we know all
     * the fields it contains.
     *
     * If a later version of SM adds additional fields and this SM
     * attempts to read it, those fields will be ignored.  It would be
     * good to avoid that, but we are primarily concerned about
     * changes to yaf.
     */
    /* for generating the export template */
    uint32_t specFlags;
    const fbInfoElementSpec_t obname = {"observationDomainName", 0, 0};

    /* internal template is always mdDNSDedupTmplSpec/md_dns_dedup_t */
    intTmpl = fbTemplateAlloc(fbTemplateGetInfoModel(extTmpl));
    mdTemplateAppendSpecArray(intTmpl, mdDNSDedupTmplSpec, ~0);
    intTid = mdSessionAddTemplate(session, TRUE, extTid, intTmpl, NULL);

    defExtTmplCtx = g_slice_new0(mdDefaultTmplCtx_t);
    defIntTmplCtx = g_slice_new0(mdDefaultTmplCtx_t);

    /* determine what the export template should contain */
    specFlags = 0;
    if (templateContents.specCase.dnsDedup & TC_DNS_DEDUP_AREC) {
        specFlags |= MD_DNS_DD_AREC;
    } else if (templateContents.specCase.dnsDedup & TC_DNS_DEDUP_OREC) {
        specFlags |= MD_DNS_DD_OREC;
    } else {
        specFlags |= MD_DNS_DD_AAAAREC;
    }
    if (templateContents.specCase.dnsDedup & TC_DNS_DEDUP_LS_V1) {
        specFlags |= MD_DNS_DD_LAST_SEEN | MD_DNS_DD_XPTR_NAME;
    } else {
        if (templateContents.specCase.dnsDedup & TC_DNS_DEDUP_LS_V2) {
            specFlags |= MD_DNS_DD_LAST_SEEN;
        }
        if (fbTemplateContainsElementByName(extTmpl, &obname)) {
            specFlags |= MD_DNS_DD_XPTR_NAME;
        }
    }

    *exporterExportTmpl =
        fbTemplateAlloc(fbTemplateGetInfoModel(extTmpl));
    mdTemplateAppendSpecArray(
        *exporterExportTmpl, mdDNSDedupTmplSpec, specFlags);

    mdSetupTemplateCtxPair(defExtTmplCtx,
                           defIntTmplCtx,
                           extTid,
                           intTid,
                           templateType,
                           templateContents,
                           TCTX_TYPE_DEFAULT);
    mdTemplateContextSetListOffsets(defIntTmplCtx, intTmpl);
    mdTemplateContextSetListOffsets(defExtTmplCtx, extTmpl);

    if (templateContents.specCase.dnsDedup &
        (TC_DNS_DEDUP_LS_V1 | TC_DNS_DEDUP_LS_V2))
    {
        /* it's a last seen template, use end time */
        CALLBACK_GET_CTX_FIELD(extTmpl, extTid, 0, 153,
                               defExtTmplCtx->dataCTimeIE);
        CALLBACK_GET_CTX_FIELD(intTmpl, intTid, 0, 153,
                               defIntTmplCtx->dataCTimeIE);
    } else {
        /* it's not last seen, use start time */
        CALLBACK_GET_CTX_FIELD(extTmpl, extTid, 0, 152,
                               defExtTmplCtx->dataCTimeIE);
        CALLBACK_GET_CTX_FIELD(intTmpl, intTid, 0, 152,
                               defIntTmplCtx->dataCTimeIE);
    }
    if (!defIntTmplCtx->dataCTimeIE) {
        g_error("%s no timestamp in DNS Dedup record", msgPref->str);
    } else {
        mdCollectorHasDataTimestampField(collector);
    }

    *tmpl_ctx = defExtTmplCtx;
    *fn = templateCtxFree;

    fbTemplateSetContext(intTmpl, defIntTmplCtx, NULL, templateCtxFree);

    *newIntTmpl = intTmpl;
    *newIntTid = intTid;

    return intTmpl;
}


/*
 *  Handles TC_DNS_RR records for mdCollectorTemplateCallback().
 */
static fbTemplate_t *
mdCollectorTemplateCallbackDnsRR(
    mdCollector_t              *collector,
    fbSession_t                *session,
    fbTemplate_t              **newIntTmpl,
    uint16_t                   *newIntTid,
    const fbTemplate_t         *extTmpl,
    uint16_t                    extTid,
    const GString              *msgPref,
    mdUtilTemplateType_t        templateType,
    mdUtilTemplateContents_t    templateContents,
    fbTemplate_t              **exporterExportTmpl,
    fbTemplate_t              **origIntTmpl,
    void                      **tmpl_ctx,
    fbTemplateCtxFree_fn       *fn)
{
    mdDefaultTmplCtx_t         *defExtTmplCtx   = NULL;
    mdDefaultTmplCtx_t         *defIntTmplCtx   = NULL;

    fbTemplate_t *intTmpl = NULL;
    uint16_t intTid;

    MD_UNUSED_PARAM(collector);
    MD_UNUSED_PARAM(exporterExportTmpl);
    MD_UNUSED_PARAM(origIntTmpl);
    g_assert(TC_DNS_RR == templateContents.general);

    copyTemplateAddToSesssion(
        session, &intTmpl, &intTid, extTmpl, extTid, msgPref);

    defExtTmplCtx   = g_slice_new0(mdDefaultTmplCtx_t);
    defIntTmplCtx   = g_slice_new0(mdDefaultTmplCtx_t);

    mdSetupTemplateCtxPair(defExtTmplCtx,
                           defIntTmplCtx,
                           extTid,
                           intTid,
                           templateType,
                           templateContents,
                           TCTX_TYPE_DEFAULT);
    mdTemplateContextSetListOffsets(defIntTmplCtx, intTmpl);
    mdTemplateContextSetListOffsets(defExtTmplCtx, extTmpl);

    /* DNS_RR records only have start time */
    /* flowStartMilliseconds */
    CALLBACK_GET_CTX_FIELD(extTmpl, extTid, 0, 152,
                           defExtTmplCtx->dataCTimeIE);
    CALLBACK_GET_CTX_FIELD(intTmpl, intTid, 0, 152,
                           defIntTmplCtx->dataCTimeIE);

    *tmpl_ctx = defExtTmplCtx;
    *fn = templateCtxFree;

    fbTemplateSetContext(intTmpl, defIntTmplCtx,
                         NULL, templateCtxFree);

    *newIntTmpl = intTmpl;
    *newIntTid = intTid;

    return intTmpl;
}


/*
 *  Handles TC_DPI records for mdCollectorTemplateCallback().
 */
static fbTemplate_t *
mdCollectorTemplateCallbackDpi(
    mdCollector_t              *collector,
    fbSession_t                *session,
    fbTemplate_t              **newIntTmpl,
    uint16_t                   *newIntTid,
    const fbTemplate_t         *extTmpl,
    uint16_t                    extTid,
    const GString              *msgPref,
    mdUtilTemplateType_t        templateType,
    mdUtilTemplateContents_t    templateContents,
    fbTemplate_t              **exporterExportTmpl,
    fbTemplate_t              **origIntTmpl,
    void                      **tmpl_ctx,
    fbTemplateCtxFree_fn       *fn)
{
    mdDefaultTmplCtx_t         *defIntTmplCtx   = NULL;

    fbTemplate_t *intTmpl = NULL;
    uint16_t intTid;

    MD_UNUSED_PARAM(collector);
    MD_UNUSED_PARAM(exporterExportTmpl);
    MD_UNUSED_PARAM(origIntTmpl);
    g_assert(TC_DPI == templateContents.general);

    copyTemplateAddToSesssion(
        session, &intTmpl, &intTid, extTmpl, extTid, msgPref);

    /* DPI template, so add template pair for proper processing */
    fbSessionAddTemplatePair(session, extTid, intTid);

    /* nothing special for context, so set up base information */
    defIntTmplCtx   = g_slice_new0(mdDefaultTmplCtx_t);
    defIntTmplCtx->contextType      = TCTX_TYPE_DEFAULT;
    defIntTmplCtx->templateType     = templateType;
    defIntTmplCtx->templateContents = templateContents;
    mdTemplateContextSetListOffsets(defIntTmplCtx, intTmpl);

    /* will never be top level if we know it's DPI here, so no need
     * to set up context pairs, or put context on external template */
    /* FIXME: yes, but this means all someone needs to do to bring down SM
     * is to send a top-level record that uses one of these DPI
     * templates */

    *tmpl_ctx = NULL;
    *fn = NULL;

    fbTemplateSetContext(intTmpl, defIntTmplCtx, NULL, templateCtxFree);

    *newIntTmpl = intTmpl;
    *newIntTid = intTid;

    return intTmpl;
}


/*
 *  Handles TC_FLOW records for mdCollectorTemplateCallback().
 */
static fbTemplate_t *
mdCollectorTemplateCallbackFlow(
    mdCollector_t              *collector,
    fbSession_t                *session,
    fbTemplate_t              **newIntTmpl,
    uint16_t                   *newIntTid,
    const fbTemplate_t         *extTmpl,
    uint16_t                    extTid,
    const GString              *msgPref,
    mdUtilTemplateType_t        templateType,
    mdUtilTemplateContents_t    templateContents,
    fbTemplate_t              **exporterExportTmpl,
    fbTemplate_t              **origIntTmpl,
    void                      **tmpl_ctx,
    fbTemplateCtxFree_fn       *fn)
{
    mdCollIntFlowTmplCtx_t         *colFlowExtTmplCtx   = NULL;
    mdCollIntFlowTmplCtx_t         *colFlowIntTmplCtx   = NULL;

    fbTemplate_t *intTmpl = NULL;
    uint16_t intTid;

    g_assert(TC_FLOW == templateContents.general);

    /* context for the incoming internal tmeplate */
    colFlowExtTmplCtx   = g_slice_new0(mdCollIntFlowTmplCtx_t);
    colFlowIntTmplCtx   = g_slice_new0(mdCollIntFlowTmplCtx_t);

    /* when global preserve_obdomain is TRUE, must disable it per incoming
     * template */
    colFlowIntTmplCtx->preserve_obdomain = md_config.preserve_obdomain;

    intTmpl = fbTemplateCopy(extTmpl, 0);
    if (!intTmpl) {
        g_error("%s Error copying template of flow record", msgPref->str);
    }

    /* FIXME: It probably would be more efficient to have one loop over
     * the template's fields looking for IEs of interest instead of these
     * separate calls to mdUtilGetIEOffset() and CALLBACK_GET_CTX_FIELD() */

    /* Check for observationDomainId; add it if not present */
    if (mdUtilGetIEOffset(intTmpl, 0, 149) == UINT16_MAX) {
        const fbInfoElementSpec_t observationDomainId =
            {"observationDomainId", 4, 0};
        if (colFlowIntTmplCtx->preserve_obdomain) {
            g_message("%s No observationDomainId to preserve - ignoring",
                      msgPref->str);
            colFlowIntTmplCtx->preserve_obdomain = FALSE;
        }
        mdTemplateAppendOneSpec(intTmpl, &observationDomainId, 0);
        g_message("%s Added observationDomainId", msgPref->str);
    } else {
        g_message("%s Already has observationDomainId", msgPref->str);
    }

    /* Check for yafFlowKeyHash; add it if not present */
    if (mdUtilGetIEOffset(intTmpl, 6871, 106) == UINT16_MAX) {
        const fbInfoElementSpec_t yafFlowKeyHash =
            {"yafFlowKeyHash", 4, 0};
        mdTemplateAppendOneSpec(intTmpl, &yafFlowKeyHash, 0);
        g_message("%s Added yafFlowKeyHash", msgPref->str);
    }

#ifdef ENABLE_SKIPSET
    if (md_ipset) {
        if (mdUtilGetIEOffset(intTmpl, 6871, 931) == UINT16_MAX) {
            /* need to add smIPSetMatchesSource,
             * smIPSetMatchesDestination */
            mdTemplateAppendSpecArray(intTmpl, md_ipset_added_to_flows, 0);
            g_message("%s Added IPSet matches elements", msgPref->str);
        }
    }
#endif  /* ENABLE_SKIPSET */

        /* If any exporter has flowDpiStrip active and if the template is from
         * YAF-2, make a copy of intTmpl, add tcp elements to it, and use it
         * as the collector's internal template.  Use the original intTmpl for
         * exporters where flowDpiStrip is FALSE. */
    if (md_config.flowDpiStrip &&
        templateContents.yafVersion != TC_YAF_VERSION_3 &&
        !fbTemplateContainsElementByName(intTmpl, mdCheckerTcpSubrec))
    {
        const fbInfoElementSpec_t reverse =
            {"reverseFlowDeltaMilliseconds", 4, 0};
        uint32_t flags;

        flags = (fbTemplateContainsElementByName(intTmpl, &reverse)
                 ? 1 : 0);

        *origIntTmpl = fbTemplateCopy(intTmpl, 0);
        mdTemplateAppendSpecArray(intTmpl, mdCheckerTcpSubrec, flags);
    }

    intTid = mdSessionAddTemplate(session, TRUE, extTid, intTmpl, NULL);

    mdSetupTemplateCtxPair(&colFlowExtTmplCtx->defCtx,
                           &colFlowIntTmplCtx->defCtx,
                           extTid,
                           intTid,
                           templateType,
                           templateContents,
                           TCTX_TYPE_COL_FLOW);
    mdTemplateContextSetListOffsets(&colFlowIntTmplCtx->defCtx, intTmpl);
    mdTemplateContextSetListOffsets(&colFlowExtTmplCtx->defCtx, extTmpl);

    /* get offsets into record for writing values SM adds to flows */

    colFlowExtTmplCtx->observationDomainOffset =
        mdUtilGetIEOffset(extTmpl, 0, 149);
    colFlowIntTmplCtx->observationDomainOffset =
        mdUtilGetIEOffset(intTmpl, 0, 149);

    colFlowExtTmplCtx->flowKeyHashOffset =
        mdUtilGetIEOffset(extTmpl, 6871, 106);
    colFlowIntTmplCtx->flowKeyHashOffset =
        mdUtilGetIEOffset(intTmpl, 6871, 106);

#ifdef ENABLE_SKIPSET
    colFlowExtTmplCtx->smIPSetMatchesSourceOffset =
        mdUtilGetIEOffset(extTmpl, CERT_PEN, 931);
    colFlowIntTmplCtx->smIPSetMatchesSourceOffset =
        mdUtilGetIEOffset(intTmpl, CERT_PEN, 931);

    colFlowExtTmplCtx->smIPSetMatchesDestinationOffset =
        mdUtilGetIEOffset(extTmpl, CERT_PEN, 932);
    colFlowIntTmplCtx->smIPSetMatchesDestinationOffset =
        mdUtilGetIEOffset(intTmpl, CERT_PEN, 932);
#endif  /* ENABLE_SKIPSET */

    colFlowExtTmplCtx->sipV6Offset =
        mdUtilGetIEOffset(extTmpl, 0, 27);
    colFlowIntTmplCtx->sipV6Offset =
        mdUtilGetIEOffset(intTmpl, 0, 27);

    if (colFlowExtTmplCtx->sipV6Offset == UINT16_MAX) {
        colFlowExtTmplCtx->v4 = TRUE;
    }
    if (colFlowIntTmplCtx->sipV6Offset == UINT16_MAX) {
        colFlowIntTmplCtx->v4 = TRUE;
    }

    colFlowExtTmplCtx->dipV6Offset =
        mdUtilGetIEOffset(extTmpl, 0, 28);
    colFlowIntTmplCtx->dipV6Offset =
        mdUtilGetIEOffset(intTmpl, 0, 28);

    /* get silkAppLabel offset. May not be in template, need to be able
     * to check if it's NULL. Can't use presense in infoModel for canon */
    colFlowExtTmplCtx->appLabelOffset =
        mdUtilGetIEOffset(extTmpl, 6871, 33);
    colFlowIntTmplCtx->appLabelOffset =
        mdUtilGetIEOffset(intTmpl, 6871, 33);

    /* get STML offset for DPI processing
     * this will change to "dpi" STL */
    if (templateContents.yafVersion == TC_YAF_VERSION_3) {
        /* yafDPIList */
        colFlowExtTmplCtx->dpiListOffset
            = mdUtilGetIEOffset(extTmpl, 6871, 432);
        colFlowIntTmplCtx->dpiListOffset =
            mdUtilGetIEOffset(intTmpl, 6871, 432);
    } else if (templateContents.yafVersion == TC_YAF_VERSION_2) {
        colFlowExtTmplCtx->dpiListOffset =
            mdUtilGetIEOffset(extTmpl, 0, 293);
        colFlowIntTmplCtx->dpiListOffset =
            mdUtilGetIEOffset(intTmpl, 0, 293);
    } else {
        /* TODO do better with orig vs v3, and decide what happens with
         * no lists. This printf goes away
         */
        g_warning("FIXME: not sure which version of YAF"
                  "...or has no lists...verify");
        colFlowExtTmplCtx->dpiListOffset = UINT16_MAX;
        colFlowIntTmplCtx->dpiListOffset = UINT16_MAX;
    }

    /* get IEs for particular flow values used by SM explicitly */
    /* get flowStartMilliseconds */
    CALLBACK_GET_CTX_FIELD(extTmpl, extTid, 0, 152,
                           colFlowExtTmplCtx->flowStartMS);
    CALLBACK_GET_CTX_FIELD(intTmpl, intTid, 0, 152,
                           colFlowIntTmplCtx->flowStartMS);

    /* get flowEndMilliseconds for time IE */
    CALLBACK_GET_CTX_FIELD(extTmpl, extTid, 0, 153,
                           colFlowExtTmplCtx->defCtx.dataCTimeIE);
    CALLBACK_GET_CTX_FIELD(intTmpl, intTid, 0, 153,
                           colFlowIntTmplCtx->defCtx.dataCTimeIE);
    if (!colFlowIntTmplCtx->defCtx.dataCTimeIE) {
        g_critical("%s No time IE for flow", msgPref->str);
    } else {
        mdCollectorHasDataTimestampField(collector);
    }

    /* get SIP4 */
    if (colFlowExtTmplCtx->v4) {
        CALLBACK_GET_CTX_FIELD(extTmpl, extTid, 0, 8,
                               colFlowExtTmplCtx->sip4);
        CALLBACK_GET_CTX_FIELD(intTmpl, intTid, 0, 8,
                               colFlowIntTmplCtx->sip4);

        /* get DIP4 */
        CALLBACK_GET_CTX_FIELD(extTmpl, extTid, 0, 12,
                               colFlowExtTmplCtx->dip4);
        CALLBACK_GET_CTX_FIELD(intTmpl, intTid, 0, 12,
                               colFlowIntTmplCtx->dip4);
    }

    /* get sport */
    CALLBACK_GET_CTX_FIELD(extTmpl, extTid, 0, 7,
                           colFlowExtTmplCtx->sport);
    CALLBACK_GET_CTX_FIELD(intTmpl, intTid, 0, 7,
                           colFlowIntTmplCtx->sport);

    /* get dport */
    CALLBACK_GET_CTX_FIELD(extTmpl, extTid, 0, 11,
                           colFlowExtTmplCtx->dport);
    CALLBACK_GET_CTX_FIELD(intTmpl, intTid, 0, 11,
                           colFlowIntTmplCtx->dport);

    /* get vlanId */
    CALLBACK_GET_CTX_FIELD(extTmpl, extTid, 0, 58,
                           colFlowExtTmplCtx->vlanId);
    CALLBACK_GET_CTX_FIELD(intTmpl, intTid, 0, 58,
                           colFlowIntTmplCtx->vlanId);

    /* get protocol */
    CALLBACK_GET_CTX_FIELD(extTmpl, extTid, 0, 4,
                           colFlowExtTmplCtx->protocol);
    CALLBACK_GET_CTX_FIELD(intTmpl, intTid, 0, 4,
                           colFlowIntTmplCtx->protocol);

    /* get flowEndReason */
    CALLBACK_GET_CTX_FIELD(extTmpl, extTid, 0, 136,
                           colFlowExtTmplCtx->flowEndReason);
    CALLBACK_GET_CTX_FIELD(intTmpl, intTid, 0, 136,
                           colFlowIntTmplCtx->flowEndReason);

    *tmpl_ctx = colFlowExtTmplCtx;
    *fn = templateCtxFree;

    fbTemplateSetContext(intTmpl, colFlowIntTmplCtx, NULL, templateCtxFree);

    if (*origIntTmpl) {
        CALLBACK_GET_CTX_FIELD(intTmpl, intTid, 0, 184,
                               colFlowIntTmplCtx->tcpSequenceNumber);
        *exporterExportTmpl = *origIntTmpl;
        //            fbTemplateSetContext(
        //                origIntTmpl,
        //                templateCtxCopy((mdDefaultTmplCtx_t *)colFlowIntTmplCtx),
        //                NULL, templateCtxFree);
    }

    *newIntTmpl = intTmpl;
    *newIntTid = intTid;

    return intTmpl;
}


/*
 *  Handles TC_GENERAL_DEDUP records for mdCollectorTemplateCallback().
 */
static fbTemplate_t *
mdCollectorTemplateCallbackGeneralDedup(
    mdCollector_t              *collector,
    fbSession_t                *session,
    fbTemplate_t              **newIntTmpl,
    uint16_t                   *newIntTid,
    const fbTemplate_t         *extTmpl,
    uint16_t                    extTid,
    const GString              *msgPref,
    mdUtilTemplateType_t        templateType,
    mdUtilTemplateContents_t    templateContents,
    fbTemplate_t              **exporterExportTmpl,
    fbTemplate_t              **origIntTmpl,
    void                      **tmpl_ctx,
    fbTemplateCtxFree_fn       *fn)
{
    mdGeneralDedupTmplCtx_t         *dedupExtTmplCtx   = NULL;
    mdGeneralDedupTmplCtx_t         *dedupIntTmplCtx   = NULL;

    const fbTemplateField_t *ie;
    fbTemplate_t *intTmpl = NULL;
    uint16_t intTid;

    MD_UNUSED_PARAM(collector);
    MD_UNUSED_PARAM(exporterExportTmpl);
    MD_UNUSED_PARAM(origIntTmpl);
    g_assert(TC_GENERAL_DEDUP == templateContents.general);

    copyTemplateAddToSesssion(
        session, &intTmpl, &intTid, extTmpl, extTid, msgPref);

    dedupExtTmplCtx = g_slice_new0(mdGeneralDedupTmplCtx_t);
    dedupIntTmplCtx = g_slice_new0(mdGeneralDedupTmplCtx_t);

    mdSetupTemplateCtxPair(&dedupExtTmplCtx->defCtx,
                           &dedupIntTmplCtx->defCtx,
                           extTid,
                           intTid,
                           templateType,
                           templateContents,
                           TCTX_TYPE_GENERAL_DEDUP);
    mdTemplateContextSetListOffsets(&dedupIntTmplCtx->defCtx, intTmpl);
    mdTemplateContextSetListOffsets(&dedupExtTmplCtx->defCtx, extTmpl);

    /* find the IE used for dedup, needed for exporting */

    dedupExtTmplCtx->numElem        = fbTemplateCountElements(extTmpl);

    ie = fbTemplateGetFieldByPosition(extTmpl,
                                      (dedupExtTmplCtx->numElem)-1);

    dedupExtTmplCtx->ieEnt                      = ie->canon->ent;
    dedupExtTmplCtx->ieNum                      = ie->canon->num;

    dedupIntTmplCtx->numElem        = fbTemplateCountElements(intTmpl);

    ie = fbTemplateGetFieldByPosition(intTmpl,
                                      (dedupIntTmplCtx->numElem)-1);

    dedupIntTmplCtx->ieEnt                      = ie->canon->ent;
    dedupIntTmplCtx->ieNum                      = ie->canon->num;

    *tmpl_ctx = dedupExtTmplCtx;
    *fn = templateCtxFree;

    fbTemplateSetContext(intTmpl, dedupIntTmplCtx,
                         NULL, templateCtxFree);

    *newIntTmpl = intTmpl;
    *newIntTid = intTid;

    return intTmpl;
}


/*
 *  Handles TC_SSL_DEDUP records for mdCollectorTemplateCallback().
 */
static fbTemplate_t *
mdCollectorTemplateCallbackSslDedup(
    mdCollector_t              *collector,
    fbSession_t                *session,
    fbTemplate_t              **newIntTmpl,
    uint16_t                   *newIntTid,
    const fbTemplate_t         *extTmpl,
    uint16_t                    extTid,
    const GString              *msgPref,
    mdUtilTemplateType_t        templateType,
    mdUtilTemplateContents_t    templateContents,
    fbTemplate_t              **exporterExportTmpl,
    fbTemplate_t              **origIntTmpl,
    void                      **tmpl_ctx,
    fbTemplateCtxFree_fn       *fn)
{
    mdDefaultTmplCtx_t         *defExtTmplCtx   = NULL;
    mdDefaultTmplCtx_t         *defIntTmplCtx   = NULL;

    fbTemplate_t *intTmpl = NULL;
    uint16_t intTid;

    MD_UNUSED_PARAM(collector);
    MD_UNUSED_PARAM(exporterExportTmpl);
    MD_UNUSED_PARAM(origIntTmpl);
    g_assert(TC_SSL_DEDUP == templateContents.general);

    copyTemplateAddToSesssion(
        session, &intTmpl, &intTid, extTmpl, extTid, msgPref);

    defExtTmplCtx   = g_slice_new0(mdDefaultTmplCtx_t);
    defIntTmplCtx   = g_slice_new0(mdDefaultTmplCtx_t);

    mdSetupTemplateCtxPair(defExtTmplCtx,
                           defIntTmplCtx,
                           extTid,
                           intTid,
                           templateType,
                           templateContents,
                           TCTX_TYPE_DEFAULT);
    mdTemplateContextSetListOffsets(defIntTmplCtx, intTmpl);
    mdTemplateContextSetListOffsets(defExtTmplCtx, extTmpl);

    /* SSL_DEDUP records have both start and end time */
    /* flowEndMilliseconds */
    CALLBACK_GET_CTX_FIELD(extTmpl, extTid, 0, 153,
                           defExtTmplCtx->dataCTimeIE);
    CALLBACK_GET_CTX_FIELD(intTmpl, intTid, 0, 153,
                           defIntTmplCtx->dataCTimeIE);

    *tmpl_ctx = defExtTmplCtx;
    *fn = templateCtxFree;

    fbTemplateSetContext(intTmpl, defIntTmplCtx,
                         NULL, templateCtxFree);

    *newIntTmpl = intTmpl;
    *newIntTid = intTid;

    return intTmpl;
}


/*
 *  Handles TC_TOMBSTONE records for mdCollectorTemplateCallback().
 */
static fbTemplate_t *
mdCollectorTemplateCallbackTombstone(
    mdCollector_t              *collector,
    fbSession_t                *session,
    fbTemplate_t              **newIntTmpl,
    uint16_t                   *newIntTid,
    const fbTemplate_t         *extTmpl,
    uint16_t                    extTid,
    const GString              *msgPref,
    mdUtilTemplateType_t        templateType,
    mdUtilTemplateContents_t    templateContents,
    fbTemplate_t              **exporterExportTmpl,
    fbTemplate_t              **origIntTmpl,
    void                      **tmpl_ctx,
    fbTemplateCtxFree_fn       *fn)
{
    mdTombstoneTmplCtx_t           *tombstoneExtTmplCtx = NULL;
    mdTombstoneTmplCtx_t           *tombstoneIntTmplCtx = NULL;
    mdDefaultTmplCtx_t         *defExtTmplCtx   = NULL;
    mdDefaultTmplCtx_t         *defIntTmplCtx   = NULL;

    const fbTemplateField_t *ie;
    fbTemplate_t *intTmpl = NULL;
    uint16_t intTid;

    MD_UNUSED_PARAM(exporterExportTmpl);
    MD_UNUSED_PARAM(origIntTmpl);
    g_assert(TC_TOMBSTONE == templateContents.general);

    switch (templateContents.specCase.tombstone) {
      case TC_TOMBSTONE_V1:
        /*
         * Since SM v1.x needlessly exports both versions of the tombstone
         * templates (but only uses V2), this template may be unused.  Do
         * not pass anything to the exporter at this time; we will figure
         * out which templates the exporter needs should we ever actually
         * read one of these, which are only emitted by yaf-2.10.0.
         *
         * In case we do see records that use this template, we specify a
         * customized internal template that has the same memory layout as
         * tombstoneMainV2Rec_t.
         */
        intTmpl = fbTemplateAlloc(fbTemplateGetInfoModel(extTmpl));
        mdTemplateAppendSpecArray(
            intTmpl, mdEmSpecTombstoneMainV1Reader, ~0);
        intTid = mdSessionAddTemplate(session, TRUE, extTid, intTmpl, NULL);

        defExtTmplCtx   = g_slice_new0(mdDefaultTmplCtx_t);
        defIntTmplCtx   = g_slice_new0(mdDefaultTmplCtx_t);

        mdSetupTemplateCtxPair(defExtTmplCtx,
                               defIntTmplCtx,
                               extTid,
                               intTid,
                               templateType,
                               templateContents,
                               TCTX_TYPE_DEFAULT);
        mdTemplateContextSetListOffsets(defIntTmplCtx, intTmpl);
        mdTemplateContextSetListOffsets(defExtTmplCtx, extTmpl);

        *tmpl_ctx = defExtTmplCtx;
        *fn = templateCtxFree;
        fbTemplateSetContext(intTmpl, defIntTmplCtx,
                             NULL, templateCtxFree);

        /* done in this function, clean up and return */
        mdCollectorUpdateMaxRecord(collector);
        return NULL;

      case TC_TOMBSTONE_ACCESS_V1:
        /* Handle similar to the previous case: add it only to the
         * collector.  Since we expect this to appear only in an STL, only
         * create the context for the internal template and add a template
         * pair. */
        copyTemplateAddToSesssion(
            session, &intTmpl, &intTid, extTmpl, extTid, msgPref);

        defIntTmplCtx   = g_slice_new0(mdDefaultTmplCtx_t);
        defIntTmplCtx->templateType        = templateType;
        defIntTmplCtx->templateContents    = templateContents;
        defIntTmplCtx->associatedExtTid    = 0;
        defIntTmplCtx->contextType         = TCTX_TYPE_DEFAULT;
        mdTemplateContextSetListOffsets(defIntTmplCtx, intTmpl);

        fbTemplateSetContext(intTmpl, defIntTmplCtx,
                             NULL, templateCtxFree);

        fbSessionAddTemplatePair(session, extTid, intTid);

        *tmpl_ctx = NULL;
        *fn = NULL;

        /* done in this function, clean up and return */
        mdCollectorUpdateMaxRecord(collector);
        return NULL;

      case TC_TOMBSTONE_V2:
        /* Treat this a normally: adding it to both the collector and
         * exporter.  At export time, the exporter will use the
         * GEN_TOMBSTONE top-level template if it exists. */
        if (templateContents.relative != TC_EXACT) {
            /* TODO handle these cases */
            g_warning("FIXME: SUPER, SUB, or MIX of tombstone 2");
        }

        copyTemplateAddToSesssion(
            session, &intTmpl, &intTid, extTmpl, extTid, msgPref);

        tombstoneExtTmplCtx   = g_slice_new0(mdTombstoneTmplCtx_t);
        tombstoneIntTmplCtx   = g_slice_new0(mdTombstoneTmplCtx_t);

        mdSetupTemplateCtxPair(&tombstoneExtTmplCtx->defCtx,
                               &tombstoneIntTmplCtx->defCtx,
                               extTid,
                               intTid,
                               templateType,
                               templateContents,
                               TCTX_TYPE_TOMBSTONE);
        mdTemplateContextSetListOffsets(&tombstoneIntTmplCtx->defCtx, intTmpl);
        mdTemplateContextSetListOffsets(&tombstoneExtTmplCtx->defCtx, extTmpl);

        ie = fbTemplateFindFieldByDataType(intTmpl, FB_SUB_TMPL_LIST,
                                           NULL, 0);
        if (!ie) {
            g_error("%s No STL in tombstone", msgPref->str);
        }
        /* store the offset for the tombstone access list STL */
        tombstoneIntTmplCtx->accessListOffset = ie->offset;

        /* observationTimeSeconds */
        CALLBACK_GET_CTX_FIELD(
            extTmpl, extTid, 0, 322,
            tombstoneExtTmplCtx->defCtx.sourceRuntimeCTimeIE);
        CALLBACK_GET_CTX_FIELD(
            intTmpl, intTid, 0, 322,
            tombstoneIntTmplCtx->defCtx.sourceRuntimeCTimeIE);

        mdCollectorHasSourceRuntimeTimestampField(collector);

        *tmpl_ctx = tombstoneExtTmplCtx;
        *fn = templateCtxFree;

        fbTemplateSetContext(intTmpl, tombstoneIntTmplCtx,
                             NULL, templateCtxFree);
        break;

      case TC_TOMBSTONE_ACCESS_V2:
        /* If GEN_TOMBSTONE is active, use that template transcoding on
         * import is the easiest place to specify the template.
         * Otherwise, add to the collector and the exporter.  Since this
         * should only be used in an STL, no need for external template
         * context. */
        if (collector->tombstoneAccessTid) {
            intTid = collector->tombstoneAccessTid;
            intTmpl = fbSessionGetTemplate(collector->session, TRUE,
                                           intTid, NULL);
        }
        if (NULL == intTmpl || !fbTemplatesAreEqual(intTmpl, extTmpl)) {
            copyTemplateAddToSesssion(
                session, &intTmpl, &intTid, extTmpl, extTid, msgPref);
        }

        /* Since we expect this to appear only in an STL, only create the
         * context for the internal template and add a template pair. */
        if (!fbTemplateGetContext(intTmpl)) {
            defIntTmplCtx   = g_slice_new0(mdDefaultTmplCtx_t);
            defIntTmplCtx->templateType        = templateType;
            defIntTmplCtx->templateContents    = templateContents;
            defIntTmplCtx->associatedExtTid    = 0;
            defIntTmplCtx->contextType         = TCTX_TYPE_DEFAULT;
            mdTemplateContextSetListOffsets(defIntTmplCtx, intTmpl);

            fbTemplateSetContext(intTmpl, defIntTmplCtx,
                                 NULL, templateCtxFree);
        }

        *tmpl_ctx = NULL;
        *fn = NULL;
        fbSessionAddTemplatePair(session, extTid, intTid);
        break;

      case TC_TOMBSTONE_NOT_SET:
        g_error("%s spec case for tombstone is NOT_SET",
                msgPref->str);
      default:
        /* FIXME: We should handle this case */
        g_error("%s Unrecognized spec case for tombstone: %d",
                msgPref->str, templateContents.specCase.tombstone);
    }

    *newIntTmpl = intTmpl;
    *newIntTid = intTid;

    return intTmpl;
}


/*
 *  Handles TC_UNKNOWN, TC_UNKNOWN_DATA, TC_UNKNOWN_OPTIONS records for
 *  mdCollectorTemplateCallback().
 */
static fbTemplate_t *
mdCollectorTemplateCallbackUnknown(
    mdCollector_t              *collector,
    fbSession_t                *session,
    fbTemplate_t              **newIntTmpl,
    uint16_t                   *newIntTid,
    const fbTemplate_t         *extTmpl,
    uint16_t                    extTid,
    const GString              *msgPref,
    mdUtilTemplateType_t        templateType,
    mdUtilTemplateContents_t    templateContents,
    fbTemplate_t              **exporterExportTmpl,
    fbTemplate_t              **origIntTmpl,
    void                      **tmpl_ctx,
    fbTemplateCtxFree_fn       *fn)
{
    mdDefaultTmplCtx_t         *defExtTmplCtx   = NULL;
    mdDefaultTmplCtx_t         *defIntTmplCtx   = NULL;

    fbTemplate_t *intTmpl = NULL;
    uint16_t intTid;

    MD_UNUSED_PARAM(collector);
    MD_UNUSED_PARAM(exporterExportTmpl);
    MD_UNUSED_PARAM(origIntTmpl);
    g_assert(TC_UNKNOWN == templateContents.general ||
             TC_UNKNOWN_DATA == templateContents.general ||
             TC_UNKNOWN_OPTIONS == templateContents.general);

    /* we don't know what it is (could be tombstone access though)
     * so we build default context, and also add as template pair */
    copyTemplateAddToSesssion(
        session, &intTmpl, &intTid, extTmpl, extTid, msgPref);

    defExtTmplCtx   = g_slice_new0(mdDefaultTmplCtx_t);
    defIntTmplCtx   = g_slice_new0(mdDefaultTmplCtx_t);

    mdSetupTemplateCtxPair(defExtTmplCtx,
                           defIntTmplCtx,
                           extTid,
                           intTid,
                           templateType,
                           templateContents,
                           TCTX_TYPE_DEFAULT);
    mdTemplateContextSetListOffsets(defIntTmplCtx, intTmpl);
    mdTemplateContextSetListOffsets(defExtTmplCtx, extTmpl);

    *tmpl_ctx = defExtTmplCtx;
    *fn = templateCtxFree;

    fbTemplateSetContext(intTmpl, defIntTmplCtx,
                         NULL, templateCtxFree);

    /* DPI template without metadata end up as UNKNOWN_DATA, so add
     * template pairs just in case */

    fbSessionAddTemplatePair(session, extTid, intTid);

    *newIntTmpl = intTmpl;
    *newIntTid = intTid;

    return intTmpl;
}


/*
 *  Handles TC_YAF_STATS records for mdCollectorTemplateCallback().
 */
static fbTemplate_t *
mdCollectorTemplateCallbackYafStats(
    mdCollector_t              *collector,
    fbSession_t                *session,
    fbTemplate_t              **newIntTmpl,
    uint16_t                   *newIntTid,
    const fbTemplate_t         *extTmpl,
    uint16_t                    extTid,
    const GString              *msgPref,
    mdUtilTemplateType_t        templateType,
    mdUtilTemplateContents_t    templateContents,
    fbTemplate_t              **exporterExportTmpl,
    fbTemplate_t              **origIntTmpl,
    void                      **tmpl_ctx,
    fbTemplateCtxFree_fn       *fn)
{
    mdYafStatsTmplCtx_t            *yafStatsExtTmplCtx  = NULL;
    mdYafStatsTmplCtx_t            *yafStatsIntTmplCtx  = NULL;

    fbTemplate_t *intTmpl = NULL;
    uint16_t intTid;

    MD_UNUSED_PARAM(exporterExportTmpl);
    MD_UNUSED_PARAM(origIntTmpl);
    g_assert(TC_YAF_STATS == templateContents.general);

    if (templateContents.specCase.yafStats == TC_YAF_STATS_V2_SCOPE2) {
        /* FIXME: Change to
         * fbTemplateCopy(extTmpl, FB_TMPL_COPY_IGNORE_SCOPE */

        /* do not propagate the template with incorrect scope */
        intTmpl = fbTemplateAlloc(fbTemplateGetInfoModel(extTmpl));
        mdTemplateAppendSpecArray(intTmpl, mdEmSpecYafStatsV2, ~0);
        fbTemplateSetOptionsScope(intTmpl, 3);
    } else {
        intTmpl = fbTemplateCopy(extTmpl, 0);
        if (!intTmpl) {
            g_error("%s Couldn't copy incoming template", msgPref->str);
        }
    }

    intTid = mdSessionAddTemplate(session, TRUE, extTid, intTmpl, NULL);

    yafStatsExtTmplCtx   = g_slice_new0(mdYafStatsTmplCtx_t);
    yafStatsIntTmplCtx   = g_slice_new0(mdYafStatsTmplCtx_t);

    mdSetupTemplateCtxPair(&yafStatsExtTmplCtx->defCtx,
                           &yafStatsIntTmplCtx->defCtx,
                           extTid,
                           intTid,
                           templateType,
                           templateContents,
                           TCTX_TYPE_YAF_STATS);
    mdTemplateContextSetListOffsets(&yafStatsIntTmplCtx->defCtx, intTmpl);
    mdTemplateContextSetListOffsets(&yafStatsExtTmplCtx->defCtx, extTmpl);

    if (templateContents.specCase.yafStats == TC_YAF_STATS_V1) {
        if (templateContents.relative != TC_EXACT) {
            /* has to be exact for v1 as it's not being updated anymore*/
            g_error("%s non exact yaf stats 1, not accepted", msgPref->str);
        }
        yafStatsExtTmplCtx->defCtx.sourceRuntimeCTimeIE = NULL;
        yafStatsIntTmplCtx->defCtx.sourceRuntimeCTimeIE = NULL;
    } else if (templateContents.specCase.yafStats == TC_YAF_STATS_V2 ||
               templateContents.specCase.yafStats == TC_YAF_STATS_V2_SCOPE2)
    {
        if (templateContents.relative == TC_EXACT) {
            /* observationTimeSeconds */
            CALLBACK_GET_CTX_FIELD(
                extTmpl, extTid, 0, 322,
                yafStatsExtTmplCtx->defCtx.sourceRuntimeCTimeIE);
            CALLBACK_GET_CTX_FIELD(
                intTmpl, intTid, 0, 322,
                yafStatsIntTmplCtx->defCtx.sourceRuntimeCTimeIE);

            if (!yafStatsIntTmplCtx->defCtx.sourceRuntimeCTimeIE) {
                g_error("%s No time IE for yaf stats v2", msgPref->str);
            } else {
                mdCollectorHasSourceRuntimeTimestampField(collector);
            }
        } else {
            /* TODO handle these cases */
            g_warning("FIXME: SUPER, SUB, or MIX of YAF STATS 2");
        }
    } else {
        g_error("%s Got an unexpected YAF STATS SPECIAL CASE in callback",
                msgPref->str);
    }

    *tmpl_ctx = yafStatsExtTmplCtx;
    *fn = templateCtxFree;

    fbTemplateSetContext(intTmpl, yafStatsIntTmplCtx,
                         NULL, templateCtxFree);

    *newIntTmpl = intTmpl;
    *newIntTid = intTid;

    return intTmpl;
}


void
mdCollectorTemplateCallback(
    fbSession_t            *session,
    uint16_t                extTid,
    fbTemplate_t           *extTmpl,
    void                   *app_ctx, /* mdCollector_t */
    void                  **tmpl_ctx,
    fbTemplateCtxFree_fn   *fn)
{
    mdExporter_t                   *exporter            = NULL;
    mdCollector_t                  *collector   = (mdCollector_t*)app_ctx;

    const fbTemplateInfo_t         *mdInfo              = NULL;
    mdUtilTemplateType_t            templateType        = TT_UNKNOWN;
    mdUtilTemplateContents_t        templateContents    = MD_TC_INIT;
    fbTemplate_t                   *tmplForExp          = NULL;
    fbTemplate_t                   *exporterExportTmpl  = NULL;
    fbTemplate_t                   *origIntTmpl         = NULL;
    fbTemplate_t                   *intTmpl             = NULL;
    uint16_t                        intTid              = 0;

    GString                        *msgPref             = g_string_new(NULL);

    /* Template received. Retrieve and determine all information */

    mdInfo                  = fbSessionGetTemplateInfo(session, extTid);

    templateType = mdUtilExamineTemplate(extTmpl, extTid,
                                         mdInfo, &templateContents);

    if (mdInfo) {
        g_string_append_printf(msgPref, "COL %s(%d) TID %s (%#06x):",
                               collector->name,
                               collector->id,
                               fbTemplateInfoGetName(mdInfo),
                               extTid);
    } else {
        g_string_append_printf(msgPref, "COL %s(%d) TID %#06x:",
                               collector->name,
                               collector->id,
                               extTid);
    }

    /* We now have everything we need to react to this template arrival */

    /* internal consistency check, and assumption validation of template IDs */
    mdUtilUpdateKnownTemplates(msgPref, templateContents, extTid,
                               &(collector->recvdTids));

    /* internal consitency check, should have data from a single YAF */
    /* What about multiple super mediators of different yafs???? */
    setCollectorYafVersion(collector, templateContents.yafVersion);

    pthread_mutex_lock(&(collector->cfg->log_mutex));

    if (fbTemplateCountElements(extTmpl)) {
        GString *tcString = mdUtilDebugTemplateContents(templateContents);
        g_message("%s received. Labeled as %s - %s",
                  msgPref->str,
                  mdUtilDebugTemplateType(templateType),
                  tcString->str);
        g_string_free(tcString, TRUE);
    } else {
        g_message("%s template revocation received", msgPref->str);

        /* TODO
         * definitely need to handle already in there and revoke */
        /* do somethign in fixbuf for template contexts of revoked templates? */
        /* will need to make a new template and context...but hopefully not hte
         * internal one...not the internal one */
        pthread_mutex_unlock(&(collector->cfg->log_mutex));
        g_string_free(msgPref, TRUE);
        return;
    }

    /* Do all collector prep for the template based on template contents:
     * - Make copy of template for internal template - pull out here?
     * - prepare context for the specific template contents
     * - set context on template(s)
     * - fill tmplForExp pointer to decide what to pass to exporter
     * - if the exporter should use a different template for its export, set
     *   exporterExportTmpl
     * - setup ctime IEs to track time based on records received
     */
    switch (templateContents.general) {
      case TC_TMD_OR_IE:
        /* records autoconsumed by fixbuf. No need to process */
        /* no tmpl ctx, return so template isn't passed to exporters */
        /* this could be worth a warning or error... */
        break;

      case TC_DNS_DEDUP:
        tmplForExp = mdCollectorTemplateCallbackDnsDedup(
            collector, session, &intTmpl, &intTid, extTmpl,
            extTid, msgPref, templateType, templateContents,
            &exporterExportTmpl, &origIntTmpl, tmpl_ctx, fn);
        break;

      case TC_DNS_RR:
        tmplForExp = mdCollectorTemplateCallbackDnsRR(
            collector, session, &intTmpl, &intTid, extTmpl,
            extTid, msgPref, templateType, templateContents,
            &exporterExportTmpl, &origIntTmpl, tmpl_ctx, fn);
        break;

      case TC_DPI:
        tmplForExp = mdCollectorTemplateCallbackDpi(
            collector, session, &intTmpl, &intTid, extTmpl,
            extTid, msgPref, templateType, templateContents,
            &exporterExportTmpl, &origIntTmpl, tmpl_ctx, fn);
        break;

      case TC_FLOW:
        tmplForExp = mdCollectorTemplateCallbackFlow(
            collector, session, &intTmpl, &intTid, extTmpl,
            extTid, msgPref, templateType, templateContents,
            &exporterExportTmpl, &origIntTmpl, tmpl_ctx, fn);
        break;

      case TC_GENERAL_DEDUP:
        tmplForExp = mdCollectorTemplateCallbackGeneralDedup(
            collector, session, &intTmpl, &intTid, extTmpl,
            extTid, msgPref, templateType, templateContents,
            &exporterExportTmpl, &origIntTmpl, tmpl_ctx, fn);
        break;

      case TC_SSL_DEDUP:
        tmplForExp = mdCollectorTemplateCallbackSslDedup(
            collector, session, &intTmpl, &intTid, extTmpl,
            extTid, msgPref, templateType, templateContents,
            &exporterExportTmpl, &origIntTmpl, tmpl_ctx, fn);
        break;

      case TC_TOMBSTONE:
        tmplForExp = mdCollectorTemplateCallbackTombstone(
            collector, session, &intTmpl, &intTid, extTmpl,
            extTid, msgPref, templateType, templateContents,
            &exporterExportTmpl, &origIntTmpl, tmpl_ctx, fn);
        break;

      case TC_UNKNOWN:
      case TC_UNKNOWN_DATA:
      case TC_UNKNOWN_OPTIONS:
        tmplForExp = mdCollectorTemplateCallbackUnknown(
            collector, session, &intTmpl, &intTid, extTmpl,
            extTid, msgPref, templateType, templateContents,
            &exporterExportTmpl, &origIntTmpl, tmpl_ctx, fn);
        break;

      case TC_YAF_STATS:
        tmplForExp = mdCollectorTemplateCallbackYafStats(
            collector, session, &intTmpl, &intTid, extTmpl,
            extTid, msgPref, templateType, templateContents,
            &exporterExportTmpl, &origIntTmpl, tmpl_ctx, fn);
        break;

      case TC_NUM_TYPES:
        g_error("NUM TYPES as general type in core callback");
        break;
    }

    /* Look at the length for this template and update the collector's max
     * record length to properly allocate a buffer to be reused */
    mdCollectorUpdateMaxRecord(collector);

    if (NULL == tmplForExp) {
        pthread_mutex_unlock(&(collector->cfg->log_mutex));
        g_string_free(msgPref, TRUE);
        return;
    }

    pthread_mutex_unlock(&(collector->cfg->log_mutex));

    /* make a copy of the tmplForExp for exporters to own.
     * Pass the template to all of the exporters to do what they need to do */
    /* have the exporters use ctx for their own copy of all the templates */
    for (exporter = md_config.firstExp; exporter; exporter = exporter->next) {
        fbTemplate_t *xxTmpl = NULL;
        if (exporterExportTmpl) {
            if (NULL == origIntTmpl) {
                xxTmpl = fbTemplateCopy(exporterExportTmpl, 0);
            } else if (!exporter->flowDpiStrip) {
                xxTmpl = fbTemplateCopy(exporterExportTmpl, 0);
            }
            /* else, leave xxTmpl as NULL */
        }

        mdExporterCallTemplateCallback(exporter,
                                       collector,
                                       intTid,
                                       fbTemplateCopy(tmplForExp, 0),
                                       mdInfo,
                                       xxTmpl,
                                       templateType,
                                       templateContents); /* mdCollector */
    }

    if (exporterExportTmpl) {
        fbTemplateFreeUnused(exporterExportTmpl);
    }
    g_string_free(msgPref, TRUE);
    return;
}


/*
 *  Checks whether either `flow` or the current collector (accessed via `ctx`)
 *  passes the filters on `exporter`.
 *
 *  A result of TRUE means the flow passed the filters and should be
 *  processed; a result of FALSE means it should not.
 *
 *  Returns TRUE if `exporter` has no filters. Otherwise, returns the result
 *  of processing the filters.  The function increments the exporter's
 *  filter-counter for `recType` if the exporter's filters return FALSE.
 */
static gboolean
mdCoreFilterCheck(
    const mdContext_t  *ctx,
    const mdFullFlow_t *flow,
    mdExporter_t       *exporter,
    int                 recType)
{
    if (exporter->filter
        && !mdFilterCheck(exporter->filter, flow, ctx->cfg->collector_id))
    {
        ++exporter->expStats.recordsFilteredOutByType[recType];
        return FALSE;
    }
    return TRUE;
}


static gboolean
mdProcessTombstoneV1(
    mdContext_t        *ctx,
    mdCollector_t      *collector,
    mdGenericRec_t     *mdRec,
    GError            **err)
{
    tombstoneMainV2Rec_t       *tombstoneV2Rec;
    fbSubTemplateList_t        *accessStl;
    fbSubTemplateList_t         cachedStl;
    tombstoneAccessV2Rec_t     *accessRec;
    mdExporter_t               *exporter;
    mdGenericRec_t              cachedGenRec;
    unsigned int                accessEntries;
    gboolean                    rc;

    MD_UNUSED_PARAM(collector);

    tombstoneV2Rec = (tombstoneMainV2Rec_t *)(mdRec->fbRec->rec);
    accessStl = &tombstoneV2Rec->accessList;
    accessEntries = fbSubTemplateListCountElements(accessStl);
    accessRec =
        (tombstoneAccessV2Rec_t *)fbSubTemplateListGetDataPtr(accessStl);
    g_assert((accessEntries > 0) ^ (NULL == accessRec));

    /* Set the observationDomainId in the record from IPFIX message header */
    tombstoneV2Rec->observationDomainId = ctx->cfg->current_domain;
    /* Use the unique-id from the V1 record as the process-id, then clear the
     * unique id */
    tombstoneV2Rec->exportingProcessId
        = tombstoneV2Rec->certToolExporterUniqueId;
    tombstoneV2Rec->certToolExporterUniqueId = 0;
    /* Set the V2 record's observationTime to be the one from the first nested
     * V1 record */
    if (accessRec) {
        tombstoneV2Rec->observationTimeSeconds =
            accessRec->observationTimeSeconds;
    }

    /* Extend the STL by one and add our information into that entry */
    accessRec = fbSubTemplateListAddNewElements(accessStl, 1);
    accessRec->certToolId = 2;
    accessRec->observationTimeSeconds = (int)time(NULL);

    g_message("Received Tombstone record: observationDomain:%d, "
              "exporterId:%d:%d, certToolTombstoneId: %d",
              tombstoneV2Rec->observationDomainId,
              tombstoneV2Rec->certToolExporterConfiguredId,
              tombstoneV2Rec->exportingProcessId,
              tombstoneV2Rec->certToolTombstoneId);

    /* Copy the current values so we can reset once complete */
    cachedGenRec = *mdRec;
    cachedStl = *accessStl;
    rc = TRUE;

    for (exporter = ctx->cfg->firstExp;
         exporter != NULL && rc;
         exporter = exporter->next)
    {
        /* FIXME: mthomas.2022.08.03. Added a check for the exporter's
         * filter. Should we do this or not? Note that mdSendTombstoneRecord()
         * already checked the exporter's filters. */
        if (!mdCoreFilterCheck(ctx, NULL, exporter, TC_TOMBSTONE)) {
            continue;
        }
        /* If the generated tombstone TIDs exist, use them.  If they do not
         * but the received tombstone V2 TIDs do, use them.  Otherwise, add
         * the generated TIDs to the session and use them.  I have no idea if
         * adding them to the session at this point propagates them to all the
         * sessions that need them (e.g., invariant files). */
        if (!exporter->genTids.tombstoneV2MainTid &&
            exporter->recvdTids.tombstoneV2MainTid &&
            exporter->recvdTids.tombstoneV2AccessTid)
        {
            /* Generated do not exist and received V2 do exist. */
            mdRec->intTid = exporter->recvdTids.tombstoneV2MainTid;
            /* Break the STL abstraction */
            accessStl->tmplID = exporter->recvdTids.tombstoneV2AccessTid;
            accessStl->tmpl =
                fbSessionGetTemplate(exporter->activeWriter->session, TRUE,
                                     accessStl->tmplID, NULL);
            rc = mdExporterWriteOptions(ctx->cfg, exporter, mdRec, err);
        } else {
            /* add generated tombstone template if needed */
            if (!exporter->genTids.tombstoneV2MainTid) {
                mdExporterAddTombstoneTemplates(
                    exporter, exporter->activeWriter->session, err);
            }
            mdRec->intTid = exporter->genTids.tombstoneV2MainTid;
            accessStl->tmplID = exporter->genTids.tombstoneV2AccessTid;
            accessStl->tmpl =
                fbSessionGetTemplate(exporter->activeWriter->session, TRUE,
                                     accessStl->tmplID, NULL);
            rc = mdExporterFormatAndSendOrigTombstone(ctx->cfg, exporter,
                                                      mdRec, err);
        }
    }

    *mdRec = cachedGenRec;
    *accessStl = cachedStl;
    return rc;
}

/**
 * mdProcesTombstone
 *
 * forward the tombstone record to the exporters that
 * are configured to receive YAF stats
 *
 */
gboolean
mdProcessTombstone(
    mdContext_t        *ctx,
    mdCollector_t      *collector,
    mdGenericRec_t     *mdRec,
    GError            **err)
{
    tombstoneMainV2Rec_t           *tombstoneV2Rec;
    tombstoneAccessV2Rec_t         *accessV2Rec;
    fbSubTemplateList_t            *accessListPtr;
    mdExporter_t                   *exporter;
    const mdTombstoneTmplCtx_t     *intTmplCtx;
    GString                        *unknownTCString;

    /* not really right. Only top level bytes */
    /*ctx->coreStats.bytesProcessed += mdRec->fbRec->recsize;*/

    /* STAT CORE recordsProcessedByType */
    ctx->coreStats.recordsProcessedByType[TC_TOMBSTONE]++;

    /*  We use no_stats for tombstone as well */
    if (ctx->cfg->no_stats) {
        return TRUE;
    }

    intTmplCtx = (mdTombstoneTmplCtx_t *)mdRec->intTmplCtx;

    switch (intTmplCtx->defCtx.templateContents.specCase.tombstone) {
      case TC_TOMBSTONE_ACCESS_V1:
      case TC_TOMBSTONE_ACCESS_V2:
        g_error("Received top-level data that uses the Tombstone Access"
                "SubList template %#06x", mdRec->fbRec->tid);

      case TC_TOMBSTONE_V1:
        return mdProcessTombstoneV1(ctx, collector, mdRec, err);

      case TC_TOMBSTONE_V2:
        tombstoneV2Rec  = (tombstoneMainV2Rec_t *)(mdRec->fbRec->rec);
        /* append ourself to the access list */
        accessListPtr   = &(tombstoneV2Rec->accessList);
        accessV2Rec     = fbSubTemplateListAddNewElements(accessListPtr, 1);
        accessV2Rec->certToolId = 2;
        accessV2Rec->observationTimeSeconds = (int)time(NULL);

        g_message("Received Tombstone record: observationDomain:%d, "
                  "exporterId:%d:%d, certToolTombstoneId: %d",
                  tombstoneV2Rec->observationDomainId,
                  tombstoneV2Rec->certToolExporterConfiguredId,
                  tombstoneV2Rec->exportingProcessId,
                  tombstoneV2Rec->certToolTombstoneId);
        break;

      default:
        unknownTCString = mdUtilDebugTemplateContents(
            intTmplCtx->defCtx.templateContents);
        g_warning("unknown tombstone version %s", unknownTCString->str);
        g_string_free(unknownTCString, TRUE);
        break;
    }

    for (exporter = ctx->cfg->firstExp; exporter; exporter = exporter->next) {
        /* FIXME: mthomas.2022.08.03. Added a check for the exporter's
         * filter. Should we do this or not? Note that mdSendTombstoneRecord()
         * already checked the exporter's filters. */
        if (!mdCoreFilterCheck(ctx, NULL, exporter, TC_TOMBSTONE)) {
            continue;
        }
        if (!mdExporterWriteOptions(ctx->cfg, exporter, mdRec, err)) {
            return FALSE;
        }
    }

    return TRUE;
}

/**
 * mdSendTombstoneRecord
 *
 * Send a generated tombstone record out to all exporters
 *
 */
gboolean
mdSendTombstoneRecord(
    mdContext_t     *ctx,
    GError          **err)
{
    tombstoneMainV2Rec_t    rec;
    tombstoneAccessV2Rec_t *accessRec;
    mdExporter_t           *exporter = NULL;
    static uint32_t         certToolTombstoneId = 0;
    uint32_t                currentTime;
    mdGenericRec_t          mdRec;
    fbRecord_t              fbRec;

    /* STAT CORE tombstoneRecordsGenerated */
    ctx->coreStats.tombstoneRecordsGenerated++;

    mdRec.fbRec     = &fbRec;
    fbRec.rec       = (uint8_t*)&rec;
    fbRec.recsize   = sizeof(tombstoneMainV2Rec_t);
    mdRec.generated = TRUE;

    memset(&rec, 0, sizeof(tombstoneMainV2Rec_t));

    rec.observationDomainId = 0; /* 0 because SM doesn't have ObsDomainID */
    rec.exportingProcessId = getpid();
    rec.certToolExporterConfiguredId = ctx->cfg->tombstone_configured_id;
    rec.certToolTombstoneId = certToolTombstoneId++;
    currentTime = (int)time(NULL);
    rec.observationTimeSeconds = currentTime;

    /* no TID, filled in by exporters.
     * Can use global tombstoneMainV2Tmpl as it's just used for length */
    accessRec = (tombstoneAccessV2Rec_t*)fbSubTemplateListInit(
                                                    &(rec.accessList), 0,
                                                    0,
                                                    tombstoneAccessV2Tmpl, 1);

    if (!accessRec) {
        return FALSE;
    }

    accessRec->certToolId = 2;
    accessRec->observationTimeSeconds = currentTime;

    for (exporter = ctx->cfg->firstExp; exporter; exporter = exporter->next) {
        if (!mdCoreFilterCheck(ctx, NULL, exporter, TC_TOMBSTONE)) {
            continue;
        }

        /* need this intermediary function for templates */
        if (!mdExporterFormatAndSendOrigTombstone(
                                        ctx->cfg, exporter, &mdRec, err))
        {
            fbSubTemplateListClear(&(rec.accessList));
            return FALSE;
        }
    }

    g_message("Sent Tombstone record: observationDomain:%d, "
              "exporterId:%d:%d, certToolTombstoneId: %d",
              rec.observationDomainId, rec.certToolExporterConfiguredId,
              rec.exportingProcessId, rec.certToolTombstoneId);
    fbSubTemplateListClear(&(rec.accessList));

    return TRUE;
}


/**
 * mdProcessStats
 *
 * forward the option stats record to the exporters that
 * are configured to receive YAF stats
 *
 */
gboolean
mdProcessYafStats(
    mdContext_t        *ctx,
    mdCollector_t      *collector,
    mdGenericRec_t     *genRec,
    GError            **err)
{
    mdExporter_t   *exporter = NULL;

    MD_UNUSED_PARAM(collector);

    /*ctx->coreStats.bytesProcessed += genRec->fbRec->recsize;*/
    /* STAT CORE recordsProcessedByType */
    ctx->coreStats.recordsProcessedByType[TC_YAF_STATS]++;

    if (ctx->cfg->no_stats) {
        return TRUE;
    }

    mdStatLogYAFStats(genRec);

    for (exporter = ctx->cfg->firstExp; exporter; exporter = exporter->next) {
        if (!mdCoreFilterCheck(ctx, NULL, exporter, TC_YAF_STATS)) {
            continue;
        }
        if (!mdExporterWriteOptions(ctx->cfg, exporter, genRec, err)) {
            g_warning("error writing stats record: %s", (*err)->message);
            return FALSE;
        }
    }

    return TRUE;
}


/**
 * mdProcessDNSDedup
 *
 */
gboolean
mdProcessDNSDedup(
    mdContext_t    *ctx,
    mdGenericRec_t *genRec,
    GError        **err)
{
    mdExporter_t *exporter;
    const mdDefaultTmplCtx_t *intTmplCtx = genRec->intTmplCtx;

    /*    ctx->coreStats.bytesProcessed += genRec->fbRec->recsize; */
    /* STAT CORE recordsProcessedByType */
    ctx->coreStats.recordsProcessedByType[TC_DNS_DEDUP]++;

    if (intTmplCtx->templateContents.specCase.dnsDedup & TC_DNS_DEDUP_LS_V1) {
        /* copy the value in the dnsHitCount to smDedupHitCount */
        md_dns_dedup_t *dnsDedupRec = (md_dns_dedup_t *)genRec->fbRec->rec;
        dnsDedupRec->smDedupHitCount = dnsDedupRec->dnsHitCount;
    }

    for (exporter = ctx->cfg->firstExp; exporter; exporter = exporter->next) {
        if (!mdCoreFilterCheck(ctx, NULL, exporter, TC_DNS_DEDUP)) {
            continue;
        }
        if (exporter->allowDnsDedup) {
            if (!mdExporterWriteDNSDedupRecord(ctx->cfg, exporter,
                                               genRec, err))
            {
                return FALSE;
            }
        }
    }

    return TRUE;
}



/**
 * mdProcessDNSRR
 *
 * forward the dns rr-only record to the exporters
 * that are configured to receive them
 *
 */
gboolean
mdProcessDNSRR(
    mdContext_t        *ctx,
    mdGenericRec_t     *mdRec,
    GError            **err)
{
    mdExporter_t   *exporter = NULL;

/*    ctx->coreStats.bytesProcessed += mdRec->fbRec->recsize;*/
    /* STAT CORE recordsProcessedByType */
    ctx->coreStats.recordsProcessedByType[TC_DNS_RR]++;

    for (exporter = ctx->cfg->firstExp; exporter; exporter = exporter->next) {
        if (!mdCoreFilterCheck(ctx, NULL, exporter, TC_DNS_RR)) {
            continue;
        }
        if (exporter->allowDnsRR &&
            !mdExporterWriteDNSRRRecord(ctx->cfg, exporter, mdRec, err))
        {
            return FALSE;
        }
    }

    return TRUE;
}


/**
 * mdProcessGeneralDedup
 *
 *
 */
gboolean
mdProcessGeneralDedup(
    mdContext_t                *ctx,
    mdGeneralDedupTmplCtx_t    *tctx,
    mdGenericRec_t             *mdRec,
    GError                    **err)
{
    md_dedup_t        dedup;
    md_dedup_sm140_t  odedup;
    mdExporter_t     *exporter = NULL;

/*    size_t         dedup_len = sizeof(dedup);*/
/*    size_t         odedup_len = sizeof(odedup);*/

/*    ctx->coreStats.bytesProcessed += mdRec->fbRec->recsize;*/
    /* STAT CORE recordsProcessedByType */
    ctx->coreStats.recordsProcessedByType[TC_GENERAL_DEDUP]++;

/*    if (!fBufSetInternalTemplate(fbuf, tctx->defCtx.associatedIntTid, err)) {
        return FALSE;
    }*/

    if (tctx->numElem < 8) {
        /* FIXME: why not check for absence of stime instead of size of
         * template, or even both? */
        memcpy(&odedup, mdRec->fbRec->rec, mdRec->fbRec->recsize);

/*        rc = fBufNext(fbuf, (uint8_t *)&odedup, &odedup_len, err);
        if (FALSE == rc) {
            g_clear_error(err);
            goto end;
        }
*/
        dedup.monitoringIntervalStartMilliSeconds = odedup.fseen;
        dedup.monitoringIntervalEndMilliSeconds = odedup.lseen;
        dedup.flowStartMilliseconds = 0;
        dedup.smDedupHitCount = odedup.count;
        memcpy(dedup.sourceIPv6Address, odedup.sip6, 16);
        dedup.sourceIPv4Address = odedup.sip;
        dedup.yafFlowKeyHash = odedup.hash;
        dedup.smDedupData.buf = odedup.data.buf;
        dedup.smDedupData.len = odedup.data.len;
        dedup.observationDomainName.buf = NULL;
        dedup.observationDomainName.len = 0;
    } else {
        memcpy(&dedup, mdRec->fbRec->rec, mdRec->fbRec->recsize);
    }
/*        rc = fBufNext(fbuf, (uint8_t *)&dedup, &dedup_len, err);

        if (FALSE == rc) {
            g_clear_error(err);
            goto end;
        }
    }

    if (fBufGetExportTime(fbuf) > (ctx->cfg->ctime/1000)) {
        ctx->cfg->ctime = (uint64_t)fBufGetExportTime(fbuf);
        ctx->cfg->ctime = ctx->cfg->ctime * 1000;
    }

    fBufGetCollectionTemplate(fbuf, &tid);*/

    for (exporter = ctx->cfg->firstExp; exporter; exporter = exporter->next) {
        if (!mdCoreFilterCheck(ctx, NULL, exporter, TC_GENERAL_DEDUP)) {
            continue;
        }
        if (exporter->dedup) {
            /* mthomas.2021.07.15 FIXME: The following fixes an issue where an
             * elementId is being passed to a function that expects an
             * fbInfoElement_t.  Instead of finding this IE every time, it is
             * probably better to either store the IE itself on the tctx or
             * change the dedup code to store the enterprise and element
             * Ids. */
            const fbInfoElement_t *ie = fbInfoModelGetElementByID(
                exporter->infoModel, tctx->ieNum, CERT_PEN);
            if (!md_dedup_write_dedup(
                    ctx, exporter, (md_dedup_general_t *)&dedup, ie, err))
            {
                return FALSE;
            }
        } else {
            if (!mdExporterWriteGeneralDedupRecord(
                    ctx->cfg, exporter, NULL, /*&dedup*/mdRec, "dedup", err))
            {
                return FALSE;
            }
        }
    }

    return TRUE;
}



#if 0
/**
 * mdProcessGeneralDedup
 *
 */
static gboolean
mdProcessGeneralDedup(
    mdContext_t *ctx,
    mdGenericRec_t *mdRec,
    GError      **err)
{
    gboolean       rc;
    md_dedup_t     dedup;
/*    size_t         dedup_len = sizeof(dedup);*/
    mdExporter_t *exporter = NULL;
/*    uint16_t       tid;*/

    g_error("dedup not built");

/*    ctx->coreStats.bytesProcessed += mdRec->fbRec->recsize;*/
    /* STAT CORE recordsProcessedByType */
    ctx->coreStats.recordsProcessedByType[TC_GENERAL_DEDUP]++;

    memcpy(&dedup, mdRec->fbRec->rec, mdRec->fbRec->recsize);

/*    if (!fBufSetInternalTemplate(fbuf, MD_DEDUP_FULL, err)) {
        return FALSE;
    }

    rc = fBufNext(fbuf, (uint8_t *)&dedup, &dedup_len, err);

    if (FALSE == rc) {
        g_clear_error(err);
        goto end;
    }

    if (fBufGetExportTime(fbuf) > (ctx->cfg->ctime/1000)) {
        ctx->cfg->ctime = (uint64_t)fBufGetExportTime(fbuf);
        ctx->cfg->ctime = ctx->cfg->ctime * 1000;
    }

    fBufGetCollectionTemplate(fbuf, &tid); */

    for (exporter = ctx->cfg->firstExp; exporter; exporter = exporter->next) {
        if (!mdCoreFilterCheck(ctx, NULL, exporter, TC_GENERAL_DEDUP)) {
            continue;
        }
        if (exporter->dedup) {
            /* ssl is the only way that should make it here */
            if (!md_dedup_write_dedup(
                    ctx, exporter, (md_dedup_general_t *)&dedup,
                    /* FIXME: THIS SHOULD BE IE, NOT NUMBER */244,
                    err))
            {
                return FALSE;
            }
        } else {
            if (!mdExporterWriteGeneralDedupRecord(ctx->cfg, exporter, NULL,
                                            /*&dedup*/mdRec, "dedup", 0,
                                            mdRec->fbRec->tid, err))
            {
                return FALSE;
            }
        }
    }

    return TRUE;
}
#endif  /* 0 */

/**
 * mdProcessSSLDedup
 * TODO doesn't work
 *
 */
gboolean
mdProcessSSLDedup(
    mdContext_t    *ctx,
    mdGenericRec_t *genRec,
    GError        **err)
{
    mdExporter_t *exporter = NULL;

/*    ctx->coreStats.bytesProcessed += genRec->fbRec->recsize;*/
    /* STAT CORE recordsProcessedByType */
    ctx->coreStats.recordsProcessedByType[TC_SSL_DEDUP]++;

/*    memcpy(&ssl, record->rec, record->recsize);

    if (!fBufSetInternalTemplate(fbuf, MD_SSL_TID, err)) {
        return FALSE;
    }

    rc = fBufNext(fbuf, (uint8_t *)&ssl, &ssl_len, err);

    if (FALSE == rc) {
        g_clear_error(err);
        goto end;
    }

    if (fBufGetExportTime(fbuf) > (ctx->cfg->ctime/1000)) {
        ctx->cfg->ctime = (uint64_t)fBufGetExportTime(fbuf);
        ctx->cfg->ctime = ctx->cfg->ctime * 1000;
    } */

    for (exporter = ctx->cfg->firstExp; exporter; exporter = exporter->next) {
        if (!mdCoreFilterCheck(ctx, NULL, exporter, TC_SSL_DEDUP)) {
            continue;
        }
        if (!mdExporterWriteSSLDedupRecord(ctx->cfg, exporter, genRec, err))
        {
            return FALSE;
        }
    }

    return TRUE;
}


/**
 * mdProcessSSLCert
 *
 */
gboolean
mdProcessSSLCert(
    mdContext_t    *ctx,
    mdGenericRec_t *mdRec,
    GError        **err)
{
    mdExporter_t *exporter = NULL;

    /* FIXME: No type for a top-level SSL Cert like those produced by
     * SSL_DEDUP */
    ctx->coreStats.recordsProcessedByType[TC_UNKNOWN_DATA]++;

    for (exporter = ctx->cfg->firstExp; exporter; exporter = exporter->next) {
        /* FIXME: Replace TC_UNKNOWN_DATA with TC_SSL_CERT ?? */
        if (!mdCoreFilterCheck(ctx, NULL, exporter, TC_UNKNOWN_DATA)) {
            continue;
        }
        if (exporter->allowSslCert) {
            /* either no filter or filter passes */
            if (!md_ssl_export_ssl_cert(ctx, exporter, mdRec, err)) {
                return FALSE;
            }
        }
    }

    return TRUE;
}


#define MD_PROCESS_FLOW_GET_VAL(_ie_, _place_)                              \
    do {                                                                    \
        if (!fbRecordCopyFieldValue(                                        \
            flow->fbRec,                                                    \
            _ie_,                                                           \
            &(_place_),                                                     \
            sizeof(_place_)))                                               \
        {                                                                   \
            g_warning("coulnd't get val fo IE: %s!\n", _ie_->canon->name);  \
            return FALSE;                                                   \
        }                                                                   \
    } while(0)



/**
 * mdProcessFlow
 *
 * Forward a normal flow record to the exporters
 * that are configured to receive it
 *
 */
gboolean
mdProcessFlow(
    mdContext_t    *ctx,
    mdFullFlow_t   *flow,
    uint8_t         yafVersion,
    GError        **err)
{
    int                             wf = 0;
    mdExporter_t                   *exporter = NULL;
    const mdCollIntFlowTmplCtx_t   *intTmplCtx = flow->intTmplCtx;
    uint8_t                        *rec = flow->fbRec->rec;

    MD_UNUSED_PARAM(yafVersion);

/*    ctx->coreStats.bytesProcessed += flow->fbRec->recsize;*/
    /* STAT CORE recordsProcessedByType */
    ctx->coreStats.recordsProcessedByType[TC_FLOW]++;

    /* retrieve values and manipulate the flow record if needed */

    /* get flow end reason */
    MD_PROCESS_FLOW_GET_VAL(intTmplCtx->flowEndReason,
                            flow->flowEndReason);

    /* get IPs */
    if (intTmplCtx->v4) {
        flow->ipv4 = TRUE;
        /* get sip 4 */
        MD_PROCESS_FLOW_GET_VAL(intTmplCtx->sip4,
                                flow->sourceIPv4Address);

        /* get sip 4 */
        MD_PROCESS_FLOW_GET_VAL(intTmplCtx->dip4,
                                flow->destinationIPv4Address);

        flow->sourceIPv6Address       = NULL;
        flow->destinationIPv6Address  = NULL;
    } else {
        flow->ipv4 = FALSE;
        flow->sourceIPv4Address       = 0;
        flow->destinationIPv4Address  = 0;
        flow->sourceIPv6Address       = rec + intTmplCtx->sipV6Offset;
        flow->destinationIPv6Address  = rec + intTmplCtx->dipV6Offset;
    }

    /* get flowStartMilliseconds */
    MD_PROCESS_FLOW_GET_VAL(intTmplCtx->flowStartMS,
                            flow->flowStartMilliseconds);

    /* get sport */
    MD_PROCESS_FLOW_GET_VAL(intTmplCtx->sport,
                            flow->sourceTransportPort);

    /* get dport */
    MD_PROCESS_FLOW_GET_VAL(intTmplCtx->dport,
                            flow->destinationTransportPort);

    /* get vlan */
    MD_PROCESS_FLOW_GET_VAL(intTmplCtx->vlanId,
                            flow->vlanId);

    /* get protocol */
    MD_PROCESS_FLOW_GET_VAL(intTmplCtx->protocol,
                            flow->protocolIdentifier);

    if (intTmplCtx->appLabelOffset != UINT16_MAX) {
        flow->silkAppLabel = *((uint16_t*)(rec + intTmplCtx->appLabelOffset));
    } else {
        flow->silkAppLabel = 0;
    }

    /* STAT CORE flowsByAppLabel */
    ctx->coreStats.flowsByAppLabel[flow->silkAppLabel]++;

    if (intTmplCtx->dpiListOffset != UINT16_MAX) {
        flow->dpiListPtr      = rec + intTmplCtx->dpiListOffset;
    } else {
        flow->dpiListPtr      = NULL;
    }

    if (!intTmplCtx->preserve_obdomain) {
        if (intTmplCtx->observationDomainOffset != UINT16_MAX) {
            flow->observationDomain =
                (uint32_t*)(rec + intTmplCtx->observationDomainOffset);
            *(flow->observationDomain) = ctx->cfg->current_domain;
        }
    } else {
        flow->observationDomain =
            (uint32_t*)(rec + intTmplCtx->observationDomainOffset);
    }

    /* get values and setup pointers for processing */
    /* flowKeyHash has to be there */
    flow->flowKeyHash = (uint32_t*)(rec + intTmplCtx->flowKeyHashOffset);
    *(flow->flowKeyHash) = md_util_flow_key_hash(flow);

#ifdef ENABLE_SKIPSET
    if (md_ipset) {
        flow->smIPSetMatchesSource =
            (uint8_t*)(rec + intTmplCtx->smIPSetMatchesSourceOffset);
        flow->smIPSetMatchesDestination =
            (uint8_t*)(rec + intTmplCtx->smIPSetMatchesDestinationOffset);

        if (flow->sourceIPv6Address || flow->destinationIPv6Address) {
            *flow->smIPSetMatchesSource = skIPSetCheckAddress(
                md_ipset->ipset, (const skipaddr_t *)&flow->sourceIPv6Address);
            *flow->smIPSetMatchesDestination = skIPSetCheckAddress(
                md_ipset->ipset,
                (const skipaddr_t *)&flow->destinationIPv6Address);
        } else {
            skipaddr_t addr;

            skipaddrSetV4(&addr, &flow->sourceIPv4Address);
            *flow->smIPSetMatchesSource = skIPSetCheckAddress(
                md_ipset->ipset, &addr);
            skipaddrSetV4(&addr, &flow->destinationIPv4Address);
            *flow->smIPSetMatchesDestination = skIPSetCheckAddress(
                md_ipset->ipset, &addr);
        }
    }
#endif  /* ENABLE_SKIPSET */

    /* copy tcpSequenceNumber and flags from STML to top level record */
    if (intTmplCtx->tcpSequenceNumber && flow->dpiListPtr &&
        6 == flow->protocolIdentifier)
    {
        const fbSubTemplateMultiList_t      *stml;
        const fbSubTemplateMultiListEntry_t *entry;
        uint16_t tid;
        size_t   count;

        stml = (fbSubTemplateMultiList_t *)flow->dpiListPtr;
        count = 0;
        entry = NULL;
        while ((entry = fbSubTemplateMultiListGetNextEntry(stml, entry))) {
            tid = fbSubTemplateMultiListEntryGetTemplateID(entry);
            if (0 == tid) {
                /* ignore */
            } else if (tid == flow->collector->recvdTids.tcpRevSubrecTid) {
                count = 12;
                break;
            } else if (tid == flow->collector->recvdTids.tcpFwdSubrecTid) {
                count = 6;
                break;
            }
        }
        if (count && entry) {
            memcpy((rec +
                    fbTemplateFieldGetOffset(intTmplCtx->tcpSequenceNumber)),
                   fbSubTemplateMultiListEntryGetDataPtr(entry),
                   count);
        }
    }

    /* flow record has been processed and is ready for emission */
    /* Iterate through the exporters and emit the flow */
    for (exporter = ctx->cfg->firstExp; exporter; exporter = exporter->next) {

        /* Ignore flows that do not pass the filter */
        if (!mdCoreFilterCheck(ctx, flow, exporter, TC_FLOW)) {
            continue;
        }

        /* Handle DNS */
        if (flow->silkAppLabel == 53) {
            if (exporter->dns_dedup) {
                md_dns_dedup_add_flow(ctx, exporter, flow);
            }
            if (exporter->generateDnsRR &&
                exporter->exportFormat == EF_IPFIX)
            {
                mdExportDNSRR(ctx->cfg, exporter, flow,
                              flow->intTid, err);
            }
        }

        /* leave here for full cert reference */
/*            if (exporter->ssl_dedup && ((flow->app_tid == SM_INTSSL_FLOW_TID)
                                     || flow->fullcert))
            {*/
        if (flow->silkAppLabel == 443 && exporter->ssl_dedup) {
            md_ssl_dedup_add_flow(ctx, exporter, flow);
        }

        if (exporter->dedup) {
            md_dedup_lookup_node(ctx, exporter, flow);
            /* continue; */
        }

        if (exporter->allowFlow) {
            /* Flow will be emitted from within mdExporterWriteFlow */
            wf = mdExporterWriteFlow(ctx->cfg, exporter, flow, err);
            if (wf < 0) {
                return FALSE;
            }
        }

        if ((exporter->dns_dedup || exporter->dedup) &&
            (0 == (ctx->coreStats.recordsProcessedByType[TC_FLOW] %
                   MD_DEDUP_FLUSH_FLOW_COUNT)))
        {
            /* only flush queues every MD_DEDUP_FLUSH_FLOW_COUNT flows */
            /* only flushes what's in the close queues */
            /* FIXME: Should SSL_DEDUP be here also?  If not, why not? */
            if (exporter->dns_dedup &&
                !md_dns_dedup_flush_queue(exporter, ctx->cfg, err))
            {
                return FALSE;
            }
            if (exporter->dedup &&
                !md_dedup_flush_queue(exporter, ctx->cfg, err))
            {
                return FALSE;
            }
        }
    }

    return TRUE;
}

#if 0
void
mdCleanUpSSLCert(
    yafSSLDPICert_t *cert)
{
    fbSubTemplateListClear(&(cert->issuer));
    fbSubTemplateListClear(&(cert->subject));
    fbSubTemplateListClear(&(cert->extension));
}
#endif  /* 0 */


/**
 * mdMakeFieldEntryFromName
 *
 *   Takes the name of an information element or a special token and creates a
 *   new mdFieldEntry structure to represent it it.
 *
 */
mdFieldEntry_t *
mdMakeFieldEntryFromName(
    const char   *field,
    gboolean      onlyFetchOne,
    GError      **err)
{
    mdFieldEntry_t *item = NULL;
    fbInfoModel_t           *md_info_model = mdInfoModel();
    const char              *actField;

    /* FIXME: Expand the list of "derived" fields to include icmpTypeCodeIPv4,
     * icmpTypeIPv4, icmpCodeIPv4, icmpCodeIPv6, .... (stupid IETF);
     * tcpSourcePort, tcpDestinationPort, udpSourcePort, ... (malicious IETF);
     * tcpControlBits which is derived for YAF that the splits them into
     * initial and union; additional things I cannot think of right now */

    item = g_slice_new0(mdFieldEntry_t);
    item->onlyFetchOne = onlyFetchOne;

    /* TODO: Support turning on DPI via custom field*/
    /* if (g_strcmp0(field, "dpi") == 0 || g_strcmp0(field, "DPI") == 0) { */
    /*     mdExporterCustomListDPI(expToBuild); */
    /*     return; */
    /* } */

    if (g_strcmp0(field, "COLLECTOR") == 0) {
        actField = "interfaceName";
        item->isDerived = TRUE;
        item->findDerived = &mdFindCollector;
    } else if (g_strcmp0(field, "SIP_ANY") == 0) {
        actField = "sourceIPv4Address";
        item->isDerived = TRUE;
        item->findDerived = &mdFindAnySIP;
    } else if (g_strcmp0(field, "DIP_ANY") == 0) {
        actField = "destinationIPv4Address";
        item->isDerived = TRUE;
        item->findDerived = &mdFindAnyDIP;
    } else if (g_strcmp0(field, "flowDurationMilliseconds") == 0) {
        actField = "flowDurationMilliseconds";
        item->isDerived = TRUE;
        item->findDerived = &mdFindDuration;
    } else if (g_strcmp0(field, "yafFlowKeyHash") == 0) {
        actField = "yafFlowKeyHash";
        item->isDerived = TRUE;
        item->findDerived = &mdFindFlowKeyHash;
    } else {
        actField = field;
        item->isDerived = FALSE;
    }

    item->elem = fbInfoModelGetElementByName(md_info_model, actField);
    if (NULL == item->elem) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Unable to find an Info Element named \"%s\" in the model",
                    actField);
        g_slice_free(mdFieldEntry_t, item);
        return NULL;
    }

    return item;
}

/**
 * mdSetExportFieldListDecoratorBasic
 *
 * create basic printer for CSV
 *
 */
/*void mdSetExportFieldListDecoratorBasic(
    mdExportFieldList_t *list,
    char          delimiter)

{
    mdExportFieldList_t *item = NULL;


    for (item = list; item; item = item->next) {
        if (item->decorator) {
            return;
        }
        switch (item->field) {
          case SIP_ANY:
            item->decorator = g_string_new("%40s");
            break;
          case DIP_ANY:
            item->decorator = g_string_new("%40s");
            break;
          case SPORT:
            item->decorator = g_string_new("%5d");
            break;
          case DPORT:
            item->decorator = g_string_new("%5d");
            break;
          case PROTOCOL:
            item->decorator = g_string_new("%3d");
            break;
          case NDPI_MASTER:
          case NDPI_SUB:
          case APPLICATION:
            item->decorator = g_string_new("%5d");
            break;
          case VLAN:
            item->decorator = g_string_new("%03x");
            break;
          case DURATION:
            item->decorator = g_string_new("%8.3f");
            break;
          case STIME:
            item->decorator = g_string_new("%s");
            break;
          case ENDTIME:
            item->decorator = g_string_new("%s");
            break;
          case RTT:
            item->decorator =   g_string_new("%8.3f");
            break;
          case PKTS:
            item->decorator = g_string_new("%8"PRIu64"");
            break;
          case RPKTS:
            item->decorator =  g_string_new("%8"PRIu64"");
            break;
          case BYTES:
            item->decorator = g_string_new("%8"PRIu64"");
            break;
          case RBYTES:
            item->decorator =  g_string_new("%8"PRIu64"");
            break;
          case IFLAGS:
            item->decorator = g_string_new("%8s");
            break;
          case RIFLAGS:
            item->decorator = g_string_new("%8s");
            break;
          case UFLAGS:
            item->decorator = g_string_new("%8s");
            break;
          case RUFLAGS:
            item->decorator = g_string_new("%8s");
            break;
          case ATTRIBUTES:
            item->decorator = g_string_new("%02x");
            break;
          case RATTRIBUTES:
            item->decorator =  g_string_new("%02x");
            break;
          case MAC:
            item->decorator =  g_string_new("%s");
            break;
          case DSTMAC:
            item->decorator =  g_string_new("%s");
            break;
          case TCPSEQ:
            item->decorator = g_string_new("%08x");
            break;
          case RTCPSEQ:
            item->decorator = g_string_new("%08x");
            break;
          case ENTROPY:
            item->decorator =  g_string_new("%3u");
            break;
          case RENTROPY:
            item->decorator = g_string_new("%3u");
            break;
          case END:
            item->decorator = g_string_new("%6s");
            break;
          case INGRESS:
            item->decorator = g_string_new("%5u");
            break;
          case EGRESS:
            item->decorator = g_string_new("%5u");
            break;
          case TOS:
            item->decorator = g_string_new(" %02x");
            break;
          case RTOS:
            item->decorator = g_string_new("%02x");
            break;
          case COLLECTOR:
            // collector is last field so no delimiter, add newline
            item->decorator = g_string_new("%s\n");
            continue;
          case PAYLOAD:
          case RPAYLOAD:
            item->decorator = g_string_new("");
            continue;
          default:
            g_warning("Invalid field for Basic Flow Print.");
            break;
        }

        g_string_append_c(item->decorator, delimiter);
    }
}*/


mdFieldEntry_t *
mdCreateBasicFlowList(
    gboolean payload,
    gboolean obdomain)
{
    /* TODO: Fix COLLECTOR SIP_ANY and DIP_ANY with derived fields */
    const char *fields[] = {
        "flowStartMilliseconds",
        "flowEndMilliseconds",
        "flowDurationMilliseconds",
        "reverseFlowDeltaMilliseconds",
        "protocolIdentifier",
        "SIP_ANY",
        "sourceTransportPort",
        "packetTotalCount",
        "octetTotalCount",
        "flowAttributes",
        "sourceMacAddress",
        "DIP_ANY",
        "destinationTransportPort",
        "reversePacketTotalCount",
        "reverseOctetTotalCount",
        "reverseFlowAttributes",
        "destinationMacAddress",
        "initialTCPFlags",
        "unionTCPFlags",
        "reverseInitialTCPFlags",
        "reverseUnionTCPFlags",
        "tcpSequenceNumber",
        "reverseTcpSequenceNumber",
        "ingressInterface",
        "egressInterface",
        "vlanId",
        "reverseVlanId",
        "silkAppLabel",
        "ipClassOfService",
        "flowEndReason",
        "COLLECTOR",
        NULL
    };
    const char *payloadFields[] = {
        "payload",
        "reversePayload",
        NULL
    };
    const char *domainFields[] = {
        "observationDomainId",
        NULL
    };

    mdFieldEntry_t *start = NULL;
    mdFieldEntry_t **item = &start;
    const char **f = fields;

    start = mdMakeFieldEntryFromName(*f, TRUE, NULL);
    for (f = fields; NULL != *f; ++f) {
        *item = mdMakeFieldEntryFromName(*f, TRUE, NULL);
        item = &((*item)->next);
    }

    if (payload) {
        for (f = payloadFields; NULL != *f; ++f) {
            *item = mdMakeFieldEntryFromName(*f, TRUE, NULL);
            item = &((*item)->next);
        }
    }
    if (obdomain) {
        for (f = domainFields; NULL != *f; ++f) {
            *item = mdMakeFieldEntryFromName(*f, TRUE, NULL);
            item = &((*item)->next);
        }
    }

    return start;
}

mdFieldEntry_t *
mdCreateIndexFlowList(
    void)
{
    const char *fields[] = {
        "flowStartMilliseconds",
        "sourceIPv4Address",
        "destinationIPv4Address",
        "protocolIdentifier",
        "sourceTransportPort",
        "destinationTransportPort",
        "vlanId",
        "observationDomainId",
        NULL
    };

    mdFieldEntry_t *start = NULL;
    mdFieldEntry_t **item = &start;
    const char **f;

    for (f = fields; NULL != *f; ++f) {
        *item = mdMakeFieldEntryFromName(*f, TRUE, NULL);
        item = &((*item)->next);
    }

    return start;
}

/**
 *  Function: attachHeadToSLL
 *  Description: attach a new entry to the front of a singly linked list
 *  Params: **head - double pointer to the current head.  *head will point
 *                to that new element at the end of this function
 *          *newEntry - a pointer to the previously allocated entry to be added
 *  Return: NONE
 */
void
attachHeadToSLL(
    mdSLL_t **head,
    mdSLL_t  *newEntry)
{
    assert(head);
    assert(newEntry);

    /*  works even if *head starts out null, being no elements attach
     *  the new entry to the head */
    newEntry->next = *head;
    /*  reassign the head pointer to the new entry */
    *head = newEntry;
}

/**
 *  Function: detachHeadOfSLL
 *  Description: remove the head entry from a singly linked list, set
 *      the head pointer to the next one in the list, and return the
 *      old head
 *  Params: **head - double pointer to the head node of the list.  After
 *                      this function, (*head) will point to the
 *                      new head (*(originalhead)->next)
 *          **toRemove - double pointer to use to return the old head
 *  Return: NONE
 */
void
detachHeadOfSLL(
    mdSLL_t **head,
    mdSLL_t **toRemove)
{
    assert(toRemove);
    assert(head);
    assert(*head);

    /*  set the outgoing pointer to point to the head listing */
    *toRemove = *head;
    /*  move the head pointer down one */
    *head = (*head)->next;
}

void
setCollectorYafVersion(
    mdCollector_t      *collector,
    uint8_t             yv)
{
    if (!yv) {
        return;
    }

    if (collector->yafVersion && (collector->yafVersion != yv)) {
        g_error("Collector %s has mismatched yaf versions", collector->name);
    }

    collector->yafVersion = yv;
}

void
setExporterYafVersion(
    mdExporter_t   *exporter,
    uint8_t         yv)
{
    if (!yv) {
        return;
    }

    if (exporter->yafVersion && (exporter->yafVersion != yv)) {
        g_error("exporter %s has mismatched yaf versions", exporter->name);
    }

    exporter->yafVersion = yv;
}

