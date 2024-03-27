/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_filter.c
 *
 *  Yaf mediator for filtering, DNS deduplication, and other mediator-like
 *  things
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

#include "mediator_core.h"
#include "mediator_filter.h"

#ifdef ENABLE_SKIPSET
#include SKIPSET_HEADER_NAME
#ifdef HAVE_SILK_SKIPADDR_H
#include <silk/skipaddr.h>
#endif
#endif



typedef struct mdFilterCallbackCtx_st {
    const mdFilterEntry_t *filterEntry;
} mdFilterCallbackCtx_t;


void
mdFilterDestroy(
    mdFilter_t  *filter)
{
    if (filter) {
        mdFilterEntry_t *cfil;

        while (filter->firstFilterEntry) {
            detachHeadOfSLL((mdSLL_t **)&(filter->firstFilterEntry),
                            (mdSLL_t **)&cfil);
#ifdef ENABLE_SKIPSET
            if (cfil->ipset) {
                mdUtilIPSetClose(cfil->ipset);
            }
#endif
            cfil->next = NULL;
            g_slice_free(mdFilterEntry_t, cfil);
        }
        g_slice_free(mdFilter_t, filter);
    }
}


mdFilterEntry_t *
mdFilterEntryNew(
    void)
{
    mdFilterEntry_t *fe = g_slice_new0(mdFilterEntry_t);
    fe->compValList = g_array_new(TRUE, TRUE, sizeof(fbRecordValue_t));
    return fe;
}

void
mdFilterEntryFree(
    mdFilterEntry_t *fe)
{
    if (fe) {
        g_array_free(fe->compValList, TRUE);
        g_slice_free(mdFilterEntry_t, fe);
    }
}


#if 0
/* mthomas.2022.07.13 I have no idea what this was intended to do, but
 * commenting it out since it always returns TRUE */
static gboolean
mdCheckFilterFields(
    const mdFilter_t   *filter,
    const mdFullFlow_t *flow)
{
    return TRUE;
}
#endif  /* 0 */


static gboolean
mdCheckFilterEntry(
    const mdFilterEntry_t     *filterEntry,
    const fbRecordValue_t     *recVal)
{
    const fieldOperator_t    oper = filterEntry->oper;
    const fbRecordValue_t   *compVal;
    unsigned int             i;

    compVal = &g_array_index(filterEntry->compValList, fbRecordValue_t, 0);
    if (fbInfoElementGetType(recVal->ie) != fbInfoElementGetType(compVal->ie))
    {
        g_log(G_LOG_DOMAIN, G_LOG_LEVEL_INFO,
              "Incompatible filterEntry and record IE's aborting comparison");
        return FALSE;
    }

    switch (fbInfoElementGetType(recVal->ie)) {
      case FB_BOOL:
      case FB_UINT_8:
      case FB_UINT_16:
      case FB_UINT_32:
      case FB_UINT_64:
        switch (oper) {
          case EQUAL:
            if (recVal->v.u64 == compVal->v.u64) {
                return TRUE;
            }
            return FALSE;
          case NOT_EQUAL:
            if (recVal->v.u64 != compVal->v.u64) {
                return TRUE;
            }
            return FALSE;
          case LESS_THAN:
            if (recVal->v.u64 < compVal->v.u64) {
                return TRUE;
            }
            return FALSE;
          case LESS_THAN_OR_EQUAL:
            if (recVal->v.u64 <= compVal->v.u64) {
                return TRUE;
            }
            return FALSE;
          case GREATER_THAN:
            if (recVal->v.u64 > compVal->v.u64) {
                return TRUE;
            }
            return FALSE;
          case GREATER_THAN_OR_EQUAL:
            if (recVal->v.u64 >= compVal->v.u64) {
                return TRUE;
            }
            return FALSE;
          case IN_LIST:
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                g_debug("Checking %" PRIu64 " vs %" PRIu64 " (index %d).",
                        recVal->v.u64, compVal->v.u64, i);
                if (recVal->v.u64 == compVal->v.u64) {
                    return TRUE;
                }
            }
            return FALSE;
          case NOT_IN_LIST:
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                if (recVal->v.u64 == compVal->v.u64) {
                    return FALSE;
                }
            }
            return TRUE;
          default:
            return FALSE;
        }
      case FB_INT_8:
      case FB_INT_16:
      case FB_INT_32:
      case FB_INT_64:
        switch(oper) {
          case EQUAL:
            if (recVal->v.s64 == compVal->v.s64) {
                return TRUE;
            }
            return FALSE;
          case NOT_EQUAL:
            if (recVal->v.s64 != compVal->v.s64) {
                return TRUE;
            }
            return FALSE;
          case LESS_THAN:
            if (recVal->v.s64 < compVal->v.s64) {
                return TRUE;
            }
            return FALSE;
          case LESS_THAN_OR_EQUAL:
            if (recVal->v.s64 <= compVal->v.s64) {
                return TRUE;
            }
            return FALSE;
          case GREATER_THAN:
            if (recVal->v.s64 > compVal->v.s64) {
                return TRUE;
            }
            return FALSE;
          case GREATER_THAN_OR_EQUAL:
            if (recVal->v.s64 >= compVal->v.s64) {
                return TRUE;
            }
            return FALSE;
          case IN_LIST:
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                if (recVal->v.s64 == compVal->v.s64) {
                    return TRUE;
                }
            }
            return FALSE;
          case NOT_IN_LIST:
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                if (recVal->v.s64 == compVal->v.s64) {
                    return FALSE;
                }
            }
            return TRUE;
          default:
            return FALSE;
        }
      case FB_DT_SEC:
      case FB_DT_MILSEC:
      case FB_DT_MICROSEC:
      case FB_DT_NANOSEC:
        switch(oper) {
          case EQUAL:
            if (recVal->v.u64 == compVal->v.u64) {
                return TRUE;
            }
            return FALSE;
          case NOT_EQUAL:
            if (recVal->v.u64 != compVal->v.u64) {
                return TRUE;
            }
            return FALSE;
          case LESS_THAN:
            if (recVal->v.u64 < compVal->v.u64) {
                return TRUE;
            }
            return FALSE;
          case LESS_THAN_OR_EQUAL:
            if (recVal->v.u64 <= compVal->v.u64) {
                return TRUE;
            }
            return FALSE;
          case GREATER_THAN:
            if (recVal->v.u64 > compVal->v.u64) {
                return TRUE;
            }
            return FALSE;
          case GREATER_THAN_OR_EQUAL:
            if (recVal->v.u64 >= compVal->v.u64) {
                return TRUE;
            }
            return FALSE;
          case IN_LIST:
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                if (recVal->v.u64 == compVal->v.u64) {
                    return TRUE;
                }
            }
            return FALSE;
          case NOT_IN_LIST:
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                if (recVal->v.u64 == compVal->v.u64) {
                    return FALSE;
                }
            }
            return TRUE;
          default:
            return FALSE;
        }
      case FB_FLOAT_32:
      case FB_FLOAT_64:
        switch(oper) {
          case EQUAL:
            if (recVal->v.dbl == compVal->v.dbl) {
                return TRUE;
            }
            return FALSE;
          case NOT_EQUAL:
            if (recVal->v.dbl != compVal->v.dbl) {
                return TRUE;
            }
            return FALSE;
          case LESS_THAN:
            if (recVal->v.dbl < compVal->v.dbl) {
                return TRUE;
            }
            return FALSE;
          case LESS_THAN_OR_EQUAL:
            if (recVal->v.dbl <= compVal->v.dbl) {
                return TRUE;
            }
            return FALSE;
          case GREATER_THAN:
            if (recVal->v.dbl > compVal->v.dbl) {
                return TRUE;
            }
            return FALSE;
          case GREATER_THAN_OR_EQUAL:
            if (recVal->v.dbl >= compVal->v.dbl) {
                return TRUE;
            }
            return FALSE;
          case IN_LIST:
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                if (recVal->v.dbl == compVal->v.dbl) {
                    return TRUE;
                }
            }
            return FALSE;
          case NOT_IN_LIST:
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                if (recVal->v.dbl == compVal->v.dbl) {
                    return FALSE;
                }
            }
            return TRUE;
          default:
            return FALSE;
        }
      case FB_MAC_ADDR:
        switch(oper) {
          case EQUAL:
            if (memcmp(recVal->v.mac, compVal->v.mac, 6) == 0) {
                return TRUE;
            }
            return FALSE;
          case NOT_EQUAL:
            if (memcmp(recVal->v.mac, compVal->v.mac, 6) != 0) {
                return TRUE;
            }
            return FALSE;
          case LESS_THAN:
          case LESS_THAN_OR_EQUAL:
          case GREATER_THAN:
          case GREATER_THAN_OR_EQUAL:
            return FALSE;
          case IN_LIST:
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                if (memcmp(recVal->v.mac, compVal->v.mac, 6) == 0) {
                    return TRUE;
                }
            }
            return FALSE;
          case NOT_IN_LIST:
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                if (memcmp(recVal->v.mac, compVal->v.mac, 6) == 0) {
                    return FALSE;
                }
            }
            return TRUE;
          default:
            return FALSE;
        }
      case FB_STRING:
      case FB_OCTET_ARRAY:
        switch(oper) {
          case EQUAL:
            if (recVal->v.varfield.len == compVal->v.varfield.len &&
                memcmp(recVal->v.varfield.buf,
                       compVal->v.varfield.buf,
                       recVal->v.varfield.len) == 0)
            {
                return TRUE;
            }
            return FALSE;
          case NOT_EQUAL:
            if (recVal->v.varfield.len == compVal->v.varfield.len &&
                memcmp(recVal->v.varfield.buf,
                       compVal->v.varfield.buf,
                       recVal->v.varfield.len) != 0)
            {
                return TRUE;
            }
            return FALSE;
          case LESS_THAN:
          case LESS_THAN_OR_EQUAL:
          case GREATER_THAN:
          case GREATER_THAN_OR_EQUAL:
            return FALSE;
          case IN_LIST:
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                if (recVal->v.varfield.len == compVal->v.varfield.len &&
                    memcmp(recVal->v.varfield.buf,
                           compVal->v.varfield.buf,
                           recVal->v.varfield.len) == 0)
                {
                    return TRUE;
                }
            }
            return FALSE;
          case NOT_IN_LIST:
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                if (recVal->v.varfield.len == compVal->v.varfield.len &&
                    memcmp(recVal->v.varfield.buf,
                           compVal->v.varfield.buf,
                           recVal->v.varfield.len) == 0)
                {
                    return FALSE;
                }
            }
            return TRUE;
          default:
            return FALSE;
        }
      case FB_IP4_ADDR:
        switch(oper) {
          case EQUAL:
            if (recVal->v.ip4 == compVal->v.ip4) {
                return TRUE;
            }
            return FALSE;
          case NOT_EQUAL:
            if (recVal->v.ip4 != compVal->v.ip4) {
                return TRUE;
            }
            return FALSE;
          case LESS_THAN:
          case LESS_THAN_OR_EQUAL:
          case GREATER_THAN:
          case GREATER_THAN_OR_EQUAL:
            return FALSE;
          case IN_LIST:
#ifdef ENABLE_SKIPSET
            if (filterEntry->ipset) {
                skipaddr_t addr;
                skipaddrSetV4(&addr, &recVal->v.ip4);
                if (skIPSetCheckAddress(filterEntry->ipset->ipset, &addr)) {
                    return TRUE;
                }
                return FALSE;
            }
#endif  /* ENABLE_SKIPSET */
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                if (recVal->v.ip4 == compVal->v.ip4) {
                    return TRUE;
                }
            }
            return FALSE;
          case NOT_IN_LIST:
#ifdef ENABLE_SKIPSET
            if (filterEntry->ipset) {
                skipaddr_t addr;
                skipaddrSetV4(&addr, &recVal->v.ip4);
                if (skIPSetCheckAddress(filterEntry->ipset->ipset, &addr)) {
                    return FALSE;
                }
                return TRUE;
            }
#endif  /* ENABLE_SKIPSET */
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                if (recVal->v.ip4 == compVal->v.ip4) {
                    return FALSE;
                }
            }
            return TRUE;
          default:
            return FALSE;
        }
      case FB_IP6_ADDR:
        switch(oper) {
          case EQUAL:
            if (memcmp(recVal->v.ip6, compVal->v.ip6, 16) == 0) {
                return TRUE;
            }
            return FALSE;
          case NOT_EQUAL:
            if (memcmp(recVal->v.ip6, compVal->v.ip6, 16) != 0) {
                return TRUE;
            }
            return FALSE;
          case LESS_THAN:
          case LESS_THAN_OR_EQUAL:
          case GREATER_THAN:
          case GREATER_THAN_OR_EQUAL:
            return FALSE;
          case IN_LIST:
#ifdef ENABLE_SKIPSET
            if (filterEntry->ipset) {
#ifndef HAVE_SKIPADDRSETV6
                return FALSE;
#else
                skipaddr_t addr;
                skipaddrSetV6(&addr, &recVal->v.ip6);
                if (skIPSetCheckAddress(filterEntry->ipset->ipset, &addr)) {
                    return TRUE;
                }
                return FALSE;
#endif  /* HAVE_SKIPADDRSETV6 */
            }
#endif  /* ENABLE_SKIPSET */
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                if (memcmp(recVal->v.ip6, compVal->v.ip6, 16) == 0) {
                    return TRUE;
                }
            }
            return FALSE;
          case NOT_IN_LIST:
#ifdef ENABLE_SKIPSET
            if (filterEntry->ipset) {
#ifndef HAVE_SKIPADDRSETV6
                return FALSE;
#else
                skipaddr_t addr;
                skipaddrSetV6(&addr, &recVal->v.ip6);
                if (skIPSetCheckAddress(filterEntry->ipset->ipset, &addr)) {
                    return FALSE;
                }
                return TRUE;
#endif  /* HAVE_SKIPADDRSETV6 */
            }
#endif  /* ENABLE_SKIPSET */
            for (i = 0; i < filterEntry->compValList->len; ++i) {
                compVal = &g_array_index(
                    filterEntry->compValList, fbRecordValue_t, i);
                if (memcmp(recVal->v.ip6, compVal->v.ip6, 16) == 0) {
                    return FALSE;
                }
            }
            return TRUE;
          default:
            return FALSE;
        }
      case FB_BASIC_LIST:
      case FB_SUB_TMPL_LIST:
      case FB_SUB_TMPL_MULTI_LIST:
      default:
        return FALSE;
    }
}


/*
 *  Helper for mdFilterCheck.
 *
 *  This callback is invoked by fbRecordFindAllElementValues() to find
 *  elements that match the field we want to filter on (that IE is in the
 *  `field` parameter).
 *
 *  'value' is the value of the field in this record.
 *
 *  'ctx' is a wrapper over `mdFilterEntry_t`, where the entry's `compValList`
 *  member is a GArray of fbRecordValue_t containing the value(s) we are
 *  trying to find.
 */
static int
mdFilterCallback(
    const fbRecord_t       *parent_record,
    const fbBasicList_t    *parent_bl,
    const fbInfoElement_t  *field,
    const fbRecordValue_t  *value,
    void                   *ctx)
{
    mdFilterCallbackCtx_t *filterCtx = (mdFilterCallbackCtx_t *)ctx;

    MD_UNUSED_PARAM(parent_record);
    MD_UNUSED_PARAM(parent_bl);
    MD_UNUSED_PARAM(field);

    return mdCheckFilterEntry(filterCtx->filterEntry, value);
}


/**
 *  Runs the tests in `filter` and returns TRUE if the filter passes.  Returns
 *  FALSE if `filter` is NULL.
 *
 *  @param filter - a list of filters
 *  @param flow - the basic flow record
 *  @param collector_id - the Collector that read this flow
 *  @return TRUE if one of the filters passed
 *
 */
gboolean
mdFilterCheck(
    const mdFilter_t   *filter,
    const mdFullFlow_t *flow,
    uint8_t             collector_id)
{
    gboolean rc;
    const mdFilterEntry_t *fe;
    const fbRecordValue_t *compVal;
    mdFilterCallbackCtx_t filterCtx;
    unsigned int i;

    if (filter == NULL) {
        return FALSE;
    }

#if 0
    /* mthomas.2022.07.13 I have no idea what this was intended to do, but
     * commenting it out since it always returns TRUE */
    if (!mdCheckFilterFields(filter, flow)) {
        return FALSE;
    }
#endif  /* 0 */

    for (fe = filter->firstFilterEntry; fe != NULL; fe = fe->next) {
        filterCtx.filterEntry = fe;
        compVal = &g_array_index(fe->compValList, fbRecordValue_t, 0);

        if (fe->isCollectorComp) {
            rc = FALSE;
            switch (fe->oper) {
              case EQUAL:
                if (compVal->v.u64 == collector_id) {
                    rc = TRUE;
                }
                break;
              case NOT_EQUAL:
                if (compVal->v.u64 != collector_id) {
                    rc = TRUE;
                }
                break;
              case IN_LIST:
                for (i = 0; i < fe->compValList->len; ++i) {
                    compVal = &g_array_index(
                        fe->compValList, fbRecordValue_t, i);
                    if (compVal->v.u64 == collector_id) {
                        rc = TRUE;
                    }
                }
                break;
              case NOT_IN_LIST:
                rc = TRUE;
                for (i = 0; i < fe->compValList->len; ++i) {
                    compVal = &g_array_index(
                        fe->compValList, fbRecordValue_t, i);
                    if (compVal->v.u64 == collector_id) {
                        rc = FALSE;
                        break;
                    }
                }
                break;
              default:
                break;
            }
        } else if (flow != NULL) {
            rc = (gboolean)fbRecordFindAllElementValues(
                flow->fbRec, compVal->ie, 0,
                mdFilterCallback, (void *)&filterCtx);
        } else {
            rc = FALSE;
        }

        /* Short circuit on early OR true */
        if (rc && !(filter->andFilter)) {
            return TRUE;
        }

        /* Short circuit on early AND false */
        if (!rc && filter->andFilter) {
            return FALSE;
        }
    }
    /* if we've made it here we're either an OR filter with all false or an
     * AND filter with all true, so we return andFilter */

    return filter->andFilter;
}
