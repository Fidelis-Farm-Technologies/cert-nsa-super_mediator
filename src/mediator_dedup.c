/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_dedup.c
 *
 *  deduplication code.
 *
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

#include "mediator_dedup.h"
#include "mediator_core.h"
#include "mediator_inf.h"
#include "mediator_print.h"

#define DEDUP_DEBUG 0
#define CERT_PEN 6871

#define FBBLNEXT(a, b) fbBasicListGetIndexedDataPtr(a, b)

#define SSL_SERIAL_IE 244
#define SSL_COMMON_NAME 3
#define SSL_ORG_UNIT 11
#define DNS_QNAME_IE 179

#define MD_APPEND_CHAR(_buf_, _ch_) \
    do {                            \
        *(_buf_->cp) = _ch_;        \
        ++(_buf_->cp);              \
    } while(0)

#if !GLIB_CHECK_VERSION(2, 32, 0)
#define g_hash_table_contains(_table, _key)                     \
    g_hash_table_lookup_extended((_table), (_key), NULL, NULL)
#endif
#if !GLIB_CHECK_VERSION(2, 68, 0)
/* g_memdup2() uses gsize in place of guint */
#define g_memdup2(_mem, _size)   g_memdup((_mem), (_size))
#endif


/*
 * FIXME: Since we customize this template based on the IE being deduplicated,
 * we should also customize whether it uses sourceIPv* or destinationIPv*.
 */
static fbInfoElementSpec_t md_dedup_spec_add[] = {
    /* Millisecond first seen and last seen (epoch) (native time) */
    {"monitoringIntervalStartMilliSeconds", 8,  0 },
    {"monitoringIntervalEndMilliSeconds",   8,  0 },
    {"flowStartMilliseconds",               8,  0 },
    {"smDedupHitCount",                     8,  0 },
    {"sourceIPv6Address",                   16, 0 },
    {"sourceIPv4Address",                   4,  0 },
    {"yafFlowKeyHash",                      4,  0 },
    {"observationDomainName",               FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};


#if 0
gboolean
md_dedup_basic_list(
    mdExporter_t   *exporter,
    fbBasicList_t  *bl,
    GString        *buf,
    GString        *tstr,
    char            delim,
    gboolean        hex,
    gboolean        escape)
{
    uint16_t      k = 0;
    fbVarfield_t *var = NULL;
    fbVarfield_t *varlist[100];
    int           hits[100];
    int           varnum = 0;
    int           w = 0;
    gboolean      found;

    if (bl->numElements < 2) {
        /* not exciting - just add hit count and done */
        g_string_append_printf(tstr, "1%c", delim);
        mdPrintDPIBasicList(exporter, buf, tstr, bl, delim, escape);
        return TRUE;
    }

    memset(hits, 0, sizeof(hits));

    varlist[varnum] = (fbVarfield_t *)FBBLNEXT(bl, 0);
    hits[varnum] = 1;
    varnum++;

    for (k = 1; (var = (fbVarfield_t *)FBBLNEXT(bl, k)); k++) {
        found = FALSE;

        if (var->len == 0) {
            continue;
        }

        for (w = 0; w < varnum; w++) {
            if (var->len != varlist[w]->len) {
                continue;
            } else {
                if (memcmp(var->buf, varlist[w]->buf, var->len) == 0) {
                    hits[w]++;
                    found = TRUE;
                    break;
                }
            }
        }
        if (!found) {
            varlist[varnum] = var;
            hits[varnum] = 1;
            varnum++;
        }
    }

    for (k = 0; k < varnum; k++) {
        g_string_append_len(buf, tstr->str, tstr->len);
        if (!mdPrintDecimal(buf, delim, hits[k])) {
            return FALSE;
        }
        if (hex) {
            md_util_hexdump_append(buf, varlist[k]->buf, varlist[k]->len);
        } else {
            if (escape) {
                if (!mdPrintEscapeChars(buf, varlist[k]->buf,
                                        varlist[k]->len, delim, FALSE))
                {
                    return FALSE;
                }
            } else {
                if (!md_util_append_buffer(buf, varlist[k]->buf,
                                           varlist[k]->len))
                {
                    return FALSE;
                }
            }
            g_string_append_c(buf, '\n');
        }
    }
    return TRUE;
}
#endif  /* 0 */

#if 0
GString *
md_dedup_basic_list_no_count(
    fbBasicList_t  *bl,
    char            delim,
    gboolean        quote,
    gboolean        hex,
    gboolean        escape)
{
    uint16_t      k = 1;
    fbVarfield_t *var = NULL;
    fbVarfield_t *varlist[100];
    int           varnum = 0;
    int           w = 0;
    gboolean      found;
    GString      *str = NULL;

    var = (fbVarfield_t *)FBBLNEXT(bl, 0);
    if (var) {
        varlist[varnum] = var;
        varnum++;
    } else {
        return NULL;
    }

    var = NULL;
    str = g_string_new(NULL);

    for (k = 1; (var = (fbVarfield_t *)FBBLNEXT(bl, k)); k++) {
        found = FALSE;

        if (var->len == 0) {
            continue;
        }

        for (w = 0; w < varnum; w++) {
            if (var->len != varlist[w]->len) {
                continue;
            } else {
                if (memcmp(var->buf, varlist[w]->buf, var->len) == 0) {
                    found = TRUE;
                    break;
                }
            }
        }
        if (!found) {
            varlist[varnum] = var;
            varnum++;
        }
    }

    for (k = 0; k < varnum; k++) {
        if (quote) {
            g_string_append_printf(str, "\"");
        }
        if (hex) {
            md_util_hexdump_append(str, varlist[k]->buf, varlist[k]->len);
        } else {
            if (escape) {
                if (quote) {
                    mdPrintEscapeStrChars(str, varlist[k]->buf,
                                          varlist[k]->len, '"');
                } else {
                    mdPrintEscapeStrChars(str, varlist[k]->buf, varlist[k]->len,
                                          delim);
                }
            } else {
                g_string_append_len(str, (gchar *)varlist[k]->buf,
                                    varlist[k]->len);
            }
        }
        if (quote) {
            g_string_append_printf(str, "\"%c", delim);
        } else {
            g_string_append_printf(str, "%c", delim);
        }
    }
    if (str->len) {
        /* remove last delimiter */
        g_string_truncate(str, str->len - 1);
    }

    return str;
}
#endif  /* 0 */

void
md_dedup_print_stats(
    md_dedup_state_t  *state,
    const char        *exp_name)
{
    if (state->stats.recvd == 0) {
        g_message("Exporter %s: %" PRIu64 " Records, %" PRIu64 " flushed",
                  exp_name, state->stats.recvd, state->stats.flushed);
        return;
    }

    g_message("Exporter %s: %" PRIu64 " Records, %" PRIu64 " flushed"
              " (%2.2f%% compression)", exp_name, state->stats.recvd,
              state->stats.flushed, (1 - (((double)state->stats.flushed) /
                                          ((double)state->stats.recvd))) * 100);
}

static void
md_dedup_ssl_decrement_cert(
    md_dedup_state_t         *state,
    md_dedup_ssl_str_node_t  *node)
{
    char           temp[4092];
    smVarHashKey_t lookup;

    --(node->cert1->count);

    if (node->cert1->count == 0) {
        if ((node->cert1->issuer_len + node->cert1->serial_len) < 4092) {
            memcpy(temp, node->cert1->serial, node->cert1->serial_len);
            memcpy(temp + node->cert1->serial_len, node->cert1->issuer,
                   node->cert1->issuer_len);
            lookup.val = (uint8_t *)temp;
            lookup.len = node->cert1->serial_len + node->cert1->issuer_len;
            g_hash_table_remove(state->cert_table, &lookup);
            g_slice_free1(node->cert1->issuer_len, node->cert1->issuer);
            g_slice_free1(node->cert1->serial_len, node->cert1->serial);
            g_slice_free(md_dedup_ssl_node_t, node->cert1);
        }
    }

    if (node->cert2) {
        --(node->cert2->count);
        if (node->cert2->count == 0) {
            if ((node->cert2->issuer_len + node->cert2->serial_len) < 4092) {
                memcpy(temp, node->cert2->serial, node->cert2->serial_len);
                memcpy(temp + node->cert2->serial_len, node->cert2->issuer,
                       node->cert2->issuer_len);
                lookup.val = (uint8_t *)temp;
                lookup.len = node->cert2->serial_len + node->cert2->issuer_len;
                g_hash_table_remove(state->cert_table, &lookup);
                g_slice_free1(node->cert2->issuer_len, node->cert2->issuer);
                g_slice_free1(node->cert2->serial_len, node->cert2->serial);
                g_slice_free(md_dedup_ssl_node_t, node->cert2);
            }
        }
    }
}



gboolean
md_dedup_flush_queue(
    mdExporter_t  *exp,
    mdConfig_t    *cfg,
    GError       **err)
{
    md_dedup_state_t  *state = exp->dedup;
    md_dedup_cqueue_t *cq = state->cq;
    md_dedup_node_t   *node;
    mdGenericRec_t     mdRec;
    fbRecord_t         fbRec;

    if (cq == NULL) {
        return TRUE;
    }
    memset(&mdRec, 0, sizeof(mdRec));

    while ((node = detachFromEndOfDLL((mdDLL_t **)&(cq->head),
                                      (mdDLL_t **)&(cq->tail))))
    {
        if (!mdExporterDedupFileOpen(cfg, exp, &(node->ietab->out_file),
                                     &(node->ietab->last_file),
                                     node->ietab->file_prefix,
                                     &(node->ietab->last_rotate_ms), err))
        {
            return FALSE;
        }

        mdRec.intTid = node->ietab->dedup_tids->intid;
        mdRec.extTid = node->ietab->dedup_tids->extid;
        mdRec.generated = TRUE;
        mdRec.fbRec = &fbRec;
        fbRec.tid = node->ietab->dedup_tids->intid;
        fbRec.tmpl = node->ietab->dedup_tids->tmpl;
        fbRec.rec = (uint8_t *)&node->exnode;
        fbRec.recsize = sizeof(md_dedup_general_t);

#if DEDUP_DEBUG
        g_debug("flushing queue node: %p, node->ietab %p, node->strnode %p",
                node, node->ietab, node->strnode);
        g_debug("file->prefix %s, intid %02x, extid %02x",
                node->ietab->file_prefix,
                node->ietab->dedup_tids->intid, node->ietab->dedup_tids->extid);
#endif /* if DEDUP_DEBUG */
        if (state->add_exporter_name &&
            node->exnode.observationDomainName.len == 0)
        {
            const char *name = mdExporterGetName(exp);
            node->exnode.observationDomainName.buf = (uint8_t *)name;
            node->exnode.observationDomainName.len = strlen(name);
        }

        if (!mdExporterWriteGeneralDedupRecord(
                cfg, exp, node->ietab->out_file, &mdRec,
                node->ietab->file_prefix, err))
        {
            return FALSE;
        }

        if (!node->ietab->ssl) {
            g_free(node->strnode->data);
            g_slice_free(md_dedup_str_node_t, node->strnode);
        } else {
            md_dedup_ssl_decrement_cert(state,
                                        (md_dedup_ssl_str_node_t *)node->strnode);
            g_slice_free(md_dedup_ssl_str_node_t,
                         (md_dedup_ssl_str_node_t *)node->strnode);
            /* check count on certs... free certs if necessary */
        }
        g_slice_free(md_dedup_node_t, node);

        state->stats.flushed++;
    }

    return TRUE;
}


static uint32_t
mdInfoElementHash(
    gconstpointer   v_ie)
{
    const fbInfoElement_t *ie = (const fbInfoElement_t *)v_ie;
    return (ie->num | (ie->ent << 15));
}

static gboolean
mdInfoElementEqual(
    gconstpointer   v_a,
    gconstpointer   v_b)
{
    const fbInfoElement_t *a = (const fbInfoElement_t *)v_a;
    const fbInfoElement_t *b = (const fbInfoElement_t *)v_b;
    return ((a->num == b->num) && (a->ent == b->ent));
}


md_dedup_state_t *
md_dedup_new_dedup_state(
    void)
{
    md_dedup_state_t *state = g_slice_new0(md_dedup_state_t);

    state->ie_table = g_hash_table_new(mdInfoElementHash, mdInfoElementEqual);
    state->cq = g_slice_new0(md_dedup_cqueue_t);

    /* set defaults */
    state->max_hit_count = DEFAULT_MAX_HIT_COUNT;
    state->flush_timeout = DEFAULT_FLUSH_TIMEOUT * 1000;

#if DEDUP_DEBUG
    g_debug("created new dedup state %p", state->ie_table);
#endif

    return state;
}

gboolean
md_dedup_add_templates(
    md_dedup_state_t  *state,
    fBuf_t            *fbuf,
    GError           **err)
{
    md_dedup_tids_t    *tnode  = NULL;
    fbSession_t        *session = fBufGetSession(fbuf);
    md_dedup_ie_t      *tn = NULL, *cn = NULL;
    fbInfoModel_t      *sm_model = mdInfoModel();
    fbInfoElementSpec_t md_dedup_ie_spec;
    GString            *template_name;
    fbTemplateInfo_t   *mdInfo = NULL;

    for (tn = state->head; tn; tn = cn) {
        cn = tn->next;
        tnode = tn->dedup_tids;

        template_name = g_string_new("md_dedup");

        if (tn->ssl == FALSE) {
            tnode->tmpl = fbTemplateAlloc(sm_model);

            md_dedup_ie_spec.name = (char *)tnode->ie->name;
            md_dedup_ie_spec.len_override = fbInfoElementGetLen(tnode->ie);
            md_dedup_ie_spec.flags = 0;

            mdTemplateAppendSpecArray(tnode->tmpl, md_dedup_spec_add, ~0);
            /* Allow this to return on failure since we are adding a
             * user-defined element. */
            if (!fbTemplateAppendSpec(tnode->tmpl, &md_dedup_ie_spec, 0, err))
            {
                fbTemplateFreeUnused(tnode->tmpl);
                tnode->tmpl = NULL;
                g_string_free(template_name, TRUE);
                return FALSE;
            }

            tnode->intid = fbSessionAddTemplate(session, TRUE, tnode->intid,
                                                tnode->tmpl, NULL, err);
            if (tnode->intid == 0) {
                fbTemplateFreeUnused(tnode->tmpl);
                tnode->tmpl = NULL;
                g_string_free(template_name, TRUE);
                return FALSE;
            }

            g_string_append_printf(template_name, "_%s", md_dedup_ie_spec.name);

            mdInfo = fbTemplateInfoAlloc();
            fbTemplateInfoInit(mdInfo, template_name->str, NULL, 0, 0);

            tnode->extid = fbSessionAddTemplate(session, FALSE,
                                                tnode->extid,
                                                tnode->tmpl,
                                                mdInfo, err);
            if (tnode->extid == 0) {
                g_string_free(template_name, TRUE);
                return FALSE;
            }
        } else {
            tnode->intid = MD_DEDUP_FULL;
            tnode->extid = MD_DEDUP_FULL;
        }
        g_string_free(template_name, TRUE);
    }

    /*    if (!fbSessionExportTemplates(session, err)) {
     *  return FALSE;
     *  }*/
    return TRUE;
}

#if 0
static void
md_dedup_reset(
    mdExporter_t  *exp,
    uint64_t       ctime)
{
    g_warning("Potentially out of memory for deduplication."
              " Resetting all tables.");
    md_dedup_flush_alltab(exp, ctime, TRUE);
}
#endif  /* 0 */

/*  flush_timeout argument expected to be in seconds */
void
md_dedup_configure_state(
    md_dedup_state_t  *state,
    int                max_hit_count,
    int                flush_timeout,
    gboolean           merge_truncated,
    gboolean           add_exporter_name)
{
    if (max_hit_count) {
        state->max_hit_count = max_hit_count;
    }
    if (flush_timeout) {
        state->flush_timeout = flush_timeout * 1000;
    }
    if (merge_truncated) {
        state->merge_truncated = merge_truncated;
    }
    if (add_exporter_name) {
        state->add_exporter_name = add_exporter_name;
    }
}

static md_dedup_str_node_t *
md_dedup_new_str_node(
    uint8_t   *data,
    size_t     caplen,
    uint64_t   ctime,
    uint32_t   hash,
    uint64_t   stime)
{
    md_dedup_str_node_t *stn;

    stn = g_slice_new0(md_dedup_str_node_t);

    stn->ftime = ctime;
    stn->ltime = ctime;
    stn->hitcount = 1;
    stn->hash = hash;
    stn->stime = stime;

    stn->data = g_memdup2(data, caplen);
    stn->caplen = caplen;

    return stn;
}

static md_dedup_ie_t *
md_dedup_ie_lookup(
    md_dedup_state_t      *state,
    const fbInfoElement_t *ie)
{
    return (md_dedup_ie_t *)g_hash_table_lookup(state->ie_table,
                                                (gconstpointer)ie);
}

void
md_dedup_add_ie(
    md_dedup_state_t      *state,
    md_dedup_ie_t         *ie_tab,
    const fbInfoElement_t *ie)
{
#if DEDUP_DEBUG
    g_debug("add ie %s to ietab %p",
            fbInfoElementGetName(ie), ie_tab);
#endif
    g_hash_table_insert(state->ie_table, (gpointer)ie, (gpointer)ie_tab);
}


/* dipSipHash is 0 for DIP, 1 for SIP, 2 for FLOWKEYHASH */
md_dedup_ie_t *
md_dedup_add_ie_table(
    md_dedup_state_t       *state,
    const char             *prefix,
    smFieldMap_t           *map,
    const fbInfoElement_t  *ie,
    int                     dipSipHash)
{
    md_dedup_ie_t   *ie_tab;

#if DEDUP_DEBUG
    g_debug("state->ie_table is %p", state->ie_table);
#endif

    if ((g_hash_table_contains(state->ie_table, (gconstpointer)ie))) {
        /* already exists */
        return NULL;
    }

    ie_tab = g_slice_new0(md_dedup_ie_t);

    ie_tab->ip_table = smCreateHashTable(sizeof(uint32_t) +
                                         ((map) ? sizeof(uint32_t) : 0),
                                         NULL, NULL);
    ie_tab->ip6_table = smCreateHashTable(sizeof(uint8_t[16]) +
                                         ((map) ? sizeof(uint32_t) : 0),
                                         NULL, NULL);

    ie_tab->file_prefix = g_strdup(prefix);
    ie_tab->sip = dipSipHash;
    ie_tab->map = map;

    g_hash_table_insert(state->ie_table, (gpointer)ie, (gpointer)ie_tab);

    attachHeadToDLL((mdDLL_t **)&(state->head),
                    (mdDLL_t **)&(state->tail),
                    (mdDLL_t *)ie_tab);

#if 0
    /* if ie == serial #, then set up SSL state */
    if (fbInfoElementCheckIdent(ie, CERT_PEN, SSL_SERIAL_IE)) {
        state->cert_table = g_hash_table_new_full(
            (GHashFunc)sm_octet_array_hash,
            (GEqualFunc)sm_octet_array_equal,
            sm_octet_array_key_destroy,
            NULL);
        ie_tab->ssl = TRUE;
    }
#endif  /* 0 */

    ie_tab->dedup_tids = g_slice_new0(md_dedup_tids_t);
    ie_tab->dedup_tids->ie = ie;

    return ie_tab;
}

static void
md_dedup_ip_node_close(
    md_dedup_ie_t       *ietab,
    md_dedup_ip_node_t  *ipnode)
{
    if (ipnode->sip6_key) {
        smHashTableRemove(ietab->ip6_table, (uint8_t *)(ipnode->sip6_key));
        g_slice_free(mdMapKey6_t, ipnode->sip6_key);
    } else {
        smHashTableRemove(ietab->ip_table, (uint8_t *)(ipnode->sip_key));
        g_slice_free(mdMapKey4_t, ipnode->sip_key);
    }

    detachThisEntryOfDLL((mdDLL_t **)&(ietab->head),
                         (mdDLL_t **)&(ietab->tail),
                         (mdDLL_t *)ipnode);
#if DEDUP_DEBUG
    g_debug("REMOVE IPNODE %p", ipnode->sip_key);
#endif

    if (ietab->ssl) {
        g_slice_free(md_dedup_ssl_ip_node_t, (md_dedup_ssl_ip_node_t *)ipnode);
    } else {
        g_slice_free(md_dedup_ip_node_t, ipnode);
    }
    --(ietab->count);
}

static void
md_dedup_str_node_close(
    mdExporter_t         *exp,
    md_dedup_ie_t        *ietab,
    md_dedup_ip_node_t   *ipnode,
    md_dedup_str_node_t  *strnode)
{
    md_dedup_cqueue_t *cq = exp->dedup->cq;
    md_dedup_node_t   *cn = g_slice_new0(md_dedup_node_t);

#if DEDUP_DEBUG
    g_debug("CLOSING STRNODE %p", strnode);
#endif
    cn->strnode = strnode;
    cn->ietab = ietab;
    cn->exnode.monitoringIntervalStartMilliSeconds = strnode->ftime;
    cn->exnode.monitoringIntervalEndMilliSeconds = strnode->ltime;
    cn->exnode.smDedupHitCount = strnode->hitcount;
    cn->exnode.yafFlowKeyHash = strnode->hash;
    cn->exnode.flowStartMilliseconds = strnode->stime;
    if (ipnode->sip_key) {
        cn->exnode.sourceIPv4Address = ipnode->sip_key->ip;
    }
    if (ipnode->sip6_key) {
        /*         memcpy(cn->exnode.sip6, ipnode->sip6_key->val, 16); */
        memcpy(cn->exnode.sourceIPv6Address, ipnode->sip6_key, 16);
    }

    if (ietab->map) {
        int mapindex = 0;
        if (ipnode->sip_key) {
            mapindex = ipnode->sip_key->map;
        } else {
            /*mapindex = ((mdMapKey6_t*)(ipnode->sip6_key->val))->map;*/
            mapindex = ((mdMapKey6_t *)(ipnode->sip6_key))->map;
        }
#if DEDUP_DEBUG
        g_debug("maps on %s", ietab->map->labels[mapindex]);
#endif
        cn->exnode.observationDomainName.buf =
            (uint8_t *)(ietab->map->labels[mapindex]);
        cn->exnode.observationDomainName.len =
            strlen(ietab->map->labels[mapindex]);
    }

    if (!ietab->ssl) {
        if (strnode->ie->type == FB_OCTET_ARRAY ||
            strnode->ie->type == FB_STRING)
        {
            ((fbVarfield_t *)(&cn->exnode.smDedupData))->buf = strnode->data;
            ((fbVarfield_t *)(&cn->exnode.smDedupData))->len =
                strnode->caplen;
        } else {
            memcpy(cn->exnode.smDedupData, strnode->data, strnode->caplen);
        }
    } else {
        md_dedup_ssl_str_node_t *ssl = (md_dedup_ssl_str_node_t *)strnode;
        cn->exnode.sslCertSerialNumber1.buf = ssl->cert1->serial;
        cn->exnode.sslCertSerialNumber1.len = ssl->cert1->serial_len;
        cn->exnode.sslCertIssuerCommonName1.buf = ssl->cert1->issuer;
        cn->exnode.sslCertIssuerCommonName1.len = ssl->cert1->issuer_len;
        if (ssl->cert2) {
            cn->exnode.sslCertSerialNumber2.buf = ssl->cert2->serial;
            cn->exnode.sslCertSerialNumber2.len = ssl->cert2->serial_len;
            cn->exnode.sslCertIssuerCommonName2.buf = ssl->cert2->issuer;
            cn->exnode.sslCertIssuerCommonName2.len = ssl->cert2->issuer_len;
        }
    }

    attachHeadToDLL((mdDLL_t **)&(cq->head),
                    (mdDLL_t **)&(cq->tail),
                    (mdDLL_t *)cn);

    detachThisEntryOfDLL((mdDLL_t **)&(ipnode->head),
                         (mdDLL_t **)&(ipnode->tail),
                         (mdDLL_t *)strnode);

    if (!ipnode->head) {
        md_dedup_ip_node_close(ietab, ipnode);
    }
}


static void
md_dedup_str_node_tick(
    mdExporter_t         *exp,
    md_dedup_ie_t        *ietab,
    md_dedup_ip_node_t   *ipnode,
    md_dedup_str_node_t  *strnode)
{
    if (ipnode->head != strnode) {
        if (strnode->prev != NULL) {
            detachThisEntryOfDLL((mdDLL_t **)&(ipnode->head),
                                 (mdDLL_t **)&(ipnode->tail),
                                 (mdDLL_t *)strnode);
        }
        attachHeadToDLL((mdDLL_t **)&(ipnode->head),
                        (mdDLL_t **)&(ipnode->tail),
                        (mdDLL_t *)strnode);
    }

    while (ipnode->tail && ((strnode->ltime - ipnode->tail->ltime) >
                            exp->dedup->flush_timeout))
    {
        md_dedup_str_node_close(exp, ietab, ipnode, ipnode->tail);
    }
}

static void
md_dedup_ip_node_tick(
    md_dedup_ie_t       *ietab,
    md_dedup_ip_node_t  *ipnode)
{
    if (ietab->head != ipnode) {
        if (ipnode->prev != NULL) {
            detachThisEntryOfDLL((mdDLL_t **)&(ietab->head),
                                 (mdDLL_t **)&(ietab->tail), (mdDLL_t *)ipnode);
        }

        attachHeadToDLL((mdDLL_t **)&(ietab->head),
                        (mdDLL_t **)&(ietab->tail),
                        (mdDLL_t *)ipnode);
    }
}

static void
md_dedup_add_node(
    mdContext_t            *ctx,
    mdExporter_t           *exp,
    md_dedup_ie_t          *ietab,
    uint8_t                *data,
    size_t                  datalen,
    const fbInfoElement_t  *ie,
    mdFullFlow_t           *flow,
    gboolean                rev)
{
    md_dedup_state_t    *state = exp->dedup;
    md_dedup_ip_node_t  *ipnode = NULL;
    md_dedup_str_node_t *strnode = NULL,  *cn = NULL, *tn = NULL;
    size_t cmpsize = datalen;
    uint32_t             sip = 0;
    uint32_t             hash = md_util_flow_key_hash(flow);
    mdMapKey4_t          mapkey4;
    mdMapKey6_t          mapkey6;
    gboolean             v6 = FALSE;

    mapkey4.map = 0;
    mapkey6.map = 0;

    if (datalen == 0 || !data) {
        /* no data to add */
        return;
    }

    if (ietab->sip == 2) {
        mapkey4.ip = hash;
        sip = hash;
    } else {
        if (flow->sourceIPv4Address || flow->destinationIPv4Address) {
            if (rev || (!rev && !ietab->sip)) {
                mapkey4.ip = flow->destinationIPv4Address;
                sip = flow->destinationIPv4Address;
            } else {
                mapkey4.ip = flow->sourceIPv4Address;
                sip = flow->sourceIPv4Address;
            }
        } else {
            if (rev || (!rev && !ietab->sip)) {
                memcpy(mapkey6.ip, flow->destinationIPv6Address, 16);
            } else {
                memcpy(mapkey6.ip, flow->sourceIPv6Address, 16);
            }
            v6 = TRUE;
        }
    }

    if (ietab->map) {
        mapkey4.map = smFieldMapTranslate(ietab->map, flow);
        if (ietab->map->discard && (mapkey4.map == 0)) {
            return;
        }
        mapkey6.map = mapkey4.map;
    }

    if (v6) {
        ipnode = smHashLookup(ietab->ip6_table, (uint8_t *)&mapkey6);
    } else {
        ipnode = smHashLookup(ietab->ip_table, (uint8_t *)&mapkey4);
#if DEDUP_DEBUG
        g_debug("looking up sip %p %04x - returned %p",
                ietab->ip_table, mapkey4.ip, ipnode);
#endif
    }

    if (ipnode) {
        for (tn = ipnode->head; tn; tn = cn) {
            cn = tn->next;
            if (!mdInfoElementEqual(ie, tn->ie)) {
                continue;
            }
            if (state->merge_truncated) {
                cmpsize = MIN(datalen, tn->caplen);
            } else if (datalen != tn->caplen) {
                /* not merging truncated fields - so if lengths don't match,
                 * continue */
                continue;
            }
            if (0 == memcmp(tn->data, data, cmpsize)) {
                /* a match */
                ++state->stats.recvd;
                ++tn->hitcount;
                tn->hash = hash;
                tn->stime = flow->flowStartMilliseconds;
                tn->ltime = ctx->cfg->ctime;
                if (tn->hitcount == state->max_hit_count) {
                    md_dedup_str_node_close(exp, ietab, ipnode, tn);
                } else {
                    md_dedup_str_node_tick(exp, ietab, ipnode, tn);
                    md_dedup_ip_node_tick(ietab, ipnode);
                }
                return;
            }
        }
    } else {
        /* IP address not found for this IE */
        ipnode = g_slice_new0(md_dedup_ip_node_t);
        if (v6) {
            ipnode->sip6_key = g_slice_new0(mdMapKey6_t);
            memcpy(ipnode->sip6_key, &mapkey6, sizeof(mdMapKey6_t));
            smHashTableInsert(ietab->ip6_table, (uint8_t *)ipnode->sip6_key,
                              (uint8_t *)ipnode);
        } else {
            ipnode->sip_key = g_slice_new0(mdMapKey4_t);
            ipnode->sip_key->ip = sip;
            ipnode->sip_key->map = mapkey4.map;
            smHashTableInsert(ietab->ip_table, (uint8_t *)ipnode->sip_key,
                              (uint8_t *)ipnode);
            /*g_hash_table_insert(ietab->ip_table,
             * GUINT_TO_POINTER((unsigned int)sip), ipnode);*/
        }
        ++(ietab->count);
    }

    strnode = md_dedup_new_str_node(data, datalen, ctx->cfg->ctime, hash,
                                    flow->flowStartMilliseconds);
    strnode->ie = ie;

    /* add to stats recvd count */
    state->stats.recvd++;

    md_dedup_str_node_tick(exp, ietab, ipnode, strnode);
    md_dedup_ip_node_tick(ietab, ipnode);
}

static void
md_dedup_free_ietab(
    mdExporter_t   *exp,
    md_dedup_ie_t  *ietab)
{
    smHashTableFree(ietab->ip_table);
    smHashTableFree(ietab->ip6_table);

    if (ietab->out_file) {
        mdExporterDedupFileClose(exp, ietab->out_file, ietab->last_file);
    }

    g_free(ietab->file_prefix);

    /* ietab->dedup_tids->tmpl should get freed when session is freed */
    g_slice_free(md_dedup_tids_t, ietab->dedup_tids);
    g_slice_free(md_dedup_ie_t, ietab);
}

static void
md_dedup_flush_ietab(
    mdExporter_t   *exp,
    md_dedup_ie_t  *ietab,
    uint64_t        ctime,
    gboolean        flush_all)
{
    if (ietab == NULL) {
        return;
    }

    ietab->last_flush = ctime;

    while (flush_all && ietab->tail) {
        md_dedup_str_node_close(exp, ietab, ietab->tail, ietab->tail->tail);
    }

    while (ietab->tail && ((ietab->last_flush - ietab->tail->tail->ltime) >
                           exp->dedup->flush_timeout))
    {
        md_dedup_str_node_close(exp, ietab, ietab->tail, ietab->tail->tail);
    }
}

void
md_dedup_flush_alltab(
    mdExporter_t  *exp,
    uint64_t       ctime,
    gboolean       flush_all)
{
    md_dedup_state_t *state = exp->dedup;
    md_dedup_ie_t    *tn = NULL, *cn = NULL;

    for (tn = state->head; tn; tn = cn) {
        cn = tn->next;
        md_dedup_flush_ietab(exp, tn, ctime, flush_all);
    }
}

gboolean
md_dedup_free_state(
    mdConfig_t    *cfg,
    mdExporter_t  *exp,
    GError       **err)
{
    md_dedup_state_t *state = exp->dedup;
    md_dedup_ie_t    *tn = NULL, *cn = NULL;

    md_dedup_flush_alltab(exp, cfg->ctime, TRUE);

    if (!md_dedup_flush_queue(exp, cfg, err)) {
        return FALSE;
    }

    for (tn = state->head; tn; tn = cn) {
        cn = tn->next;
        md_dedup_free_ietab(exp, tn);
    }

    g_hash_table_destroy(state->ie_table);

    if (state->cert_table) {
        g_hash_table_destroy(state->cert_table);
    }

    g_slice_free(md_dedup_cqueue_t, state->cq);

    return TRUE;
}


#if 0
static md_dedup_ssl_node_t *
md_dedup_new_ssl_node(
    uint8_t  *serial,
    size_t    serial_len,
    uint8_t  *issuer,
    size_t    issuer_len)
{
    md_dedup_ssl_node_t *node = g_slice_new0(md_dedup_ssl_node_t);

    node->serial = g_slice_alloc0(serial_len);
    memcpy(node->serial, serial, serial_len);
    node->serial_len = serial_len;

    node->issuer = g_slice_alloc0(issuer_len);
    memcpy(node->issuer, issuer, issuer_len);
    node->issuer_len = issuer_len;

    return node;
}
#endif  /* 0 */

#if 0
static void
md_dedup_ssl_add_node(
    mdContext_t    *ctx,
    mdExporter_t   *exp,
    md_dedup_ie_t  *ietab,
    yaf_newssl_t   *ssl,
    mdFullFlow_t   *flow)
{
    yafSSLDPICert_t         *cert = NULL;
    yaf_ssl_subcert_t       *obj = NULL;
    yaf_ssl_subcert_t       *ou = NULL;
    md_dedup_state_t        *state = exp->dedup;
    md_dedup_ssl_node_t     *cert1 = NULL, *cert2 = NULL;
    md_dedup_ssl_str_node_t *cn = NULL, *tn = NULL;
    md_dedup_ssl_str_node_t *strnode = NULL;
    md_dedup_ssl_ip_node_t  *ipnode = NULL;
    smVarHashKey_t           lookup;
    smVarHashKey_t          *newkey;
    uint32_t hash = md_util_flow_key_hash(flow);
    uint32_t sip;
    mdMapKey4_t              mapkey4;
    mdMapKey6_t              mapkey6;
    gboolean found;
    gboolean v6 = FALSE;
    uint8_t  temp[4092];
    int      cert_no = 0;

    if (ietab->sip == 2) {
        mapkey4.ip = hash;
        sip = hash;
    } else {
        if (flow->sourceIPv4Address || flow->destinationIPv4Address) {
            if (ietab->sip == 0) {
                mapkey4.ip = flow->destinationIPv4Address;
                sip = flow->destinationIPv4Address;
            } else {
                mapkey4.ip = flow->sourceIPv4Address;
                sip = flow->sourceIPv4Address;
            }
        } else {
            if (ietab->sip == 0) {
                memcpy(mapkey6.ip, flow->destinationIPv6Address, 16);
            } else {
                memcpy(mapkey6.ip, flow->sourceIPv6Address, 16);
            }
            v6 = TRUE;
        }
    }

    if (ietab->map) {
        mapkey4.map = smFieldMapTranslate(ietab->map, flow);
        mapkey6.map = mapkey4.map;
    }

    while ((cert = fbSTLNext(yafSSLDPICert_t, &(ssl->sslCertList), cert))) {
        obj = NULL;
        ou = NULL;
        if (cert->sslCertSerialNumber.len == 0) {
            /* no serial number */
            if (cert_no == 0) {
                return;
            } else {
                break;
            }
        }

        found = FALSE;
        while ((obj = fbSTLNext(yaf_ssl_subcert_t, &(cert->issuer), obj))) {
            if (obj->sslObjectType != SSL_COMMON_NAME) {
                if (obj->sslObjectType == SSL_ORG_UNIT) {
                    /* save just in case */
                    ou = obj;
                }
                continue;
            }

            if (obj->sslObjectValue.len == 0) {
                continue;
            }

            found = TRUE;
            break;
        }

        if (!found) {
            if (ou) {
                obj = ou;
            } else {return;}
        }

        if (cert->sslCertSerialNumber.len + obj->sslObjectValue.len < 4092) {
            memcpy(temp, cert->sslCertSerialNumber.buf,
                   cert->sslCertSerialNumber.len);
            memcpy(temp + cert->sslCertSerialNumber.len,
                   obj->sslObjectValue.buf,
                   obj->sslObjectValue.len);
        } else {
            /* cut this off somehow */
            g_debug("COMBO serial + issuer name over 4092");
            return;
        }

        lookup.val = temp;
        lookup.len = cert->sslCertSerialNumber.len + obj->sslObjectValue.len;

        if (!cert1) {
            cert1 = g_hash_table_lookup(state->cert_table, &lookup);

            if (!cert1) {
                /* add this cert */
                cert1 = md_dedup_new_ssl_node(cert->sslCertSerialNumber.buf,
                                              cert->sslCertSerialNumber.len,
                                              obj->sslObjectValue.buf,
                                              obj->sslObjectValue.len);
                newkey = sm_new_hash_key(lookup.val, lookup.len);
                g_hash_table_insert(state->cert_table, newkey, cert1);
            }
        } else if (!cert2) {
            cert2 = g_hash_table_lookup(state->cert_table, &lookup);

            if (!cert2) {
                /* add this cert */
                cert2 = md_dedup_new_ssl_node(cert->sslCertSerialNumber.buf,
                                              cert->sslCertSerialNumber.len,
                                              obj->sslObjectValue.buf,
                                              obj->sslObjectValue.len);
                newkey = sm_new_hash_key(lookup.val, lookup.len);
                g_hash_table_insert(state->cert_table, newkey, cert2);
            }
        }

        if (cert1 && cert2) {
            break;
        }
    }

    if (!cert1) {
        /* must have 1 valid cert! */
        return;
    }

    if (v6) {
        ipnode = smHashLookup(ietab->ip6_table, (uint8_t *)&mapkey6);
        /*ipnode = g_hash_table_lookup(ietab->ip6_table, &iplookup);*/
    } else {
        ipnode = smHashLookup(ietab->ip_table, (uint8_t *)&mapkey4);
#if DEDUP_DEBUG
        g_debug("looking up sip %u - returned %p", sip, ipnode);
#endif
        /*ipnode = g_hash_table_lookup(ietab->ip_table,
         * GUINT_TO_POINTER((unsigned int)sip));*/
    }

    if (ipnode) {
        for (tn = ipnode->head; tn; tn = cn) {
            cn = tn->next;

            if (cert1 != tn->cert1) {
                continue;
            }
            if (cert2 != tn->cert2) {
                continue;
            }
            /* found a match */
            state->stats.recvd++;
            ++(tn->hitcount);
            tn->ltime = ctx->cfg->ctime;
            tn->hash = hash;
            tn->stime = flow->flowStartMilliseconds;
            if (tn->hitcount == state->max_hit_count) {
                md_dedup_str_node_close(exp, ietab,
                                        (md_dedup_ip_node_t *)ipnode,
                                        (md_dedup_str_node_t *)tn);
            } else {
                md_dedup_str_node_tick(exp, ietab, (md_dedup_ip_node_t *)ipnode,
                                       (md_dedup_str_node_t *)tn);
                md_dedup_ip_node_tick(ietab, (md_dedup_ip_node_t *)ipnode);
            }
            return;
        }
    } else {
        /* IP address not found in this table */
        ipnode = g_slice_new0(md_dedup_ssl_ip_node_t);
        if (v6) {
            ipnode->sip6_key = g_slice_new0(mdMapKey6_t);
            memcpy(ipnode->sip6_key, &mapkey6, sizeof(mdMapKey6_t));
            /*ipnode->sip6_key = sm_new_hash_key(iplookup.val, iplookup.len);*/
            /*g_hash_table_insert(ietab->ip6_table, ipnode->sip6_key,
             * ipnode);*/
            smHashTableInsert(ietab->ip6_table, (uint8_t *)ipnode->sip6_key,
                              (uint8_t *)ipnode);
        } else {
            ipnode->sip_key = g_slice_new0(mdMapKey4_t);
            ipnode->sip_key->ip = sip;
            ipnode->sip_key->map = mapkey4.map;
            smHashTableInsert(ietab->ip_table, (uint8_t *)ipnode->sip_key,
                              (uint8_t *)ipnode);
            /*g_hash_table_insert(ietab->ip_table,
             * GUINT_TO_POINTER((unsigned int)sip), ipnode);*/
        }
        ++(ietab->count);
    }

    strnode = g_slice_new0(md_dedup_ssl_str_node_t);
    strnode->ftime = ctx->cfg->ctime;
    strnode->ltime = ctx->cfg->ctime;
    strnode->hitcount = 1;
    strnode->hash = hash;
    strnode->stime = flow->flowStartMilliseconds;
    strnode->cert1 = cert1;
    strnode->cert2 = cert2;
    ++(cert1->count);
    if (cert2) {
        ++(cert2->count);
    }

    state->stats.recvd++;

    md_dedup_str_node_tick(exp, ietab, (md_dedup_ip_node_t *)ipnode,
                           (md_dedup_str_node_t *)strnode);
    md_dedup_ip_node_tick(ietab, (md_dedup_ip_node_t *)ipnode);
}
#endif  /* 0 */

gboolean
md_dedup_write_dedup(
    mdContext_t            *ctx,
    mdExporter_t           *exp,
    md_dedup_general_t     *dedup,
    const fbInfoElement_t  *ie,
    GError                **err)
{
    md_dedup_state_t *state = exp->dedup;
    md_dedup_ie_t    *ietab = NULL;
    mdGenericRec_t    mdRec;
    fbRecord_t        fbRec;

    ietab = md_dedup_ie_lookup(state, ie);

    if (!ietab) {
        g_message("Ignoring incoming record: No IE dedup table for ie %s",
                  ie->name);
        return TRUE;
    }

    if (!mdExporterDedupFileOpen(ctx->cfg, exp, &(ietab->out_file),
                                 &(ietab->last_file),
                                 ietab->file_prefix,
                                 &(ietab->last_rotate_ms), err))
    {
        return FALSE;
    }

    memset(&mdRec, 0, sizeof(mdRec));
    mdRec.intTid = ietab->dedup_tids->intid;
    mdRec.extTid = ietab->dedup_tids->extid;
    mdRec.generated = TRUE;
    mdRec.fbRec = &fbRec;
    fbRec.tid = ietab->dedup_tids->intid;
    fbRec.tmpl = ietab->dedup_tids->tmpl;
    fbRec.rec = (uint8_t *)dedup;
    fbRec.recsize = sizeof(md_dedup_general_t);

    if (!mdExporterWriteGeneralDedupRecord(
            ctx->cfg, exp, ietab->out_file, &mdRec, ietab->file_prefix, err))
    {
        return FALSE;
    }

    state->stats.flushed++;

    return TRUE;
}


static int
md_dedup_lookup_callback(
    const fbRecord_t       *parent_record,
    const fbBasicList_t    *parent_bl,
    const fbInfoElement_t  *field,
    const fbRecordValue_t  *value,
    void                   *ctx)
{
    md_dedup_cb_ctx_t *callback_ctx = (md_dedup_cb_ctx_t *)ctx;
    uint8_t           *data;
    size_t             datalen;
    uint64_t           temp_time;
#if 0
    yaf_newssl_t      *sslflow;
    yaf_dns_t         *dnsflow;
    yafDnsQR_t        *dnsqrflow;
#endif  /* 0 */

    /* TODO: Deal with automatic reversal for:
     *       36, 37, 107, 242, 243, 287 and maybe:
     *       14, 15, 18, 35, 38,39, 40, 500->510*/
    const uint64_t UNIX_TO_NTP_EPOCH = UINT64_C(0x83AA7E80);
    const uint64_t NTPFRAC = UINT64_C(0x100000000);

    MD_UNUSED_PARAM(parent_record);
    MD_UNUSED_PARAM(parent_bl);

#if 0
    if (fbInfoElementCheckIdent(field, CERT_PEN, SSL_SERIAL_IE)) {
        sslflow = (yaf_newssl_t *)callback_ctx->flow->app;
        md_dedup_ssl_add_node(callback_ctx->ctx, callback_ctx->exp,
                              callback_ctx->ietab, sslflow, callback_ctx->flow);
        return 0;
    }

    if (fbInfoElementCheckIdent(field, CERT_PEN, DNS_QNAME_IE)) {
        dnsflow = (yaf_dns_t *)callback_ctx->flow->app;
        dnsqrflow = NULL;
        while ((dnsqrflow = fbSTLNext(yafDnsQR_t, &(dnsflow->dnsQRList),
                                                    dnsqrflow)))
        {
            if (dnsqrflow->dnsQueryResponse == 0) {
                md_dedup_add_node(callback_ctx->ctx, callback_ctx->exp,
                                  callback_ctx->ietab, dnsqrflow->dnsName.buf,
                                  dnsqrflow->dnsName.len, field,
                                  callback_ctx->flow, FALSE);
            }
        }
        return 0;
    }
#endif  /* 0 */

    switch (fbInfoElementGetType(field)) {
      case FB_BOOL:
      case FB_UINT_8:
      case FB_UINT_16:
      case FB_UINT_32:
      case FB_UINT_64:
      case FB_INT_8:
      case FB_INT_16:
      case FB_INT_32:
      case FB_INT_64:
      case FB_FLOAT_32:
      case FB_FLOAT_64:
      case FB_IP4_ADDR:
      case FB_MAC_ADDR:
      case FB_IP6_ADDR:
        data = (uint8_t *)&(value->v);
        datalen = field->len;
        break;
      case FB_DT_SEC:
        data = (uint8_t *)(&(value->v.dt.tv_sec));
        datalen = 4;
        break;
      case FB_DT_MILSEC:
        temp_time = value->v.dt.tv_sec * 1000 + value->v.dt.tv_nsec / 1000;
        data = (uint8_t *)(&(temp_time));
        datalen = 8;
        break;
      case FB_DT_MICROSEC:
      case FB_DT_NANOSEC:
        temp_time = ((uint64_t)(value->v.dt.tv_sec) + UNIX_TO_NTP_EPOCH) << 32;
        temp_time = temp_time + ((uint64_t)(value->v.dt.tv_nsec) * NTPFRAC) /
            1000000000;
        data = (uint8_t *)(&(temp_time));
        datalen = 8;
        break;
      case FB_STRING:
      case FB_OCTET_ARRAY:
        data = value->v.varfield.buf;
        datalen = value->v.varfield.len;
        break;
      case FB_BASIC_LIST:
      case FB_SUB_TMPL_LIST:
      case FB_SUB_TMPL_MULTI_LIST:
      default:
        return 0;
    }
    md_dedup_add_node(callback_ctx->ctx, callback_ctx->exp, callback_ctx->ietab,
                      data, datalen, field, callback_ctx->flow,
                      callback_ctx->reverse);
    return 0;
}


void
md_dedup_lookup_node(
    mdContext_t   *ctx,
    mdExporter_t  *exp,
    mdFullFlow_t  *flow)
{
    md_dedup_state_t       *state = exp->dedup;
    md_dedup_ie_t          *tn = NULL;
    const fbInfoElement_t  *current_ie;
    md_dedup_cb_ctx_t       callback_ctx;

    callback_ctx.ctx = ctx;
    callback_ctx.exp = exp;
    callback_ctx.flow = flow;

    for (tn = state->head; tn; tn = tn->next) {
        current_ie = tn->dedup_tids->ie;
        callback_ctx.ietab = tn;
        callback_ctx.reverse = FALSE;
        fbRecordFindAllElementValues(flow->fbRec, current_ie, 0,
                                     md_dedup_lookup_callback,
                                     (void *)(&callback_ctx));
    }

    /* attempt to flush all tables */
    md_dedup_flush_alltab(exp, ctx->cfg->ctime, FALSE);
}
