/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_ssl.c
 *
 *  SSL Cert Deduplication
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

#include "mediator_ssl.h"
#include "mediator_inf.h"
#include "mediator_core.h"
#include "specs.h"

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>

#ifndef SM_USE_OPENSSL_EVP_MD_FETCH
#if OPENSSL_VERSION_NUMBER < 0x30000000
#define SM_USE_OPENSSL_EVP_MD_FETCH 0
#else
#define SM_USE_OPENSSL_EVP_MD_FETCH 1
#endif
#endif  /* #ifndef SM_USE_OPENSSL_EVP_MD_FETCH */

#if !SM_USE_OPENSSL_EVP_MD_FETCH
#include <openssl/md5.h>
#include <openssl/sha.h>
#endif
#endif  /* HAVE_OPENSSL */


/*
 *  FIXME:
 *  -- Merge serial and issuer into a single data structure
 *  -- Do not use Glib2 slices for copying strings/octetArrays.
 */

typedef struct md_ssl_serial_node_st md_ssl_serial_node_t;

typedef struct md_ssl_issuer_node_st md_ssl_issuer_node_t;

typedef struct md_ssl_node_st md_ssl_node_t;

typedef struct md_ssl_dedup_stats_st {
    uint64_t       ssl_recvd;
    uint64_t       ssl_filtered;
    uint64_t       ssl_flushed;
} md_ssl_dedup_stats_t;


typedef struct md_ssl_cqueue_st {
    md_ssl_node_t *head;
    md_ssl_node_t *tail;
} md_ssl_cqueue_t;

typedef struct md_ssl_hashtab_st {
    smHashTable_t        *table;
    uint64_t             last_flush;
    uint32_t             count;
    md_ssl_serial_node_t *head;
    md_ssl_serial_node_t *tail;
} md_ssl_hashtab_t;


struct md_ssl_dedup_state_st {
    md_ssl_hashtab_t       cert_table;
    md_ssl_dedup_stats_t   stats;
    md_ssl_cqueue_t        cq;
    char                   *cert_file;
    FILE                   *file;
    char                   *last_file;
    smFieldMap_t           *map;
    /* epoch millisec timestamp of most recent output rotation */
    uint64_t               last_rotate_ms;
    /* flush timeout, in milliseconds */
    uint64_t               flush_timeout;
    uint32_t               max_hit_count;
    gboolean               add_exporter_name;
};

struct md_ssl_node_st {
    struct md_ssl_node_st *next;
    struct md_ssl_node_st *prev;
    md_ssl_t ssl_node;
};


struct md_ssl_issuer_node_st {
    md_ssl_issuer_node_t *next;
    md_ssl_issuer_node_t *prev;
    /* first time, in epoch milliseconds */
    uint64_t             ftime;
    /* last time, in epoch milliseconds */
    uint64_t             ltime;
    uint64_t             hitcount;
    size_t               issuer_len;
    uint8_t              *issuer;
};

struct md_ssl_serial_node_st {
    md_ssl_serial_node_t *next;
    md_ssl_serial_node_t *prev;
    md_ssl_issuer_node_t *head;
    md_ssl_issuer_node_t *tail;
    smVarHashKey_t       *serial;
    int                   mapindex;
};

typedef struct md_ssl_add_node_ctx_st {
    md_ssl_dedup_state_t   *state;
    /* current time, in epoch milliseconds */
    uint64_t                ctime;
    mdFullFlow_t           *fullFlow;
    mdExporter_t           *exp;
    mdConfig_t             *cfg;
    GError                 *err;
    /* number of certifcates printed on this flow */
    uint8_t                 certNum;
} md_ssl_add_node_ctx_t;



#define DNS_DEBUG 0

#define FBSTLNEXT(a, b) fbSubTemplateListGetNextPtr(a, b)
#define SSL_COMMON_NAME 3
#define SSL_ORG_UNIT 11
/* ASN.1 Tag Numbers (for SSL) */
#define CERT_BOOL               0x01
#define CERT_INT                0x02
#define CERT_BITSTR             0x03
#define CERT_OCTSTR             0x04
#define CERT_NULL               0x05
/* Object Identifer */
#define CERT_OID                0x06
/* Start of Sequence */
#define CERT_SEQ                0x10
/* Start of Set */
#define CERT_SET                0x11
/* Printable String */
#define CERT_PRINT              0x13
/* UTC Time */
#define CERT_TIME               0x17
#define CERT_EXPLICIT           0xa0
/* ASN.1 P/C Bit (primitive, constucted) */
#define CERT_PRIM               0x00
#define CERT_CONST              0x01
/* ASN.1 Length 0x81 is length follows in 1 byte */
#define CERT_1BYTE              0x81
/* ASN.1 Length 0x82 is length follows in 2 bytes */
#define CERT_2BYTE              0x82
#define CERT_IDCE               0x551D
#define CERT_IDAT               0x5504
/* {iso(1) member-body (2) us(840) rsadsi(113459) pkcs(1) 9} */
#define CERT_PKCS               0x2A864886
/* 0.9.2342.19200300.100.1.25 */
#define CERT_DC                 0x09922689

/**
 * md_ssl_dedup_print_stats
 *
 * Prints stats to the log.
 *
 *
 */
void
md_ssl_dedup_print_stats(
    md_ssl_dedup_state_t *state,
    const char           *exp_name)
{
    if (state->stats.ssl_recvd == 0) {
        return;
    }

    g_message("Exporter %s: %" PRIu64 " SSL records, %" PRIu64 " filtered,"
              " %" PRIu64 " flushed (%2.2f%% compression)",
              exp_name, state->stats.ssl_recvd, state->stats.ssl_filtered,
              state->stats.ssl_flushed,
              100.0 * (1.0 - ((double)state->stats.ssl_flushed /
                              (double)state->stats.ssl_recvd)));
}


/**
 * md_dns_dedup_reset
 *
 * Flushes all Hash Tables.
 *
 */

static void
md_ssl_dedup_reset(
    md_ssl_dedup_state_t *state,
    uint64_t             cur_time)
{
    g_warning("Out of Memory Error.  Resetting all Hash Tables");
    md_ssl_dedup_flush_tab(state, cur_time, TRUE);
}


gboolean
md_ssl_dedup_free_state(
    mdConfig_t       *cfg,
    mdExporter_t     *exp,
    GError          **err)

{
    md_ssl_dedup_state_t *state = exp->ssl_dedup;

    md_ssl_dedup_flush_tab(state, cfg->ctime, TRUE);
    if (!md_ssl_dedup_flush_queue(exp, cfg, err)) {
        return FALSE;
    }

    if (state->cert_table.table) {
        /*g_hash_table_destroy(state->cert_table.table);*/
        smHashTableFree(state->cert_table.table);
    }

    if (state->cert_file) {
        mdExporterDedupFileClose(exp, state->file, state->last_file);
        g_free(state->cert_file);
    }

    return TRUE;
}

/**
 * md_debug_table
 *
 *
 */
#if DNS_DEBUG == 1
static void
md_debug_table(
    md_ssl_hashtab_t *nodeTab)
{
    md_ssl_issuer_node_t *cq;
    md_ssl_serial_node_t *hn;

    for (hn = nodeTab->head; hn; hn = hn->next) {
        for (cq = hn->head; cq; cq = cq->next) {
            /* g_debug("%d %p rrname %s", cq->rrtype, cq, */
            /*        hn->rrname); */
            g_debug("cq->next is %p", cq->next);
        }
    }
}
#endif

md_ssl_dedup_state_t *
md_ssl_dedup_new_state(
    void)
{
    md_ssl_dedup_state_t *state = g_slice_new0(md_ssl_dedup_state_t);

    /*    state->cert_table.table = g_hash_table_new((GHashFunc)sm_octet_array_hash,
          (GEqualFunc)sm_octet_array_equal);*/
    state->cert_table.table = smCreateHashTable(0xFF,
                                                sm_octet_array_key_destroy,
                                                NULL);

    /* set defaults */
    state->max_hit_count = DEFAULT_MAX_HIT_COUNT;
    state->flush_timeout = DEFAULT_FLUSH_TIMEOUT * 1000;

    return state;
}

/* flush_timeout should be specified in seconds */
void
md_ssl_dedup_configure_state(
    md_ssl_dedup_state_t *state,
    int                   max_hit,
    int                   flush_timeout,
    const char           *filename,
    smFieldMap_t          *map,
    gboolean              export_name)
{
    if (!state) {
        return;
    }
    if (max_hit) {
        state->max_hit_count = max_hit;
    }
    if (flush_timeout) {
        state->flush_timeout = flush_timeout * 1000;
    }
    if (filename) {
        state->cert_file = g_strdup(filename);
    }
    if (map) {
        state->map = map;
    }
    if (export_name) {
        state->add_exporter_name = export_name;
    }
}

/**
 * md_ssl_dedup_flush_queue
 *
 * Flushes all records in the close queue.
 *
 */
gboolean
md_ssl_dedup_flush_queue(
    mdExporter_t   *exp,
    mdConfig_t     *cfg,
    GError        **err)
{
    md_ssl_node_t          *node;
    md_ssl_t               *sslDedupRec;
    md_ssl_dedup_state_t   *state   = exp->ssl_dedup;
    md_ssl_cqueue_t        *cq      = &exp->ssl_dedup->cq;
    uint16_t                tid     = exp->genTids.sslDedupTid;
    mdGenericRec_t          mdRec;
    fbRecord_t              fbRec;

    if (cq == NULL) {
         return TRUE;
    }

    mdRec.intTid    = tid;
    mdRec.extTid    = tid;
    mdRec.generated = TRUE;
    mdRec.fbRec     = &fbRec;
    fbRec.recsize   = sizeof(md_ssl_t);

    while ((node = detachFromEndOfDLL((mdDLL_t **)&(cq->head),
                                      (mdDLL_t **)&(cq->tail))))
    {
        sslDedupRec = &(node->ssl_node);
        fbRec.rec = (uint8_t*)sslDedupRec;

        if (state->add_exporter_name &&
            sslDedupRec->observationDomainName.len == 0)
        {
            const char *name = mdExporterGetName(exp);
            sslDedupRec->observationDomainName.buf = (uint8_t *)name;
            sslDedupRec->observationDomainName.len = strlen(name);
        }

        if (!mdExporterWriteSSLDedupRecord(cfg, exp, &mdRec, err))
        {
             return FALSE;
        }

        state->stats.ssl_flushed++;
        /* free the node we just sent out */
        g_slice_free1(sslDedupRec->sslCertSerialNumber.len,
                      sslDedupRec->sslCertSerialNumber.buf);
        g_slice_free1(sslDedupRec->sslCertIssuerCommonName.len,
                      sslDedupRec->sslCertIssuerCommonName.buf);
        g_slice_free(md_ssl_node_t, node);
    }

    return TRUE;
}



/**
 * nodeClose
 *
 * closes the HASHnode, this means that there is no more
 * cache nodes that belong to this "hash node."  Basically
 * this means that we flushed all information associated
 * with this query name.
 *
 * @param struct that contains node hash table
 * @param pointer to the node entry that we want to close
 *
 */
static void
md_ssl_serial_node_close(
    md_ssl_hashtab_t     *nodeTab,
    md_ssl_serial_node_t *snode)
{
    /*Remove it from table*/

    /*g_hash_table_remove(nodeTab->table, &(snode->serial));*/
    smHashTableRemove(nodeTab->table, (uint8_t*)snode->serial);

    detachThisEntryOfDLL((mdDLL_t**)&(nodeTab->head),
                         (mdDLL_t**)&(nodeTab->tail), (mdDLL_t*)snode);

    /* free the serial */

    /*g_slice_free1(snode->serial.len, snode->serial.val);*/
    g_slice_free(md_ssl_serial_node_t, snode);

    --(nodeTab->count);
}

/**
 * hashTick
 *
 * advances a node to the head of the
 * queue - bottom of queue gets examined
 * for flush timeouts
 *
 * @param pointer to table
 * @param pointer to node
 *
 */
static void
md_ssl_serial_node_tick(
    md_ssl_hashtab_t     *nodeTab,
    md_ssl_serial_node_t *entry)
{
    if (nodeTab->head != entry) {
        if (entry->prev != NULL) {
            detachThisEntryOfDLL((mdDLL_t**)&(nodeTab->head),
                                 (mdDLL_t**)&(nodeTab->tail), (mdDLL_t*)entry);
        }
        attachHeadToDLL((mdDLL_t**)&(nodeTab->head),
                        (mdDLL_t**)&(nodeTab->tail),
                        (mdDLL_t*)entry);
    }

    /*    md_debug_table(nodeTab);*/
}

/**
 * md_ssl_issuer_node_close
 *
 * creates a new md_dns_node_t for output,
 * attaches it to the close queue, and frees the
 * cache node associated with the domain name.
 *
 *
 * @param hashNode
 * @param CacheNode to close
 * @param filepointers
 */
static void
md_ssl_issuer_node_close(
    md_ssl_dedup_state_t    *state,
    md_ssl_serial_node_t    *snode,
    md_ssl_issuer_node_t    *inode)
{
    md_ssl_cqueue_t         *cq = &state->cq;
    md_ssl_node_t *node = g_slice_new0(md_ssl_node_t);

    node->ssl_node.flowStartMilliseconds = inode->ftime;
    node->ssl_node.flowEndMilliseconds = inode->ltime;
    node->ssl_node.smDedupHitCount = inode->hitcount;

    node->ssl_node.sslCertIssuerCommonName.buf =
        g_slice_alloc0(inode->issuer_len);
    memcpy(node->ssl_node.sslCertIssuerCommonName.buf, inode->issuer,
           inode->issuer_len);
    node->ssl_node.sslCertIssuerCommonName.len = inode->issuer_len;

    if (snode->mapindex < 0) {
        node->ssl_node.sslCertSerialNumber.buf =
            g_slice_alloc0(snode->serial->len);
        memcpy(node->ssl_node.sslCertSerialNumber.buf, snode->serial->val,
               snode->serial->len);
        node->ssl_node.sslCertSerialNumber.len = snode->serial->len;
        node->ssl_node.observationDomainName.len = 0;
    } else {
        node->ssl_node.sslCertSerialNumber.len =
            snode->serial->len - sizeof(uint32_t);
        node->ssl_node.sslCertSerialNumber.buf =
            g_slice_alloc0(node->ssl_node.sslCertSerialNumber.len);
        memcpy(node->ssl_node.sslCertSerialNumber.buf,
               snode->serial->val + sizeof(uint32_t),
               node->ssl_node.sslCertSerialNumber.len);
        node->ssl_node.observationDomainName.buf =
            (uint8_t *)(state->map->labels[snode->mapindex]);
        node->ssl_node.observationDomainName.len =
            strlen(state->map->labels[snode->mapindex]);
    }


    /*node->ssl_node.serial.buf = g_slice_alloc0(snode->serial.len);
    memcpy(node->ssl_node.serial.buf, snode->serial.val, snode->serial.len);
    node->ssl_node.serial.len = snode->serial.len;*/


    attachHeadToDLL((mdDLL_t **)&(cq->head),
                    (mdDLL_t **)&(cq->tail),
                    (mdDLL_t *)node);

    detachThisEntryOfDLL((mdDLL_t**)&(snode->head),
                         (mdDLL_t**)&(snode->tail),
                         (mdDLL_t*)inode);

    g_slice_free1(inode->issuer_len, inode->issuer);
    g_slice_free(md_ssl_issuer_node_t, inode);

    if (!snode->head) {
        /*last issuer associated with this serial # - remove from hashtable*/
        md_ssl_serial_node_close(&state->cert_table, snode);
    }
}

/**
 * md_ssl_dedup_emit_record
 *
 * Adds the record to the close queue without removing
 * the node.
 *
 * @param cq - the close queue to add it to
 * @param cn - the node to add
 *
 */

#if 0

static void
md_ssl_dedup_emit_record(
    md_ssl_cqueue_t         *cq,
    md_ssl_serial_node_t    *snode,
    md_ssl_issuer_node_t    *inode)
{
    md_ssl_node_t *node = g_slice_new0(md_ssl_node_t);

    node->ssl_node.fseen = inode->ftime;
    node->ssl_node.lseen = inode->ltime;
    node->ssl_node.hitcount = inode->hitcount;
    node->ssl_node.issuer.buf = g_slice_alloc0(inode->issuer_len);
    memcpy(node->ssl_node.issuer.buf, inode->issuer, inode->issuer_len);
    node->ssl_node.issuer.len = inode->issuer_len;
    node->ssl_node.serial.buf = g_slice_alloc0(snode->serial->len);
    memcpy(node->ssl_node.serial.buf, snode->serial->val, snode->serial->len);
    node->ssl_node.serial.len = snode->serial->len;


    attachHeadToDLL((mdDLL_t **)&(cq->head),
                    (mdDLL_t **)&(cq->tail),
                    (mdDLL_t *)node);
}

#endif  /* 0 */


/**
 * md_ssl_issuer_node_tick
 *
 * advances a node to the head of the cache queue
 * bottom gets examined for flush timeouts
 *
 * @param pointer to head of table
 * @param pointer to node
 *
 */
static void
md_ssl_issuer_node_tick(
    mdExporter_t             *exp,
    md_ssl_serial_node_t     *snode,
    md_ssl_issuer_node_t     *inode)
{
    if (snode->head != inode) {
        if (inode->prev != NULL) {
            detachThisEntryOfDLL((mdDLL_t**)&(snode->head),
                                 (mdDLL_t**)&(snode->tail),
                                 (mdDLL_t*)inode);
        }
        attachHeadToDLL((mdDLL_t**)&(snode->head),
                        (mdDLL_t**)&(snode->tail),
                        (mdDLL_t*)inode);
    }

    while (snode->tail && ((inode->ltime - snode->tail->ltime) >
                           exp->ssl_dedup->flush_timeout))
    {
        md_ssl_issuer_node_close(exp->ssl_dedup, snode, snode->tail);
    }
}

/**
 * md_ssl_dedup_flush_tab
 *
 * Checks entries in the hash table to see if they are past the
 * flush limit.  If so, it outputs to the appropriate file and deallocates
 * the memory
 *
 * @param the struct that contains the hash table and linked list
 * @param cur_time to keep track of how often we're flushing
 * @param flush_all (if TRUE -> close all)
 *
 */
void
md_ssl_dedup_flush_tab(
    md_ssl_dedup_state_t *state,
    uint64_t             cur_time,
    gboolean             flush_all)
{
    md_ssl_hashtab_t *nodeTab = &state->cert_table;

    if (nodeTab == NULL) {
        return;
    }

    nodeTab->last_flush = cur_time;

    if (flush_all) {
        while (nodeTab->tail) {
            md_ssl_issuer_node_close(state, nodeTab->tail, nodeTab->tail->tail);
        }
        return;
    }

    while (nodeTab->tail && (nodeTab->last_flush - nodeTab->tail->tail->ltime >
                             state->flush_timeout))
    {
        md_ssl_issuer_node_close(state, nodeTab->tail, nodeTab->tail->tail);
    }
}


/**
 * md_ssl_export_ssl_cert
 * sends an incoming record out...not a conversion
 *
 *
 *
 */
gboolean
md_ssl_export_ssl_cert(
    mdContext_t    *ctx,
    mdExporter_t   *exp,
    mdGenericRec_t *mdRec,
    GError        **err)
{
    md_ssl_dedup_state_t *state = exp->ssl_dedup;
    FILE                 *fp = NULL;
    fbVarfield_t          issuerName = {0, NULL};
    mdUtilTemplateContents_t    tc = mdRec->extTmplCtx->templateContents;

    if (TC_APP_DPI_SSL_L2 == tc.specCase.dpi) {
        if (0 == exp->genTids.fullCertFromSSLDedupTid) {
            /* We are not generating SSL_DEDUP records so the flattened cert
             * template is not available.  Read the data as a traditional
             * certificate with the STL of type/value entries */
            yafSSLDPICert_t    *cert = (yafSSLDPICert_t *)mdRec->fbRec->rec;
            yaf_ssl_subcert_t  *obj = NULL;
            while ((obj = fbSTLNext(yaf_ssl_subcert_t, &cert->issuer, obj))) {
                if (obj->sslObjectType == SSL_COMMON_NAME &&
                    obj->sslObjectValue.len > 0)
                {
                    /* sslCertIssuerCommonName -- use this */
                    issuerName = obj->sslObjectValue;
                    break;
                }
                if (obj->sslObjectType == SSL_ORG_UNIT &&
                    obj->sslObjectValue.len > 0)
                {
                    /* sslCertIssuerOrgUnitName -- store this and use it if we
                     * do not find what we really want */
                    issuerName = obj->sslObjectValue;
                }
            }
        } else {
            /* convert it to a flattened record */
            md_ssl_certificate_t *flatCert;
            fbRecord_t      flatRec;
            fbBasicList_t  *bl;
            fbVarfield_t   *vf;
            if (!mdUtilFlattenOneSslCertificate(
                    mdRec->fbRec, &flatRec, NULL, err))
            {
                return FALSE;
            }
            flatCert = (md_ssl_certificate_t *)flatRec.rec;
            bl = &flatCert->sslCertIssuerCommonNameList;
            vf = NULL;
            while ((vf = fbBLNext(fbVarfield_t, bl, vf))) {
                if (vf->len) {
                    issuerName = *vf;
                    break;
                }
            }
            if (0 == issuerName.len) {
                bl = &flatCert->sslCertIssuerOrgUnitNameList;
                vf = NULL;
                while ((vf = fbBLNext(fbVarfield_t, bl, vf))) {
                    if (vf->len) {
                        issuerName = *vf;
                        break;
                    }
                }
            }
        }
    }

    if (state) {
        if (state->cert_file) {
            if (!mdExporterDedupFileOpen(ctx->cfg, exp,
                                         &(state->file), &(state->last_file),
                                         state->cert_file,
                                         &(state->last_rotate_ms), err))
            {
                return FALSE;
            }
        }
        fp = state->file;
    }

    if (!mdExporterSSLCertRecord(ctx->cfg, exp, fp, mdRec,
                                 NULL, issuerName.buf, issuerName.len, 0, err))
    {
        return FALSE;
    }

    return TRUE;
}


/*
 *  Callback invoked on each TLS/SSL Certificate (sslLevel2Tid,
 *  mdCheckerYafSSLLevel2) in a TLS/SSL DPI.  `ctx` is an
 *  md_ssl_add_node_ctx_t.
 */
static int
md_ssl_dedup_get_sslLvl2_callback(
    const fbRecord_t   *record,
    void               *ctx)
{
    yafSSLDPICert_t        *cert = NULL;
    md_ssl_add_node_ctx_t  *sslCtx = (md_ssl_add_node_ctx_t*)ctx;
    md_ssl_dedup_state_t   *state   = sslCtx->state;
    uint64_t                ctime   = sslCtx->ctime;
    mdFullFlow_t           *flow    = sslCtx->fullFlow;
    mdExporter_t           *exp     = sslCtx->exp;
    mdConfig_t             *cfg     = sslCtx->cfg;
    fbRecord_t              copiedRecord;
    yafSSLDPICert_t         copiedCert;
    mdDefaultTmplCtx_t     *tmplCtx = fbTemplateGetContext(record->tmpl);
    mdUtilTemplateContents_t templateContents = tmplCtx->templateContents;
    yaf_ssl_subcert_t    *obj;
    md_ssl_issuer_node_t *inode = NULL, *tinode = NULL;
    md_ssl_serial_node_t *snode = NULL;
    md_ssl_hashtab_t     *mdtab = &state->cert_table;
    uint8_t              namebuf[1024];
    smVarHashKey_t       serial;
    uint32_t             mapkey = 0;
    int                  rv;
    mdGenericRec_t       mdRec;
    fbVarfield_t         issuerName = {0, NULL};
    uint8_t              buf[2048];
    fbRecord_t           flatRec = FB_RECORD_INIT;

    /* these exact/super/sub are relative to yafSSLDPICert_t,
     * the assumption is that something else verified that sslLevel2Tid
     * has enough fields for SSL dedup
     */
    switch (templateContents.relative) {
      case TC_EXACT_DEF:
      case TC_EXACT:
        cert = (yafSSLDPICert_t *)record->rec;
        break;

      case TC_SUPER:
      case TC_SUB:
      case TC_MIX:
        if (tmplCtx->stlCount == 0) {
            g_set_error(&sslCtx->err, MD_ERROR_DOMAIN, MD_ERROR_TMPL,
                        "Template for ssl certs does not have an STL");
            return -1;
        }
        cert = &copiedCert;
        copiedRecord.rec            = (uint8_t *)cert;
        copiedRecord.reccapacity    = sizeof(yafSSLDPICert_t);
        if (!fbRecordCopyToTemplate(record, &copiedRecord, yafV2SSLLevel2Tmpl,
                                    record->tid, &sslCtx->err))
        {
            g_prefix_error(&sslCtx->err,
                           "failed to copy ssl rec to new template; ");
            return -1;
        }
        memcpy(&cert->issuer, (record->rec + tmplCtx->stlOffsets[0]),
               sizeof(fbSubTemplateList_t));
        if (tmplCtx->stlCount > 2) {
            memcpy(&cert->subject, (record->rec + tmplCtx->stlOffsets[1]),
                   sizeof(fbSubTemplateList_t));
            memcpy(&cert->issuer, (record->rec + tmplCtx->stlOffsets[2]),
                   sizeof(fbSubTemplateList_t));
        } else if (tmplCtx->stlCount > 1) {
            memcpy(&cert->subject, (record->rec + tmplCtx->stlOffsets[1]),
                   sizeof(fbSubTemplateList_t));
        }
        break;
    }

    if (cert->sslCertSerialNumber.len == 0) {
        /* no serial number */
        state->stats.ssl_filtered++;
        return 0;
    }

    serial.len = MIN(cert->sslCertSerialNumber.len,
                     sizeof(namebuf) - sizeof(uint32_t));
    serial.val = cert->sslCertSerialNumber.buf;

    /* Search the issuer for the CommonName; if no CommonName is found, use
     * the OrganizationalUnit if found */
    obj = NULL;
    while ((obj = fbSTLNext(yaf_ssl_subcert_t, &cert->issuer, obj))) {
        if (obj->sslObjectType == SSL_COMMON_NAME &&
            obj->sslObjectValue.len > 0)
        {
            issuerName = obj->sslObjectValue;
            /* update stats */
            state->stats.ssl_recvd++;
            break;
        }
        if (obj->sslObjectType == SSL_ORG_UNIT &&
            obj->sslObjectValue.len > 0)
        {
            /* save just in case */
            issuerName = obj->sslObjectValue;
        }
    }

    if (0 == issuerName.len) {
        state->stats.ssl_filtered++;
        return 0;
    }

    /* create temp key from VLAN/OBID MAP and the serial number */
    if (state->map) {
        mapkey = smFieldMapTranslate(state->map, flow);
        if (state->map->discard && mapkey == 0) {
            return 0;
        }
        memcpy(namebuf, &mapkey, sizeof(uint32_t));
        memcpy(namebuf + sizeof(uint32_t),
               cert->sslCertSerialNumber.buf, serial.len);
        serial.len += sizeof(uint32_t);
        serial.val = namebuf;
    }

    /*if (( snode = g_hash_table_lookup(mdtab->table, &serial))) {*/
    if ((snode = smHashLookup(mdtab->table, (uint8_t*)&serial))) {
        for (tinode = snode->head; tinode; tinode = inode) {
            inode = tinode->next;
            if (issuerName.len == tinode->issuer_len
                && (0 == memcmp(issuerName.buf, tinode->issuer,
                                tinode->issuer_len)))
            {
                /* match */
                ++tinode->hitcount;
                tinode->ltime = ctime;
                if (tinode->hitcount == state->max_hit_count) {
                    md_ssl_issuer_node_close(state, snode, tinode);
                } else {
                    md_ssl_issuer_node_tick(exp, snode, tinode);
                    md_ssl_serial_node_tick(mdtab, snode);
                }
                goto END;
            }
        }
    } else {
        snode = g_slice_new0(md_ssl_serial_node_t);

        /* copy key over */
        snode->serial = sm_new_hash_key(serial.val, serial.len);
        /*snode->serial.val = g_slice_alloc0(serial.len);*/
        if (snode->serial == NULL) {
            md_ssl_dedup_reset(state, ctime);
            /*snode->serial.val = g_slice_alloc0(serial.len);*/
            snode->serial = sm_new_hash_key(serial.val, serial.len);
        }
        /*memcpy(snode->serial.val, serial.val, serial.len);
             snode->serial.len = serial.len;*/

        if (state->map) {
            snode->mapindex = mapkey;
        } else {
            snode->mapindex = -1;
        }

        /* Insert into hashtable */
        /*g_hash_table_insert(mdtab->table, &(snode->serial), snode);*/
        smHashTableInsert(mdtab->table, (uint8_t*)snode->serial,
                          (uint8_t*)snode);
        ++(mdtab->count);
    }

    /* did not find issuer for this serial number; create one */
    inode = g_slice_new0(md_ssl_issuer_node_t);
    inode->issuer = g_slice_alloc0(issuerName.len);
    memcpy(inode->issuer, issuerName.buf, issuerName.len);
    inode->issuer_len = issuerName.len;
    inode->ftime = ctime;
    inode->ltime = ctime;
    (inode->hitcount)++;

    /* generate the output */
    if (state->cert_file) {
        if (!mdExporterDedupFileOpen(cfg, exp,
                                     &(state->file), &(state->last_file),
                                     state->cert_file,
                                     &(state->last_rotate_ms), &sslCtx->err))
        {
            return -1;
        }
    }

    flatRec.rec = buf;
    flatRec.reccapacity = sizeof(buf);
    flatRec.tid = exp->genTids.fullCertFromSSLDedupTid;
    flatRec.tmpl = fbSessionGetTemplate(exp->defaultWriter->session,
                                        TRUE, flatRec.tid, &sslCtx->err);
    if (NULL == flatRec.tmpl) {
        return -1;
    }
    if (!mdUtilFlattenOneSslCertificate(
            record, &flatRec, tmplCtx, &sslCtx->err))
    {
        return -1;
    }

    memset(&mdRec, 0, sizeof(mdRec));
    mdRec.intTid    = exp->genTids.fullCertFromSSLDedupTid;
    mdRec.extTid    = exp->genTids.fullCertFromSSLDedupTid;
    mdRec.generated = TRUE;
    mdRec.fbRec     = &flatRec;
    mdRec.intTmplCtx = fbTemplateGetContext(flatRec.tmpl);

    /* this is where we write the full SSL record that we just generated*/
    rv = mdExporterSSLCertRecord(cfg, exp, state->file, &mdRec,
                                 flow->fullcert,
                                 inode->issuer,
                                 inode->issuer_len, sslCtx->certNum,
                                 &sslCtx->err);
    /* FIXME: The FreeLists() call should be uncommented, but we need to
     * ensure we do not free something still being used by the original
     * record. */
    /* fbRecordFreeLists(&flatRec); */
    if (!rv) {
        return -1;
    }

    /* bump this node to front of queue; this may also flush old items */
    md_ssl_issuer_node_tick(exp, snode, inode);
    md_ssl_serial_node_tick(mdtab, snode);

  END:
    sslCtx->certNum++;

    /* attempt a flush on all tables */
    md_ssl_dedup_flush_tab(state, ctime, FALSE);

    return 0;
}


/**
 * md_ssl_dedup_add_flow
 *
 * add the dns node to the appropriate hash table
 * this is the main part of deduplication.
 *
 * @param ctx
 * @param mdflow
 *
 */

gboolean
md_ssl_dedup_add_flow(
    mdContext_t  *ctx,
    mdExporter_t *exp,
    mdFullFlow_t *flow)
{
    md_ssl_dedup_state_t   *state = exp->ssl_dedup;
    md_ssl_add_node_ctx_t   sslCtx;

    sslCtx.state    = state;
    sslCtx.ctime    = ctx->cfg->ctime;
    sslCtx.fullFlow = flow;
    sslCtx.exp      = exp;
    sslCtx.cfg      = ctx->cfg;
    sslCtx.err      = NULL;
    sslCtx.certNum  = 0;

    /* Look for sub-records that match the traditional YAF SSL record
     * containing 3 STLs of key-value pairs. */
    if (exp->recvdTids.sslLevel2Tid) {
        if (fbRecordFindAllSubRecords(flow->fbRec, exp->recvdTids.sslLevel2Tid,
                                      0, md_ssl_dedup_get_sslLvl2_callback,
                                      &sslCtx))
        {
            g_error("Error returned from SSL sub records callback: %s",
                    sslCtx.err->message);
        }
    }

#if 0
    /* Look for sub-records that match the flattened SSL record from a
     * previous invocation of super_mediator */
    if (exp->recvdTids.sslFlattenedTid) {
        if (fbRecordFindAllSubRecords(flow->fbRec, exp->recvdTids.sslLevel2Tid,
                                      0, md_ssl_dedup_get_record_callback,
                                      &sslCtx))
        {
            g_error("Error returned from SSL sub records callback: %s",
                    sslCtx.err->message);
        }
    }
#endif  /* 0 */

    /* attempt a flush on all tables */
    md_ssl_dedup_flush_tab(state, ctx->cfg->ctime, FALSE);

    return TRUE;
}


fbTemplate_t *
md_ssl_make_full_cert_template(
    const fbTemplate_t         *srcTmpl,
    GError                    **err)
{
    return mdUtilMakeSslFlatCertTmpl(srcTmpl, NULL, UINT32_MAX, err);
}


#if 0
static gboolean
md_ssl_decode_oid(
    uint8_t         *buffer,
    uint16_t        *offset,
    uint8_t         obj_len)
{
    uint32_t tobjid;

    if (obj_len == 9) {
        /* pkcs-9 */
        tobjid = ntohl(*(uint32_t *)(buffer + *offset));
        if (tobjid != CERT_PKCS) {
            return FALSE;
        }
        *offset += 8;
    } else if (obj_len == 10) {
        /* LDAP Domain Component */
        tobjid = ntohl(*(uint32_t *)(buffer + *offset));
        if (tobjid != CERT_DC) {
            return FALSE;
        }
        *offset += 9;
    } else if (obj_len == 3) {
        *offset += 2;
    } else {
        /* this isn't the usual id-at, pkcs, or dc - so lets ignore it */
        return FALSE;
    }

    return TRUE;
}


static uint8_t
md_ssl_get_extension_count(
    uint8_t                *buffer,
    uint16_t                ext_len)
{
    uint16_t               offsetptr = 0;
    md_asn_tlv_t           tlv;
    uint16_t               len = 2;
    uint16_t               obj_len = 0;
    uint16_t               id_ce;
    uint8_t                obj_type = 0;
    uint8_t                count = 0;

    obj_len = md_util_decode_tlv(&tlv, buffer, &offsetptr);
    while (tlv.tag == CERT_SEQ && len < ext_len) {
        len += obj_len + 2;
        if (*(buffer + offsetptr) == CERT_OID) {
            id_ce = ntohs(*(uint16_t *)(buffer + offsetptr + 2));
            if (id_ce == CERT_IDCE) {
                obj_type = *(buffer + offsetptr + 4);
                switch (obj_type) {
                  case 14:
                    /* subject key identifier */
                  case 15:
                    /* key usage */
                  case 16:
                    /* private key usage period */
                  case 17:
                    /* alternative name */
                  case 18:
                    /* alternative name */
                  case 29:
                    /* authority key identifier */
                  case 31:
                    /* CRL dist points */
                  case 32:
                    /* Cert Policy ID */
                  case 35:
                    /* Authority Key ID */
                  case 37:
                    count++;
                  default:
                    break;
                }
            }
        }
        offsetptr += obj_len;
        obj_len = md_util_decode_tlv(&tlv, buffer, &offsetptr);
    }

    return count;
}


yafSSLDPICert_t *
md_ssl_cert_decode(
    uint8_t      *cert,
    size_t        cert_len,
    fbTemplate_t  *tmpl)
{
    yafSSLDPICert_t       *sslCert = NULL;
    uint16_t                offsetptr = 0;
    uint16_t                tot_ext_len = 0;
    uint16_t                ext_hold = 0;
    uint8_t                 seq_count;
    uint8_t                 obj_type = 0;
    md_asn_tlv_t            tlv;
    yaf_ssl_subcert_t       *sslObject = NULL;
    uint16_t                obj_len;
    uint16_t                set_len;
    uint16_t                off_hold;
    uint16_t                id_ce;

    if (ntohs(*(uint16_t *)(cert + offsetptr)) != 0x3082) {
        g_warning("Error decoding template. Invalid header.");
        return NULL;
    }

    sslCert = g_slice_new0(yafSSLDPICert_t);

    /* 2 bytes for above, 2 for length of CERT */
    /* Next we have a signed CERT so 0x3082 + length */

    offsetptr += 8;

    /* A0 is for explicit tagging of Version Number */
    /* 03 is an Integer - 02 is length, 01 is for tagging */
    if (*(cert + offsetptr) == CERT_EXPLICIT) {
        offsetptr += 4;
        sslCert->sslCertVersion = *(cert + offsetptr);
        offsetptr++;
    } else {
        /* default version is version 1 [0] */
        sslCert->sslCertVersion = 0;
    }

    /* serial number */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len > cert_len) {
        g_debug("Error decoding certificate: Invalid serial number length");
        goto err;
    }
    if (tlv.tag == CERT_INT) {
        sslCert->sslCertSerialNumber.buf = cert + offsetptr;
        sslCert->sslCertSerialNumber.len = obj_len;
    }
    offsetptr += obj_len;

    /* signature */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len > cert_len) {
        g_debug("Error decoding certificate: Invalid signature length");
        goto err;
    }

    if (tlv.tag != CERT_SEQ) {
        offsetptr += obj_len;
    } else {
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (tlv.tag == CERT_OID) {
            if (obj_len > cert_len) {
                g_debug("Error decoding certificate: Invalid object length");
                goto err;
            }
            sslCert->sslCertSignature.buf = cert + offsetptr;
            sslCert->sslCertSignature.len = obj_len;
        }
        offsetptr += obj_len;
    }

    /* issuer - sequence */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len > cert_len) {
        g_debug("Error decoding certificate: Invalid sequence length");
        goto err;
    }

    if (tlv.tag == CERT_SEQ) {
        seq_count = md_util_asn1_sequence_count((cert + offsetptr), obj_len);
    } else {
        g_debug("Error decoding certificate: Invalid issuer sequence");
        goto err;
    }

    sslObject =
        (yaf_ssl_subcert_t *)fbSubTemplateListInit(
            &sslCert->issuer, 0, YAF_SSL_SUBCERT_TID, tmpl, seq_count);
    while (seq_count && sslObject) {
        set_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (set_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid set length");
            goto err;
        }
        if (tlv.tag != CERT_SET) {
            break;
        }
        off_hold = offsetptr;
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (obj_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid object length");
            goto err;
        }
        if (tlv.tag != CERT_SEQ) {
            break;
        }
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (obj_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid object length");
            goto err;
        }

        if (tlv.tag != CERT_OID) {
            break;
        }

        if (!md_ssl_decode_oid(cert, &offsetptr, obj_len)) {
            sslObject++;
            seq_count--;
            offsetptr = off_hold + set_len;
            continue;
        }

        sslObject->sslObjectType = *(cert + offsetptr);
        offsetptr += 2;
        sslObject->sslObjectValue.len = md_util_decode_length(cert, &offsetptr);
        if (sslObject->sslObjectValue.len >= cert_len) {
            g_debug("Error decoding certificate: Invalid object length");
            goto err;
        }
        offsetptr++;
        /* OBJ VALUE */
        sslObject->sslObjectValue.buf = cert + offsetptr;
        offsetptr += sslObject->sslObjectValue.len;
        seq_count--;
        sslObject++;
    }

    /* VALIDITY is a sequence of times */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len >= cert_len) {
        g_debug("Error decoding certificate: Invalid object length");
        goto err;
    }

    if (tlv.tag != CERT_SEQ) {
        g_debug("Error decoding certificate: Invalid validity sequence");
        goto err;
    }

    /* notBefore time */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len >= cert_len) {
        g_debug("Error decoding certificate: Invalid object length notBeforeTime");
        goto err;
    }
    if (tlv.tag != CERT_TIME) {
        g_debug("Error decoding certificate: Invalid Time Tag");
        goto err;
    }
    sslCert->sslCertValidityNotBefore.buf = cert + offsetptr;
    sslCert->sslCertValidityNotBefore.len = obj_len;

    offsetptr += obj_len;

    /* not After time */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len >= cert_len) {
        g_debug("Error decoding certificate: Invalid object length notAfter Time");
        goto err;
    }
    if (tlv.tag != CERT_TIME) {
        g_debug("Error decoding certificate: Invalid Time Tag");
        goto err;
    }
    sslCert->sslCertValidityNotAfter.buf = cert + offsetptr;
    sslCert->sslCertValidityNotAfter.len = obj_len;

    offsetptr += obj_len;

    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len >= cert_len) {
        g_debug("Error decoding certificate: Invalid object length for subject seq");
        goto err;
    }

    /* subject - sequence */
    if (tlv.tag == CERT_SEQ) {
        seq_count = md_util_asn1_sequence_count((cert + offsetptr), obj_len);
    } else {
        g_debug("Error decoding certificate: Invalid subject sequence");
        goto err;
    }

    sslObject =
        (yaf_ssl_subcert_t *)fbSubTemplateListInit(
            &sslCert->subject, 0, YAF_SSL_SUBCERT_TID, tmpl, seq_count);

    while (seq_count && sslObject) {
        set_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (set_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid subject set length");
            goto err;
        }
        off_hold = offsetptr;
        if (tlv.tag != CERT_SET) {
            break;
        }
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (obj_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid object length");
            goto err;
        }

        if (tlv.tag != CERT_SEQ) {
            break;
        }
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (obj_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid object length");
            goto err;
        }
        if (tlv.tag != CERT_OID) {
            break;
        }

        if (!md_ssl_decode_oid(cert, &offsetptr, obj_len)) {
            sslObject++;
            seq_count--;
            offsetptr = off_hold + set_len;
            continue;
        }
        sslObject->sslObjectType = *(cert + offsetptr);
        offsetptr += 2;
        sslObject->sslObjectValue.len = md_util_decode_length(cert, &offsetptr);
        if (sslObject->sslObjectValue.len >= cert_len) {
            g_debug("Error decoding certificate: Invalid object length");
            goto err;
        }
        offsetptr++;
        /* OBJ VALUE */
        sslObject->sslObjectValue.buf = cert + offsetptr;
        offsetptr += sslObject->sslObjectValue.len;
        seq_count--;
        sslObject++;
    }

    /* subject public key info */
    /* this is a sequence of a sequence of algorithms and public key */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len >= cert_len) {
        g_debug("Error decoding certificate: Invalid object length for pk info");
        goto err;
    }
    /* this needs to be a sequence */
    if (tlv.tag != CERT_SEQ) {
        offsetptr += obj_len;
    } else {
        /* this is also a seq */
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (obj_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid sequence");
            goto err;
        }
        if (tlv.tag != CERT_SEQ) {
            offsetptr += obj_len;
        } else {
            obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
            if (obj_len >= cert_len) {
                g_debug("Error decoding certificate: Invalid object length");
                goto err;
            }
            /* this is the algorithm id */
            if (tlv.tag == CERT_OID) {
                sslCert->sslPublicKeyAlgorithm.buf = cert + offsetptr;
                sslCert->sslPublicKeyAlgorithm.len = obj_len;
            }
            offsetptr += obj_len;
            obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
            if (obj_len >= cert_len) {
                g_debug("Error decoding certificate: Invalid object length");
                goto err;
            }
            /* this is the actual public key */
            if (tlv.tag == CERT_BITSTR) {
                sslCert->sslPublicKeyLength = obj_len;
            }
            offsetptr += obj_len;
        }
    }

    /* EXTENSIONS! - ONLY AVAILABLE FOR VERSION 3 */
    /* since it's optional - it has a tag if it's here */
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len >= cert_len) {
        g_debug("Error decoding certificate: "
                "Invalid object length for Extensions");
        goto err;
    }

    if ((tlv.class != 2) || (sslCert->sslCertVersion != 2)) {
        /* no extensions */
        ext_hold = offsetptr;
        fbSubTemplateListInit(&(sslCert->extension), 0,
                              YAF_SSL_SUBCERT_TID,
                              tmpl, 0);
    } else {
        uint16_t ext_len;
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        tot_ext_len = obj_len;
        if (obj_len >= cert_len) {
            g_debug("Error decoding certificate: Invalid ext object length");
            goto err;
        }

        ext_hold = offsetptr;

        if (tlv.tag == CERT_SEQ) {
            seq_count = md_ssl_get_extension_count((cert + offsetptr), obj_len);
        } else {
            g_debug("Error decoding certificate: Invalid extension sequence");
            goto err;
        }
        /* extensions */
        sslObject =
            (yaf_ssl_subcert_t *)fbSubTemplateListInit(
                &sslCert->extension, 0, YAF_SSL_SUBCERT_TID, tmpl, seq_count);
        /* exts is a sequence of a sequence of {id, critical flag, value} */
        while (seq_count && sslObject) {
            ext_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
            if (ext_len >= cert_len) {
                g_debug("Error decoding certificate: Invalid ext object length");
                goto err;
            }

            if (tlv.tag != CERT_SEQ) {
                g_debug("Error decoding certificate: Invalid ext sequence tag");
                goto err;
            }

            off_hold = offsetptr;
            obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
            if (obj_len >= ext_len) {
                g_debug("Error decoding certificate: Invalid ext object length");
                goto err;
            }

            if (tlv.tag != CERT_OID) {
                g_debug("Error decoding certificate: Invalid ext object tag");
                goto err;
            }
            id_ce = ntohs(*(uint16_t *)(cert + offsetptr));
            if (id_ce != CERT_IDCE) {
                /* jump past this */
                offsetptr = off_hold + ext_len;
                continue;
            }
            offsetptr += 2;
            obj_type = *(cert + offsetptr);
            offsetptr++;
            obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
            if (obj_len >= ext_len) {
                g_debug("Error decoding certificate: Invalid ext object length");
                goto err;
            }
            if (tlv.tag == CERT_BOOL) {
                /* this is optional CRITICAL flag */
                offsetptr += obj_len;
                obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
                if (obj_len >= ext_len) {
                    g_debug("Error decoding certificate: Invalid ext object length");
                    goto err;
                }
            }
            switch (obj_type) {
              case 14:
                /* subject key identifier */
              case 15:
                /* key usage */
              case 16:
                /* private key usage period */
              case 17:
                /* alternative name */
              case 18:
                /* alternative name */
              case 29:
                /* authority key identifier */
              case 31:
                /* CRL dist points */
              case 32:
                /* Cert Policy ID */
              case 35:
                /* Authority Key ID */
              case 37:
                /* ext. key usage */
                sslObject->sslObjectType = obj_type;
                sslObject->sslObjectValue.len = obj_len;
                sslObject->sslObjectValue.buf = cert + offsetptr;
                offsetptr += obj_len;
                seq_count--;
                sslObject++;
                break;
              default:
                offsetptr = off_hold + ext_len;
                continue;
            }

        }
    }

    /* signature again */
    offsetptr = ext_hold + tot_ext_len;
    if (offsetptr > cert_len) {
        goto err;
    }
    obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
    if (obj_len > cert_len) {
        goto err;
    }

    if (tlv.tag == CERT_SEQ) {
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        if (tlv.tag != CERT_OID) {
            goto err;
        }

        offsetptr += obj_len;
        if (offsetptr > cert_len) {
            goto err;
        }
        obj_len = md_util_decode_tlv(&tlv, cert, &offsetptr);
        /*get past padding */
        offsetptr++;
        if ((offsetptr + obj_len) > cert_len) {
            goto err;
        }
        if (tlv.tag != CERT_BITSTR) {
            goto err;
        }
        if ((obj_len-1) % 16) {
            goto err;
        }
        sslCert->sslCertificateHash.len = obj_len - 1;
        sslCert->sslCertificateHash.buf = cert + offsetptr;
    }

  err:
    return sslCert;
}
#endif  /* 0 */

#ifdef HAVE_OPENSSL
/**
 * Use `method` to compute the digest of `data` having length `data_len` and
 * store the result in `hash`, a buffer of at least EVP_MAX_MD_SIZE octets.
 * If `hash_len_out` is non-NULL, store the length of the result in its
 * referent.
 */
void
smCertDigestCompute(
    const uint8_t      *data,
    size_t              data_len,
    unsigned char      *hash,
    unsigned int       *hash_len_out,
    smCertDigestType_t  method)
{
    const EVP_MD *type;

#if !SM_USE_OPENSSL_EVP_MD_FETCH
    switch (method) {
      case SM_DIGEST_MD5:
        type = EVP_md5();
        break;
      case SM_DIGEST_SHA1:
        type = EVP_sha1();
        break;
      default:
        g_error("Invalid digest type id %d", (int)method);
    }
#else  /* SM_USE_OPENSSL_EVP_MD_FETCH */
    switch (method) {
      case SM_DIGEST_MD5:
        type = EVP_MD_fetch(NULL, "MD5", NULL);
        break;
      case SM_DIGEST_SHA1:
        type = EVP_MD_fetch(NULL, "SHA1", NULL);
        break;
      default:
        g_error("Invalid digest type id %d", (int)method);
    }

    if (!type) {
        g_error("Cannot load method for digest type %d", (int)method);
    }
#endif  /* SM_USE_OPENSSL_EVP_MD_FETCH */

    if (!EVP_Digest(data, data_len, hash, hash_len_out, type, NULL)) {
        *hash = '\0';
        if (hash_len_out) {
            *hash_len_out = 0;
        }
    }

#if SM_USE_OPENSSL_EVP_MD_FETCH
    EVP_MD_free((EVP_MD *)type);
#endif
}
#endif  /* HAVE_OPENSSL */
