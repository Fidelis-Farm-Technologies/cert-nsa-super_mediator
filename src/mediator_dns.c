/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_dns.c
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

#include "mediator_dns.h"
#include "mediator_inf.h"
#include "mediator_util.h"
#include "specs.h"

#define DNS_DEBUG 0

#define A_REC_TID(_id_) (_id_ |= MD_DNS_AREC)
#define OTHER_REC_TID(_id_) (_id_ |= MD_DNS_OREC)

/*
 *  The DNS DEDUP flow record (md_dns_dedup_t) is defined in templates.h.  Its
 *  template (mdDNSDedupTmplSpec) is declared in specs.h and defined in
 *  mediator_specs.c.
 *
 *  typedef struct md_dns_dedup_st md_dns_dedup_t;    // templates.h
 *  extern fbInfoElementSpec_t mdDNSDedupTmplSpec[];  // specs.h
 */

typedef struct md_cache_node_st md_cache_node_t;
struct md_cache_node_st {
    md_cache_node_t *next;
    md_cache_node_t *prev;
    /* earliest time, in epoch milliseconds */
    uint64_t      ftime;
    /* latest time, in epoch milliseconds */
    uint64_t      ltime;
    uint32_t      ttl;
    uint16_t      rrtype;
    uint16_t      hitcount;
    size_t        caplen;
    uint32_t      ip;
    uint8_t       ipv6[16];
    uint8_t       *rrdata;
};

typedef struct md_hashtab_node_st md_hashtab_node_t;
struct md_hashtab_node_st {
    md_hashtab_node_t *next;
    md_hashtab_node_t *prev;
    md_cache_node_t   *head;
    md_cache_node_t   *tail;
    smVarHashKey_t    *rkey;
    int               mapindex;
    size_t        rrname_len;
    uint8_t       *rrname;
};

typedef struct md_type_hashtab_st {
    smHashTable_t       *table;
    /* most recent flush time, in epoch milliseconds */
    uint64_t            last_flush;
    uint32_t            count;
    md_hashtab_node_t   *head;
    md_hashtab_node_t   *tail;
} md_type_hashtab_t;

typedef struct md_dns_dedup_stats_st {
    uint64_t       dns_recvd;
    uint64_t       dns_filtered;
    uint64_t       dns_flushed;
} md_dns_dedup_stats_t;

typedef struct md_dns_dedup_dll_st md_dns_dedup_dll_t;
struct md_dns_dedup_dll_st {
    struct md_dns_dedup_dll_st *next;
    struct md_dns_dedup_dll_st *prev;
    md_dns_dedup_t              dns_rec;
};

/* dns close queue */
typedef struct md_dns_dedup_cqueue_st {
    md_dns_dedup_dll_t *head;
    md_dns_dedup_dll_t *tail;
} md_dns_dedup_cqueue_t;

/* In mediator_structs.h:
 *
 * typedef struct md_dns_dedup_stats_st md_dns_dedup_stats_t; */
struct md_dns_dedup_state_st {
    md_dns_dedup_stats_t    stats;
    md_dns_dedup_cqueue_t   cq;
    md_type_hashtab_t      *a_table;
    md_type_hashtab_t      *ns_table;
    md_type_hashtab_t      *cname_table;
    md_type_hashtab_t      *soa_table;
    md_type_hashtab_t      *ptr_table;
    md_type_hashtab_t      *mx_table;
    md_type_hashtab_t      *txt_table;
    md_type_hashtab_t      *aaaa_table;
    md_type_hashtab_t      *srv_table;
    md_type_hashtab_t      *nx_table;
    smFieldMap_t           *map;
    int                    *dedup_type_list;
    /* flush timeout, in milliseconds */
    uint64_t                flush_timeout;
    uint32_t                max_hit_count;
    gboolean                add_exporter_name;
    gboolean                print_lastseen;
};

typedef struct md_dns_add_node_ctx_st {
    md_dns_dedup_state_t   *state;
    /* current time, in epoch milliseconds */
    uint64_t                ctime;
    mdFullFlow_t           *fullFlow;
} md_dns_add_node_ctx_t;




static void
md_dns_dedup_flush_tab(
    md_type_hashtab_t    *nodeTab,
    md_dns_dedup_state_t *state,
    uint64_t             ctime,
    gboolean             flush_all);


/**
 * allocTypeTab
 *
 *
 */
static md_type_hashtab_t *
allocTypeTab(
    uint64_t            cur_time)
{
    md_type_hashtab_t *md_type_tab;

    md_type_tab = g_slice_new0(md_type_hashtab_t);
    /*md_type_tab->table = g_hash_table_new((GHashFunc)g_str_hash,
      (GEqualFunc)g_str_equal);*/
    md_type_tab->table = smCreateHashTable(0xFF,
                                           sm_octet_array_key_destroy, NULL);
    if (md_type_tab->table == NULL) {
        return NULL;
    }

    md_type_tab->last_flush = cur_time;

    return md_type_tab;
}

/**
 * md_dns_dedup_print_stats
 *
 * Prints stats to the log.
 *
 *
 */
void
md_dns_dedup_print_stats(
    md_dns_dedup_state_t *state,
    const char           *exp_name)
{
    if (state->stats.dns_recvd == 0) {
        return;
    }

    g_message("Exporter %s: %" PRIu64 " DNS records, %" PRIu64 " filtered,"
              " %" PRIu64 " flushed (%2.2f%% compression)",
              exp_name, state->stats.dns_recvd, state->stats.dns_filtered,
              state->stats.dns_flushed,
              100.0 * (1.0 - ((double)state->stats.dns_flushed /
                              (double)state->stats.dns_recvd)));
}

/**
 * md_dns_dedup_reset
 *
 * Flushes all Hash Tables.
 *
 */

static void
md_dns_dedup_reset(
    md_dns_dedup_state_t *state,
    uint64_t             cur_time)
{
    g_warning("Out of Memory Error.  Resetting all Hash Tables");
    md_dns_dedup_flush_all_tab(state, cur_time, TRUE);
}

static void
md_dns_dedup_attempt_flush_tab(
    md_type_hashtab_t    *md_type_tab,
    md_dns_dedup_state_t *state,
    uint64_t             ctime)
{
    if (md_type_tab && ((ctime - md_type_tab->last_flush) >
                        state->flush_timeout))
    {
        md_dns_dedup_flush_tab(md_type_tab, state, ctime, FALSE);
    }
}

static void
md_dns_dedup_attempt_all_flush(
    md_dns_dedup_state_t *state,
    uint64_t             cur_time)
{
    md_dns_dedup_attempt_flush_tab(state->a_table, state, cur_time);
    md_dns_dedup_attempt_flush_tab(state->ns_table, state, cur_time);
    md_dns_dedup_attempt_flush_tab(state->cname_table, state, cur_time);
    md_dns_dedup_attempt_flush_tab(state->soa_table, state, cur_time);
    md_dns_dedup_attempt_flush_tab(state->ptr_table, state, cur_time);
    md_dns_dedup_attempt_flush_tab(state->mx_table, state, cur_time);
    md_dns_dedup_attempt_flush_tab(state->txt_table, state, cur_time);
    md_dns_dedup_attempt_flush_tab(state->aaaa_table, state, cur_time);
    md_dns_dedup_attempt_flush_tab(state->srv_table, state, cur_time);
    md_dns_dedup_attempt_flush_tab(state->nx_table, state, cur_time);
}




/**
 * md_dns_destroy_tab
 *
 * destroys all hash tables
 *
 */
static void
md_dns_destroy_tab(
    md_dns_dedup_state_t *state)
{
    if (state->a_table && state->a_table->table) {
        smHashTableFree(state->a_table->table);
    }
    if (state->ns_table && state->ns_table->table) {
        smHashTableFree(state->ns_table->table);
    }
    if (state->cname_table && state->cname_table->table) {
        smHashTableFree(state->cname_table->table);
    }
    if (state->soa_table && state->soa_table->table) {
        smHashTableFree(state->soa_table->table);
    }
    if (state->ptr_table && state->ptr_table->table) {
        smHashTableFree(state->ptr_table->table);
    }
    if (state->mx_table && state->mx_table->table) {
        smHashTableFree(state->mx_table->table);
    }
    if (state->txt_table && state->txt_table->table) {
        smHashTableFree(state->txt_table->table);
    }
    if (state->aaaa_table && state->aaaa_table->table) {
        smHashTableFree(state->aaaa_table->table);
    }
    if (state->nx_table && state->nx_table->table) {
        smHashTableFree(state->nx_table->table);
    }
    if (state->srv_table && state->srv_table->table) {
        smHashTableFree(state->srv_table->table);
    }
}

gboolean
md_dns_dedup_free_state(
    mdConfig_t       *cfg,
    mdExporter_t     *exp,
    GError          **err)

{
    md_dns_dedup_state_t *state = exp->dns_dedup;

    md_dns_dedup_flush_all_tab(state, cfg->ctime, TRUE);

    if (!md_dns_dedup_flush_queue(exp, cfg, err)) {
        return FALSE;
    }

    md_dns_destroy_tab(state);
    if (state->dedup_type_list) {
        g_free(state->dedup_type_list);
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
    md_type_hashtab_t *nodeTab)
{
    md_cache_node_t *cq;
    md_hashtab_node_t *hn;

    for (hn = nodeTab->head; hn; hn = hn->next) {
        for (cq = hn->head; cq; cq = cq->next) {
            g_debug("%d %p rrname %s", cq->rrtype, cq,
                    hn->rrname);
            g_debug("cq->next is %p", cq->next);
        }
    }
}
#endif  /* DNS_DEBUG == 1 */


gboolean
md_dns_dedup_get_print_lastseen(
    const md_dns_dedup_state_t *state)
{
    return state->print_lastseen;
}

gboolean
md_dns_dedup_get_add_exporter_name(
    const md_dns_dedup_state_t *state)
{
    return state->add_exporter_name;
}



#if 0
/**
 * md_dns_dedup_new_queue
 *
 * creates a new close queue for dns-dedup
 */
md_dns_dedup_cqueue_t *
md_dns_dedup_new_queue(
    void)
{
    md_dns_dedup_cqueue_t *cq = g_slice_new0(md_dns_dedup_cqueue_t);

    cq->head = NULL;
    cq->tail = NULL;

    return cq;
}
#endif  /* 0 */

md_dns_dedup_state_t *
md_new_dns_dedup_state(
    void)
{
    md_dns_dedup_state_t *state = g_slice_new0(md_dns_dedup_state_t);

    /* set defaults */
    state->max_hit_count = DEFAULT_MAX_HIT_COUNT;
    state->flush_timeout = DEFAULT_FLUSH_TIMEOUT * 1000;
    state->print_lastseen = FALSE;

    return state;
}

void
md_dns_dedup_configure_state(
    md_dns_dedup_state_t *state,
    int                  *dedup_list,
    int                   max_hit,
    int                   flush_timeout,
    gboolean              lastseen,
    smFieldMap_t          *map,
    gboolean              export_name)
{
    if (!state) {
        return;
    }

    state->dedup_type_list = dedup_list;
    state->print_lastseen = lastseen;
    state->add_exporter_name = export_name;
    if (max_hit) {
        state->max_hit_count = max_hit;
    }
    if (flush_timeout) {
        state->flush_timeout = flush_timeout * 1000;
    }
    if (map) {
        state->map = map;
    }
}

/**
 * md_dns_dedup_flush_queue
 *
 * Flushes all records in the close queue.
 *
 */
gboolean
md_dns_dedup_flush_queue(
    mdExporter_t   *exporter,
    mdConfig_t     *cfg,
    GError        **err)
{
    md_dns_dedup_dll_t     *node;
    md_dns_dedup_t         *dnsDedupRec;
    md_dns_dedup_state_t   *state = exporter->dns_dedup;
    md_dns_dedup_cqueue_t  *cq = &exporter->dns_dedup->cq;
    mdGenericRec_t          mdRec;
    fbRecord_t              fbRec;
    uint16_t                intTid  = exporter->dnsDedupIntTid;
    uint16_t                extTid  = 0;
    uint16_t                extATid;
    uint16_t                extOTid;
    uint16_t                extAAAATid;

    if (cq == NULL) {
        return TRUE;
    }

    if (state->print_lastseen) {
        extATid = exporter->genTids.dnsDedupArecLSExtTid;
        extAAAATid = exporter->genTids.dnsDedupAAAArecLSExtTid;
        extOTid = exporter->genTids.dnsDedupOrecLSExtTid;
    } else {
        extATid = exporter->genTids.dnsDedupArecExtTid;
        extAAAATid = exporter->genTids.dnsDedupAAAArecExtTid;
        extOTid = exporter->genTids.dnsDedupOrecExtTid;
    }

    mdRec.intTid    = intTid;
    mdRec.generated = TRUE;
    mdRec.fbRec     = &fbRec;
    fbRec.recsize   = sizeof(md_dns_dedup_t);

    while ((node = detachFromEndOfDLL((mdDLL_t **)&(cq->head),
                                      (mdDLL_t **)&(cq->tail))))
    {
        dnsDedupRec = &(node->dns_rec);
        fbRec.rec = (uint8_t*)dnsDedupRec;

        intTid = exporter->dnsDedupIntTid;

        if (dnsDedupRec->rrtype == 1) { /* pick template here */
            extTid = extATid;
        } else if(dnsDedupRec->rrtype == 28){
            extTid = extAAAATid;
        } else {
            extTid = extOTid;
        }

        mdRec.extTid = extTid;
        if (state->add_exporter_name &&
            node->dns_rec.observationDomainName.len == 0)
        {
            const char *name = mdExporterGetName(exporter);
            dnsDedupRec->observationDomainName.buf = (uint8_t *)name;
            dnsDedupRec->observationDomainName.len = strlen(name);
        }

        /* wrap in mdGenericRec_t's) */
        if (!mdExporterWriteDNSDedupRecord(cfg, exporter, &mdRec, err))
        {
            return FALSE;
        }

        state->stats.dns_flushed++;
        g_slice_free1(node->dns_rec.rrdata.len, node->dns_rec.rrdata.buf);
        g_slice_free1(node->dns_rec.rrname.len, node->dns_rec.rrname.buf);
        g_slice_free(md_dns_dedup_dll_t, node);

    }

    /* free the node we just sent out */

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
nodeClose(
    md_type_hashtab_t *nodeTab,
    md_hashtab_node_t *hnode)
{
    /*Remove it from list*/

    /*    g_hash_table_remove(nodeTab->table, hnode->rrname);*/
    smHashTableRemove(nodeTab->table, (uint8_t*)hnode->rkey);

    detachThisEntryOfDLL((mdDLL_t**)&(nodeTab->head),
                         (mdDLL_t**)&(nodeTab->tail), (mdDLL_t*)hnode);

    /* free the rrname */

    /*     g_slice_free1(hnode->rrname_len, hnode->rrname); */
    g_slice_free(md_hashtab_node_t, hnode);

    --(nodeTab->count);
}

/**
 * newCacheNode
 *
 * creates a new cache node which will go into
 * a linked list by hash node.  Basically this
 * has the same query name, but a different type
 * or rrdata
 */
static md_cache_node_t *
newCacheNode(
    uint64_t            start_time,
    md_cache_node_t     *find)
{
    md_cache_node_t *cn;

    cn = g_slice_new0(md_cache_node_t);
    cn->hitcount = 1;
    cn->ftime = start_time;
    cn->ltime = start_time;
    cn->rrtype = find->rrtype;
    cn->ip = find->ip;
    if(cn->rrtype == 28){
        memcpy(cn->ipv6,find->ipv6,find->caplen);
        cn->caplen = 16;
    }else if(find->caplen){
        cn->rrdata = g_slice_alloc0(find->caplen);
        if (cn->rrdata == NULL) {
            return NULL;
        }
        memcpy(cn->rrdata,find->rrdata,find->caplen);
        cn->caplen = find->caplen;
    }

    return cn;
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
hashTick(
    md_type_hashtab_t *nodeTab,
    md_hashtab_node_t *entry)
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
 * md_dns_dedup_emit_record
 *
 * Adds the record to the close queue without removing
 * the node.
 *
 * @param cq - the close queue to add it to
 * @param cn - the node to add
 *
 */

static void
md_dns_dedup_emit_record(
    md_dns_dedup_state_t   *state,
    md_dns_dedup_cqueue_t  *cq,
    md_hashtab_node_t      *hn,
    md_cache_node_t        *cn)
{
    md_dns_dedup_dll_t *node = g_slice_new0(md_dns_dedup_dll_t);

    node->dns_rec.flowStartMilliseconds = cn->ftime;
    node->dns_rec.flowEndMilliseconds = cn->ltime;
    node->dns_rec.rrtype = cn->rrtype;
    node->dns_rec.sourceIPv4Address = cn->ip;
    if (cn->rrtype == 28) {
         memcpy(node->dns_rec.sourceIPv6Address,cn->ipv6,
                sizeof(node->dns_rec.sourceIPv6Address));
    }
    else if (cn->caplen) {
        node->dns_rec.rrdata.buf = g_slice_alloc0(cn->caplen);
        memcpy(node->dns_rec.rrdata.buf, cn->rrdata, cn->caplen);
        node->dns_rec.rrdata.len = cn->caplen;
    }
    node->dns_rec.smDedupHitCount = cn->hitcount;
    node->dns_rec.dnsTTL = cn->ttl;
    if (hn->mapindex < 0) {
        node->dns_rec.rrname.buf = g_slice_alloc0(hn->rkey->len);
        memcpy(node->dns_rec.rrname.buf, hn->rkey->val, hn->rkey->len);
        node->dns_rec.rrname.len = hn->rkey->len;
        node->dns_rec.observationDomainName.len = 0;
    } else {
        node->dns_rec.rrname.len = hn->rkey->len - sizeof(uint32_t);
        node->dns_rec.rrname.buf = g_slice_alloc0(node->dns_rec.rrname.len);
        memcpy(node->dns_rec.rrname.buf, hn->rkey->val+sizeof(uint32_t),
               node->dns_rec.rrname.len);
        node->dns_rec.observationDomainName.buf =
            (uint8_t *)(state->map->labels[hn->mapindex]);
        node->dns_rec.observationDomainName.len =
            strlen(state->map->labels[hn->mapindex]);
    }

    /*node->dns_rec.rrname.buf = g_slice_alloc0(hn->rrname_len);
    memcpy(node->dns_rec.rrname.buf, hn->rrname, hn->rrname_len);
    node->dns_rec.rrname.len = hn->rrname_len;*/

    attachHeadToDLL((mdDLL_t **)&(cq->head),
                    (mdDLL_t **)&(cq->tail),
                    (mdDLL_t *)node);
}

/**
 * cacheNodeClose
 *
 * creates a new md_dns_dedup_dll_t for output,
 * attaches it to the close queue, and frees the
 * cache node associated with the domain name.
 *
 *
 * @param hashNode
 * @param CacheNode to close
 * @param filepointers
 */
static void
cacheNodeClose(
    md_type_hashtab_t       *nodeTab,
    md_hashtab_node_t       *hn,
    md_cache_node_t         *cn,
    md_dns_dedup_state_t    *state)
{
    md_dns_dedup_cqueue_t   *cq = &state->cq;

    if (state->print_lastseen) {
       md_dns_dedup_emit_record(state,cq,hn,cn);
    }
    detachThisEntryOfDLL((mdDLL_t**)&(hn->head),
                         (mdDLL_t**)&(hn->tail),
                         (mdDLL_t*)cn);

    if(cn->rrtype != 28){
    g_slice_free1(cn->caplen, cn->rrdata);
    }
    g_slice_free(md_cache_node_t, cn);

    if (!hn->head) {
        /*last cacheNode in hashTabNode - remove from hashtable*/
        nodeClose(nodeTab, hn);
    }
}




/**
 * hashCacheTick
 *
 * advances a node to the head of the cache queue
 * bottom gets examined for flush timeouts
 *
 * @param pointer to head of table
 * @param pointer to node
 *
 */
static void
hashCacheTick(
    md_dns_dedup_state_t  *state,
    md_type_hashtab_t     *nodeTab,
    md_hashtab_node_t     *hn,
    md_cache_node_t       *cn)
{
    if (hn->head != cn) {
        if (cn->prev != NULL) {
            detachThisEntryOfDLL((mdDLL_t**)&(hn->head),
                                 (mdDLL_t**)&(hn->tail),
                                 (mdDLL_t*)cn);
        }
        attachHeadToDLL((mdDLL_t**)&(hn->head),
                        (mdDLL_t**)&(hn->tail),
                        (mdDLL_t*)cn);
    }

    while (hn->tail &&((cn->ltime - hn->tail->ltime) > state->flush_timeout))
    {
        cacheNodeClose(nodeTab, hn, hn->tail, state);
    }

}


/**
 * md_dns_dedup_flush_tab
 *
 * Checks entries in the hash table to see if they are past the
 * flush limit.  If so, it outputs to the appropriate file and deallocates
 * the memory
 *
 * @param the struct that contains the hash table and linked list
 * @param cq - the close queue.
 * @param cur_time to keep track of how often we're flushing
 * @param flush_all (if TRUE -> close all)
 *
 */
static void
md_dns_dedup_flush_tab(
    md_type_hashtab_t      *nodeTab,
    md_dns_dedup_state_t   *state,
    uint64_t                cur_time,
    gboolean                flush_all)
{
    if (nodeTab == NULL) {
        return;
    }

    nodeTab->last_flush = cur_time;

    if (flush_all) {
        while (nodeTab->tail) {
            cacheNodeClose(nodeTab, nodeTab->tail, nodeTab->tail->tail, state);
        }
        return;
    }

    while (nodeTab->tail && (nodeTab->last_flush - nodeTab->tail->tail->ltime >
                             state->flush_timeout))
    {
        cacheNodeClose(nodeTab, nodeTab->tail, nodeTab->tail->tail, state);
    }
}


/**
 * md_dns_dedup_flush_all_tab
 *
 * Flushes all entries from all hash tables
 *
 * @param cq
 *
 */
void
md_dns_dedup_flush_all_tab(
    md_dns_dedup_state_t   *state,
    uint64_t                cur_time,
    gboolean                flush_all)
{
    md_dns_dedup_flush_tab(state->a_table, state, cur_time, flush_all);
    md_dns_dedup_flush_tab(state->ns_table, state, cur_time, flush_all);
    md_dns_dedup_flush_tab(state->cname_table, state, cur_time, flush_all);
    md_dns_dedup_flush_tab(state->soa_table, state, cur_time, flush_all);
    md_dns_dedup_flush_tab(state->ptr_table, state, cur_time, flush_all);
    md_dns_dedup_flush_tab(state->mx_table, state, cur_time, flush_all);
    md_dns_dedup_flush_tab(state->txt_table, state, cur_time, flush_all);
    md_dns_dedup_flush_tab(state->aaaa_table, state, cur_time, flush_all);
    md_dns_dedup_flush_tab(state->srv_table, state, cur_time, flush_all);
    md_dns_dedup_flush_tab(state->nx_table, state, cur_time, flush_all);
}

static int
md_dns_dedup_get_record_callback(
    const fbRecord_t   *record,
    void               *ctx)
{
    yafDnsQR_t             *dnsQR   = NULL;
    md_dns_add_node_ctx_t  *dnsCtx  = (md_dns_add_node_ctx_t*)ctx;
    md_dns_dedup_state_t   *state   = dnsCtx->state;
    uint64_t                ctime   = dnsCtx->ctime;
    mdFullFlow_t           *flow    = dnsCtx->fullFlow;
    md_cache_node_t        *cn = NULL, *tn = NULL;
    int                    *type_list = state->dedup_type_list;
    md_cache_node_t         find;
    md_hashtab_node_t      *hn = NULL;
    md_type_hashtab_t      *md_type_tab = NULL;
    uint8_t                 namebuf[1024];
    uint16_t                name_offset=0;
    size_t                  namelen = 0;
    gboolean                found = FALSE;
    int                     nx = 0;
    smVarHashKey_t          key;
    uint32_t                mapkey = 0;
    mdDefaultTmplCtx_t     *tmplCtx = fbTemplateGetContext(record->tmpl);
    mdUtilTemplateContents_t templateContents = tmplCtx->templateContents;
    fbRecord_t              copiedRecord;
    yafDnsQR_t              copiedDnsQR;
    GError                 *err = NULL;
    fbSubTemplateList_t    *srcStl = NULL;

    /* these exact/super/sub are relative to yafDnsQR_t,
     * the assumption is that something else verified that exp->dnsDPITid
     * has enough fields for DNS dedup
     */
    switch (templateContents.relative) {
      case TC_EXACT_DEF:
      case TC_EXACT:
        dnsQR = (yafDnsQR_t*)record->rec;
        break;
      case TC_SUPER:
      case TC_SUB:
      case TC_MIX:
        copiedRecord.rec            = (uint8_t*)&copiedDnsQR;
        copiedRecord.reccapacity    = sizeof(yafDnsQR_t);

        if (templateContents.yafVersion == TC_YAF_VERSION_2) {
            if (!fbRecordCopyToTemplate(record, &copiedRecord, yafDnsQRTmplV2,
                                        record->tid, &err))
            {
                g_warning("failed to copy dns rec to new template %s",
                                        err->message);
            }
        } else if (templateContents.yafVersion == TC_YAF_VERSION_3) {
            if (!fbRecordCopyToTemplate(record, &copiedRecord, yafDnsQRTmplV3,
                                        record->tid, &err))
            {
                g_warning("failed to copy dns rec to new template %s",
                                        err->message);
            }
        }

        dnsQR   = &copiedDnsQR;
        if (tmplCtx->stlCount == 0) {
            g_error("Template for dns QR does not have an STL");
            return -1;
        }

        srcStl = (fbSubTemplateList_t*)(record->rec + tmplCtx->stlOffsets[0]);

        memcpy(&dnsQR->dnsRRList, srcStl, sizeof(fbSubTemplateList_t));

        break;
    }

    /* at this point, dnsQR points to a DNS record we can handle
     * via the struct */
    find.ip = 0;
    find.caplen = 0;
    find.rrdata = NULL;
    memset(find.ipv6,0,sizeof(find.ipv6));
    namelen = 0;
    name_offset = 0;
    found = FALSE;
    nx = 0;
    find.rrtype = dnsQR->dnsRRType;
    find.ttl = dnsQR->dnsTTL;

    if (dnsQR->dnsResponseCode == 3 && dnsQR->dnsSection == 0) {
        find.rrtype = 0;
        nx = 1;
    }

    if (!nx && !dnsQR->dnsQueryResponse) {
        /* don't do queries */
        return 0;
    }

    if (find.rrtype > 34) {
        /* not a valid DNS type for super_mediator dedup */
        state->stats.dns_filtered++;
        return 0;
    }

    if (type_list) {
        if (type_list[find.rrtype] == 0) {
            /* filtered out*/
            state->stats.dns_filtered++;
            return 0;
        }
    }
    if (nx == 1) {
        /* NXDomain */
        if (dnsQR->dnsName.buf) {
            if (state->nx_table == NULL) {
                state->nx_table = allocTypeTab(ctime);
            }
            md_type_tab = state->nx_table;
        } else {
            state->stats.dns_filtered++;
            return 0;
        }
    } else if (dnsQR->dnsQueryResponse) {
        if (dnsQR->dnsName.len == 0) {
            state->stats.dns_filtered++;
            return 0;
        }
        switch (dnsQR->dnsRRType) {
          case 1:
            {
                yaf_dnsA_t *aflow = NULL;
                if (state->a_table == NULL) {
                    state->a_table = allocTypeTab(ctime);
                }
                while ((aflow =
                        fbSTLNext(yaf_dnsA_t, &dnsQR->dnsRRList, aflow)))
                {
                    md_type_tab = state->a_table;
                    find.ip = aflow->dnsA;
                }
            }
            break;
          case 2:
            {
                yaf_dnsNS_t *nsflow  = NULL;
                if (state->ns_table == NULL) {
                    state->ns_table = allocTypeTab(ctime);
                }
                while ((nsflow =
                        fbSTLNext(yaf_dnsNS_t, &dnsQR->dnsRRList, nsflow)))
                {
                    md_type_tab = state->ns_table;
                    find.caplen = nsflow->dnsNSDName.len;
                    find.rrdata = nsflow->dnsNSDName.buf;
                }
            }
            break;
          case 5:
            {
                yaf_dnsCNAME_t *cflow = NULL;
                if (state->cname_table == NULL) {
                    state->cname_table = allocTypeTab(ctime);
                }
                while ((cflow =
                        fbSTLNext(yaf_dnsCNAME_t, &dnsQR->dnsRRList, cflow)))
                {
                    md_type_tab = state->cname_table;
                    find.caplen = cflow->dnsCNAME.len;
                    find.rrdata = cflow->dnsCNAME.buf;
                }
            }
            break;
          case 12:
            {
                yaf_dnsPTR_t *ptrflow = NULL;
                if (state->ptr_table == NULL) {
                    state->ptr_table = allocTypeTab(ctime);
                }
                while ((ptrflow =
                        fbSTLNext(yaf_dnsPTR_t, &dnsQR->dnsRRList, ptrflow)))
                {
                    md_type_tab = state->ptr_table;
                    find.caplen = ptrflow->dnsPTRDName.len;
                    find.rrdata = ptrflow->dnsPTRDName.buf;
                }
            }
            break;
          case 15:
            {
                yaf_dnsMX_t *mx = NULL;
                if (state->mx_table == NULL) {
                    state->mx_table = allocTypeTab(ctime);
                }
                while ((mx =
                        fbSTLNext(yaf_dnsMX_t, &dnsQR->dnsRRList, mx)))
                {
                    md_type_tab = state->mx_table;
                    find.caplen = mx->dnsMXExchange.len;
                    find.rrdata = mx->dnsMXExchange.buf;
                }

            }
            break;
          case 28:
            {
                yaf_dnsAAAA_t *aa = NULL;
                if (state->aaaa_table == NULL) {
                    state->aaaa_table = allocTypeTab(ctime);
                }
                while ((aa =
                        fbSTLNext(yaf_dnsAAAA_t, &dnsQR->dnsRRList, aa)))
                {
                    md_type_tab = state->aaaa_table;
                    find.caplen = 16;
                    memcpy(find.ipv6,aa->dnsAAAA,find.caplen);
                }
            }
            break;
          case 16:
            {
                yaf_dnsTXT_t *txt = NULL;
                if (state->txt_table == NULL) {
                    state->txt_table = allocTypeTab(ctime);
                }
                while ((txt =
                        fbSTLNext(yaf_dnsTXT_t, &dnsQR->dnsRRList, txt)))
                {
                    md_type_tab = state->txt_table;
                    find.caplen = txt->dnsTXTData.len;
                    find.rrdata = txt->dnsTXTData.buf;
                }
            }
            break;
          case 33:
            {
                yaf_dnsSRV_t *srv = NULL;
                if (state->srv_table == NULL) {
                    state->srv_table = allocTypeTab(ctime);
                }
                while ((srv =
                        fbSTLNext(yaf_dnsSRV_t, &dnsQR->dnsRRList, srv)))
                {
                    md_type_tab = state->srv_table;
                    find.rrdata = srv->dnsSRVTarget.buf;
                    find.caplen = srv->dnsSRVTarget.len;
                }
            }
            break;
          case 6:
            {
                yaf_dnsSOA_t *soa = NULL;
                if (state->soa_table == NULL) {
                    state->soa_table = allocTypeTab(ctime);
                }
                while ((soa =
                        fbSTLNext(yaf_dnsSOA_t, &dnsQR->dnsRRList, soa)))
                {
                    md_type_tab = state->soa_table;
                    find.rrdata = soa->dnsSOAMName.buf;
                    find.caplen = soa->dnsSOAMName.len;
                }
            }
            break;
          default:
            /* we don't do this one */
            state->stats.dns_filtered++;
            return 0;
        }
    }
    if (find.rrtype == 28){
            char testsip[16];
            memset(testsip, 0, sizeof(testsip));
            if(memcmp(find.ipv6,testsip,
                sizeof(find.ipv6)) == 0){
                if (nx == 0) {
                    /* got nothing */
                    state->stats.dns_filtered++;
                    return 0;
                }
            }
        }
    if (find.caplen == 0 && find.ip == 0 ) {
        if (nx == 0) {
            /* got nothing */
            state->stats.dns_filtered++;
            return 0;
        }
    }

    /* update stats */
    state->stats.dns_recvd++;

    if (state->map) {
        mapkey = smFieldMapTranslate(state->map, flow);
        if (state->map->discard && mapkey == 0) {
            return 0;
        }
        memcpy(namebuf, &mapkey, sizeof(uint32_t));
        name_offset += sizeof(uint32_t);
        namelen += sizeof(uint32_t);
    }

    memcpy(namebuf + name_offset, dnsQR->dnsName.buf,
           dnsQR->dnsName.len);
    /* get rid of trailing "." */
    namelen += dnsQR->dnsName.len;
    key.val = namebuf;
    key.len = namelen;
    /* namebuf[dnsQR->dnsName.len] = '\0'; */
    if (( hn = smHashLookup(md_type_tab->table, (uint8_t *)&key))) {
        for (tn = hn->head; tn; tn = cn) {
            cn = tn->next;
            if (find.rrtype != tn->rrtype) {
                continue;
            }
            /*Comparing Union based on the record type*/
            if (find.ip && (dnsQR->dnsRRType == 1)) {
                    if (find.ip == tn->ip) {
                       ++tn->hitcount;
                        tn->ltime = ctime;
                        if (find.ttl > tn->ttl) tn->ttl = find.ttl;
                        if (tn->hitcount == state->max_hit_count) {
                            cacheNodeClose(md_type_tab, hn, tn, state);
                        } else {
                            hashCacheTick(state, md_type_tab, hn, tn);
                            hashTick(md_type_tab, hn);
                        }
                        found = TRUE;
                        break;
                        }
            } else if (dnsQR->dnsRRType == 28) {
                    if (memcmp(find.ipv6, tn->ipv6, sizeof(find.ipv6)) == 0) {
                        /* match */
                        ++tn->hitcount;
                        tn->ltime = ctime;
                        if (find.ttl > tn->ttl) tn->ttl = find.ttl;
                        if (tn->hitcount == state->max_hit_count) {
                            cacheNodeClose(md_type_tab, hn, tn, state);
                    } else {
                            hashCacheTick(state, md_type_tab, hn, tn);
                            hashTick(md_type_tab, hn);
                        }
                        found = TRUE;
                        break;
                    }
             }else if (find.caplen == tn->caplen) {
                    if (memcmp(find.rrdata, tn->rrdata, find.caplen) == 0) {
                        /* match */
                        ++tn->hitcount;
                        tn->ltime = ctime;
                        if (find.ttl > tn->ttl) tn->ttl = find.ttl;
                        if (tn->hitcount == state->max_hit_count) {
                            cacheNodeClose(md_type_tab, hn, tn, state);
                    } else {
                            hashCacheTick(state, md_type_tab, hn, tn);
                            hashTick(md_type_tab, hn);
                        }
                        found = TRUE;
                        break;
                    }
             }
         }
    } else {
        hn = g_slice_new0(md_hashtab_node_t);

        /* copy key over */
        /*hn->rrname = g_slice_alloc0(dnsQR->dnsName.len + 1);*/
        hn->rkey = sm_new_hash_key(key.val, key.len);
        /*            if (hn->rrname == NULL) {*/
        if (hn->rkey == NULL) {
            md_dns_dedup_reset(state, ctime);
            hn->rkey = sm_new_hash_key(key.val, key.len);
        }

        if (state->map) {
            hn->mapindex = mapkey;
        } else {
            hn->mapindex = -1;
        }

        /* Insert into hash table */
        smHashTableInsert(md_type_tab->table, (uint8_t*)hn->rkey,
                          (uint8_t*)hn);
        /*g_hash_table_insert(md_type_tab->table, hn->rrname, hn);*/
        ++(md_type_tab->count);
    }
    if (!found) {
        cn = newCacheNode(ctime, &find);
        if (cn == NULL) {
            md_dns_dedup_reset(state, ctime);
            cn = newCacheNode(ctime, &find);
        }
        cn->ttl = find.ttl;
        if (!state->print_lastseen) {
            md_dns_dedup_emit_record(state, &state->cq, hn, cn);
        }
        hashCacheTick(state, md_type_tab, hn, cn);
        if (hn) hashTick(md_type_tab, hn);
    }
    return 0;
}

/**
 * md_dns_dedup_add_flow
 *
 * add the dns node to the appropriate hash table
 * this is the main part of deduplication.
 *
 * @param ctx
 * @param mdflow
 *
 */

void
md_dns_dedup_add_flow(
    mdContext_t *ctx,
    mdExporter_t *exp,
    mdFullFlow_t *flow)
{
    md_dns_dedup_state_t   *state       = exp->dns_dedup;
    md_dns_add_node_ctx_t   dnsCtx;

    dnsCtx.state    = state;
    dnsCtx.ctime    = ctx->cfg->ctime;
    dnsCtx.fullFlow = flow;

    if (fbRecordFindAllSubRecords(flow->fbRec, exp->recvdTids.dnsDPITid, 0,
                                  md_dns_dedup_get_record_callback,
                                  &dnsCtx))
    {
        g_error("Error returned from DNS sub records callback");
    }

    /* attempt a flush on all tables */
    md_dns_dedup_attempt_all_flush(state, ctx->cfg->ctime);
}
