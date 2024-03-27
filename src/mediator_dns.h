/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_dns.h
 *
 *  header file for mediator_dns.c
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

#ifndef _MEDIATOR_DNS_H
#define _MEDIATOR_DNS_H

#include "templates.h"
#include "mediator_util.h"

/*
 *  The DNS DEDUP flow record (md_dns_dedup_t) is defined in templates.h.  Its
 *  template (mdDNSDedupTmplSpec) is declared in specs.h and defined in
 *  mediator_specs.c.
 *
 *  typedef struct md_dns_dedup_st md_dns_dedup_t;    // templates.h
 *  extern fbInfoElementSpec_t mdDNSDedupTmplSpec[];  // specs.h
 */


#if 0

typedef struct md_cache_node_st md_cache_node_t;
struct md_cache_node_st {
    md_cache_node_t *next;
    md_cache_node_t *prev;
    /* earliest time, in epoch milliseconds */
    uint64_t      ftime;
    /* latest time, in epoch milliseconds */
    uint64_t      ltime;
    uint32_t      ip;
    uint32_t      ttl;
    uint16_t      rrtype;
    uint16_t      hitcount;
    size_t        caplen;
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

md_dns_dedup_cqueue_t *
md_dns_dedup_new_queue(
    void);

#endif  /* 0 */

md_dns_dedup_state_t *
md_new_dns_dedup_state(
    void);

/* flush_timeout should be specified in seconds */
void
md_dns_dedup_configure_state(
    md_dns_dedup_state_t *state,
    int                  *dedup_list,
    int                   max_hit,
    int                   flush_timeout,
    gboolean              lastseen,
    smFieldMap_t          *map,
    gboolean              exporter_name);

gboolean
md_dns_dedup_get_print_lastseen(
    const md_dns_dedup_state_t *state);

gboolean
md_dns_dedup_get_add_exporter_name(
    const md_dns_dedup_state_t *state);

gboolean
md_dns_dedup_flush_queue(
    mdExporter_t    *exp,
    mdConfig_t      *cfg,
    GError         **err);

gboolean
md_dns_dedup_free_state(
    mdConfig_t       *cfg,
    mdExporter_t     *state,
    GError          **err);

void
md_dns_dedup_print_stats(
    md_dns_dedup_state_t *state,
    const char           *exp_name);

void
md_dns_dedup_add_flow(
    mdContext_t *ctx,
    mdExporter_t *exp,
    mdFullFlow_t *flow);

void
md_dns_dedup_flush_all_tab(
    md_dns_dedup_state_t *state,
    uint64_t           ctime,
    gboolean           flush_all);

#endif  /* _MEDIATOR_DNS_H */
