/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_dedup.h
 *
 *  header file for mediator_dedup.c
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

#ifndef _MEDIATOR_DEDUP_H
#define _MEDIATOR_DEDUP_H

#include "templates.h"
#include "mediator_util.h"


typedef struct mdMapKey4_st {
    uint32_t   ip;
    uint32_t   map;
} mdMapKey4_t;

typedef struct mdMapKey6_st {
    uint8_t    ip[16];
    uint32_t   map;
} mdMapKey6_t;

typedef struct md_dedup_tids_st {
    fbTemplate_t           *tmpl;
    uint16_t                intid;
    uint16_t                extid;
    const fbInfoElement_t  *ie;
} md_dedup_tids_t;

typedef struct md_dedup_stats_st {
    uint64_t   recvd;
    uint64_t   flushed;
} md_dedup_stats_t;

typedef struct md_dedup_ssl_node_st {
    uint8_t   *serial;
    size_t     serial_len;
    uint8_t   *issuer;
    size_t     issuer_len;
    uint64_t   count;
} md_dedup_ssl_node_t;

typedef struct md_dedup_ssl_str_node_st md_dedup_ssl_str_node_t;
struct md_dedup_ssl_str_node_st {
    md_dedup_ssl_str_node_t  *next;
    md_dedup_ssl_str_node_t  *prev;
    uint64_t                  ftime;
    uint64_t                  ltime;
    uint64_t                  hitcount;
    uint64_t                  stime;
    uint32_t                  hash;
    md_dedup_ssl_node_t      *cert1;
    md_dedup_ssl_node_t      *cert2;
};

typedef struct md_dedup_ssl_ip_node_st md_dedup_ssl_ip_node_t;
struct md_dedup_ssl_ip_node_st {
    md_dedup_ssl_ip_node_t   *next;
    md_dedup_ssl_ip_node_t   *prev;
    md_dedup_ssl_str_node_t  *head;
    md_dedup_ssl_str_node_t  *tail;
    smFieldMap_t             *map;
    /*    smVarHashKey_t         *sip6_key;*/
    mdMapKey6_t              *sip6_key;
    mdMapKey4_t              *sip_key;
};


typedef struct md_dedup_str_node_st md_dedup_str_node_t;
struct md_dedup_str_node_st {
    md_dedup_str_node_t    *next;
    md_dedup_str_node_t    *prev;
    /* earliest time, in epoch milliseconds */
    uint64_t                ftime;
    /* latest time, in epoch milliseconds */
    uint64_t                ltime;
    uint64_t                hitcount;
    uint64_t                stime;
    uint32_t                hash;
    const fbInfoElement_t  *ie;
    size_t                  caplen;
    uint8_t                *data;
};

typedef struct md_dedup_ip_node_st md_dedup_ip_node_t;
struct md_dedup_ip_node_st {
    md_dedup_ip_node_t   *next;
    md_dedup_ip_node_t   *prev;
    md_dedup_str_node_t  *head;
    md_dedup_str_node_t  *tail;
    smFieldMap_t         *map;
    /*smVarHashKey_t      *sip6_key;*/
    mdMapKey6_t          *sip6_key;
    mdMapKey4_t          *sip_key;
};

typedef struct md_dedup_ie_st md_dedup_ie_t;
struct md_dedup_ie_st {
    md_dedup_ie_t       *next;
    md_dedup_ie_t       *prev;
    md_dedup_ip_node_t  *head;
    md_dedup_ip_node_t  *tail;
    smHashTable_t       *ip_table;
    smHashTable_t       *ip6_table;
    smFieldMap_t        *map;
    FILE                *out_file;
    char                *file_prefix;
    char                *last_file;
    md_dedup_tids_t     *dedup_tids;
    /* most recent output file rotation, in epoch milliseconds */
    uint64_t             last_rotate_ms;
    uint64_t             count;
    /* most recent flush time, in epoch milliseconds */
    uint64_t             last_flush;
    /* 1 for SIP, 0 for DIP */
    int                  sip;
    /* TRUE if this is an ssl table */
    gboolean             ssl;
};

typedef struct md_dedup_node_st md_dedup_node_t;
struct md_dedup_node_st {
    md_dedup_node_t      *next;
    md_dedup_node_t      *prev;
    md_dedup_str_node_t  *strnode;
    md_dedup_ie_t        *ietab;
    md_dedup_general_t    exnode;
};

typedef struct md_dedup_cqueue_st {
    md_dedup_node_t  *head;
    md_dedup_node_t  *tail;
} md_dedup_cqueue_t;

/* typedef struct md_dedup_state_st md_dedup_stats_t; */
struct md_dedup_state_st {
    GHashTable         *ie_table;
    GHashTable         *cert_table;
    md_dedup_cqueue_t  *cq;
    md_dedup_ie_t      *head;
    md_dedup_ie_t      *tail;
    md_dedup_stats_t    stats;
    /* flush timeout, in milliseconds */
    uint64_t            flush_timeout;
    uint32_t            max_hit_count;
    gboolean            add_exporter_name;
    gboolean            merge_truncated;
};

typedef struct md_dedup_cb_ctx_st {
    mdContext_t    *ctx;
    mdExporter_t   *exp;
    mdFullFlow_t   *flow;
    md_dedup_ie_t  *ietab;
    gboolean        reverse;
} md_dedup_cb_ctx_t;

void
md_dedup_flush_alltab(
    mdExporter_t  *exp,
    uint64_t       ctime,
    gboolean       flush_all);

#if 0
gboolean
md_dedup_basic_list(
    mdExporter_t   *exporter,
    fbBasicList_t  *bl,
    GString        *buf,
    GString        *tstr,
    char            delim,
    gboolean        hex,
    gboolean        escape);
#endif  /* 0 */

#if 0
GString *
md_dedup_basic_list_no_count(
    fbBasicList_t  *bl,
    char            delim,
    gboolean        quote,
    gboolean        hex,
    gboolean        escape);
#endif  /* 0 */

gboolean
md_dedup_flush_queue(
    mdExporter_t  *exp,
    mdConfig_t    *cfg,
    GError       **err);

void
md_dedup_configure_state(
    md_dedup_state_t  *state,
    int                max_hit_count,
    int                flush_timeout,
    gboolean           merge_truncated,
    gboolean           exporter_name);

md_dedup_state_t *
md_dedup_new_dedup_state(
    void);

md_dedup_ie_t *
md_dedup_add_ie_table(
    md_dedup_state_t       *state,
    const char             *prefix,
    smFieldMap_t           *map,
    const fbInfoElement_t  *ie,
    int                     dipSipHash);

void
md_dedup_add_ie(
    md_dedup_state_t      *state,
    md_dedup_ie_t         *ie_tab,
    const fbInfoElement_t *ie);

void
md_dedup_lookup_node(
    mdContext_t   *ctx,
    mdExporter_t  *exp,
    mdFullFlow_t  *flow);

gboolean
md_dedup_free_state(
    mdConfig_t    *cfg,
    mdExporter_t  *exp,
    GError       **err);

void
md_dedup_print_stats(
    md_dedup_state_t  *state,
    const char        *exp_name);

gboolean
md_dedup_add_templates(
    md_dedup_state_t  *state,
    fBuf_t            *fbuf,
    GError           **err);

gboolean
md_dedup_write_dedup(
    mdContext_t            *ctx,
    mdExporter_t           *exp,
    md_dedup_general_t     *dedup,
    const fbInfoElement_t  *ie,
    GError                **err);

#endif  /* _MEDIATOR_DEDUP_H */
