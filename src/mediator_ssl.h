/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_ssl.h
 *
 *  header file for mediator_ssl.c
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

#ifndef _MEDIATOR_SSL_H
#define _MEDIATOR_SSL_H

#include "templates.h"
#include "mediator_util.h"

#if 0
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
    md_ssl_hashtab_t       *cert_table;
    md_ssl_dedup_stats_t   stats;
    md_ssl_cqueue_t        *cq;
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
    smVarHashKey_t        *serial;
    int                   mapindex;
};

typedef struct md_ssl_add_node_ctx_st {
    md_ssl_dedup_state_t   *state;
    /* current time, in epoch milliseconds */
    uint64_t                ctime;
    mdFullFlow_t           *fullFlow;
    mdExporter_t           *exp;
    mdConfig_t             *cfg;
} md_ssl_add_node_ctx_t;

#endif  /* 0 */

md_ssl_dedup_state_t *
md_ssl_dedup_new_state(
    void);

void
md_ssl_dedup_configure_state(
    md_ssl_dedup_state_t *state,
    int                   max_hit,
    int                   flush_timeout,
    const char            *filename,
    smFieldMap_t          *map,
    gboolean              exporter_name);

gboolean
md_ssl_dedup_flush_queue(
    mdExporter_t   *exp,
    mdConfig_t     *cfg,
    GError        **err);

gboolean
md_ssl_dedup_free_state(
    mdConfig_t     *cfg,
    mdExporter_t   *state,
    GError        **err);

void
md_ssl_dedup_print_stats(
    md_ssl_dedup_state_t *state,
    const char           *exp_name);

void
md_ssl_dedup_flush_tab(
    md_ssl_dedup_state_t   *state,
    uint64_t                cur_time,
    gboolean                flush_all);

gboolean
md_ssl_dedup_add_flow(
    mdContext_t    *ctx,
    mdExporter_t   *exp,
    mdFullFlow_t   *flow);

//yafSSLDPICert_t *md_ssl_cert_decode(
//    uint8_t      *cert,
//    size_t        cert_len,
//    fbTemplate_t  *tmpl);

gboolean
md_ssl_export_ssl_cert(
    mdContext_t *ctx,
    mdExporter_t *exp,
    mdGenericRec_t *mdRec,
    GError **err);

fbTemplate_t *
md_ssl_make_full_cert_template(
    const fbTemplate_t         *srcTmpl,
    GError                    **err);

#ifdef HAVE_OPENSSL
void
smCertDigestCompute(
    const uint8_t      *data,
    size_t              data_len,
    unsigned char      *hash,
    unsigned int       *hash_len_out,
    smCertDigestType_t  method);
#endif  /* HAVE_OPENSSL */

#endif  /* _MEDIATOR_SSL_H */
