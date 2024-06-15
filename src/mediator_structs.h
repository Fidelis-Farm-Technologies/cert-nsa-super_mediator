/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_structs.h
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

#ifndef _MEDIATOR_STRUCTS_H
#define _MEDIATOR_STRUCTS_H


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <libgen.h>
#include <unistd.h>
#include <errno.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <assert.h>
#include <pthread.h>
#include <fixbuf/public.h>
#include "mediator_autohdr.h"
#include "mediator_config.h"
#include "templates.h"

#include <ndpi/ndpi_api.h>

#ifdef HAVE_MYSQL
#include <mysql.h>
#endif
#ifdef ENABLE_SKIPSET
#include SKIPSET_HEADER_NAME
#endif

#define CERT_PEN 6871
#define IS_CERT_IE(entVal)  ((entVal) == CERT_PEN)

#define MAX_LIST 300 /* used for filter val array */
/* 30 sec */
#define MD_RESTART_MS  30 * 1000 /* how long to wait to restart exporters */
#define MD_MSGLEN_STD 0x10000 /* msg len for text exporter buffers */
#define MAX_MAPS 100

#define DEFAULT_POLLING_INTERVAL    30 /* seconds */
#define DEFAULT_ROTATE_DELAY        300 /* seconds */

/* for dedup, how often to flush, in seconds */
#define DEFAULT_FLUSH_TIMEOUT       300

/* for dedup, flush when this number of items are seen */
#define DEFAULT_MAX_HIT_COUNT       5000

/* maximum number of user elements that may be created */
/* FIXME: why is this limited? */
#define MAX_USER_ELEMENTS           50

/* Flush the DNS DEDUP and GENERAL DEDUP close queues every time we process
 * this number of flow (TC_FLOW) records */
#define MD_DEDUP_FLUSH_FLOW_COUNT   50

/* default listening port for collectors */
#define MD_DEFAULT_LISTEN_PORT      "18000"

/* default export port for exporters  */
#define MD_DEFAULT_EXPORT_PORT      "18001"

/* To mark a function parameter as unused in the body of a function. */
#define MD_UNUSED_PARAM(_x)         (void)(_x)

/* ENUMS */

/* possible formats for data export,
 * notably taking json out from under text exporters
 */
typedef enum mdExportFormat_en {
    EF_NONE, /* for error checking, once SM really starts, can't be NONE */
    EF_IPFIX = 1,
    EF_JSON,
    EF_TEXT
} mdExportFormat_t;

#define EXPORTFORMAT_IS_TEXT_OR_JSON(ef) ((ef) > EF_IPFIX)

/* Independent of format, how is the data emitted */
typedef enum mdExportMethod_en {
    EM_NONE, /* for error checking, once SM really starts, can't be NONE */
    EM_SINGLE_FILE = 10, /* invariant isn't single...too bad */
    EM_ROTATING_FILES,
    EM_TCP,
    EM_UDP
} mdExportMethod_t;

#define EXPORTMETHOD_IS_SOCKET(em)  ((em) > EM_ROTATING_FILES)
#define EXPORTMETHOD_IS_FILE(em)    ((em) < EM_TCP)

/* SM only accept IPFIX input, this is the collection method */
typedef enum mdCollectionMethod_en {
    CM_NONE, /* for error checking, once SM really starts, can't be NONE */
    CM_SINGLE_FILE = 20,
    CM_DIR_POLL,
    CM_TCP,
    CM_UDP
} mdCollectionMethod_t;

#define COLLMETHOD_IS_SOCKET(cm) ((cm) > CM_DIR_POLL)
#define COLLMETHOD_IS_FILE(cm)   ((cm) < CM_TCP)

/* used for filtering */
typedef enum fieldOperator_en {
    OPER_UNTOUCHED,
    IN_LIST,
    NOT_IN_LIST,
    EQUAL,
    NOT_EQUAL,
    LESS_THAN,
    LESS_THAN_OR_EQUAL,
    GREATER_THAN,
    GREATER_THAN_OR_EQUAL
} fieldOperator_t;

/* REMOVE: will go away when we have dynamic field filtering like pipeline */
typedef enum mdAcceptFilterField_en {
    SIP_ANY,
    DIP_ANY,
    SIP_V4,
    DIP_V4,
    OBDOMAIN,
    VLAN,
    FLOWKEYHASH
} mdAcceptFilterField_t;

/* used by mediator_log */
typedef enum mdLogLevel_en {
    MD_DEBUG,
    MESSAGE,
    WARNING,
    ERROR,
    QUIET
} mdLogLevel_t;

typedef enum mdUtilTemplateType_en {
    TT_UNKNOWN, /* used for debugging as we should classify everything */
    TT_TOP_FLOW, /* main flow template */
    TT_TOP_OTHER, /* non options top level data...like dedup */
    TT_TOP_OPTIONS, /* top level optiosn record...yaf stats */
    TT_NESTED_DATA, /* DPI template with room for eventual dedup nested */
    TT_NESTED_OPTIONS, /* nested templates used for tombstone */
    TT_NO_TMD_FLOW,
    TT_NO_TMD_DATA,
    TT_NO_TMD_OPTIONS,
    TT_TMD,
    TT_IE_SPEC /* special case as it has no TMD with it, but has nersted also */
} mdUtilTemplateType_t;

/* used to label templates based on their contents in a very detailed way */
typedef enum mdUtilTCGeneral_en {
    TC_UNKNOWN      = 0, /* means not set, no records should be UNKNOWN */
    TC_FLOW,
    TC_YAF_STATS,
    TC_TOMBSTONE,
    TC_DNS_DEDUP, /* start of exporter generated possibilities */
    TC_SSL_DEDUP,
    TC_GENERAL_DEDUP,
    TC_DNS_RR, /* end of exporter generated possibilities */
    TC_TMD_OR_IE,
    TC_DPI,
    TC_UNKNOWN_DATA,
    TC_UNKNOWN_OPTIONS,
    TC_NUM_TYPES            /* to allow for loops over types and to get size */
} mdUtilTCGeneral_t;

/* TC Spec based on which TC General.
 * Some have to be set, and some are extras */

/* A general way to set the field to 0 */
typedef enum mdUtilTCSpecNotSet_en {
    TC_SPEC_NOT_SET
} mdUtilTCSpecNotSet_t;

/* create combinations, but can still use bit masking to check for either */

typedef enum mdUtilTCSpecFlow_en {
    TC_FLOW_DEFAULT             = 0, /* NO REV, NO LISTS */
    TC_FLOW_REV                 = 0x01,
    TC_FLOW_HAS_LISTS           = 0x02,
    TC_FLOW_REV_AND_HAS_LISTS   = 0x03, /* REV + LISTS */
} mdUtilTCSpecFlow_t;

typedef enum mdUtilTCSpecDNSDedup_en {
    TC_DNS_DEDUP_NOT_SET        = 0,
    TC_DNS_DEDUP_AREC           = 0x01,
    TC_DNS_DEDUP_OREC           = 0x02,
    TC_DNS_DEDUP_AAAAREC        = 0x04,
    /* LS (lastseen) values should never be seen directly; they are OR'ed with
     * the *_AREC and *_OREC bits */
    /* LS_V1 uses dnsHitCount for all SM-1.x versions */
    TC_DNS_DEDUP_LS_V1          = 0x08,
    TC_DNS_DEDUP_LS_AREC_V1,
    TC_DNS_DEDUP_LS_OREC_V1,
    TC_DNS_DEDUP_LS_AAAAREC_V1  = 0x08 | 0x04,
    /* LS_V2 uses smDedupHitCount, starting from SM-2.0 */
    TC_DNS_DEDUP_LS_V2          = 0x010,
    TC_DNS_DEDUP_LS_AREC_V2,
    TC_DNS_DEDUP_LS_OREC_V2,
    TC_DNS_DEDUP_LS_AAAAREC_V2 = 0x010 | 0x04,
} mdUtilTCSpecDNSDedup_t;

typedef enum mdUtilTCSpecDNSRR_en {
    TC_DNS_RR_NOT_SET           = 0,
    TC_DNS_RR_FULL_4,
    TC_DNS_RR_FULL_6
} mdUtilTCSpecDNSRR_t;

typedef enum mdUtilTCSpecYafStats_en {
    TC_YAF_STATS_NOT_SET        = 0,
    TC_YAF_STATS_V1,
    TC_YAF_STATS_V2,
    /* matches mdEmSpecYafStatsV2 exactly but has a scope count of 2. These
     * are exported by super_mediator-1.x. */
    TC_YAF_STATS_V2_SCOPE2
} mdUtilTCSpecYafStats_t;

typedef enum mdUtilTCSpecTombstone_en {
    TC_TOMBSTONE_NOT_SET        = 0,
    TC_TOMBSTONE_V1,
    TC_TOMBSTONE_V2,
    TC_TOMBSTONE_ACCESS_V1,
    TC_TOMBSTONE_ACCESS_V2
} mdUtilTCSpecTombstone_t;

typedef enum mdUtilTCSpecDPI_en {
    TC_APP_UNKNOWN              = 0,
    TC_APP_DPI_DNS,
    TC_APP_DPI_SSL_L1,
    TC_APP_DPI_SSL_L1_CERT_LIST,
    TC_APP_DPI_SSL_L2,
    TC_APP_DPI_SSL_L3,
    TC_APP_DPI_SSL_RW_L2,
    TC_APP_DPI_TCP_REV,
    TC_APP_DPI_TCP_FWD
} mdUtilTCSpecDPI_t;

typedef enum mdUtilTCYafVersion_en {
    TC_YAF_ALL_VERSIONS,
    TC_YAF_VERSION_2    = 2,
    TC_YAF_VERSION_3    = 3
} mdUtilTCYafVersion_t;

typedef enum mdUtilTCRelative_en {
    TC_EXACT_DEF,
    TC_SUB              = FB_TMPL_SETCMP_SUBSET,
    TC_EXACT            = FB_TMPL_SETCMP_EQUAL,
    TC_SUPER            = FB_TMPL_SETCMP_SUPERSET,
    TC_MIX              = FB_TMPL_SETCMP_COMMON
} mdUtilTCRelative_t;

typedef union mdUtilTCSpecCase_un {
    mdUtilTCSpecNotSet_t    notSet;
    mdUtilTCSpecFlow_t      flow;
    mdUtilTCSpecDNSDedup_t  dnsDedup;
    mdUtilTCSpecDNSRR_t     dnsRR;
    mdUtilTCSpecYafStats_t  yafStats;
    mdUtilTCSpecTombstone_t tombstone;
    mdUtilTCSpecDPI_t       dpi;
} mdUtilTCSpecCase_t;

typedef struct mdUtilTemplateContents_st {
    mdUtilTCGeneral_t       general;
    /* different part of union based on general */
    mdUtilTCSpecCase_t      specCase;
    mdUtilTCRelative_t      relative;
    mdUtilTCYafVersion_t    yafVersion;
} mdUtilTemplateContents_t;

#define MD_TC_INIT                                                      \
    { TC_UNKNOWN, { TC_SPEC_NOT_SET }, TC_EXACT_DEF, TC_YAF_ALL_VERSIONS }



/* Format of template contents:
 * 0x000YGGSR though not every bit is used */
/*#define TC_UNKNOWN              0*/ /* generally used to mean "not set" */
/*#define TC_FLOW                 0x0100
    #define TC_FLOW_REV             0x0010
    #define TC_FLOW_HAS_LISTS       0x0020 */ /* DPI or other nested items */
                                            /* if not set, no dedup */
/*#define TC_DPI                  0x0200
#define TC_DNS_DEDUP            0x0300
    #define TC_DNS_DEDUP_AREC       0x0010
    #define TC_DNS_DEDUP_OREC       0x0020
    #define TC_DNS_DEDUP_LS_V1      0x0040
    #define TC_DNS_DEDUP_LS_V2      0x0080
#define TC_SSL_DEDUP            0x0400
#define TC_GENERAL_DEDUP        0x0500
#define TC_DNS_RR               0x0600
    #define TC_DNS_RR_FULL_4        0x0010
    #define TC_DNS_RR_FULL_6        0x0020
#define TC_YAF_STATS            0x0700
    #define TC_YAF_STATS_V1         0x0010
    #define TC_YAF_STATS_V2         0x0020
    #define TC_YAF_STATS_V2_SCOPE2  0x0030
#define TC_TOMBSTONE            0x0800
    #define TC_TOMBSTONE_V1         0x0010
    #define TC_TOMBSTONE_V2         0x0020
#define TC_TMD_OR_IE            0x0900
#define TC_UNKNOWN_DATA         0x0A00
#define TC_UNKNOWN_OPTIONS      0x0B00
#define TC_NUM_TYPES            0x0C00

#define TC_GENERAL_FLAG         0xFF00
#define TC_SPEC_CASE_FLAG       0x00F0
#define TC_RELATIVE_FLAG        0x0007
#define TC_YAF_VERSION_FLAG     0xF0000 */

#define TC_EXACT_DEF            0x0000 /* didn't check, allow unset */
/*#define TC_SUB                  FB_TMPL_SETCMP_SUBSET
#define TC_EXACT                FB_TMPL_SETCMP_EQUAL
#define TC_SUPER                FB_TMPL_SETCMP_SUPERSET
#define TC_MIX                  FB_TMPL_SETCMP_COMMON *//* 4 */

/* These are DPI specifications that can be under TC_DPI or TC_UNKNOWN_DATA */
/*#define TC_APP_DPI_DNS              0x0010 main DNS "CF00" template
#define TC_APP_DPI_SSL_L1           0x0020
#define TC_APP_DPI_SSL_L1_CERT_LIST 0x0030
#define TC_APP_DPI_SSL_L2           0x0040
#define TC_APP_DPI_SSL_L3           0x0050
#define TC_APP_DPI_SSL_RW_L2        0x0060

#define TC_YAF_ALL_VERSIONS         0x00000
#define TC_YAF_VERSION_2            0x20000
#define TC_YAF_VERSION_3            0x30000 */

/*#define TC_GEN_TO_INT(__gen__)                                              \
    (__gen__ >> 8)           */


/* helpers to isolate certain pieces of the template contents */
/*#define TC_GET_GENERAL(_tc_)                                                \
    (_tc_ & TC_GENERAL_FLAG)

#define TC_GET_SPEC_CASE(_tc_)                                              \
    (_tc_ & TC_SPEC_CASE_FLAG)

#define TC_GET_RELATIVE(_tc_)                                               \
    (_tc_ & TC_RELATIVE_FLAG)

#define TC_GET_YAF_VERSION(_tc_)                                            \
    (_tc_ & TC_YAF_VERSION_FLAG)*/


/* a super set of the fields in YAF_STATS_V2 would be:
 * TC_YAF_STATS + TC_YAF_STATS_V2 + TC_SUPER = 0x721
 *
 * An exact match to DNS_DEDUP AREC with LAST_SEEN:
 * TC_DNS_DEDUP + TC_DNS_DEDUP_AREC + TC_DNS_DEDUP_LS_V1 + TC_EXACT = 0x0360
 */


typedef enum mdTmplCtxType_en {
    TCTX_TYPE_UNKNOWN,
    TCTX_TYPE_DEFAULT,
    TCTX_TYPE_COL_FLOW,
    TCTX_TYPE_GENERAL_DEDUP,
    TCTX_TYPE_EXPORTER,
    TCTX_TYPE_TOMBSTONE,
    TCTX_TYPE_YAF_STATS
} mdTmplCtxType_t;

/**
 *  The types of certificate digests that may be requested.
 *
 *  The prefix begins with "SM" to avoid confusion with OpenSSL's use of "MD"
 *  in many of its digest functions.
 */
typedef enum smCertDigestType_en {
    SM_DIGEST_MD5,
    SM_DIGEST_SHA1,
//    SM_DIGEST_SHA256,
    SM_DIGEST_NUM_TYPES
} smCertDigestType_t;


/* END OF ENUMS */

/* STRUCTS and TYPEDEFS */

typedef struct mdConfig_st mdConfig_t;
typedef struct mdCollector_st mdCollector_t;
typedef struct mdExporter_st mdExporter_t;
typedef struct mdDLL_st mdDLL_t;
typedef struct mdSLL_st mdSLL_t;
typedef struct smFieldMap_st smFieldMap_t;
typedef struct md_dns_dedup_state_st md_dns_dedup_state_t;
typedef struct md_dedup_state_st md_dedup_state_t;
typedef struct md_ssl_dedup_state_st md_ssl_dedup_state_t;
typedef struct mdFilter_st mdFilter_t;
typedef struct mdFullFlow_st mdFullFlow_t;
typedef struct mdFieldEntry_st mdFieldEntry_t;
#ifdef ENABLE_SKIPSET
/* from mediator_utils.h */
typedef struct mdIPSet_st mdIPSet_t;
#endif

/*  SMALL HELPER FUNCTIONAL STRUCTS */

struct mdDLL_st {
    mdDLL_t *next;
    mdDLL_t *prev;
};


struct mdSLL_st {
    mdSLL_t *next;
};

typedef struct smHashTable_st {
    size_t     len;
    GHashTable *table;
} smHashTable_t;

/* FIXME: Change this to an array instead of single linked list */
struct smFieldMap_st {
    smFieldMap_t            *next;
    mdAcceptFilterField_t   field;
    smHashTable_t           *table;
    char                    *name;
    char                   **labels;
    size_t                  count;
    gboolean                discard;
};

typedef struct smFieldMapKV_st {
    uint32_t              val;
} smFieldMapKV_t;


typedef struct mdBuf_st {
    char   *cp;
    char   *buf;
    size_t buflen;
} mdBuf_t;

typedef int
(*mdDerivedFind_fn)(
    mdFullFlow_t               *flow,
    mdFieldEntry_t             *field,
    unsigned int                flags,
    fbRecordValueCallback_fn    callback,
    void                       *ctx);

struct mdFieldEntry_st {
    mdFieldEntry_t   *next;
    const fbInfoElement_t  *elem;
    gboolean          isDerived;
    gboolean          onlyFetchOne;
    mdDerivedFind_fn  findDerived;
    // Details about where this element might be
};

typedef struct mdFilterEntry_st mdFilterEntry_t;

struct mdFilterEntry_st {
    /* Filters are stored as a linked list; this is the next one */
    mdFilterEntry_t *next;
    /* The comparison operator: ==, !=, IN_LIST, ... */
    fieldOperator_t  oper;
    /* TRUE when is this is a test to match the collector name */
    gboolean         isCollectorComp;
    /* An array of fbRecordValue_t; has 1 element unless oper is NOT_/IN_LIST.
     * The first entry holds the IE to match (when not isCollectorComp) and
     * the value to compare against.  Additional array elements hold the
     * additional values for NOT_/IN_LIST. */
    GArray          *compValList;
#ifdef ENABLE_SKIPSET
    mdIPSet_t       *ipset;
#endif
};

struct mdFilter_st {
    gboolean          andFilter;
    mdFilterEntry_t  *firstFilterEntry;
};

/* TEMPLATE CONTEXT STRUCTS */
/* this is the base of every template context. They are all to be created
 * here. These are the first N elements. It will be safe to cast all template
 * context pointers to this struct to access the first N fields */

typedef struct mdDefaultTmplCtx_st {
    mdUtilTemplateType_t        templateType;
    mdUtilTemplateContents_t    templateContents;
    /* if this is an internal template, what is the external */
    uint16_t                    associatedExtTid;
    /* if this is an external template, what is the associated internal one */
    uint16_t                    associatedIntTid;
    mdTmplCtxType_t             contextType;
    uint16_t                    cTimeOffset;
    const fbTemplateField_t    *dataCTimeIE;
    const fbTemplateField_t    *sourceRuntimeCTimeIE;
    uint16_t                   *blOffsets;
    uint16_t                    blCount;
    uint16_t                   *stlOffsets;
    uint16_t                    stlCount;
    uint16_t                   *stmlOffsets;
    uint16_t                    stmlCount;
} mdDefaultTmplCtx_t;

typedef struct mdCollIntFlowTmplCtx_st {
    mdDefaultTmplCtx_t  defCtx;
    /* store offsets when fields may not be there, or IPv6
     * use TemplateFields when fields are verifiably guaranteed */
    /* for writing */
    uint16_t                observationDomainOffset;
    uint16_t                flowKeyHashOffset;
    uint16_t                smIPSetMatchesSourceOffset;
    uint16_t                smIPSetMatchesDestinationOffset;
    /* for reading */
    uint16_t                sipV6Offset;
    uint16_t                dipV6Offset;
    uint16_t                appLabelOffset;
    uint16_t                dpiListOffset;
    gboolean                v4;
    gboolean                preserve_obdomain;
    const fbTemplateField_t    *flowStartMS;
    const fbTemplateField_t    *sip4;
    const fbTemplateField_t    *dip4;
    const fbTemplateField_t    *sport;
    const fbTemplateField_t    *dport;
    const fbTemplateField_t    *vlanId;
    const fbTemplateField_t    *protocol;
    const fbTemplateField_t    *flowEndReason;

    /* This is non-NULL when flowDpiStrip is TRUE and the incoming record is a
     * YAF2 record where the TCP fields are in the STML.  This specifies the
     * location where the TCP values from the STML should be copied. */
    const fbTemplateField_t    *tcpSequenceNumber;
} mdCollIntFlowTmplCtx_t;

typedef struct mdGeneralDedupTmplCtx_st {
    mdDefaultTmplCtx_t      defCtx;
    uint32_t                    ieEnt;
    uint16_t                    ieNum;
    size_t                      numElem;
} mdGeneralDedupTmplCtx_t;

typedef struct mdExpFlowTmplCtx_st {
    mdDefaultTmplCtx_t      defCtx;
//    uint16_t                    sslTopDPITID;
//    uint16_t                    sslRewriteTID;
//    uint16_t                    addedTcpOffset;
//    uint8_t                     ignore;
} mdExpFlowTmplCtx_t;

typedef struct mdTombstoneTmplCtx_st {
    mdDefaultTmplCtx_t      defCtx;
    uint16_t                accessListOffset;
} mdTombstoneTmplCtx_t;

typedef struct mdYafStatsTmplCtx_st {
    mdDefaultTmplCtx_t      defCtx;
} mdYafStatsTmplCtx_t;

/* END OF TEMPLATE CONTEXT STRUCTS */

/*
typedef struct md_main_template_st {
    uint64_t    flowStartMilliseconds;
    uint64_t    flowEndMilliseconds;
    uint64_t    octetTotalCount;
    uint64_t    reverseOctetTotalCount;
    uint64_t    octetDeltaCount;
    uint64_t    reverseOctetDeltaCount;
    uint64_t    packetTotalCount;
    uint64_t    reversePacketTotalCount;
    uint64_t    packetDeltaCount;
    uint64_t    reversePacketDeltaCount;

    uint8_t     sourceIPv6Address[16];
    uint8_t     destinationIPv6Address[16];

    uint32_t    sourceIPv4Address;
    uint32_t    destinationIPv4Address;

    uint16_t    sourceTransportPort;
    uint16_t    destinationTransportPort;
    uint16_t    flowAttributes;
    uint16_t    reverseFlowAttributes;

    uint8_t     protocolIdentifier;
    uint8_t     flowEndReason;
    uint16_t    silkAppLabel;
    int32_t     reverseFlowDeltaMilliseconds;

    uint32_t    tcpSequenceNumber;
    uint32_t    reverseTcpSequenceNumber;

    uint8_t     initialTCPFlags;
    uint8_t     unionTCPFlags;
    uint8_t     reverseInitialTCPFlags;
    uint8_t     reverseUnionTCPFlags;
    uint16_t    vlanId;
    uint16_t    reverseVlanId;

    uint32_t    ingressInterface;
    uint32_t    egressInterface;

    uint8_t     ipClassOfService;
    uint8_t     reverseIpClassOfService;
    uint8_t     mplsTopLabelStackSection[3];
    uint8_t     mplsLabelStackSection2[3];

    uint8_t     mplsLabelStackSection3[3];
    uint8_t     paddingOctets;
    uint32_t    observationDomainId;

    uint32_t    yafFlowKeyHash;
    uint16_t    ndpiL7Protocol;
    uint16_t    ndpiL7SubProtocol;

    fbSubTemplateMultiList_t subTemplateMultiList;

} md_main_template_t;
*/

typedef struct mdGenericRec_st {
    const fbRecord_t               *fbRec;
    const mdDefaultTmplCtx_t       *extTmplCtx;
    const mdDefaultTmplCtx_t       *intTmplCtx;
    uint16_t                        extTid;
    uint16_t                        intTid;
    const fbTemplate_t             *intTmpl;
    const fbTemplate_t             *extTmpl;
    mdCollector_t                  *collector;
    gboolean                        generated;
} __attribute__ ((__may_alias__)) mdGenericRec_t;

struct mdFullFlow_st {
    /* Keep the initial fields in sync with mdGenericRec_t */
    const fbRecord_t               *fbRec;
    const mdCollIntFlowTmplCtx_t   *extTmplCtx;
    const mdCollIntFlowTmplCtx_t   *intTmplCtx;
    uint16_t                        extTid;
    uint16_t                        intTid;
    const fbTemplate_t             *intTmpl;
    const fbTemplate_t             *extTmpl;
    mdCollector_t                  *collector;
    gboolean                        generated;
    /* Keep the above fields in sync with mdGenericRec_t */

    /* fields used explicitly by SM for flow processing */
    uint8_t    *dpiListPtr;
    uint8_t    *sourceIPv6Address;
    uint8_t    *destinationIPv6Address;
    uint16_t    silkAppLabel;
    uint32_t   *observationDomain;
    uint64_t    flowStartMilliseconds;
    uint32_t    sourceIPv4Address;
    uint32_t    destinationIPv4Address;
    uint32_t   *flowKeyHash;
    uint8_t    *smIPSetMatchesSource;
    uint8_t    *smIPSetMatchesDestination;
    uint16_t    sourceTransportPort;
    uint16_t    destinationTransportPort;
    uint16_t    vlanId;
    uint8_t     protocolIdentifier;
    uint8_t     flowEndReason;
//    gboolean    rev;
    gboolean    ipv4;
//
//    void       *ventropy;
//    void       *vmac;
//    void       *vpay;
//    void       *vp0f;
//    void       *vstats;
//    void       *vmptcp;
//    void       *vfullcert;
//    void      **vsslcerts;
//    void       *vfp;
    yfSSLFullCert_t     *fullcert;
//    yafSSLDPICert_t  **sslcerts;
//    fbSubTemplateMultiListEntry_t  *cert;
};





/* EXPORTER STRUCTS */

typedef struct mdMySQLInfo_st {
    char     *user;
    char     *password;
    char     *db_name;
    char     *db_host;
    char     *table;
#ifdef HAVE_MYSQL
    MYSQL    *conn;
#endif
} mdMySQLInfo_t;


typedef enum mdSSLConfigType_en {
    MD_SSLCONFIG_ISSUER     = 1,
    MD_SSLCONFIG_SUBJECT    = 2,
    MD_SSLCONFIG_OTHER      = 3,
    MD_SSLCONFIG_EXTENSIONS = 4
} mdSSLConfigType_t;

/* maximum value in the previous enum */
#define MD_SSLCONFIG_TYPE_MAX  4

/**
 *  the maximum value each SSL_CONFIG type supports
 *
 *  mediator_export.c defines MEDIATOR_EXPORT_SOURCE to defined the variable
 */
extern unsigned int mdSSLConfigArraySize[1 + MD_SSLCONFIG_TYPE_MAX];
#ifdef MEDIATOR_EXPORT_SOURCE
/* for extensions, yaf only exports id-ce 14-37 */
unsigned int mdSSLConfigArraySize[1 + MD_SSLCONFIG_TYPE_MAX] = {
    0, 256, 256, 300, 50
};
#endif

typedef struct mdSSLConfig_st {
    uint8_t  *enabled[1 + MD_SSLCONFIG_TYPE_MAX];
} mdSSLConfig_t;


typedef gboolean
(*mdBLPrint_fn)(
    mdExporter_t *,
    fbBasicList_t *,
    char *,
    size_t,
    char *,
    gboolean);
typedef gboolean
(*mdVLPrint_fn)(
    mdExporter_t *,
    const uint8_t *,
    const char *,
    const char *,
    size_t,
    uint16_t,
    size_t,
    gboolean);

/*typedef void (*exporterTemplateCallback_fn)(
                                mdExporter_t               *exporter,
                                fbSession_t                *incomingSession,
                                uint16_t                    tid,
                                fbTemplate_t               *tmpl,
                                const fbTemplateInfo_t     *mdInfo,
                                mdCollector_t              *collector,
                                mdUtilTemplateType_t        templateType,
                                mdUtilTemplateContents_t    templateContents);
* just in case we need this later */

typedef struct mdFlowExporterCollectorInfo_st {
    uint8_t             id;
    fbTemplate_t       *expIntTmplByColIntTid[UINT16_MAX];
    uint16_t            expIntTidByColIntTid[UINT16_MAX];
/*    uint8_t             ignoreByColIntTid[UINT16_MAX];*/
} mdFlowExporterCollectorInfo_t;

// FIXME: We know these are template IDs, could we remove Tid from the member
// name?
typedef struct mdKnownTemplates_st {
    uint16_t                    tombstoneV1MainTid;
    uint16_t                    tombstoneV1AccessTid;
    uint16_t                    tombstoneV2MainTid;
    uint16_t                    tombstoneV2AccessTid;
    uint16_t                    yafStatsTid;
    uint16_t                    tcpRevSubrecTid;
    uint16_t                    tcpFwdSubrecTid;
    uint16_t                    dnsDPITid;
    uint16_t                    dnsDedupArecExtTid;
    uint16_t                    dnsDedupAAAArecExtTid;
    uint16_t                    dnsDedupOrecExtTid;
    uint16_t                    dnsDedupArecLSExtTid;
    uint16_t                    dnsDedupAAAArecLSExtTid;
    uint16_t                    dnsDedupOrecLSExtTid;
    uint16_t                    sslLevel1Tid;
    uint16_t                    sslLevel2Tid;
    uint16_t                    sslLevel3Tid;
    uint16_t                    sslDedupTid;
    uint16_t                    fullCertFromSSLDedupTid;
    uint16_t                    fullCertSubFromSSLDedupTid;
    uint16_t                    dnsRRExtTid;
    uint16_t                    dnsRR4FullExtTid;
    uint16_t                    dnsRR6FullExtTid;
    uint16_t                    flattenedSSLTid;
} mdKnownTemplates_t;

typedef struct invariants_st {
    uint32_t    observationDomain;
    uint16_t    vlanId;
    uint16_t    year;
    uint16_t    silkAppLabel;
    /* following 3 are larger than needed to make the size 16 octets */
    uint16_t    month;
    uint16_t    day;
    uint16_t    hour;
} invariants_t;

typedef struct mdFileWriter_st mdFileWriter_t;

struct mdFileWriter_st {
    mdFileWriter_t *next; /* for linked list */
    mdFileWriter_t *prev; /* for linked list */
    fbSession_t    *session;
    fbExporter_t   *fbExporter;
    fBuf_t         *fbuf;
    FILE           *lfp;
    char           *outspec;
    char           *currentFname;
    char           *mvPath;
    uint8_t        *key; /* copy...do not free */
    uint64_t        bytesWrittenSinceLastRotate;
    /* epoch millisecond time of most recent rotatation */
    uint64_t        lastRotate;
    mdExporter_t   *exporter;
};

typedef struct mdExporterInvariantState_st {
    GHashTable     *fileWritersTable;
    mdFileWriter_t *head;
    mdFileWriter_t *tail;
    long            maxFPs;
    uint16_t        currentFPs;
    uint64_t        minFileSize;
    uint64_t        maxFileSize;
    uint64_t        minTimeMillisec;
    uint64_t        maxTimeMillisec;
} mdExporterInvariantState_t;

typedef struct mdColStats_st {
    /* number of files opened by this collector
     * incremented in mdCollectorFileNext */
    uint32_t    filesRead;
    /* number of bytes read from this collector
     * updated in mdCollectFBuf after fBufNextRecord()
     * Can't access full bytes read, only top level at this point */
/*    uint64_t    bytesRead;*/
    /* number of times this collector restarted
     * incremented in mdCollectorRestartListener */
    uint16_t    restarts;
    /* total records read by this collector
     * calculated in mdStatGetCollectorSummary, rather than every record++ */
    uint64_t    totalRecordsRead; /* filled by summary */
    /* number of records read of each type.
     * incremented in mdCollectFBuf after reading the record */
    uint64_t    recordsReadByType[TC_NUM_TYPES];
    /* number of records filtered out of each type (only flows for now)
     * incremented in mdCollectFBuf after running collector filter */
    uint64_t    recordsFilteredOutByType[TC_NUM_TYPES];
} mdColStats_t;

typedef struct mdCoreStats_st {
    /* TBD if needed */
    uint64_t    uniflows;
    /* total number of bytes processed by core
     * updated in each mdProcess* function based on genRec->fbRec->recsize */
    /* this isn't right as it doesn't include DPI bytes */
    /*    uint64_t    bytesProcessed;*/
    /* total number of records of each type processed by core
     * incremented in mdProcess* for each type */
    uint64_t    recordsProcessedByType[TC_NUM_TYPES];
    /* number of tombstone records generated by this super mediator
     * this is different than tombstone records received and processed from YAF
     * incremented in mdSendTombstoneRecord */
    uint64_t    tombstoneRecordsGenerated;
    /* number of flows of each app label processed by core
     * incremented in mdProcessFlow */
    uint64_t    flowsByAppLabel[UINT16_MAX];                /* cr|e|o */
} mdCoreStats_t;

typedef struct mdExpStats_st {
    /* number of files written by this exporter (currently not including
     * invariants
     * updated in mdOpenTextOutput or mdIpfixOutputOpen */
    uint32_t    filesWritten;
    /* total number of bytes written by this exporter
     * accurate for ipfix expoters, not text or json,
     * updated in ExporterWrite* */
    uint64_t    bytesWritten;
    /* number of time this exporter restarts, typically for sockets
     * incremented in mdExporterRestart */
    uint16_t    restarts;
    /* total number of records written by this exporter
     * calculated in mdStatGetExporterSummary, rather than every record */
    uint64_t    totalRecordsWritten;
    /* records of each type ignored/dropped by user specification
     * incremented in mdExporterWrite* if exporter->*Allowed is false */
    uint64_t    recordsIgnoredByType[TC_NUM_TYPES];
    /* records of each type filtered out by exporter
     * incremented in mdProcess* if filter fails */
    uint64_t    recordsFilteredOutByType[TC_NUM_TYPES];
    /* records generated of each type
     * incremented in the various dedup or dnsRR code */
    uint64_t    recordsGeneratedByType[TC_NUM_TYPES];
    /* records processed and forwarded by this exporter by type
     * incremented in mdExporterWrite* */
    uint64_t    recordsForwardedByType[TC_NUM_TYPES];
    /* record count of flows by app label
     * incremented in mdExporterWriteFlow() */
    uint64_t    flowsByAppLabel[UINT16_MAX];
} mdExpStats_t;

struct mdExporter_st {
    mdExporter_t       *next;
    mdConfig_t         *cfg;            /* copy of global config pointer */
    mdExpStats_t        expStats;       /* stats for this exporter */
    mdFilter_t            *filter;
    md_dns_dedup_state_t   *dns_dedup;  /* means doing DNS DEDUP */
    md_dedup_state_t       *dedup;      /* means doing GENERAL DEDUP */
    md_ssl_dedup_state_t   *ssl_dedup;  /* means doing SSL DEDUP */
    mdExportFormat_t            exportFormat;
    mdExportMethod_t            exportMethod;
    fbInfoModel_t              *infoModel;
    /* Use for processing, allowing the switching out of writers */
    mdFileWriter_t             *activeWriter;
    /* default writer. used with no invariant, and non-flows with invariant */
    mdFileWriter_t             *defaultWriter;
    mdMySQLInfo_t              *mysql;
    mdFieldEntry_t    *customFieldList;
    mdSSLConfig_t     *ssl_config;
    GHashTable        *dpi_field_table;
    const char        *name;
    GString           *buf;
    // FIXME: Value is never referenced
    //    mdBLPrint_fn      BLprint_fn;
    mdVLPrint_fn      VLprint_fn;
    fbConnSpec_t      spec;
    /* how often to rotate output files, in milliseconds */
    uint64_t          rotateInterval;
    /* last restart time, in epoch milliseconds */
    uint64_t          last_restart_ms;
    // FIXME: Value is never referenced
    //    uint64_t          lastUdpTempTime;

    // FIXME: Value is set and never read
    //    uint64_t          time_started;
    char                        delimiter;
    char                        dpi_delimiter;
    uint8_t                     id;
    gboolean                    lock;
    gboolean                    gzip;
    gboolean                    custom_list_dpi;
    gboolean                    basic_list_dpi;
    gboolean                    print_header;
    gboolean                    remove_empty;
    gboolean                    multi_files;
    gboolean                    no_index;
    gboolean                    timestamp_files;
    gboolean          escape_chars;
    gboolean          remove_uploaded;
    gboolean          active;
    gboolean          json;
    gboolean          dns_resp_only;
    // FIXME: Value is set and never read
    //    gboolean          dedup_per_flow;

    gboolean          hash_md5;
    gboolean          hash_sha1;

    /** Whether to export Template metadata */
    gboolean          metadataExportTemplates;
    /** Whether to export RFC5610 IE metadata */
    gboolean          metadataExportElements;
    uint16_t                    largestRecTemplateSize;
    mdFlowExporterCollectorInfo_t   collInfoById[UINT8_MAX];

    /* store TIDs of templates of records we can generate
     * so if we have to forward them, they use the same templates */
    uint8_t                     yafVersion;
    uint16_t                    rwSSLLevel2STLOffset;
    uint16_t                    dnsDedupIntTid;
    uint16_t                    dnsRRIntTid;
    mdKnownTemplates_t          recvdTids;
    mdKnownTemplates_t          genTids;
    gboolean                    dnsRRFull;

    /*
     * For record types that SM can create (dns-dedup, ssl-dedup, etc) there
     * is a 'allow<type>' member and a 'generate<type>' member.
     *
     * allow<type> is TRUE if an Exporter should pass-through any incoming
     * records.  generate<type> is TRUE when the Exporter should generate the
     * record itself.  By default, allow* is TRUE and generate* is FALSE.
     *
     * A <TYPE> keyword in the config file sets generate<type> to TRUE.  A
     * <TYPE>_ONLY keyword also sets all other allow* values to FALSE.
     */

    gboolean                    allowDnsDedup;
    gboolean                    generateDnsDedup;
    gboolean                    allowDnsRR;
    gboolean                    generateDnsRR;
    gboolean                    allowSslDedup;
    gboolean                    generateSslDedup;
    gboolean                    allowGeneralDedup;
    gboolean                    generateGeneralDedup;

    /* These either pass through (are allowed) or not; all TRUE by default. */

    gboolean                    allowFlow;
    gboolean                    allowTombstone;
    gboolean                    allowYafStats;
    gboolean                    allowSslCert;

    /* For standard flow records, SM can either require the record have DPI or
     * strip the DPI.  Both are FALSE by default. */

    gboolean                    flowDpiRequired;
    gboolean                    flowDpiStrip;

    gboolean                    flattenSSLCerts;
    // FIXME: Value is never referenced
    //    gboolean                    usedDNSDedupConfig;
    // FIXME: Value is set and never read
    //    gboolean                    usedSSLDedupConfig;
    gboolean                    usedGeneralDedupConfig;
    gboolean                    statsAddedToFlowOnlyOrDPIOnly;
    // FIXME: Value is set and never read
    //    gboolean                    unknownRecordsAllowed;
    gboolean                    flowStatsAllowedInTextExporters;

    gboolean                    invariant;
    mdExporterInvariantState_t  invState;
    //
    // nDPI struct for printing ndpiL7Protocol & ndpiL7SubProtocol
    struct ndpi_detection_module_struct * ndpiStruct;
};

/* END OF EXPORTER STRUCTS */

struct mdCollector_st {
    mdCollector_t      *next;
    mdConfig_t         *cfg;            /* copy of global config ptr */
    const char         *name;
    mdColStats_t        colStats;       /* stats for this collector */
    uint8_t             id;
    GError             *err;
    /* directly set from config file */
    mdCollectionMethod_t collectionMethod;
    char               *inspec;
    char               *move_dir;
    char               *decompressWorkingDirectory;
    uint16_t            pollingInterval; /* seconds */
    gboolean            noLockedFiles;
    gboolean            delete_files;

    /* set because of config file */
    mdFilter_t        *filter;
    fbConnSpec_t        connspec;

    /* used in processing */
    /* fixbuf structures */
    fBuf_t             *fbuf;
    fbCollector_t      *collector;
    fbListener_t       *listener;
    fbSession_t        *listenerSession;
    FILE               *lfp;
    fbSession_t        *session;
    uint32_t            domain;

    /* other processing variables */
    pthread_cond_t      cond;
    pthread_mutex_t     mutex;
    GString            *fname_in;
    GString            *fname_lock;
    pthread_t           thread;
    gboolean            active;
    gboolean            data;
    gboolean            restart;
    gboolean            std_in;
    /* buffer used to hold records. Size is set to the largest template that
     * was received */
    uint8_t            *recBuf;
    uint16_t            largestRecTemplateSize;
    /* ctime related information */
    gboolean            hasTimestampField;
    gboolean            hasDataTimestampField;
    gboolean            hasSourceRuntimeTimestampField;
/* known templates to expect TODO - clean up - recvdTids */
    uint8_t             yafVersion;
//    uint16_t            yafStatsTid;
//    uint16_t            tombstoneMainTid;
    /* When GEN_TOMBSTONE is active, define the tombstone access STL internal
     * template on the collector to read any incoming tombstone records.  It
     * is easier to set the TIDs on the STL at that time and pass them to the
     * Exporters than to have the Exporters map the incoming TIDs to those
     * used by GEN_TOMBSTONE.  (One potential issue of mapping the TIDs at
     * export time occurs when the access STL appears somewhere you are not
     * aware needs to be mapped.) */
    uint16_t            tombstoneAccessTid;
//    uint16_t            sslDedupTid;
//    uint16_t            dnsRRTid;
//    uint16_t            yafDnsQRTid;
    mdKnownTemplates_t  recvdTids;
};

struct mdConfig_st {
    mdCollector_t           *firstCol;
    mdExporter_t            *firstExp;
    smFieldMap_t            *maps;
    /* The contents of the FILTER block, separate from filters on individual
     * collectors and exporters. */
    mdFilter_t              *sharedFilter;
    const char              *collector_name;
    pthread_mutex_t         log_mutex;
    gboolean                no_stats;
    gboolean                lockmode;
    gboolean                dns_base64_encode;
    gboolean                dns_print_lastseen;
    gboolean                preserve_obdomain;
    gboolean                gen_tombstone;
    gboolean                rewrite_ssl_certs;
    /* whether true for *any* exporter */
    gboolean                flowDpiStrip;
    uint16_t                tombstone_configured_id;
    uint64_t                udp_template_timeout;
    uint64_t                ctime;
    uint32_t                current_domain;
    unsigned int            usec_sleep;
    uint8_t                 num_listeners;
    uint8_t                 collector_id;
};

extern mdConfig_t   md_config;

#ifdef MEDIATOR_MAIN_SOURCE
mdConfig_t md_config = {
    NULL,                       /* firstCol */
    NULL,                       /* firstExp */
    NULL,                       /* maps */
    NULL,                       /* sharedFilter */
    NULL,                       /* collector_name */
    PTHREAD_MUTEX_INITIALIZER,  /* log_mutex */
    FALSE,                      /* no_stats */
    FALSE,                      /* lockmode */
    FALSE,                      /* dns_base64_encode */
    FALSE,                      /* dns_print_lastseen */
    FALSE,                      /* preserve_obdomain */
    FALSE,                      /* gen_tombstone */
    FALSE,                      /* rewrite_ssl_certs */
    FALSE,                      /* flowDpiStrip */
    0,                          /* tombstone_configured_id */
    600,                        /* udp_template_timeout */
    0,                          /* ctime */
    0,                          /* current_domain */
    0,                          /* usec_sleep */
    0,                          /* num_listeners */
    0                           /* collector_id */
};
#endif  /* MEDIATOR_MAIN_SOURCE */

typedef struct mdContext_st {
    mdConfig_t     *cfg;
    mdCoreStats_t   coreStats;
    mdColStats_t    colSummary;
    mdExpStats_t    expSummary;
    GError         *err;
} mdContext_t;

/* END OF STRUCTS AND TYPEDEFS */

/* GLOBALS */

extern volatile int     md_quit;

/* configuration options */
extern int              md_stats_timeout;
extern char            *md_pidfile;
extern char            *md_ipsetfile;
#ifdef ENABLE_SKIPSET
extern mdIPSet_t       *md_ipset;
extern int              app_registered;
#endif
extern fbInfoElement_t *user_elements;

/* END OF GLOBALS */
#endif  /* _MEDIATOR_STRUCTS_H */
