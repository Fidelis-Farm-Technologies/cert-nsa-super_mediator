%{
/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_config_parse.y
 *
 *  Grammar for mediator.conf configuration files.
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

#include "mediator_autohdr.h"
#include "mediator_log.h"
#include "mediator_structs.h"
#include "mediator_core.h"
#include "mediator_filter.h"
#include "mediator_inf.h"
#include "mediator_dns.h"
#include "mediator_dedup.h"
#include "mediator_ssl.h"

#define REQUIRE_NOTNULL(var)                                 \
    if (NULL != (var)) { /* okay */ } else {                 \
        mediator_config_error(                               \
            "Programmer error: %s is NULL in %s(), line %d", \
            #var, __func__, __LINE__);                       \
    }


#ifndef VALUELISTTEMP_DEBUG
#define VALUELISTTEMP_DEBUG 0
#endif
#if     !VALUELISTTEMP_DEBUG
#define  VLT_DEBUG_GET(idx, format, value)
#define  VLT_DEBUG_SET(format, value)
#define  VLT_DEBUG_RESET()
#else

#define  VLT_DEBUG_GET(idx, format, value)            \
    fprintf(stderr, "line %d [%s]: getting"           \
            " vLT(type=%s) %d of %d as " format "\n", \
            __LINE__, __func__,                       \
            valueTypeName(valueListTemp.type), idx,   \
            valueListTemp.rvals->len, value)
#define  VLT_DEBUG_SET(format, value)           \
    fprintf(stderr, "line %d [%s]: set"         \
            " vLT(type=%s) %d to " format "\n", \
            __LINE__, __func__,                 \
            valueTypeName(valueListTemp.type),  \
            valueListTemp.rvals->len, value)
#define  VLT_DEBUG_RESET()                                  \
    if (NULL == valueListTemp.rvals) {                      \
        fprintf(stderr, "line %d [%s], initializing vTL\n", \
                __LINE__, __func__);                        \
    } else {                                                \
        fprintf(stderr, "line %d [%s]: resetting"           \
                " vLT(type=%s) with %d items\n",            \
                __LINE__, __func__,                         \
                valueTypeName(valueListTemp.type),          \
                valueListTemp.rvals->len);                  \
    }

#endif  /* #else of #if !VALUELISTTEMP_DEBUG */

/* Set to 1 to print tracing messages as parser runs */
int  yydebug = 0;

/*Exporter stuff */
/* first in list */
static mdExporter_t *firstExp = NULL;
/* used for processing various config blocks */
static mdExporter_t *etemp = NULL;
static mdExporter_t *expToBuild = NULL;

/*Collector Stuff */
static mdCollector_t   *firstCol    = NULL;
static mdCollector_t   *colToBuild  = NULL;
/* Shared */
static mdFilterEntry_t *tempFilterEntries = NULL;
static gboolean         andFilter = FALSE;

static gboolean         default_tables = FALSE;
static gboolean         custom_tables = FALSE;

static smFieldMap_t    *maptemp = NULL;
static smFieldMap_t    *mapitem = NULL;

/* Elements of a valueList "[ item, item, ... ]" */
static struct valueListTemp_st {
    /* An array of fbRecordValue_t; use items->len to get the number of
     * items */
    GArray    *rvals;
    /* Type of elements it contains, VAL_INTEGER, VAL_QSTRING, etc */
    int        type;
    /* Whether "*" was seen as an item */
    gboolean   wild;
} valueListTemp = { NULL, -1, FALSE };

static int  numUserElements = 0;

/* File local structure for holding DNS_DEDUP values during parsing. */
static struct cfg_dns_dedup_st {
    char          *temp_name;
    int           *type_list;
    smFieldMap_t  *map;
    int            max_hit;
    int            flush_timeout;
    gboolean       lastseen;
    gboolean       exportname;
} cfg_dns_dedup = {NULL, NULL, NULL, 0, 0, FALSE, FALSE};

/* parsing function defs */
static void
validateConfFile(
    void);

static void
parseCollectorBegin(
    mdCollectionMethod_t   colMethod,
    char                  *name);
static void
parseCollectorEnd(
    void);
static void
parseCollectorPort(
    int   port);
static void
parseCollectorHost(
    char  *host);
static void
parseCollectorPath(
    char  *file);
static void
parseCollectorPollingInterval(
    int   pollingInterval);
static void
parseCollectorNoLockedFiles(
    void);
static void
parseCollectorMovePath(
    char  *dir);
static void
parseCollectorDecompressDirectory(
    char  *path);
static void
parseCollectorDelete(
    gboolean   delete);
static void
parseFilterBegin(
    void);
static void
parseFilterEnd(
    void);
static void
parseComparison(
    char             *elemName,
    fieldOperator_t   oper,
    char             *val,
    int               val_type);
static void
parseExporterBegin(
    mdExportFormat_t   exportFormat,
    mdExportMethod_t   exportMethod,
    char              *name);
static void
parseExporterEnd(
    void);
static void
parseExporterPort(
    int   port);
static void
parseExporterHost(
    char  *host);
static void
parseExporterFile(
    char  *file);
static void
parseExporterTextDelimiter(
    char  *delim);
static void
parseExporterDPIDelimiter(
    char  *delim);
static void
parseExporterLock(
    void);
static void
parsePidFile(
    char  *pid_file);
static void
parseIpsetFile(
    char  *ipset_file);
static void
parseExporterRotateSeconds(
    int   secs);
static void
parseExporterUDPTimeout(
    int   mins);
static void
parseExporterFlowOnly(
    void);
static void
parseExporterDPIOnly(
    void);
static void
parseStatisticsConfig(
    void);
static void
parsePreserveObDomainConfig(
    void);
static void
parseRewriteSslCertsConfig(
    void);
static void
parseGenTombstoneConfig(
    void);
static void
parseTombstoneIdConfig(
    int   configured_id);
static void
parseExporterDnsDedup(
    gboolean   only);
static void
parseExporterMovePath(
    char  *dir);
static void
parseExporterSslDedup(
    gboolean   only);
static void
parseExporterPrintHeader(
    void);
static void
parseExporterEscapeChars(
    void);
static void
parseLogConfig(
    char  *log_file);
static void
parseLogDir(
    char  *log_dir);
static void
parseStatsTimeout(
    int   timeout);
static void
parseExporterNoStats(
    void);
static void
parseExporterRemoveEmpty(
    void);
static void
parseExporterAddStats(
    void);
static void
parseValueListItems(
    char  *val,
    int    val_type);
static void
resetValueListTemp(
    void);
static void
parseExporterFields(
    void);
static void
parseExporterDpiFieldList(
    void);
static void
parseTableList(
    char  *table);
static void
parseTableListBegin(
    char  *index_label);
static void
parseTransportAsMethod(
    mdConfTransport_t      transport,
    mdCollectionMethod_t  *colMethod,
    mdExportMethod_t      *expMethod);
static void
parseExporterMultiFiles(
    void);
static void
parseExporterNoIndex(
    void);
static void
parseExporterTimestamp(
    void);
static void
parseExporterNoFlowStats(
    void);
static void
parseMySQLParams(
    char  *user,
    char  *pw,
    char  *db,
    char  *host,
    char  *table);
static void
parseExporterRemoveUploaded(
    void);
static void
parseUserInfoElement(
    int         num,
    char       *name,
    const int  *app);
static void
parseExporterDnsRR(
    gboolean   only,
    gboolean   full);
static void
parseExporterDnsResponseOnly(
    void);
static void
parseDNSDedupRecordTypeList(
    void);
static void
parseDNSDedupConfigEnd(
    void);
static smFieldMap_t *
parseMapStmt(
    char  *mapname);
static void
parseSSLConfigBegin(
    char  *name);
static void
parseSSLConfigTypeList(
    mdSSLConfigType_t   type);
static void
parseExporterDedupPerFlow(
    void);
static void
parseDedupConfigBegin(
    char  *exp_name);
static void
parseFileList(
    char                   *file,
    mdAcceptFilterField_t   field,
    char                   *mapname);
static int
parseNumericValue(
    char  *number,
    int    base);
static void
parseSSLCertDedup(
    void);
static void
parseSSLCertFile(
    char  *filename);
static void
parseExporterCertDigest(
    smCertDigestType_t   method);
static void
parseExporterGzipFiles(
    void);
static void
parseExporterDedupOnly(
    void);
static void
parseExporterNoFlow(
    void);
static void
parseMapBegin(
    mdAcceptFilterField_t   map_type,
    char                   *name);
static void
parseMapLine(
    char  *label);
static void
parseMapOther(
    char  *name);
static void
parseMapDiscard(
    void);
static void
parseMapEnd(
    mdAcceptFilterField_t   map_type);
static void
parseExporterMetadataExport(
    void);
static void
parseExporterDisableMetadataExport(
    void);

/*  Tell uncrustify to ignore the next part of the file */
/*  *INDENT-OFF* */
%}

%union {
    char                   *str;
    int                     integer;
    smFieldMap_t           *fieldMap;
    mdExportFormat_t        exportFormat;
    mdAcceptFilterField_t   field;
    fieldOperator_t         oper;
    mdConfTransport_t       transport;
    mdLogLevel_t            log_level;
    smCertDigestType_t      certDigest;
}

%token EOS

%token COMMA
%token LEFT_SQ_BRACKET
%token RIGHT_SQ_BRACKET
%token LEFT_PAREN
%token RIGHT_PAREN
%token WILD

%token TOK_COLLECTOR TOK_EXPORTER TOK_DNS_DEDUP TOK_DNS_DEDUP_ONLY TOK_NO_STATS
%token TOK_PORT TOK_HOSTNAME TOK_PATH TOK_DELIM TOK_PRINT_HEADER
%token TOK_MOVE TOK_DELETE TOK_LOCK TOK_UDP_TEMPLATE_TIMEOUT
%token TOK_COLLECTOR_FILTER
%token TOK_ROTATE_INTERVAL TOK_END TOK_FILTER TOK_LOG_FILE
%token TOK_FLOW_ONLY TOK_DPI_ONLY TOK_POLL TOK_MAX_HIT_COUNT
%token TOK_FLUSH_TIMEOUT
%token TOK_LOG_LEVEL TOK_BASE_64 TOK_LAST_SEEN TOK_REMOVE_EMPTY_FILES
%token TOK_STATS_ONLY
%token TOK_TABLE TOK_DPI_CONFIG TOK_MULTI_FILES TOK_NO_INDEX
%token TOK_TIMESTAMP_FILES TOK_NO_FLOW_STATS TOK_PID_FILE TOK_MY_REMOVE
%token TOK_MY_USER TOK_MY_PW TOK_MY_DB TOK_MY_HOST TOK_MY_TABLE
%token TOK_FIELDS TOK_DPI_FIELD_LIST TOK_DPI_DELIMITER TOK_STATS_TIMEOUT
%token TOK_USERIE TOK_AND_FILTER TOK_ESCAPE TOK_DNSRR_ONLY TOK_FULL
%token TOK_LOG_DIR TOK_RECORDS TOK_DNSRESPONSE_ONLY TOK_SSL_CONFIG
%token TOK_ISSUER TOK_SUBJECT TOK_OTHER TOK_EXTENSIONS TOK_DEDUP_PER_FLOW
%token TOK_DEDUP_CONFIG TOK_FILE_PREFIX TOK_MERGE_TRUNCATED
%token TOK_SSL_DEDUP TOK_CERT_FILE
%token TOK_SSL_DEDUP_ONLY TOK_MD5 TOK_SHA1 TOK_GZIP TOK_DNSRR
%token TOK_DEDUP_ONLY TOK_NO_FLOW TOK_OBID_MAP TOK_VLAN_MAP TOK_MAP
%token TOK_DISCARD TOK_ADD_EXPORTER_NAME TOK_DECOMPRESS_DIRECTORY
%token TOK_METADATA_EXPORT
%token TOK_GEN_TOMBSTONE TOK_TOMBSTONE_CONFIGURED_ID TOK_TOMBSTONE_CONFIG
%token TOK_PRESERVE_OBDOMAIN TOK_REWRITE_SSL_CERTS TOK_DISABLE
%token TOK_INVARIANT
%token TOK_MAX_BYTES TOK_MAX_SECONDS TOK_IPSET_FILE

 /* values returned from lex -- types defined in the %union above */
%token <str>            VAL_ATOM
%token <str>            VAL_DATETIME
%token <str>            VAL_DOUBLE
%token <str>            VAL_HEXADECIMAL
%token <str>            VAL_INTEGER
%token <str>            VAL_IP
%token <str>            VAL_QSTRING
%token <transport>      VAL_TRANSPORT
%token <exportFormat>   VAL_EXPORT_FORMAT
%token <oper>           VAL_OPER
%token <field>          VAL_FIELD
%token <log_level>      VAL_LOGLEVEL
%token <certDigest>     VAL_CERT_DIGEST

%token END_OF_FILE      0

 /* result of parsing statements */
%type <integer>         maxHitCount
%type <integer>         flushSeconds
%type <str>             optionalName
%type <str>             atomOrQstring
%type <fieldMap>        mapStmt
%type <integer>         numericValue

%%

mediatorConfFile:       mediatorConf END_OF_FILE
{
    validateConfFile();
};

mediatorConf:           stmtList
;

stmtList:               /* empty */
                        | stmtList stmt
;

stmt:                   EOS
                        | collectorBlock
                        | filterBlock
                        | exporterBlock
                        | statsConfig
                        | preserveObDomainConfig
                        | rewriteSslCertsConfig
                        | tombstoneConfig
                        | logConfig
                        | logLevelConfig
                        | logDirConfig
                        | pidConfig
                        | ipsetConfig
                        | dnsDedupBlock
                        | dpiConfigBlock
                        | sslConfigBlock
                        | dedupConfigBlock
                        | statsTimeout
                        | userIE
                        | vlanMapBlock
                        | obidMapBlock
                        | VAL_ATOM
{
    /* match an unknown token */
    ++lineNumber;
    mediator_config_error("Unknown keyword %s", $1);
};

collectorBlock:         collectorBegin collectorStmtList collectorEnd
;

collectorBegin:         TOK_COLLECTOR VAL_TRANSPORT optionalName EOS
{
    mdCollectionMethod_t colMethod;
    parseTransportAsMethod($2, &colMethod, NULL);
    parseCollectorBegin(colMethod, $3);
};

collectorEnd:           TOK_COLLECTOR TOK_END EOS
{
    parseCollectorEnd();
};

collectorStmtList:      /* empty */
                        | collectorStmtList collectorStmt
;

collectorStmt:          EOS
                        | col_port
                        | col_host
                        | col_path
                        | col_polling_interval
                        | col_lock
                        | col_move_path
                        | col_delete
                        | col_decompress
                        | filter_comparison
                        | filter_and_filter
                        | VAL_ATOM EOS
{
    /* prevent lone unknown token from being considered start of a filter */
    mediator_config_error("Unknown keyword %s", $1);
};

col_port:               TOK_PORT numericValue EOS
{
    parseCollectorPort($2);
};

col_host:               TOK_HOSTNAME atomOrQstring EOS
{
    parseCollectorHost($2);
}
                        | TOK_HOSTNAME VAL_IP EOS
{
    parseCollectorHost($2);
};

col_path:               TOK_PATH atomOrQstring EOS
{
    parseCollectorPath($2);
};

col_polling_interval:   TOK_POLL numericValue EOS
{
    parseCollectorPollingInterval($2);
};

col_decompress:         TOK_DECOMPRESS_DIRECTORY atomOrQstring EOS
{
    parseCollectorDecompressDirectory($2);
};

col_lock:               TOK_LOCK EOS
{
    parseCollectorNoLockedFiles();
};

col_move_path:          TOK_MOVE atomOrQstring EOS
{
    parseCollectorMovePath($2);
};

col_delete:             TOK_DELETE EOS
{
    parseCollectorDelete(TRUE);
};

filterBlock:            filterBegin filterStmtList filterEnd
;

filterStmtList:         /* empty */
                        | filterStmtList filterStmt
;

filterStmt:             EOS
                        | filter_comparison
                        | filter_and_filter
;

filterBegin:            TOK_FILTER EOS
{
    parseFilterBegin();
};

filterEnd:              TOK_FILTER TOK_END EOS
{
    parseFilterEnd();
};

filter_and_filter:      TOK_AND_FILTER EOS
{
    andFilter = TRUE;
};


    /* '[' <item>, <item>, ..., <item> ']' */
valueList:              valueListStart valueListItems valueListEnd
;

valueListStart:         LEFT_SQ_BRACKET
{
    resetValueListTemp();
};

valueListEnd:           RIGHT_SQ_BRACKET
;

valueListItems:         valueListItem
                        | valueListItems COMMA valueListItem
;

valueListItem:          VAL_ATOM
{
    parseValueListItems($1, VAL_ATOM);
}
                        | VAL_DATETIME
{
    parseValueListItems($1, VAL_DATETIME);
}
                        | VAL_INTEGER
{
    parseValueListItems($1, VAL_INTEGER);
}
                        | VAL_HEXADECIMAL
{
    /* numericValue is limited to 32 bits, use VAL_HEXADECIMAL instead */
    parseValueListItems($1, VAL_HEXADECIMAL);
}
                        | VAL_DOUBLE
{
    parseValueListItems($1, VAL_DOUBLE);
}
                        | VAL_IP
{
    parseValueListItems($1, VAL_IP);
}
                        | VAL_QSTRING
{
    parseValueListItems($1, VAL_QSTRING);
}
                        | WILD
{
    valueListTemp.wild = TRUE;
};

filter_comparison:      atomOrQstring VAL_OPER VAL_ATOM EOS
{
    parseComparison($1, $2, $3, VAL_ATOM);
}
                        | atomOrQstring VAL_OPER valueList EOS
{
    parseComparison($1, $2, NULL, VAL_ATOM);
}
                        | atomOrQstring VAL_OPER VAL_INTEGER EOS
{
    parseComparison($1, $2, $3, VAL_INTEGER);
}
                        | atomOrQstring VAL_OPER VAL_HEXADECIMAL EOS
{
    /* numericValue is limited to 32 bits, use VAL_HEXADECIMAL instead */
    parseComparison($1, $2, $3, VAL_HEXADECIMAL);
}
                        | atomOrQstring VAL_OPER VAL_DOUBLE EOS
{
    parseComparison($1, $2, $3, VAL_DOUBLE);
}
                        | atomOrQstring VAL_OPER VAL_QSTRING EOS
{
    parseComparison($1, $2, $3, VAL_QSTRING);
}
                        | atomOrQstring VAL_OPER VAL_IP EOS
{
    parseComparison($1, $2, $3, VAL_IP);
}
                        | atomOrQstring VAL_OPER VAL_DATETIME EOS
{
    parseComparison($1, $2, $3, VAL_DATETIME);
}
                        | TOK_COLLECTOR_FILTER VAL_OPER atomOrQstring EOS
{
    parseComparison(NULL, $2, $3, TOK_COLLECTOR_FILTER);
};

exporterBlock:          exporterBegin exporterStmtList exporterEnd
;

    /* EXPORTER <IPFIX|JSON|TEXT> <TCP|UDP|SINGLE FILE|ROTATING FILES> <name> */
exporterBegin:          TOK_EXPORTER VAL_EXPORT_FORMAT VAL_TRANSPORT optionalName EOS
{
    mdExportMethod_t expMethod;
    parseTransportAsMethod($3, NULL, &expMethod);
    parseExporterBegin($2, expMethod, $4);
};

exporterEnd:            TOK_EXPORTER TOK_END EOS
{
    parseExporterEnd();
};

exporterStmtList:       /* empty */
                        | exporterStmtList exporterStmt
;

exporterStmt:           EOS
                        | exp_port
                        | exp_host
                        | exp_path
                        | exp_lock
                        | exp_delim
                        | exp_dpi_delim
                        | exp_rotate
                        | exp_udp_timeout
                        | exp_flow_only
                        | exp_dpi_only
                        | exp_no_stats
                        | exp_stats_only
                        | exp_dedup_flow
                        | exp_remove_empty
                        | exp_print_headers
                        | exp_multi_files
                        | exp_no_index
                        | exp_timestamp
                        | exp_no_flow_stats
                        | filter_comparison
                        | filter_and_filter
                        | exp_fields
                        | exp_dpiFieldList
                        | exp_mysqlConfig
                        | exp_remove_uploaded
                        | exp_escape
                        | exp_dns_dedup
                        | exp_dns_rr
                        | exp_dns_resp_only
                        | exp_ssl_dedup
                        | exp_cert_digest
                        | exp_gzip_files
                        | exp_move_path
                        | exp_no_flow
                        | exp_dedup_only
                        | exp_metadata_export
                        | exp_disable_metadata_export
                        | exp_invariant
                        | exp_inv_max_bytes
                        | exp_inv_max_seconds
                        | VAL_ATOM EOS
{
    /* prevent lone unknown token from being considered start of a filter */
    mediator_config_error("Unknown keyword %s", $1);
};

exp_invariant:          TOK_INVARIANT EOS
{
    mediator_config_error(
        "Invariant support is disabled in this version");

    /* REQUIRE_NOTNULL(expToBuild); */
    /* expToBuild->invariant = TRUE; */
};

exp_inv_max_bytes:      TOK_MAX_BYTES numericValue EOS
{
    REQUIRE_NOTNULL(expToBuild);
    expToBuild->invState.maxFileSize = $2;
};

exp_inv_max_seconds:    TOK_MAX_SECONDS numericValue EOS
{
    REQUIRE_NOTNULL(expToBuild);
    expToBuild->invState.maxTimeMillisec = $2 * 1000;
};

exp_cert_digest:        VAL_CERT_DIGEST EOS
{
    parseExporterCertDigest($1);
};

exp_move_path:          TOK_MOVE atomOrQstring EOS
{
    parseExporterMovePath($2);
};

exp_port:               TOK_PORT numericValue EOS
{
    parseExporterPort($2);
};

exp_host:               TOK_HOSTNAME atomOrQstring EOS
{
    parseExporterHost($2);
}
                        | TOK_HOSTNAME VAL_IP EOS
{
    parseExporterHost($2);
};

exp_path:               TOK_PATH atomOrQstring EOS
{
    parseExporterFile($2);
};

exp_delim:              TOK_DELIM  atomOrQstring EOS
{
    parseExporterTextDelimiter($2);
};

exp_dpi_delim:          TOK_DPI_DELIMITER atomOrQstring EOS
{
    parseExporterDPIDelimiter($2);
};

exp_lock:               TOK_LOCK EOS
{
    parseExporterLock();
};

exp_rotate:             TOK_ROTATE_INTERVAL numericValue EOS
{
    parseExporterRotateSeconds($2);
};

exp_udp_timeout:        TOK_UDP_TEMPLATE_TIMEOUT numericValue EOS
{
    parseExporterUDPTimeout($2);
};

exp_flow_only:          TOK_FLOW_ONLY EOS
{
    parseExporterFlowOnly();
};

exp_dpi_only:           TOK_DPI_ONLY EOS
{
    parseExporterDPIOnly();
};

exp_no_stats:           TOK_NO_STATS EOS
{
    parseExporterNoStats();
};

exp_stats_only:         TOK_STATS_ONLY EOS
{
    parseExporterAddStats();
};

exp_remove_empty:       TOK_REMOVE_EMPTY_FILES EOS
{
    parseExporterRemoveEmpty();
};

exp_multi_files:        TOK_MULTI_FILES EOS
{
    parseExporterMultiFiles();
};

exp_no_flow_stats:      TOK_NO_FLOW_STATS EOS
{
    parseExporterNoFlowStats();
};

    /* turns stats forwarding off*/
statsConfig:            TOK_NO_STATS EOS
{
    parseStatisticsConfig();
};

preserveObDomainConfig: TOK_PRESERVE_OBDOMAIN EOS
{
    parsePreserveObDomainConfig();
};

rewriteSslCertsConfig:  TOK_REWRITE_SSL_CERTS EOS
{
    parseRewriteSslCertsConfig();
};

    /* have super mediator create its own tombstone records*/
tombstoneConfig:        tombstoneBegin tombstoneStmtList tombstoneEnd
;

tombstoneBegin:         TOK_TOMBSTONE_CONFIG EOS
;

tombstoneEnd:           TOK_TOMBSTONE_CONFIG TOK_END EOS
;

tombstoneStmtList:      /* empty */
                        | tombstoneStmtList tombstoneStmt
;

tombstoneStmt:          EOS
                        | genTombstoneConfig
                        | tombstoneIdConfig
;

genTombstoneConfig:     TOK_GEN_TOMBSTONE EOS
{
    parseGenTombstoneConfig();
};

tombstoneIdConfig:      TOK_TOMBSTONE_CONFIGURED_ID numericValue EOS
{
    parseTombstoneIdConfig($2);
};


statsTimeout:           TOK_STATS_TIMEOUT numericValue EOS
{
    parseStatsTimeout($2);
};

exp_dns_dedup:          TOK_DNS_DEDUP_ONLY EOS
{
    parseExporterDnsDedup(TRUE);
}
                        | TOK_DNS_DEDUP EOS
{
    parseExporterDnsDedup(FALSE);
};

exp_ssl_dedup:          TOK_SSL_DEDUP_ONLY EOS
{
    parseExporterSslDedup(TRUE);
}
                        | TOK_SSL_DEDUP EOS
{
    parseExporterSslDedup(FALSE);
};

exp_no_flow:            TOK_NO_FLOW EOS
{
    parseExporterNoFlow();
};

exp_dedup_only:         TOK_DEDUP_ONLY EOS
{
    parseExporterDedupOnly();
};

exp_print_headers:      TOK_PRINT_HEADER EOS
{
    parseExporterPrintHeader();
};

exp_no_index:           TOK_NO_INDEX EOS
{
    parseExporterNoIndex();
};

exp_escape:             TOK_ESCAPE EOS
{
    parseExporterEscapeChars();
};

exp_dedup_flow:         TOK_DEDUP_PER_FLOW EOS
{
    parseExporterDedupPerFlow();
};

exp_timestamp:          TOK_TIMESTAMP_FILES EOS
{
    parseExporterTimestamp();
};

exp_dns_rr:             TOK_DNSRR_ONLY EOS
{
    /* first boolean reflects ONLY, second reflects FULL */
    parseExporterDnsRR(TRUE, FALSE);
}
                        | TOK_DNSRR_ONLY TOK_FULL EOS
{
    parseExporterDnsRR(TRUE, TRUE);
}
                        | TOK_DNSRR EOS
{
    parseExporterDnsRR(FALSE, FALSE);
}
                        | TOK_DNSRR TOK_FULL EOS
{
    parseExporterDnsRR(FALSE, TRUE);
};

exp_dns_resp_only:      TOK_DNSRESPONSE_ONLY EOS
{
    parseExporterDnsResponseOnly();
};

exp_gzip_files:         TOK_GZIP EOS
{
    parseExporterGzipFiles();
};

exp_metadata_export:    TOK_METADATA_EXPORT EOS
{
    parseExporterMetadataExport();
};

exp_disable_metadata_export: TOK_DISABLE TOK_METADATA_EXPORT EOS
{
    parseExporterDisableMetadataExport();
};

    /* logging */
logConfig:              TOK_LOG_FILE atomOrQstring EOS
{
    parseLogConfig($2);
};

logDirConfig:           TOK_LOG_DIR atomOrQstring EOS
{
    parseLogDir($2);
};

logLevelConfig:         TOK_LOG_LEVEL VAL_LOGLEVEL EOS
{
    mdLoggerSetLevel($2);
};

pidConfig:              TOK_PID_FILE atomOrQstring EOS
{
    parsePidFile($2);
};

ipsetConfig:            TOK_IPSET_FILE atomOrQstring EOS
{
    parseIpsetFile($2);
};

dedupConfigBlock:       dedupConfigBegin dedupStmtList dedupConfigEnd
;

dedupConfigBegin:       TOK_DEDUP_CONFIG optionalName EOS
{
    parseDedupConfigBegin($2);
};

dedupConfigEnd:         TOK_DEDUP_CONFIG TOK_END EOS
{
    etemp = NULL;
};

dedupStmtList:          /* empty */
                        | dedupStmtList dedupStmt
;

dedupStmt:              EOS
                        | dedupHitConfig
                        | dedupFlushConfig
                        | dedupFileStmt
                        | dedupMergeTruncated
                        | dedupAddExporterName
;

dedupHitConfig:         maxHitCount
{
    /* TOK_MAX_HIT_COUNT */
    REQUIRE_NOTNULL(etemp);
    md_dedup_configure_state(etemp->dedup, $1, 0, FALSE, FALSE);
};

dedupFlushConfig:       flushSeconds
{
    /* TOK_FLUSH_TIMEOUT */
    REQUIRE_NOTNULL(etemp);
    md_dedup_configure_state(etemp->dedup, 0, $1, FALSE, FALSE);
};

dedupAddExporterName:   TOK_ADD_EXPORTER_NAME EOS
{
    REQUIRE_NOTNULL(etemp);
    md_dedup_configure_state(etemp->dedup, 0, 0, FALSE, TRUE);
};

dedupMergeTruncated:    TOK_MERGE_TRUNCATED EOS
{
    REQUIRE_NOTNULL(etemp);
    md_dedup_configure_state(etemp->dedup, 0, 0, TRUE, FALSE);
};

dedupFileStmt:          TOK_FILE_PREFIX atomOrQstring VAL_FIELD valueList EOS
{
    /* PREFIX "name" {SIP|DIP|FLOWKEYHASH} [ IE, IE, ... ] */
    parseFileList($2, $3, NULL);
}
                        | TOK_FILE_PREFIX atomOrQstring valueList EOS
{
    /* PREFIX "name" [ IE, IE, ... ] */
    /* uses SIP by default */
    parseFileList($2, SIP_V4, NULL);
}
                        | TOK_FILE_PREFIX atomOrQstring VAL_FIELD TOK_MAP LEFT_PAREN atomOrQstring RIGHT_PAREN valueList EOS
{
    /* PREFIX "name" {SIP|DIP|FLOWKEYHASH} MAP ( "name" ) [ IE, IE, ... ] */
    parseFileList($2, $3, $6);
}                      | TOK_FILE_PREFIX atomOrQstring TOK_MAP LEFT_PAREN atomOrQstring RIGHT_PAREN valueList EOS
{
    /* PREFIX "name" MAP ( "name" ) [ IE, IE, ... ] */
    parseFileList($2, SIP_V4, $5);
};

dnsDedupBlock:          dnsDedupBegin dnsDedupStmtList dnsDedupEnd
;

dnsDedupBegin:          TOK_DNS_DEDUP optionalName EOS
{
    cfg_dns_dedup.temp_name = $2;
};

dnsDedupEnd:            TOK_DNS_DEDUP TOK_END
{
    parseDNSDedupConfigEnd();
};

dnsDedupStmtList:       /* empty */
                        | dnsDedupStmtList dnsDedupStmt
;

dnsDedupStmt:           EOS
                        | dnsDedupHitConfig
                        | dnsDedupFlushConfig
                        | dnsDedupBase64Config
                        | dnsDedupLastSeenConfig
                        | dnsDedupRecordList
                        | dnsDedupMapStmt
                        | dnsDedupAddExporterName
;

dnsDedupRecordList:     TOK_RECORDS valueList EOS
{
    parseDNSDedupRecordTypeList();
};

dnsDedupMapStmt:        mapStmt
{
    /* MAP("name") */
    if (cfg_dns_dedup.map) {
        mediator_config_error(
            "MAP already defined for this DNS_DEDUP config block.");
    }
    cfg_dns_dedup.map = $1;
};

dnsDedupAddExporterName: TOK_ADD_EXPORTER_NAME EOS
{
    cfg_dns_dedup.exportname = TRUE;
};

dnsDedupHitConfig:      maxHitCount
{
    /* TOK_MAX_HIT_COUNT */
    if ($1 > (int)UINT16_MAX) {
        mediator_config_error("MAX_HIT_COUNT is above maximum of %u",
                              UINT16_MAX);
    }
    cfg_dns_dedup.max_hit = $1;
};

dnsDedupFlushConfig:    flushSeconds
{
    /* TOK_FLUSH_TIMEOUT */
    if ($1 > (int)UINT16_MAX) {
        mediator_config_error("FLUSH_TIMEOUT is above maximum of %u",
                              UINT16_MAX);
    }
    cfg_dns_dedup.flush_timeout = $1;
};

dnsDedupBase64Config:   TOK_BASE_64 EOS
{
    md_config.dns_base64_encode = TRUE;
};

dnsDedupLastSeenConfig: TOK_LAST_SEEN EOS
{
    cfg_dns_dedup.lastseen = TRUE;
};

dpiConfigBlock:         dpiConfigBegin dpiConfigStmtList dpiConfigEnd
;

dpiConfigBegin:         TOK_DPI_CONFIG optionalName EOS
{
    parseTableListBegin($2);
};

dpiConfigEnd:           TOK_DPI_CONFIG TOK_END EOS
{
    resetValueListTemp();
};

dpiConfigStmtList:      /* empty */
                        | dpiConfigStmtList dpiConfigStmt
;

dpiConfigStmt:          EOS
                        | tableStmt
;

tableStmt:              TOK_TABLE atomOrQstring valueList EOS
{
    parseTableList($2);
};

exp_fields:             TOK_FIELDS valueList EOS
{
    parseExporterFields();
};

exp_dpiFieldList:       TOK_DPI_FIELD_LIST valueList EOS
{
    parseExporterDpiFieldList();
};

exp_mysqlConfig:        TOK_MY_USER atomOrQstring EOS
{
    parseMySQLParams($2, NULL, NULL, NULL, NULL);
}
                        | TOK_MY_PW atomOrQstring EOS
{
    parseMySQLParams(NULL, $2, NULL, NULL, NULL);
}
                        | TOK_MY_DB atomOrQstring EOS
{
    parseMySQLParams(NULL, NULL, $2, NULL, NULL);
}
                        | TOK_MY_HOST atomOrQstring EOS
{
    parseMySQLParams(NULL, NULL, NULL, $2, NULL);
}
                        | TOK_MY_TABLE atomOrQstring EOS
{
    parseMySQLParams(NULL, NULL, NULL, NULL, $2);
};

userIE:                 TOK_USERIE numericValue atomOrQstring EOS
{
    parseUserInfoElement($2, $3, NULL);
}
                        | TOK_USERIE numericValue atomOrQstring numericValue EOS
{
    int app = $4;
    parseUserInfoElement($2, $3, &app);
};

exp_remove_uploaded:    TOK_MY_REMOVE EOS
{
    parseExporterRemoveUploaded();
};

sslConfigBlock:         sslConfigBegin sslConfigStmtList sslConfigEnd
;

sslConfigBegin:         TOK_SSL_CONFIG atomOrQstring EOS
{
    parseSSLConfigBegin($2);
};

sslConfigEnd:           TOK_SSL_CONFIG TOK_END
{
    etemp = NULL;
    resetValueListTemp();
};

sslConfigStmtList:      /* empty */
                        | sslConfigStmtList sslConfigStmt
;

sslConfigStmt:          EOS
                        | sslIssuerList
                        | sslSubjectList
                        | sslOtherList
                        | sslExtensionList
                        | sslCertDedup
                        | sslDedupHitConfig
                        | sslDedupFlushConfig
                        | sslCertFile
                        | ssldedupAddExporterName
                        | sslMapStmt
;

ssldedupAddExporterName: TOK_ADD_EXPORTER_NAME EOS
{
    REQUIRE_NOTNULL(etemp);
    md_ssl_dedup_configure_state(etemp->ssl_dedup, 0, 0, NULL, NULL, TRUE);
};

sslMapStmt:             mapStmt
{
    /* MAP("name") */
    REQUIRE_NOTNULL(etemp);
    md_ssl_dedup_configure_state(etemp->ssl_dedup, 0, 0, NULL, $1, FALSE);
};

sslIssuerList:          TOK_ISSUER valueList EOS
{
    parseSSLConfigTypeList(MD_SSLCONFIG_ISSUER);
};

sslSubjectList:         TOK_SUBJECT valueList EOS
{
    parseSSLConfigTypeList(MD_SSLCONFIG_SUBJECT);
};

sslOtherList:           TOK_OTHER valueList EOS
{
    parseSSLConfigTypeList(MD_SSLCONFIG_OTHER);
};

sslExtensionList:       TOK_EXTENSIONS valueList EOS
{
    parseSSLConfigTypeList(MD_SSLCONFIG_EXTENSIONS);
};

sslCertDedup:           TOK_SSL_DEDUP EOS
{
    parseSSLCertDedup();
};

sslDedupHitConfig:      maxHitCount
{
    /* TOK_MAX_HIT_COUNT */
    REQUIRE_NOTNULL(etemp);
    md_ssl_dedup_configure_state(etemp->ssl_dedup, $1, 0, NULL, NULL, FALSE);
};

sslDedupFlushConfig:    flushSeconds
{
    /* TOK_FLUSH_TIMEOUT */
    REQUIRE_NOTNULL(etemp);
    md_ssl_dedup_configure_state(etemp->ssl_dedup, 0, $1, NULL, NULL, FALSE);
};

sslCertFile:            TOK_CERT_FILE atomOrQstring EOS
{
    parseSSLCertFile($2);
};

    /* VLAN_MAP and OBID_MAP use the same statement parsing production */
vlanMapBlock:           vlanMapBegin voMapStmtList vlanMapEnd
;

vlanMapBegin:           TOK_VLAN_MAP atomOrQstring EOS
{
    parseMapBegin(VLAN, $2);
};

vlanMapEnd:             TOK_VLAN_MAP TOK_END EOS
{
    parseMapEnd(VLAN);
};

    /* VLAN_MAP and OBID_MAP use the same statement parsing production */
obidMapBlock:           obidMapBegin voMapStmtList obidMapEnd
;

obidMapBegin:           TOK_OBID_MAP atomOrQstring EOS
{
    parseMapBegin(OBDOMAIN, $2);
};

obidMapEnd:             TOK_OBID_MAP TOK_END
{
    parseMapEnd(OBDOMAIN);
};

voMapStmtList:          /* empty */
                        | voMapStmtList voMapStmt
;

voMapStmt:              EOS
                        | voMapStmtItem
                        | voMapStmtOther
                        | voMapStmtDiscard
;

voMapStmtItem:          atomOrQstring valueList EOS
{
    parseMapLine($1);
};

voMapStmtOther:         atomOrQstring TOK_OTHER EOS
{
    parseMapOther($1);
};

voMapStmtDiscard:       TOK_DISCARD EOS
{
    parseMapDiscard();
};

maxHitCount:            TOK_MAX_HIT_COUNT numericValue EOS
{
    if (($2) < 1) {
        mediator_config_error("MAX_HIT_COUNT must be a positive integer");
    }
    $$ = $2;
};

flushSeconds:           TOK_FLUSH_TIMEOUT numericValue EOS
{
    if (($2) < 1) {
        mediator_config_error("FLUSH_TIMEOUT must be a positive integer");
    }
    $$ = $2;
};

mapStmt:                TOK_MAP LEFT_PAREN atomOrQstring RIGHT_PAREN EOS
{
    $$ = parseMapStmt($3);
};

optionalName:           /*empty*/
{
    $$ = NULL;
}
                        | atomOrQstring
;

atomOrQstring:          VAL_ATOM | VAL_QSTRING
;

numericValue:           VAL_INTEGER
{
    /* parse into a signed 32 bit integer */
    $$ = parseNumericValue($1, 10);
}
                        | VAL_HEXADECIMAL
{
    /* parse into a signed 32 bit integer */
    $$ = parseNumericValue($1, 16);
};

%%

/*  Return the name of a VAL_* */
static const char *
valueTypeName(
    int   value_type)
{
    static char  bad[64];

    switch (value_type) {
      case VAL_ATOM:                return "ATOM";
      case VAL_DATETIME:            return "DATETIME";
      case VAL_DOUBLE:              return "DOUBLE";
      case VAL_HEXADECIMAL:         return "HEXADECIMAL";
      case VAL_INTEGER:             return "INTEGER";
      case VAL_IP:                  return "IP";
      case VAL_QSTRING:             return "QSTRING";
      case VAL_TRANSPORT:           return "TRANSPORT";
      case VAL_EXPORT_FORMAT:       return "EXPORT_FORMAT";
      case VAL_OPER:                return "OPER";
      case VAL_FIELD:               return "FIELD";
      case VAL_LOGLEVEL:            return "LOGLEVEL";
      case TOK_COLLECTOR_FILTER:    return "COLLECTOR";
      default:
        snprintf(bad, sizeof(bad), "UNKNOWN(%d)", value_type);
        return bad;
    }
}

/*  Reenable uncrustify */
/*  *INDENT-ON* */

/*
 *  Finds the exporter whose name is `name` when `name` is not NULL, or
 *  reports a fatal error if no such exporter is found.  If `name` is NULL and
 *  only one exporter exists, returns it; otherwise, reports a fatal error.
 *  Parameter `block_type` is the current block and is used in the error.
 */
static mdExporter_t *
findExporter(
    const char  *exp_name,
    const char  *block_type)
{
    if (exp_name) {
        mdExporter_t *exp;

        for (exp = firstExp; exp; exp = exp->next) {
            if (mdExporterCompareNames(exp, exp_name)) {
                return exp;
            }
        }
    } else if (NULL != firstExp && NULL == firstExp->next) {
        return firstExp;
    }

    /* ERROR */
    if (NULL == firstExp) {
        mediator_config_error("Cannot find an exporter for %s. "
                              "No exporters have been defined", block_type);
    }
    if (exp_name) {
        mediator_config_error("Cannot find an exporter named \"%s\" for %s",
                              exp_name, block_type);
    }
    mediator_config_error("Cannot find an exporter for %s. Must specify"
                          " exporter name when multiple exporters exist",
                          block_type);

    abort();                    /* UNREACHABLE */
}


/*
 *  Finds the map whose name is `mapname`, which must not be NULL.  Reports a
 *  fatal error if no such map is found unless 'no_error' is TRUE.
 */
static smFieldMap_t *
findFieldMap(
    const char  *mapname,
    gboolean     no_error)
{
    smFieldMap_t *map;

    REQUIRE_NOTNULL(mapname);

    for (map = maptemp; map; map = map->next) {
        if (strcmp(map->name, mapname) == 0) {
            return map;
        }
    }
    if (no_error) {
        return NULL;
    }

    /* ERROR */
    if (NULL == maptemp) {
        mediator_config_error("Cannot find a MAP named \"%s\". "
                              "No Previous MAPS defined in configuration file",
                              mapname);
    }
    mediator_config_error("Cannot find a MAP named \"%s\"", mapname);

    abort();                    /* UNREACHABLE */
}


static void
validateConfFile(
    void)
{
    if (NULL == firstExp) {
        mediator_config_error("No Exporter Information Given. "
                              " Need an Exporter or DEDUP File.");
    }
    if (NULL == firstCol) {
        mediator_config_error("No Collector Information Given. "
                              " Need a COLLECTOR.");
    }

    md_config.firstExp = firstExp;
    md_config.firstCol = firstCol;
    md_config.maps = maptemp;
}

static void
parseCollectorBegin(
    mdCollectionMethod_t   colMethod,
    char                  *name)
{
    if (colToBuild) {
        mediator_config_error("Non-Null colToBuild in collector begin."
                              " Programmer error");
    }

    /* new collector makes copy of name string */
    colToBuild = mdNewCollector(colMethod, name);
    if (!colToBuild) {
        mediator_config_error("mdNewCollector failed");
    }

    free(name);
}

static void
parseCollectorPort(
    int   port)
{
    char    portStr[32];
    GError *err = NULL;

    REQUIRE_NOTNULL(colToBuild);

    /* port string is copied by SetPort */
    snprintf(portStr, sizeof(portStr), "%d", port);
    if (!mdCollectorSetPort(colToBuild, portStr, &err)) {
        mediator_config_error("Error setting PORT on Collector %s: %s",
                              mdCollectorGetName(colToBuild), err->message);
    }
}

static void
parseCollectorHost(
    char  *host)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(colToBuild);

    if (!COLLMETHOD_IS_SOCKET(colToBuild->collectionMethod)) {
        mediator_config_error("HOST only valid for TCP or UDP Collectors");
    }
    /* hostname copied in SetInSpec */
    if (!mdCollectorSetInSpec(colToBuild, host, &err)) {
        mediator_config_error("%s", err->message);
    }

    free(host);
}


static void
parseCollectorPath(
    char  *file)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(colToBuild);

    if (COLLMETHOD_IS_SOCKET(colToBuild->collectionMethod)) {
        mediator_config_error("PATH only valid for file based Collectors");
    }
    /* SINGLE_FILE or DIRECTORY_POLL */
    if (!mdCollectorSetInSpec(colToBuild, file, &err)) {
        mediator_config_error("%s", err->message);
    }

    free(file);
}

static void
parseCollectorPollingInterval(
    int   pollingInterval)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(colToBuild);

    if (!mdCollectorSetPollingInterval(colToBuild, pollingInterval, &err)) {
        mediator_config_error("Error setting POLL interval: %s",
                              err->message);
    }
}

static void
parseCollectorNoLockedFiles(
    void)
{
    REQUIRE_NOTNULL(colToBuild);

    if (colToBuild->collectionMethod != CM_DIR_POLL) {
        mediator_config_error("Invalid Keyword: LOCK may only be used with "
                              "a DIRECTORY_POLL Collector");
    }

    mdCollectorSetNoLockedFilesMode(colToBuild);
}

static void
parseCollectorDecompressDirectory(
    char  *path)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(colToBuild);

    if (!mdCollectorSetDecompressWorkingDir(colToBuild, path, &err)) {
        mediator_config_error("Error setting DECOMPRESS_DIRECTORY: %s",
                              err->message);
    }
    free(path);
}

static void
parseCollectorMovePath(
    char  *path)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(colToBuild);

    /* set move dir makes copy of path */
    if (!mdCollectorSetMoveDir(colToBuild, path, &err)) {
        mediator_config_error("Error setting MOVE: %s", err->message);
    }

    free(path);
}

static void
parseCollectorDelete(
    gboolean   delete)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(colToBuild);

    if (!mdCollectorSetDeleteFiles(colToBuild, delete, &err)) {
        mediator_config_error("Error setting DELETE: %s", err->message);
    }
}

static void
parseCollectorEnd(
    void)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(colToBuild);

    if (!mdCollectorVerifySetup(colToBuild, &err)) {
        mediator_config_error("Error verifying Collector %s: %s",
                              mdCollectorGetName(colToBuild), err->message);
    }

    if (tempFilterEntries) {
        /* Do not allow a COLLECTOR filter in a COLLECTOR block. */
        mdFilterEntry_t *fnode;
        for (fnode = tempFilterEntries; (fnode); fnode = fnode->next) {
            if (fnode->isCollectorComp) {
                mediator_config_error("May not filter on a COLLECTOR"
                                      " within in a COLLECTOR block.");
            }
        }

        colToBuild->filter = g_slice_new0(mdFilter_t);
        colToBuild->filter->firstFilterEntry = tempFilterEntries;
        colToBuild->filter->andFilter = andFilter;
    }

    attachHeadToSLL((mdSLL_t **)&(firstCol), (mdSLL_t *)colToBuild);

    colToBuild = NULL;
    tempFilterEntries = NULL;
    andFilter = FALSE;
    resetValueListTemp();
}


static void
parseFilterBegin(
    void)
{
    if (md_config.sharedFilter) {
        mediator_config_error("Only one FILTER block is supported");
    }
}

static void
parseFilterEnd(
    void)
{
    mdFilter_t *filter;

    if (tempFilterEntries == NULL) {
        mediator_config_error("No filter comparisons in FILTER block");
    }

    filter = g_slice_new0(mdFilter_t);
    filter->firstFilterEntry = tempFilterEntries;
    filter->andFilter = andFilter;

    md_config.sharedFilter = filter;

    tempFilterEntries = NULL;
    andFilter = FALSE;
}


static void
parseExporterBegin(
    mdExportFormat_t   exportFormat,
    mdExportMethod_t   exportMethod,
    char              *name)
{
    if (expToBuild) {
        g_warning("expToBuild not NULL in exporter begin");
        expToBuild = NULL;
    }

    expToBuild = mdNewExporter(exportFormat, exportMethod, name);
    free(name);
}

static void
parseExporterPort(
    int   port)
{
    char    portStr[32];
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    /* port string is copied by SetPort */
    snprintf(portStr, sizeof(portStr), "%d", port);
    if (!mdExporterSetPort(expToBuild, portStr, &err)) {
        mediator_config_error("Error setting PORT: %s", err->message);
    }
}

static void
parseExporterHost(
    char  *host)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterSetHost(expToBuild, host, &err)) {
        mediator_config_error("Error setting HOSTNAME: %s", err->message);
    }

    free(host);
}

static void
parseExporterFile(
    char  *file)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterSetFileSpec(expToBuild, file, &err)) {
        mediator_config_error("Error setting PATH: %s", err->message);
    }

    free(file);
}

static void
parseExporterLock(
    void)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterEnableLocks(expToBuild, &err)) {
        mediator_config_error("Error setting LOCK: %s", err->message);
    }
}

static void
parseExporterNoFlowStats(
    void)
{
    REQUIRE_NOTNULL(expToBuild);

    mdExporterSetNoFlowStats(expToBuild);
}

static void
parseExporterRotateSeconds(
    int   secs)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterSetRotateInterval(expToBuild, secs, &err)) {
        mediator_config_error("Error setting ROTATE_INTERVAL to %d: %s",
                              secs, err->message);
    }
}

static void
parseExporterUDPTimeout(
    int   mins)
{
    GError *err = NULL;

    /* Note: This value is not used anywhere. */

    if (expToBuild->exportMethod != EM_UDP) {
        mediator_config_error("Invalid Keyword: UDP TEMPLATE TIMEOUT "
                              "only valid for UDP Exporters.");
    }

    /* For whatever reason, the man page for config files says MINUTES, not
     * SECONDS, and man page for the program says seconds.  Also, this is
     * parsed in the context of an exporter, but there is a single global
     * value. */
    mins *= 60;
    if (!mdExporterSetUdpTemplateTimeout(expToBuild, mins, &err)) {
        mediator_config_error("Error setting UDP TEMPLATE TIMEOUT: %s",
                              err->message);
    }
}

static void
parseExporterEnd(
    void)
{
    mdExporter_t *attachedExp = NULL;
    GError       *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    attachHeadToSLL((mdSLL_t **)&(firstExp),
                    (mdSLL_t *)expToBuild);
    attachedExp = expToBuild;
    expToBuild = NULL;

    if (tempFilterEntries) {
        attachedExp->filter = g_slice_new0(mdFilter_t);
        attachedExp->filter->firstFilterEntry = tempFilterEntries;
        attachedExp->filter->andFilter = andFilter;
    }

    if (!mdExporterVerifySetup(attachedExp, &err)) {
        mediator_config_error("Error verifying Exporter %s: %s",
                              mdExporterGetName(attachedExp), err->message);
    }

    tempFilterEntries = NULL;
    andFilter = FALSE;
    resetValueListTemp();
}

static void
parseExporterTextDelimiter(
    char  *delim)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);
    REQUIRE_NOTNULL(delim);

    if (!mdExporterSetDelimiters(expToBuild, delim, NULL, &err)) {
        mediator_config_error("Error setting DELIMITER: %s", err->message);
    }

    free(delim);
}

static void
parseExporterDPIDelimiter(
    char  *delim)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);
    REQUIRE_NOTNULL(delim);

    if (!mdExporterSetDelimiters(expToBuild, NULL, delim, &err)) {
        mediator_config_error("Error setting DPI_DELIMITER: %s", err->message);
    }

    free(delim);
}

static void
parseExporterFlowOnly(
    void)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterEnableBasicFlowsOnly(expToBuild, &err)) {
        mediator_config_error("Error setting FLOW_ONLY: %s", err->message);
    }
}


static void
parseExporterDPIOnly(
    void)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterEnableFlowsWithDpiOnly(expToBuild, &err)) {
        mediator_config_error("Error setting DPI_ONLY: %s", err->message);
    }
}


static void
parseExporterRemoveEmpty(
    void)
{
    REQUIRE_NOTNULL(expToBuild);

    if (EXPORTMETHOD_IS_SOCKET(expToBuild->exportMethod)) {
        mediator_config_error("REMOVE_EMPTY_FILES only valid for file based "
                              "exporters");
    }

    mdExporterSetRemoveEmpty(expToBuild);
}

static void
parseExporterNoStats(
    void)
{
    REQUIRE_NOTNULL(expToBuild);

    mdExporterSetStats(expToBuild, 1);
}

static void
parseExporterAddStats(
    void)
{
    REQUIRE_NOTNULL(expToBuild);
    mdExporterSetStats(expToBuild, 2);
}

static void
parseExporterPrintHeader(
    void)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterSetPrintHeader(expToBuild, &err)) {
        mediator_config_error("Error setting PRINT_HEADER: %s", err->message);
    }
}

static void
parseExporterEscapeChars(
    void)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterSetEscapeChars(expToBuild, &err)) {
        mediator_config_error("Error setting ESCAPE_CHARS: %s", err->message);
    }
}

static void
parseExporterDnsRR(
    gboolean   only,
    gboolean   full)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterEnableDnsRR(expToBuild, only, full, &err)) {
        mediator_config_error("Error setting DNS_RR%s: %s",
                              ((only) ? "_ONLY" : ""), err->message);
    }
}

static void
parseExporterDnsResponseOnly(
    void)
{
    REQUIRE_NOTNULL(expToBuild);
    mdExporterEnableDnsResponseOnly(expToBuild);
}

static void
parseExporterDedupPerFlow(
    void)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterEnableDedupPerFlow(expToBuild, &err)) {
        mediator_config_error("Error setting DEDUP_PER_FLOW: %s",
                              err->message);
    }
}

static void
parseExporterNoIndex(
    void)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterSetNoIndex(expToBuild, TRUE, &err)) {
        mediator_config_error("Error setting NO_INDEX: %s", err->message);
    }
}

static void
parseExporterNoFlow(
    void)
{
    REQUIRE_NOTNULL(expToBuild);

    mdExporterSetNoFlow(expToBuild);
}

static void
parseExporterTimestamp(
    void)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterSetTimestampFiles(expToBuild, &err)) {
        mediator_config_error("Error setting TIMESTAMP_FILES: %s",
                              err->message);
    }
}


static void
parseExporterMultiFiles(
    void)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterEnableMultiFiles(expToBuild, &err)) {
        mediator_config_error("Error setting MULTI_FILES: %s", err->message);
    }
}

static void
parseExporterMetadataExport(
    void)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterSetMetadataExport(expToBuild, TRUE, TRUE, &err)) {
        mediator_config_error("Error setting METADATA_EXPORT: %s",
                              err->message);
    }
    mediator_config_warn("Metadata export enabled by default."
                         " METADATA_EXPORT not neeeded in configuration file");
}

static void
parseExporterDisableMetadataExport(
    void)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterSetMetadataExport(expToBuild, FALSE, FALSE, &err)) {
        mediator_config_error("Error setting DISABLE METADATA_EXPORT: %s",
                              err->message);
    }
}

static void
parseStatsTimeout(
    int   timeout)
{
    md_stats_timeout = timeout;
}

static void
parseLogConfig(
    char  *log_file)
{
    GError *err = NULL;

    if (!mdLoggerSetDestination(log_file, &err)) {
        mediator_config_error("Error setting LOG: %s", err->message);
    }
    free(log_file);
}

static void
parseLogDir(
    char  *log_dir)
{
    GError *err = NULL;

    if (!mdLoggerSetDirectory(log_dir, &err)) {
        mediator_config_error("Error setting LOG_DIR: %s", err->message);
    }
    free(log_dir);
}

static void
parsePidFile(
    char  *pid_file)
{
    md_pidfile = g_strdup(pid_file);
    free(pid_file);
}

static void
parseIpsetFile(
    char  *ipset_file)
{
    md_ipsetfile = g_strdup(ipset_file);
    free(ipset_file);
}

static void
parseStatisticsConfig(
    void)
{
    md_config.no_stats = TRUE;
}

static void
parsePreserveObDomainConfig(
    void)
{
    md_config.preserve_obdomain = TRUE;
}

static void
parseRewriteSslCertsConfig(
    void)
{
    md_config.rewrite_ssl_certs = TRUE;
}

static void
parseGenTombstoneConfig(
    void)
{
    md_config.gen_tombstone = TRUE;
}

static void
parseTombstoneIdConfig(
    int   configured_id)
{
    if (configured_id > UINT16_MAX) {
        mediator_config_error("TOMBSTONE ID has a maximum of %u", UINT16_MAX);
    }
    md_config.tombstone_configured_id = configured_id;
}

static void
parseExporterDnsDedup(
    gboolean   only)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterEnableDnsDedup(expToBuild, only, &err)) {
        mediator_config_error("Error setting DNS_DEDUP%s: %s",
                              ((only) ? "_ONLY" : ""), err->message);
    }
}

static void
parseComparisonCheckType(
    const char  *elemName,
    int          expectedType,
    int          receivedType,
    const void  *ipset)
{
#ifndef ENABLE_SKIPSET
    MD_UNUSED_PARAM(ipset);
#else
    if (ipset) {
        if (VAL_IP == expectedType) {
            return;
        }
        mdUtilIPSetClose((mdIPSet_t *)ipset);
        mediator_config_error("May not compare %s to an IPSet", elemName);
    }
#endif  /* ENABLE_SKIPSET */
    if (expectedType != receivedType) {
        mediator_config_error("Must compare %s with a %s or a list of %sS",
                              elemName, valueTypeName(expectedType),
                              valueTypeName(expectedType));
    }
}

static void
parseComparison(
    char             *elemName,
    fieldOperator_t   oper,
    char             *val,
    int               val_type)
{
#ifdef ENABLE_SKIPSET
    mdIPSet_t             *ipset = NULL;
#else
    void                  *ipset = NULL;
#endif
    mdFilterEntry_t       *currentFilterEntry = NULL;
    mdCollector_t         *col;
    fbInfoModel_t         *md_info_model = NULL;
    GError                *err = NULL;
    const fbInfoElement_t *compIE = NULL;
    fbRecordValue_t        compVal = FB_RECORD_VALUE_INIT;
    fbRecordValue_t       *rval;
    unsigned int           i;
    gboolean               isList = FALSE;

    /* find the element; NULL if filtering on a collector */
    if (NULL != elemName) {
        md_info_model = mdInfoModel();
        compIE = fbInfoModelGetElementByName(md_info_model, elemName);
        if (NULL == compIE) {
            mediator_config_error("No such filter IE \"%s\" in infomodel",
                                  elemName);
            return;
        }
    } else if (TOK_COLLECTOR_FILTER != val_type) {
        g_error("%s:%d: Programmer error: elemName may only be NULL when"
                " val_type is TOK_COLLECTOR_FILTER", __FILE__, __LINE__);
    }

    /* if value is a list, get the type of its contents */
    if (VAL_ATOM == val_type) {
        if (NULL != val) {
            mediator_config_error(
                "The value in a comparison filter may not be a bare word;"
                " use a quoted string instead");
        }
        if (0 == valueListTemp.rvals->len) {
            mediator_config_error("Will not compare %s to an empty list",
                                  elemName);
        }
        val_type = valueListTemp.type;
        isList = TRUE;
    } else if (NULL == val) {
        g_error("%s:%d: Programmer error: Expected val_type to be VAL_ATOM"
                " when val is NULL", __FILE__, __LINE__);
    }

    /* Must use the == or != Operators when filtering on collector */
    if (TOK_COLLECTOR_FILTER == val_type &&
        !(EQUAL == oper || NOT_EQUAL == oper))
    {
        mediator_config_error("When filtering by COLLECTOR,"
                              " the operator must be == or !=");
    }

    /* Operators IN_LIST and NOT_IN_LIST are valid if value is a list or (when
     * enabled) a string giving the path to an IPSet. List values may only be
     * used with the IN_LIST and NOT_IN_LIST Ops. Ops == and != are valid for
     * all other data types. Ops <=, =>, etc are valid only for numbers. */
    if (IN_LIST == oper || NOT_IN_LIST == oper) {
#ifndef ENABLE_SKIPSET
        if (!isList) {
            mediator_config_error("The IN_LIST and NOT_IN_LIST operators"
                                  " may only be used with a list of values"
                                  " (%s was built without IPSet support)",
                                  g_get_prgname());
        }
#else  /* ENABLE_SKIPSET */
        if (!isList) {
            if (VAL_QSTRING != val_type) {
                mediator_config_error("The IN_LIST and NOT_IN_LIST operators"
                                      " may only be used with a list of values"
                                      " or the path to an IPSet file");
            }
            /* treat as the path to an IPSet file */
            ipset = mdUtilIPSetOpen(val, &err);
            if (!ipset) {
                mediator_config_error("Error with %sIN_LIST comparison: %s",
                                      ((NOT_IN_LIST == oper) ? "NOT_" : ""),
                                      err->message);
            }
        }
#endif  /* ENABLE_SKIPSET */
    } else if (isList) {
        mediator_config_error("Must use the IN_LIST or NOT_IN_LIST "
                              " operator with a list of values");
    } else if (EQUAL == oper || NOT_EQUAL == oper) {
        /* valid for all (non list) types */
    } else if (VAL_INTEGER == val_type ||
               VAL_HEXADECIMAL == val_type ||
               VAL_DOUBLE == val_type)
    {
        /* accepts all comparison operators */
    } else {
        mediator_config_error(
            "May not use <=, <, >, or => operator with a %s value",
            valueTypeName(val_type));
    }

    /* Handle a collector comparison and return */
    if (TOK_COLLECTOR_FILTER == val_type) {
        g_assert(NULL == elemName);
        g_assert(NULL == compIE);
        g_assert(EQUAL == oper || NOT_EQUAL == oper);
        g_assert(!isList);
        g_assert(!ipset);

        /* The parser does not support matching a collector to a list since
         * there is no way to create a list of them. */

        /* find the collector */
        for (col = firstCol; col; col = col->next) {
            if (0 == strcmp(val, mdCollectorGetName(col))) {
                break;
            }
        }
        if (NULL == col) {
            mediator_config_error("No COLLECTOR exists with name '%s'.", val);
        }
        compVal.v.u64 = mdCollectorGetID(col);

        currentFilterEntry = mdFilterEntryNew();
        currentFilterEntry->oper = oper;
        currentFilterEntry->isCollectorComp = TRUE;
        g_array_append_val(currentFilterEntry->compValList, compVal);

        attachHeadToSLL((mdSLL_t **)&(tempFilterEntries),
                        (mdSLL_t *)currentFilterEntry);
        resetValueListTemp();
        free(val);
        return;
    }
    /* else we are filtering on an IE */

    /*
     * if not given a list, parse the value and set its IE pointer.  if given
     * a list, the values were parsed when they were added to the list; set
     * their IE pointers
     */
    if (ipset) {
        compVal.ie = compIE;
    } else if (!isList) {
        switch (val_type) {
          case VAL_INTEGER:
            errno = 0;
            compVal.v.s64 = (int64_t)strtoll(val, NULL, 10);
            if (ERANGE == errno || compVal.v.s64 < 0) {
                mediator_config_error("Value %s exceeds maximum", val);
            }
            break;
          case VAL_HEXADECIMAL:
            val_type = VAL_INTEGER;
            errno = 0;
            compVal.v.s64 = (int64_t)strtoll(val, NULL, 16);
            if (ERANGE == errno || compVal.v.s64 < 0) {
                mediator_config_error("Value %s exceeds maximum", val);
            }
            break;
          case VAL_DOUBLE:
            compVal.v.dbl = strtod(val, NULL);
            break;
          case VAL_IP:
            if (!mdUtilParseIP(&compVal, val, NULL, &err)) {
                mediator_config_error("%s", err->message);
            }
            break;
          case VAL_QSTRING:
            compVal.stringbuf = g_string_new(val);
            compVal.v.varfield.buf = (uint8_t *)compVal.stringbuf->str;
            compVal.v.varfield.len = strlen(val);
            break;
          default:
            mediator_config_error("Invalid value. Filters do not support "
                                  "comparisons with %s values",
                                  valueTypeName(val_type));
        }
        compVal.ie = compIE;
    } else {
#if VALUELISTTEMP_DEBUG
        char  ipbuf[128];
#endif
        for (i = 0; i < valueListTemp.rvals->len; ++i) {
            rval = &g_array_index(valueListTemp.rvals, fbRecordValue_t, i);
            rval->ie = compIE;
#if VALUELISTTEMP_DEBUG
            switch (valueListTemp.type) {
              case VAL_INTEGER:
                VLT_DEBUG_GET(i, "int (%" PRId64 ")", rval->v.s64);
                break;
              case VAL_DOUBLE:
                VLT_DEBUG_GET(i, "double (%f)", rval->v.dbl);
                break;
              case VAL_IP:
                snprintf(ipbuf, sizeof(ipbuf),
                         "v4:%u.%u.%u.%u, v6"
                         ":%02x%02x:%02x%02x:%02x%02x:%02x%02x"
                         ":%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                         ((rval->v.ip4 >> 24) & 0xff),
                         ((rval->v.ip4 >> 16) & 0xff),
                         ((rval->v.ip4 >> 8) & 0xff),
                         ((rval->v.ip4) & 0xff),
                         rval->v.ip6[0], rval->v.ip6[1],
                         rval->v.ip6[2], rval->v.ip6[3],
                         rval->v.ip6[4], rval->v.ip6[5],
                         rval->v.ip6[6], rval->v.ip6[7],
                         rval->v.ip6[8], rval->v.ip6[9],
                         rval->v.ip6[10], rval->v.ip6[11],
                         rval->v.ip6[12], rval->v.ip6[13],
                         rval->v.ip6[14], rval->v.ip6[15]);
                VLT_DEBUG_GET(i, "ip (%s)", ipbuf);
                break;
              case VAL_QSTRING:
                VLT_DEBUG_GET(i, "string (%s)", rval->stringbuf->str);
                break;
              default:
                g_error("%s:%d: Programmer error:"
                        " Unexpected type in value list %s",
                        __FILE__, __LINE__, valueTypeName(valueListTemp.type));
            }
#endif  /* VALUELISTTEMP_DEBUG */
        }
    }

    currentFilterEntry = mdFilterEntryNew();
    currentFilterEntry->oper = oper;

    /*
     * Ensure the type of value is valid for the InfoElement and set the
     * value(s) on the mdFilterEntry.  When isList is true, bulk copy the
     * values.
     *
     * Treat unsigned, signed, and datetime elements as integers.  There are
     * no checks as to whether the values are within the range supported by
     * the element's type.
     */
    switch (fbInfoElementGetType(compIE)) {
      case FB_BOOL:
      case FB_UINT_8:
      case FB_UINT_16:
      case FB_UINT_32:
      case FB_UINT_64:
      case FB_INT_8:
      case FB_INT_16:
      case FB_INT_32:
      case FB_INT_64:
      case FB_DT_SEC:
      case FB_DT_MILSEC:
      case FB_DT_MICROSEC:
      case FB_DT_NANOSEC:
        parseComparisonCheckType(elemName, VAL_INTEGER, val_type, ipset);
        if (!isList) {
            g_array_append_val(currentFilterEntry->compValList, compVal);
        } else {
            g_array_append_vals(currentFilterEntry->compValList,
                                (gconstpointer)valueListTemp.rvals->data,
                                valueListTemp.rvals->len);
        }
        break;

      case FB_FLOAT_32:
      case FB_FLOAT_64:
        parseComparisonCheckType(elemName, VAL_DOUBLE, val_type, ipset);
        if (!isList) {
            g_array_append_val(currentFilterEntry->compValList, compVal);
        } else {
            /* bulk copy the values */
            g_array_append_vals(currentFilterEntry->compValList,
                                (gconstpointer)valueListTemp.rvals->data,
                                valueListTemp.rvals->len);
        }
        break;

      case FB_MAC_ADDR:
        /* Perhaps MAC addresses comparisons use integers instead of strings;
         * this would be easier if the parser supported hexadecimal numbers */
        parseComparisonCheckType(elemName, VAL_QSTRING, val_type, ipset);
        if (!isList) {
            if (compVal.v.varfield.len != 6) {
                mediator_config_error("Must compare %s with a string of"
                                      " exactly 6 characters", elemName);
            }
            g_array_append_val(currentFilterEntry->compValList, compVal);
        } else {
            for (i = 0; i < valueListTemp.rvals->len; ++i) {
                rval = &g_array_index(valueListTemp.rvals, fbRecordValue_t, i);
                if (rval->v.varfield.len != 6) {
                    mediator_config_error("Must compare %s with a string of"
                                          " exactly 6 characters", elemName);
                }
            }
            g_array_append_vals(currentFilterEntry->compValList,
                                (gconstpointer)valueListTemp.rvals->data,
                                valueListTemp.rvals->len);
        }
        break;

      case FB_STRING:
      case FB_OCTET_ARRAY:
        parseComparisonCheckType(elemName, VAL_QSTRING, val_type, ipset);
        if (!isList) {
            g_array_append_val(currentFilterEntry->compValList, compVal);
        } else {
            g_array_append_vals(currentFilterEntry->compValList,
                                (gconstpointer)valueListTemp.rvals->data,
                                valueListTemp.rvals->len);
        }
        break;

      case FB_IP4_ADDR:
      case FB_IP6_ADDR:
        /* FIXME: Should be better at handling IPv4 vs IPv6 addresses */
        parseComparisonCheckType(elemName, VAL_IP, val_type, ipset);
        if (!isList) {
            g_array_append_val(currentFilterEntry->compValList, compVal);
#ifdef ENABLE_SKIPSET
            if (ipset) {
                currentFilterEntry->ipset = ipset;
                ipset = NULL;
            }
#endif  /* ENABLE_SKIPSET */
        } else {
            g_array_append_vals(currentFilterEntry->compValList,
                                (gconstpointer)valueListTemp.rvals->data,
                                valueListTemp.rvals->len);
        }
        break;

      case FB_BASIC_LIST:
      case FB_SUB_TMPL_LIST:
      case FB_SUB_TMPL_MULTI_LIST:
        mediator_config_error("Cannot compare %s whose type is"
                              " structed data (a list)", elemName);
    }

    /* If value was a list it was bulk copied to currentFilterEntry.  Set the
     * size of valueListTemp to 0 so any strings it contains are not freed;
     * currentFilterEntry owns them now. */
    if (isList) {
        VLT_DEBUG_RESET();
        g_array_set_size(valueListTemp.rvals, 0);
    }
#ifdef ENABLE_SKIPSET
    if (ipset) {
        mdUtilIPSetClose(ipset);
    }
#endif  /* ENABLE_SKIPSET */

    attachHeadToSLL((mdSLL_t **)&(tempFilterEntries),
                    (mdSLL_t *)currentFilterEntry);

    currentFilterEntry = NULL;
    resetValueListTemp();
    free(elemName);
    free(val);
}

static smFieldMap_t *
parseMapStmt(
    char  *mapname)
{
    smFieldMap_t *map = NULL;

    map = findFieldMap(mapname, FALSE);
    free(mapname);

    return map;
}

static void
parseTableListBegin(
    char  *index_label)
{
    void *currentTable = NULL;

    if (default_tables) {
        mediator_config_error("Error: Default Tables already defined. "
                              "Remove application label from USER_IE line "
                              "to build custom tables.");
    }

    custom_tables = TRUE;

    if (index_label == NULL) {
        currentTable = mdNewTable(INDEX_DEFAULT);
    } else {
        currentTable = mdNewTable(index_label);
    }

    /* FIXME: This is passing NULL into a GHashTable of string.  What is this
     * trying to do? */
//    if (!mdInsertTableItem(currentTable, 0)) {
//        mediator_config_error("Error Creating Index Table for DPI Config.");
//    }

    g_free(index_label);
}


static void
parseTableList(
    char  *table)
{
    unsigned int           i = 0;
    void                  *currentTable = NULL;
    const fbInfoElement_t *ie;
    fbRecordValue_t       *rval;
    fbInfoModel_t         *md_info_model = mdInfoModel();

    if (valueListTemp.rvals->len == 0) {
        mediator_config_error("No items in DPI_CONFIG TABLE.");
    }
    if (VAL_INTEGER != valueListTemp.type) {
        mediator_config_error("DPI_CONFIG TABLE items must be integers.");
    }

    currentTable = mdNewTable(table);

    for (i = 0; i < valueListTemp.rvals->len; i++) {
        rval = &g_array_index(valueListTemp.rvals, fbRecordValue_t, i);
        VLT_DEBUG_GET(i, "int (%" PRId64 ")", rval->v.s64);
        if (rval->v.s64 < 1 || rval->v.s64 > INT16_MAX) {
            mediator_config_error("Illegal elementId %" PRId64,
                                  rval->v.s64);
        }
        ie = fbInfoModelGetElementByID(md_info_model, rval->v.s64, CERT_PEN);
        if (NULL == ie) {
            mediator_config_error(
                "No such DPI_CONFIG IE %" PRId64 " in CERT infomodel",
                rval->v.s64);
        }
        if (!mdInsertTableItem(currentTable, fbInfoElementGetName(ie))) {
            mediator_config_error("Item can not be present in another list.");
        }
    }

    free(table);
}


static void
parseDNSDedupRecordTypeList(
    void)
{
    fbRecordValue_t *rval;
    unsigned int     i;

    if (cfg_dns_dedup.type_list) {
        mediator_config_error(
            "RECORD list already defined for this DNS_DEDUP config block.");
    }
    if (valueListTemp.rvals->len == 0) {
        mediator_config_error("No items in list.");
    }
    if (VAL_INTEGER != valueListTemp.type) {
        mediator_config_error("RECORD list items must be integers.");
    }

    cfg_dns_dedup.type_list = g_new0(int, 35);

    for (i = 0; i < valueListTemp.rvals->len; i++) {
        /* turn types of records "on" */
        rval = &g_array_index(valueListTemp.rvals, fbRecordValue_t, i);
        VLT_DEBUG_GET(i, "int (%" PRId64 ")", rval->v.s64);
        if (rval->v.s64 > 34) {
            mediator_config_error("Invalid RECORD Type. "
                                  "Valid Types: 0,1,2,5,6,12,15,16,28,33");
        }
        cfg_dns_dedup.type_list[rval->v.s64] = 1;
    }

    resetValueListTemp();
}

static void
parseValueListItems(
    char  *val,
    int    val_type)
{
    fbRecordValue_t  rval = FB_RECORD_VALUE_INIT;
    GError          *err  = NULL;
    gboolean         isv6;
    int              list_type;

    /* map HEXADECIMAL to INTEGER for a list's contents */
    list_type = ((VAL_HEXADECIMAL == val_type) ? VAL_INTEGER : val_type);
    if (valueListTemp.rvals->len == 0) {
        valueListTemp.type = list_type;
    } else if (valueListTemp.type != list_type) {
        mediator_config_error(
            "Value lists must contain only one type of value;"
            " attempting to add a %s to a list of %s",
            valueTypeName(list_type), valueTypeName(valueListTemp.type));
    }

    switch (val_type) {
      case VAL_INTEGER:
        errno = 0;
        rval.v.s64 = (int64_t)strtoll(val, NULL, 10);
        if (ERANGE == errno || rval.v.s64 < 0) {
            mediator_config_error("Value %s exceeds maximum", val);
        }
        VLT_DEBUG_SET("int (%" PRId64 ")", rval.v.s64);
        break;
      case VAL_HEXADECIMAL:
        errno = 0;
        rval.v.s64 = (int64_t)strtoll(val, NULL, 16);
        if (ERANGE == errno || rval.v.s64 < 0) {
            mediator_config_error("Value %s exceeds maximum", val);
        }
        VLT_DEBUG_SET("hex (%#" PRIx64 ")", rval.v.s64);
        break;
      case VAL_DOUBLE:
        rval.v.dbl = strtod(val, NULL);
        VLT_DEBUG_SET("double (%f)", rval.v.dbl);
        break;
      case VAL_IP:
        if (!mdUtilParseIP(&rval, val, &isv6, &err)) {
            mediator_config_error("%s", err->message);
        }
#if VALUELISTTEMP_DEBUG
        if (isv6) {
            char  ipv6[64];
            snprintf(ipv6, sizeof(ipv6),
                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
                     ":%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                     rval.v.ip6[0], rval.v.ip6[1],
                     rval.v.ip6[2], rval.v.ip6[3],
                     rval.v.ip6[4], rval.v.ip6[5],
                     rval.v.ip6[6], rval.v.ip6[7],
                     rval.v.ip6[8], rval.v.ip6[9],
                     rval.v.ip6[10], rval.v.ip6[11],
                     rval.v.ip6[12], rval.v.ip6[13],
                     rval.v.ip6[14], rval.v.ip6[15]);
            VLT_DEBUG_SET("ipv6 (%s)", ipv6);
        } else {
            VLT_DEBUG_SET("ipv4 (%#10x)", rval.v.ip4);
        }
#endif  /* VALUELISTTEMP_DEBUG */
        break;
      case VAL_QSTRING:
        rval.stringbuf = g_string_new(val);
        rval.v.varfield.buf = (uint8_t *)rval.stringbuf->str;
        rval.v.varfield.len = strlen(val);
        VLT_DEBUG_SET("string (%s)", rval.stringbuf->str);
        break;
      case VAL_ATOM:
        /* work-around for incorrect line number */
        ++lineNumber;
        mediator_config_error("Lists of bare words are not supported;"
                              " use double-quoted strings instead");
        break;
      default:
        /* work-around for incorrect line number */
        ++lineNumber;
        mediator_config_error("Lists of %s values are not supported.",
                              valueTypeName(val_type));
        break;
    }

    g_array_append_val(valueListTemp.rvals, rval);

    free(val);
}

static void
resetValueListTemp(
    void)
{
    fbRecordValue_t *rval;
    unsigned int     i;

    VLT_DEBUG_RESET();

    if (NULL == valueListTemp.rvals) {
        valueListTemp.rvals = g_array_new(TRUE, TRUE, sizeof(fbRecordValue_t));
    } else {
        if (valueListTemp.type == VAL_QSTRING) {
            for (i = 0; i < valueListTemp.rvals->len; ++i) {
                rval = &g_array_index(valueListTemp.rvals, fbRecordValue_t, i);
                g_string_free(rval->stringbuf, TRUE);
            }
        }
        g_array_set_size(valueListTemp.rvals, 0);
    }

    valueListTemp.type = -1;
    valueListTemp.wild = FALSE;
}

static void
parseExporterFields(
    void)
{
    mdFieldEntry_t  *fieldList;
    mdFieldEntry_t **item;
    fbRecordValue_t *rval;
    unsigned int     i;
    gboolean         dpiInFieldList;
    GError          *err = NULL;

    REQUIRE_NOTNULL(expToBuild);
    if (valueListTemp.rvals->len && valueListTemp.type != VAL_QSTRING) {
        mediator_config_error(
            "Custom list FIELDS must contain quoted strings");
    }

    fieldList = NULL;
    item = &fieldList;

    dpiInFieldList = FALSE;
    for (i = 0; i < valueListTemp.rvals->len; i++) {
        rval = &g_array_index(valueListTemp.rvals, fbRecordValue_t, i);
        VLT_DEBUG_GET(i, "string (%s)", rval->v.varfield.buf);
        if (g_strcmp0((char *)rval->v.varfield.buf, "dpi") == 0 ||
            g_strcmp0((char *)rval->v.varfield.buf, "DPI") == 0)
        {
            dpiInFieldList = TRUE;
        } else {
            *item = mdMakeFieldEntryFromName(
                (const char *)rval->v.varfield.buf, FALSE, &err);
            if (NULL == *item) {
                mediator_config_error("Error setting FIELDS: %s", err->message);
            }
            item = &((*item)->next);
        }
    }
    /* FIXME: the logic of this "if" needs to be in the exporter */
    if (dpiInFieldList) {
        expToBuild->basic_list_dpi = TRUE;
        expToBuild->custom_list_dpi = TRUE;
    } else {
        expToBuild->flowDpiStrip = TRUE;
    }
    if (!mdExporterSetCustomList(expToBuild, fieldList, &err)) {
        mediator_config_error("Error setting FIELDS: %s", err->message);
    }

    resetValueListTemp();
}

static void
parseExporterDpiFieldList(
    void)
{
    fbRecordValue_t *rval;
    unsigned int     i;
    GError          *err = NULL;

    REQUIRE_NOTNULL(expToBuild);
    if (VAL_INTEGER != valueListTemp.type) {
        mediator_config_error("DPI_FIELD_LIST must contain integers.");
    }

    for (i = 0; i < valueListTemp.rvals->len; i++) {
        rval = &g_array_index(valueListTemp.rvals, fbRecordValue_t, i);
        VLT_DEBUG_GET(i, "int (%" PRId64 ")", rval->v.s64);
        if (rval->v.s64 < 0 || rval->v.s64 > UINT16_MAX) {
            mediator_config_error("Illegal DPI FIELD ID %" PRId64,
                                  rval->v.s64);
        }
        if (!mdExporterInsertDPIFieldItem(expToBuild, rval->v.s64, &err)) {
            mediator_config_error("Error setting DPI_FIELD_LIST: %s",
                                  err->message);
        }
    }

    resetValueListTemp();
}

static void
parseMySQLParams(
    char  *user,
    char  *pw,
    char  *db,
    char  *host,
    char  *table)
{
    REQUIRE_NOTNULL(expToBuild);
    mediator_config_error("MYSQL temporarily disabled");

    if (!mdExporterAddMySQLInfo(expToBuild, user, pw, db, host, table)) {
        exit(-1);
    }
    free(user);
    free(pw);
    free(db);
    free(host);
    free(table);
}

static void
parseExporterRemoveUploaded(
    void)
{
    REQUIRE_NOTNULL(expToBuild);

    mdExporterSetRemoveUploaded(expToBuild);
}


/**
 *  Creates a new information element of type octetArray using 'name' and
 *  'ie_num' and CERT_PEN.  Exits the program with an error if either 'name'
 *  or 'ie_num' is already in use.  The 'app_num' parameter is a pointer in
 *  order to distinguish "not given" (NULL) from zero.
 */
static void
parseUserInfoElement(
    int         ie_num,
    char       *name,
    const int  *app_num)
{
    void                  *table;
    fbInfoElement_t        add_element = FB_IE_NULL;
    const fbInfoElement_t *ie;
    fbInfoModel_t         *md_info_model;

    if (ie_num > INT16_MAX || ie_num < 1) {
        mediator_config_error("Invalid Information Element ID number %d. "
                              "Number must be between 1 and %d",
                              ie_num, INT16_MAX);
    }
    if (app_num) {
        if (*app_num > UINT16_MAX || *app_num < 1) {
            mediator_config_error("Invalid Application ID number %d. "
                                  "Number must be between 1 and %d",
                                  *app_num, UINT16_MAX);
        }
    }
    if (0 == strlen(name) || !g_ascii_isgraph(*name)) {
        mediator_config_error("Will not create an element named \"%s\"", name);
    }

    if (user_elements == NULL) {
        /* add one for final NULL element */
        user_elements = g_new0(fbInfoElement_t, MAX_USER_ELEMENTS + 1);
    } else if (numUserElements >= MAX_USER_ELEMENTS) {
        mediator_config_error("Max Limit reached on adding user-defined"
                              " Information Elements");
    }

    memset(&add_element, 0, sizeof(fbInfoElement_t));

    add_element.num = ie_num;
    add_element.ent = CERT_PEN;
    add_element.len = FB_IE_VARLEN;
    add_element.name = g_strdup(name);
    add_element.flags = 0;
    add_element.type = FB_OCTET_ARRAY;

    md_info_model = mdInfoModel();
    if (fbInfoModelContainsElement(md_info_model, &add_element)) {
        mediator_config_error(
            "Cannot add element %s, id=%d, pen=%d since"
            " it conflicts with an existing element.",
            add_element.name, add_element.num, add_element.ent);
    }

    fbInfoModelAddElement(md_info_model, &add_element);
    ie = fbInfoModelGetElementByName(md_info_model, add_element.name);
    if (NULL == ie) {
        mediator_config_error("Failed to add element %s id=%d",
                              add_element.name, add_element.num);
    }

    memcpy((user_elements + numUserElements), &add_element,
           sizeof(fbInfoElement_t));
    numUserElements++;

    if (app_num) {
        if (custom_tables) {
            mediator_config_error(
                "Invalid application label for USER_IE "
                "Add Information Element Number to DPI_CONFIG tables.");
        }
        if (!default_tables) {
            mdBuildDefaultTableHash();
            default_tables = TRUE;
        }

        table = mdGetTableByApplication(*app_num);
        if (!table) {
            mediator_config_error("Not a valid application label for USER_IE");
        }

        if (!mdInsertTableItem(table, fbInfoElementGetName(ie))) {
            mediator_config_error("Information Element already defined.");
        }
    }

    free(name);
}


void
parseTransportAsMethod(
    mdConfTransport_t      transport,
    mdCollectionMethod_t  *colMethod,
    mdExportMethod_t      *expMethod)
{
    mdCollectionMethod_t  cm;
    mdExportMethod_t      em;

    if (NULL == colMethod) { colMethod = &cm; }
    if (NULL == expMethod) { expMethod = &em; }

    switch (transport) {
      case MD_CONF_TPORT_NONE:
        g_error("transport was not properly set");
      case MD_CONF_TPORT_DIRECTORY_POLL:
        *colMethod = CM_DIR_POLL;
        if (expMethod != &em) {
            mediator_config_error("Invalid exporter method DIRECTORY_POLL");
        }
        break;
      case MD_CONF_TPORT_ROTATING_FILES:
        if (colMethod != &cm) {
            mediator_config_error("Invalid collector method ROTATING_FILES");
        }
        *expMethod = EM_ROTATING_FILES;
        break;
      case MD_CONF_TPORT_SINGLE_FILE:
        *colMethod = CM_SINGLE_FILE;
        *expMethod = EM_SINGLE_FILE;
        break;
      case MD_CONF_TPORT_TCP:
        *colMethod = CM_TCP;
        *expMethod = EM_TCP;
        break;
      case MD_CONF_TPORT_UDP:
        *colMethod = CM_UDP;
        *expMethod = EM_UDP;
        break;
    }
}


static void
parseDNSDedupConfigEnd(
    void)
{
    mdExporter_t *exp = NULL;

    exp = findExporter(cfg_dns_dedup.temp_name, "DNS_DEDUP");
    if (!exp->dns_dedup) {
        mediator_config_error("Exporter \"%s\" for DNS_DEDUP config"
                              " block does not have DNS_DEDUP enabled",
                              mdExporterGetName(exp));
    }

    if (exp->dedup && exp->exportFormat == EF_TEXT) {
        mediator_config_error("Exporter already configured for DEDUP. "
                              "Define a separate TEXT EXPORTER for DNS_DEDUP");
    }

    md_dns_dedup_configure_state(exp->dns_dedup,
                                 cfg_dns_dedup.type_list,
                                 cfg_dns_dedup.max_hit,
                                 cfg_dns_dedup.flush_timeout,
                                 cfg_dns_dedup.lastseen,
                                 cfg_dns_dedup.map,
                                 cfg_dns_dedup.exportname);

    free(cfg_dns_dedup.temp_name);
    cfg_dns_dedup.temp_name = NULL;
    cfg_dns_dedup.type_list = NULL;
    cfg_dns_dedup.map = NULL;
    cfg_dns_dedup.max_hit = 0;
    cfg_dns_dedup.flush_timeout = 0;
    cfg_dns_dedup.lastseen = FALSE;
    cfg_dns_dedup.exportname = FALSE;
}

static void
parseSSLConfigBegin(
    char  *exp_name)
{
    mdExporter_t *exp;

    exp = findExporter(exp_name, "SSL_CONFIG");
    etemp = exp;
    resetValueListTemp();
    free(exp_name);
}


static void
parseSSLConfigTypeList(
    mdSSLConfigType_t   type)
{
    const char      *listname[1 + MD_SSLCONFIG_TYPE_MAX] = {
        "ERROR", "ISSUER", "SUBJECT", "OTHER", "EXTENSIONS"
    };
    fbRecordValue_t *rval;
    unsigned int     i;
    uint8_t         *enabled;
    GError          *err = NULL;

    REQUIRE_NOTNULL(etemp);
    g_assert(type > 0 && type <= MD_SSLCONFIG_TYPE_MAX);
    g_assert(type < (sizeof(listname) / sizeof(listname[0])));

    enabled = g_new0(uint8_t, mdSSLConfigArraySize[type]);

    if (valueListTemp.wild) {
        /* TURN THEM ALL ON */
        for (i = 0; i < mdSSLConfigArraySize[type]; i++) {
            enabled[i] = 1;
        }
        if (!mdExporterSetSSLConfig(etemp, enabled, type, &err)) {
            mediator_config_error("Error setting %s in SSL_CONFIG block: %s",
                                  listname[type], err->message);
        }
        resetValueListTemp();
        return;
    }

    if (valueListTemp.rvals->len == 0) {
        mediator_config_error("No items in %s list.", listname[type]);
    }
    if (VAL_INTEGER != valueListTemp.type) {
        mediator_config_error("%s list must contain integers", listname[type]);
    }

    if (MD_SSLCONFIG_EXTENSIONS == type) {
        /* FIXME: Seems we could do better than having this set of values
         * specified here */
        for (i = 0; i < valueListTemp.rvals->len; i++) {
            rval = &g_array_index(valueListTemp.rvals, fbRecordValue_t, i);
            VLT_DEBUG_GET(i, "int (%" PRId64 ")", rval->v.s64);
            switch (rval->v.s64) {
              case 14:
              case 15:
              case 16:
              case 17:
              case 18:
              case 29:
              case 31:
              case 32:
                enabled[rval->v.s64] = 1;
                break;
              default:
                mediator_config_error(
                    "SSL_CONFIG %s list only allows values"
                    " 14--18 inclusive, 29, 31, 32",
                    listname[type]);
                break;
            }
        }
    } else {
        for (i = 0; i < valueListTemp.rvals->len; i++) {
            rval = &g_array_index(valueListTemp.rvals, fbRecordValue_t, i);
            VLT_DEBUG_GET(i, "int (%" PRId64 ")", rval->v.s64);
            if (rval->v.s64 >= mdSSLConfigArraySize[type]) {
                mediator_config_error(
                    "SSL_CONFIG %s list only allows values 0--%u inclusive",
                    listname[type], mdSSLConfigArraySize[type] - 1);
            }
            /* turn types of records "on" */
            enabled[rval->v.s64] = 1;
        }
    }

    if (!mdExporterSetSSLConfig(etemp, enabled, type, &err)) {
        mediator_config_error("Error setting %s in SSL_CONFIG block: %s",
                              listname[type], err->message);
    }

    resetValueListTemp();
}


static void
parseDedupConfigBegin(
    char  *exp_name)
{
    mdExporter_t *exp = NULL;
    GError       *err = NULL;

    exp = findExporter(exp_name, "DEDUP_CONFIG");

    if (!mdExporterEnableGeneralDedup(exp, FALSE, &err)) {
        mediator_config_error("Unable to create DEDUP_CONFIG block for %s: %s",
                              mdExporterGetName(exp), err->message);
    }

    if (exp->exportFormat == EF_TEXT) {
        if (exp->dns_dedup) {
            mediator_config_error(
                "Exporter already configured for DNS_DEDUP."
                " Define a separate TEXT EXPORTER for DEDUP");
        } else if (exp->ssl_dedup) {
            mediator_config_error(
                "Exporter already configured for SSL_DEDUP."
                " Define a separate TEXT EXPORTER for DEDUP");
        }
    }

    /* set temp node */
    etemp = exp;
    etemp->dedup = md_dedup_new_dedup_state();

    resetValueListTemp();

    free(exp_name);
}

static void
generalDedupCheckElementType(
    const fbInfoElement_t  *ie)
{
    switch (fbInfoElementGetType(ie)) {
      case FB_OCTET_ARRAY:
      case FB_STRING:
        break;
      default:
        if (fbInfoElementIsList(ie)) {
            mediator_config_error(
                "May not dedup %s since it is a list element",
                fbInfoElementGetName(ie));
        }
        mediator_config_error(
            "May not dedup %s; only string and octetArray element types"
            " are currently supported", fbInfoElementGetName(ie));
    }
}

static void
parseFileList(
    char                   *file,
    mdAcceptFilterField_t   field,
    char                   *mapname)
{
    int                    sip;
    md_dedup_ie_t         *ietab = NULL;
    smFieldMap_t          *map = NULL;
    const fbInfoElement_t *ieList[MAX_VALUE_LIST];
    const fbInfoElement_t *compIE = NULL;
    fbRecordValue_t       *rval;
    unsigned int           i;
    fbInfoModel_t         *md_info_model = mdInfoModel();

    REQUIRE_NOTNULL(etemp);

    if (valueListTemp.rvals->len == 0) {
        mediator_config_error("No items in FILE List.");
    }

    switch (field) {
      case SIP_V4:
      case SIP_ANY:
        sip = 1;
        break;
      case DIP_V4:
      case DIP_ANY:
        sip = 0;
        break;
      case FLOWKEYHASH:
        sip = 2;
        break;
      default:
        mediator_config_error(
            "Invalid Field in DEDUP_CONFIG."
            "  SIP, DIP, and FLOWKEYHASH are the only valid fields.");
    }

    if (mapname) {
        map = findFieldMap(mapname, FALSE);
        free(mapname);
    }

    if (VAL_QSTRING == valueListTemp.type) {
        for (i = 0; i < valueListTemp.rvals->len; i++) {
            rval = &g_array_index(valueListTemp.rvals, fbRecordValue_t, i);
            VLT_DEBUG_GET(i, "string (%s)", rval->v.varfield.buf);
            compIE = fbInfoModelGetElementByName(
                md_info_model, (const char *)rval->v.varfield.buf);
            if (NULL == compIE) {
                mediator_config_error("No such dedup IE \"%s\" in infomodel",
                                      (char *)rval->v.varfield.buf);
                return;
            }
            generalDedupCheckElementType(compIE);
            ieList[i] = compIE;
        }
    } else if (VAL_INTEGER == valueListTemp.type) {
        for (i = 0; i < valueListTemp.rvals->len; i++) {
            rval = &g_array_index(valueListTemp.rvals, fbRecordValue_t, i);
            VLT_DEBUG_GET(i, "int (%" PRIu64 ")", rval->v.s64);
            if (rval->v.s64 < 1 || rval->v.s64 > INT16_MAX) {
                mediator_config_error("Illegal elementId %" PRId64,
                                      rval->v.s64);
            }
            compIE = fbInfoModelGetElementByID(
                md_info_model, rval->v.s64, CERT_PEN);
            if (NULL == compIE) {
                mediator_config_error(
                    "No such dedup IE %" PRId64 " in CERT infomodel",
                    rval->v.s64);
                return;
            }
            generalDedupCheckElementType(compIE);
            ieList[i] = compIE;
        }
    } else {
        mediator_config_error(
            "PREFIX requires a list of quoted strings or integers");
    }

    if (etemp->exportFormat == EF_IPFIX) {
        /* create a table for each element in the list bc it needs a template
         * for each element in the list */
        for (i = 0; i < valueListTemp.rvals->len; i++) {
            ietab = md_dedup_add_ie_table(etemp->dedup, file, map,
                                          ieList[i], sip);
            if (!ietab) {
                mediator_config_error(
                    "Information Element \"%s\" already in FILE Table.",
                    fbInfoElementGetName(ieList[i]));
            }
        }
    } else {
        ietab = md_dedup_add_ie_table(etemp->dedup, file, map, ieList[0], sip);
        if (!ietab) {
            mediator_config_error(
                "Information Element \"%s\" already in FILE Table.",
                fbInfoElementGetName(ieList[0]));
        }
        if ((fbInfoElementCheckIdent(ieList[0], CERT_PEN, 244))
            && (valueListTemp.rvals->len > 1))
        {
            mediator_config_error("244 (SSL) must exist in a list by itself.");
        }
        for (i = 1; i < valueListTemp.rvals->len; i++) {
            if (fbInfoElementCheckIdent(ieList[i], CERT_PEN, 244)) {
                mediator_config_error(
                    "244 (SSL) must exist in a list by itself.");
            }
            md_dedup_add_ie(etemp->dedup, ietab, ieList[i]);
        }
    }

    free(file);
    resetValueListTemp();
}

/**
 *  Parses 'number' as a number in 'base', frees 'number' and returns the
 *  result.  Exits the program if parsing fails or the value is negative or
 *  greater than INT_MAX.
 */
static int
parseNumericValue(
    char  *number,
    int    base)
{
    long  val;

    errno = 0;
    val = strtol(number, NULL, base);
    if (val < 0 || val > INT_MAX) {
        mediator_config_error("Value %s exceeds maximum", number);
    }
    free(number);
    return val;
}

static void
parseSSLCertDedup(
    void)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(etemp);

    if (etemp->dns_dedup && (etemp->exportFormat == EF_TEXT)) {
        mediator_config_error("Exporter already configured for DNS_DEDUP."
                              " Define a separate TEXT EXPORTER for SSL_DEDUP");
    } else if (etemp->dedup && (etemp->exportFormat == EF_TEXT)) {
        mediator_config_error("Exporter already configured for DEDUP."
                              " Define a separate TEXT EXPORTER for SSL_DEDUP");
    }

    /* may have already been enabled with SSL_DEDUP_ONLY */
    if (!mdExporterEnableSslDedup(etemp, FALSE, &err)) {
        mediator_config_error("Error setting SSL_DEDUP: %s", err->message);
    }
}

static void
parseSSLCertFile(
    char  *filename)
{
    REQUIRE_NOTNULL(etemp);

    if (etemp->exportFormat != EF_TEXT) {
        mediator_config_error("CERT_FILE only valid for TEXT exporters");
    }

    md_ssl_dedup_configure_state(etemp->ssl_dedup, 0, 0, filename, NULL, FALSE);

    free(filename);
}

static void
parseExporterSslDedup(
    gboolean   only)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterEnableSslDedup(expToBuild, only, &err)) {
        mediator_config_error("Error setting SSL_DEDUP%s: %s",
                              ((only) ? "_ONLY" : ""), err->message);
    }
}


static void
parseExporterDedupOnly(
    void)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterEnableGeneralDedup(expToBuild, TRUE, &err)) {
        mediator_config_error("Error setting DEDUP_ONLY: %s", err->message);
    }
}

static void
parseExporterCertDigest(
    smCertDigestType_t   method)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterEnableCertDigest(expToBuild, method, &err)) {
        mediator_config_error("Error enabling certificate %s hashing: %s",
                              ((SM_DIGEST_MD5 == method) ? "MD5" : "SHA1"),
                              err->message);
    }
}

static void
parseExporterGzipFiles(
    void)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    if (!mdExporterSetGZIPFiles(expToBuild, &err)) {
        mediator_config_error("Error setting GZIP_FILES: %s", err->message);
    }
}

static void
parseExporterMovePath(
    char  *path)
{
    GError *err = NULL;

    REQUIRE_NOTNULL(expToBuild);

    /* SetMovePath makes a copy of path */
    if (!mdExporterSetMovePath(expToBuild, path, &err)) {
        mediator_config_error("Error setting MOVE: %s", err->message);
    }

    free(path);
}

static void
parseMapLine(
    char  *label)
{
    smFieldMapKV_t  *value;
    smFieldMapKV_t  *key;
    fbRecordValue_t *rval;
    unsigned int     i;
    uint32_t         maxval;

    REQUIRE_NOTNULL(mapitem);

    /* vlanId is 12 bits */
    maxval = (VLAN == mapitem->field) ? 0xfff : UINT32_MAX;

    if (valueListTemp.rvals->len == 0) {
        mediator_config_error("No items in %s_MAP %s list.",
                              ((VLAN == mapitem->field) ? "VLAN" : "OBID"),
                              mapitem->name);
    }
    if (valueListTemp.type != VAL_INTEGER) {
        mediator_config_error("%s_MAP %s must contain a list of integers",
                              ((VLAN == mapitem->field) ? "VLAN" : "OBID"),
                              mapitem->name);
    }

    /* entry 0 is reserved for OTHER; must substract 1 when checking limit */

    if (mapitem->labels == NULL) {
        mapitem->labels = (char **)calloc(MAX_MAPS, sizeof(char *));
    } else if (mapitem->count >= MAX_MAPS - 1) {
        mediator_config_error("%s_MAP %s Maximum number of labels reached",
                              ((VLAN == mapitem->field) ? "VLAN" : "OBID"),
                              mapitem->name);
    }

    ++mapitem->count;
    mapitem->labels[mapitem->count] = g_strdup(label);
    free(label);

    for (i = 0; i < valueListTemp.rvals->len; i++) {
        rval = &g_array_index(valueListTemp.rvals, fbRecordValue_t, i);
        VLT_DEBUG_GET(i, "int (%" PRId64 ")", rval->v.s64);
        if (rval->v.s64 > (int64_t)maxval) {
            mediator_config_error("Entry's value of %" PRId64 " is larger than"
                                  " %s_MAP's allowed maximum of %" PRIu32,
                                  rval->v.s64,
                                  ((VLAN == mapitem->field) ? "VLAN" : "OBID"),
                                  maxval);
        }
        key = g_slice_new0(smFieldMapKV_t);
        key->val = (uint32_t)rval->v.s64;
        value = g_slice_new0(smFieldMapKV_t);
        value->val = mapitem->count;
        smHashTableInsert(mapitem->table, (uint8_t *)key, (uint8_t *)value);
    }

    resetValueListTemp();
}

/* Handle OBID_MAP or VLAN_MAP */
static void
parseMapBegin(
    mdAcceptFilterField_t   map_type,
    char                   *name)
{
    if (!(VLAN == map_type || OBDOMAIN == map_type)) {
        mediator_config_error("Unexpected map type value %d", map_type);
    }
    if (NULL != findFieldMap(name, TRUE)) {
        mediator_config_error("Cannot create %s_MAP named \"%s\":"
                              " name already in use by another map",
                              ((VLAN == map_type) ? "VLAN" : "OBID"), name);
    }

    mapitem = g_slice_new0(smFieldMap_t);
    mapitem->field = map_type;
    mapitem->name = g_strdup(name);
    mapitem->table = smCreateHashTable(sizeof(uint32_t), md_free_hash_key,
                                       md_free_hash_key);
    resetValueListTemp();
    attachHeadToSLL((mdSLL_t **)&(maptemp), (mdSLL_t *)mapitem);
    free(name);
}

static void
parseMapEnd(
    mdAcceptFilterField_t   map_type)
{
    REQUIRE_NOTNULL(mapitem);

    if (mapitem->field != map_type) {
        mediator_config_error("Unexpected map type value %d", map_type);
    }
    if (mapitem->labels == NULL) {
        mediator_config_error("No labels were created in MAP block.");
    }
    if ((mapitem->labels[0] == NULL) && !mapitem->discard) {
        mediator_config_error(
            "Must specify either OTHER Map List or DISCARD_OTHER");
    }

    mapitem = NULL;
}

static void
parseMapOther(
    char  *name)
{
    REQUIRE_NOTNULL(mapitem);

    if (mapitem->discard) {
        mediator_config_error("DISCARD_OTHER not valid with OTHER list");
    }
    if (mapitem->labels == NULL) {
        mapitem->labels = (char **)calloc(MAX_MAPS, sizeof(char *));
    }

    mapitem->labels[0] = g_strdup(name);
    mapitem->count++;
}

static void
parseMapDiscard(
    void)
{
    REQUIRE_NOTNULL(mapitem);

    if (mapitem->labels[0] != NULL) {
        mediator_config_error("OTHER is not valid with DISCARD_OTHER");
    }
    mapitem->discard = TRUE;
}


int
yyerror(
    const char  *s)
{
    /* mediator config error subtracts one */
    lineNumber++;
    mediator_config_error("%s", s);
    return 0;
}
