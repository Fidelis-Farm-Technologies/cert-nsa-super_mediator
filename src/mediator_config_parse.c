/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.3"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Using locations.  */
#define YYLSP_NEEDED 0



/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     END_OF_FILE = 0,
     EOS = 258,
     COMMA = 259,
     LEFT_SQ_BRACKET = 260,
     RIGHT_SQ_BRACKET = 261,
     LEFT_PAREN = 262,
     RIGHT_PAREN = 263,
     WILD = 264,
     TOK_COLLECTOR = 265,
     TOK_EXPORTER = 266,
     TOK_DNS_DEDUP = 267,
     TOK_DNS_DEDUP_ONLY = 268,
     TOK_NO_STATS = 269,
     TOK_PORT = 270,
     TOK_HOSTNAME = 271,
     TOK_PATH = 272,
     TOK_DELIM = 273,
     TOK_PRINT_HEADER = 274,
     TOK_MOVE = 275,
     TOK_DELETE = 276,
     TOK_LOCK = 277,
     TOK_UDP_TEMPLATE_TIMEOUT = 278,
     TOK_COLLECTOR_FILTER = 279,
     TOK_ROTATE_INTERVAL = 280,
     TOK_END = 281,
     TOK_FILTER = 282,
     TOK_LOG_FILE = 283,
     TOK_FLOW_ONLY = 284,
     TOK_DPI_ONLY = 285,
     TOK_POLL = 286,
     TOK_MAX_HIT_COUNT = 287,
     TOK_FLUSH_TIMEOUT = 288,
     TOK_LOG_LEVEL = 289,
     TOK_BASE_64 = 290,
     TOK_LAST_SEEN = 291,
     TOK_REMOVE_EMPTY_FILES = 292,
     TOK_STATS_ONLY = 293,
     TOK_TABLE = 294,
     TOK_DPI_CONFIG = 295,
     TOK_MULTI_FILES = 296,
     TOK_NO_INDEX = 297,
     TOK_TIMESTAMP_FILES = 298,
     TOK_NO_FLOW_STATS = 299,
     TOK_PID_FILE = 300,
     TOK_MY_REMOVE = 301,
     TOK_MY_USER = 302,
     TOK_MY_PW = 303,
     TOK_MY_DB = 304,
     TOK_MY_HOST = 305,
     TOK_MY_TABLE = 306,
     TOK_FIELDS = 307,
     TOK_DPI_FIELD_LIST = 308,
     TOK_DPI_DELIMITER = 309,
     TOK_STATS_TIMEOUT = 310,
     TOK_USERIE = 311,
     TOK_AND_FILTER = 312,
     TOK_ESCAPE = 313,
     TOK_DNSRR_ONLY = 314,
     TOK_FULL = 315,
     TOK_LOG_DIR = 316,
     TOK_RECORDS = 317,
     TOK_DNSRESPONSE_ONLY = 318,
     TOK_SSL_CONFIG = 319,
     TOK_ISSUER = 320,
     TOK_SUBJECT = 321,
     TOK_OTHER = 322,
     TOK_EXTENSIONS = 323,
     TOK_DEDUP_PER_FLOW = 324,
     TOK_DEDUP_CONFIG = 325,
     TOK_FILE_PREFIX = 326,
     TOK_MERGE_TRUNCATED = 327,
     TOK_SSL_DEDUP = 328,
     TOK_CERT_FILE = 329,
     TOK_SSL_DEDUP_ONLY = 330,
     TOK_MD5 = 331,
     TOK_SHA1 = 332,
     TOK_GZIP = 333,
     TOK_DNSRR = 334,
     TOK_DEDUP_ONLY = 335,
     TOK_NO_FLOW = 336,
     TOK_OBID_MAP = 337,
     TOK_VLAN_MAP = 338,
     TOK_MAP = 339,
     TOK_DISCARD = 340,
     TOK_ADD_EXPORTER_NAME = 341,
     TOK_DECOMPRESS_DIRECTORY = 342,
     TOK_METADATA_EXPORT = 343,
     TOK_GEN_TOMBSTONE = 344,
     TOK_TOMBSTONE_CONFIGURED_ID = 345,
     TOK_TOMBSTONE_CONFIG = 346,
     TOK_PRESERVE_OBDOMAIN = 347,
     TOK_REWRITE_SSL_CERTS = 348,
     TOK_DISABLE = 349,
     TOK_INVARIANT = 350,
     TOK_MAX_BYTES = 351,
     TOK_MAX_SECONDS = 352,
     TOK_IPSET_FILE = 353,
     VAL_ATOM = 354,
     VAL_DATETIME = 355,
     VAL_DOUBLE = 356,
     VAL_HEXADECIMAL = 357,
     VAL_INTEGER = 358,
     VAL_IP = 359,
     VAL_QSTRING = 360,
     VAL_TRANSPORT = 361,
     VAL_EXPORT_FORMAT = 362,
     VAL_OPER = 363,
     VAL_FIELD = 364,
     VAL_LOGLEVEL = 365,
     VAL_CERT_DIGEST = 366
   };
#endif
/* Tokens.  */
#define END_OF_FILE 0
#define EOS 258
#define COMMA 259
#define LEFT_SQ_BRACKET 260
#define RIGHT_SQ_BRACKET 261
#define LEFT_PAREN 262
#define RIGHT_PAREN 263
#define WILD 264
#define TOK_COLLECTOR 265
#define TOK_EXPORTER 266
#define TOK_DNS_DEDUP 267
#define TOK_DNS_DEDUP_ONLY 268
#define TOK_NO_STATS 269
#define TOK_PORT 270
#define TOK_HOSTNAME 271
#define TOK_PATH 272
#define TOK_DELIM 273
#define TOK_PRINT_HEADER 274
#define TOK_MOVE 275
#define TOK_DELETE 276
#define TOK_LOCK 277
#define TOK_UDP_TEMPLATE_TIMEOUT 278
#define TOK_COLLECTOR_FILTER 279
#define TOK_ROTATE_INTERVAL 280
#define TOK_END 281
#define TOK_FILTER 282
#define TOK_LOG_FILE 283
#define TOK_FLOW_ONLY 284
#define TOK_DPI_ONLY 285
#define TOK_POLL 286
#define TOK_MAX_HIT_COUNT 287
#define TOK_FLUSH_TIMEOUT 288
#define TOK_LOG_LEVEL 289
#define TOK_BASE_64 290
#define TOK_LAST_SEEN 291
#define TOK_REMOVE_EMPTY_FILES 292
#define TOK_STATS_ONLY 293
#define TOK_TABLE 294
#define TOK_DPI_CONFIG 295
#define TOK_MULTI_FILES 296
#define TOK_NO_INDEX 297
#define TOK_TIMESTAMP_FILES 298
#define TOK_NO_FLOW_STATS 299
#define TOK_PID_FILE 300
#define TOK_MY_REMOVE 301
#define TOK_MY_USER 302
#define TOK_MY_PW 303
#define TOK_MY_DB 304
#define TOK_MY_HOST 305
#define TOK_MY_TABLE 306
#define TOK_FIELDS 307
#define TOK_DPI_FIELD_LIST 308
#define TOK_DPI_DELIMITER 309
#define TOK_STATS_TIMEOUT 310
#define TOK_USERIE 311
#define TOK_AND_FILTER 312
#define TOK_ESCAPE 313
#define TOK_DNSRR_ONLY 314
#define TOK_FULL 315
#define TOK_LOG_DIR 316
#define TOK_RECORDS 317
#define TOK_DNSRESPONSE_ONLY 318
#define TOK_SSL_CONFIG 319
#define TOK_ISSUER 320
#define TOK_SUBJECT 321
#define TOK_OTHER 322
#define TOK_EXTENSIONS 323
#define TOK_DEDUP_PER_FLOW 324
#define TOK_DEDUP_CONFIG 325
#define TOK_FILE_PREFIX 326
#define TOK_MERGE_TRUNCATED 327
#define TOK_SSL_DEDUP 328
#define TOK_CERT_FILE 329
#define TOK_SSL_DEDUP_ONLY 330
#define TOK_MD5 331
#define TOK_SHA1 332
#define TOK_GZIP 333
#define TOK_DNSRR 334
#define TOK_DEDUP_ONLY 335
#define TOK_NO_FLOW 336
#define TOK_OBID_MAP 337
#define TOK_VLAN_MAP 338
#define TOK_MAP 339
#define TOK_DISCARD 340
#define TOK_ADD_EXPORTER_NAME 341
#define TOK_DECOMPRESS_DIRECTORY 342
#define TOK_METADATA_EXPORT 343
#define TOK_GEN_TOMBSTONE 344
#define TOK_TOMBSTONE_CONFIGURED_ID 345
#define TOK_TOMBSTONE_CONFIG 346
#define TOK_PRESERVE_OBDOMAIN 347
#define TOK_REWRITE_SSL_CERTS 348
#define TOK_DISABLE 349
#define TOK_INVARIANT 350
#define TOK_MAX_BYTES 351
#define TOK_MAX_SECONDS 352
#define TOK_IPSET_FILE 353
#define VAL_ATOM 354
#define VAL_DATETIME 355
#define VAL_DOUBLE 356
#define VAL_HEXADECIMAL 357
#define VAL_INTEGER 358
#define VAL_IP 359
#define VAL_QSTRING 360
#define VAL_TRANSPORT 361
#define VAL_EXPORT_FORMAT 362
#define VAL_OPER 363
#define VAL_FIELD 364
#define VAL_LOGLEVEL 365
#define VAL_CERT_DIGEST 366




/* Copy the first part of user declarations.  */
#line 1 "mediator_config_parse.y"

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


/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif

#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 392 "mediator_config_parse.y"
{
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
/* Line 193 of yacc.c.  */
#line 723 "mediator_config_parse.c"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 216 of yacc.c.  */
#line 736 "mediator_config_parse.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int i)
#else
static int
YYID (i)
    int i;
#endif
{
  return i;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  4
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   496

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  112
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  150
/* YYNRULES -- Number of rules.  */
#define YYNRULES  297
/* YYNRULES -- Number of states.  */
#define YYNSTATES  518

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   366

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     6,     8,     9,    12,    14,    16,    18,
      20,    22,    24,    26,    28,    30,    32,    34,    36,    38,
      40,    42,    44,    46,    48,    50,    52,    54,    56,    60,
      65,    69,    70,    73,    75,    77,    79,    81,    83,    85,
      87,    89,    91,    93,    95,    98,   102,   106,   110,   114,
     118,   122,   125,   129,   132,   136,   137,   140,   142,   144,
     146,   149,   153,   156,   160,   162,   164,   166,   170,   172,
     174,   176,   178,   180,   182,   184,   186,   191,   196,   201,
     206,   211,   216,   221,   226,   231,   235,   241,   245,   246,
     249,   251,   253,   255,   257,   259,   261,   263,   265,   267,
     269,   271,   273,   275,   277,   279,   281,   283,   285,   287,
     289,   291,   293,   295,   297,   299,   301,   303,   305,   307,
     309,   311,   313,   315,   317,   319,   321,   323,   325,   327,
     329,   331,   334,   337,   341,   345,   348,   352,   356,   360,
     364,   368,   372,   376,   379,   383,   387,   390,   393,   396,
     399,   402,   405,   408,   411,   414,   417,   421,   424,   428,
     429,   432,   434,   436,   438,   441,   445,   449,   452,   455,
     458,   461,   464,   467,   470,   473,   476,   479,   482,   485,
     489,   492,   496,   499,   502,   505,   509,   513,   517,   521,
     525,   529,   533,   537,   541,   542,   545,   547,   549,   551,
     553,   555,   557,   559,   561,   564,   567,   573,   578,   588,
     597,   601,   605,   608,   609,   612,   614,   616,   618,   620,
     622,   624,   626,   628,   632,   634,   637,   639,   641,   644,
     647,   651,   655,   659,   660,   663,   665,   667,   672,   676,
     680,   684,   688,   692,   696,   700,   705,   711,   714,   718,
     722,   725,   726,   729,   731,   733,   735,   737,   739,   741,
     743,   745,   747,   749,   751,   754,   756,   760,   764,   768,
     772,   775,   777,   779,   783,   787,   791,   795,   799,   803,
     806,   807,   810,   812,   814,   816,   818,   822,   826,   829,
     833,   837,   843,   844,   846,   848,   850,   852
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int16 yyrhs[] =
{
     113,     0,    -1,   114,     0,    -1,   115,    -1,    -1,   115,
     116,    -1,     3,    -1,   117,    -1,   130,    -1,   142,    -1,
     167,    -1,   168,    -1,   169,    -1,   170,    -1,   192,    -1,
     194,    -1,   193,    -1,   195,    -1,   196,    -1,   207,    -1,
     219,    -1,   230,    -1,   197,    -1,   177,    -1,   228,    -1,
     245,    -1,   248,    -1,    99,    -1,   118,   120,   119,    -1,
      10,   106,   259,     3,    -1,    10,    26,     3,    -1,    -1,
     120,   121,    -1,     3,    -1,   122,    -1,   123,    -1,   124,
      -1,   125,    -1,   127,    -1,   128,    -1,   129,    -1,   126,
      -1,   141,    -1,   135,    -1,    99,     3,    -1,    15,   261,
       3,    -1,    16,   260,     3,    -1,    16,   104,     3,    -1,
      17,   260,     3,    -1,    31,   261,     3,    -1,    87,   260,
       3,    -1,    22,     3,    -1,    20,   260,     3,    -1,    21,
       3,    -1,   133,   131,   134,    -1,    -1,   131,   132,    -1,
       3,    -1,   141,    -1,   135,    -1,    27,     3,    -1,    27,
      26,     3,    -1,    57,     3,    -1,   137,   139,   138,    -1,
       5,    -1,     6,    -1,   140,    -1,   139,     4,   140,    -1,
      99,    -1,   100,    -1,   103,    -1,   102,    -1,   101,    -1,
     104,    -1,   105,    -1,     9,    -1,   260,   108,    99,     3,
      -1,   260,   108,   136,     3,    -1,   260,   108,   103,     3,
      -1,   260,   108,   102,     3,    -1,   260,   108,   101,     3,
      -1,   260,   108,   105,     3,    -1,   260,   108,   104,     3,
      -1,   260,   108,   100,     3,    -1,    24,   108,   260,     3,
      -1,   143,   145,   144,    -1,    11,   107,   106,   259,     3,
      -1,    11,    26,     3,    -1,    -1,   145,   146,    -1,     3,
      -1,   152,    -1,   153,    -1,   154,    -1,   157,    -1,   155,
      -1,   156,    -1,   158,    -1,   159,    -1,   160,    -1,   161,
      -1,   162,    -1,   163,    -1,   185,    -1,   164,    -1,   182,
      -1,   165,    -1,   183,    -1,   186,    -1,   166,    -1,   141,
      -1,   135,    -1,   225,    -1,   226,    -1,   227,    -1,   229,
      -1,   184,    -1,   178,    -1,   187,    -1,   188,    -1,   179,
      -1,   150,    -1,   189,    -1,   151,    -1,   180,    -1,   181,
      -1,   190,    -1,   191,    -1,   147,    -1,   148,    -1,   149,
      -1,    99,     3,    -1,    95,     3,    -1,    96,   261,     3,
      -1,    97,   261,     3,    -1,   111,     3,    -1,    20,   260,
       3,    -1,    15,   261,     3,    -1,    16,   260,     3,    -1,
      16,   104,     3,    -1,    17,   260,     3,    -1,    18,   260,
       3,    -1,    54,   260,     3,    -1,    22,     3,    -1,    25,
     261,     3,    -1,    23,   261,     3,    -1,    29,     3,    -1,
      30,     3,    -1,    14,     3,    -1,    38,     3,    -1,    37,
       3,    -1,    41,     3,    -1,    44,     3,    -1,    14,     3,
      -1,    92,     3,    -1,    93,     3,    -1,   171,   173,   172,
      -1,    91,     3,    -1,    91,    26,     3,    -1,    -1,   173,
     174,    -1,     3,    -1,   175,    -1,   176,    -1,    89,     3,
      -1,    90,   261,     3,    -1,    55,   261,     3,    -1,    13,
       3,    -1,    12,     3,    -1,    75,     3,    -1,    73,     3,
      -1,    81,     3,    -1,    80,     3,    -1,    19,     3,    -1,
      42,     3,    -1,    58,     3,    -1,    69,     3,    -1,    43,
       3,    -1,    59,     3,    -1,    59,    60,     3,    -1,    79,
       3,    -1,    79,    60,     3,    -1,    63,     3,    -1,    78,
       3,    -1,    88,     3,    -1,    94,    88,     3,    -1,    28,
     260,     3,    -1,    61,   260,     3,    -1,    34,   110,     3,
      -1,    45,   260,     3,    -1,    98,   260,     3,    -1,   198,
     200,   199,    -1,    70,   259,     3,    -1,    70,    26,     3,
      -1,    -1,   200,   201,    -1,     3,    -1,   202,    -1,   203,
      -1,   206,    -1,   205,    -1,   204,    -1,   256,    -1,   257,
      -1,    86,     3,    -1,    72,     3,    -1,    71,   260,   109,
     136,     3,    -1,    71,   260,   136,     3,    -1,    71,   260,
     109,    84,     7,   260,     8,   136,     3,    -1,    71,   260,
      84,     7,   260,     8,   136,     3,    -1,   208,   210,   209,
      -1,    12,   259,     3,    -1,    12,    26,    -1,    -1,   210,
     211,    -1,     3,    -1,   215,    -1,   216,    -1,   217,    -1,
     218,    -1,   212,    -1,   213,    -1,   214,    -1,    62,   136,
       3,    -1,   258,    -1,    86,     3,    -1,   256,    -1,   257,
      -1,    35,     3,    -1,    36,     3,    -1,   220,   222,   221,
      -1,    40,   259,     3,    -1,    40,    26,     3,    -1,    -1,
     222,   223,    -1,     3,    -1,   224,    -1,    39,   260,   136,
       3,    -1,    52,   136,     3,    -1,    53,   136,     3,    -1,
      47,   260,     3,    -1,    48,   260,     3,    -1,    49,   260,
       3,    -1,    50,   260,     3,    -1,    51,   260,     3,    -1,
      56,   261,   260,     3,    -1,    56,   261,   260,   261,     3,
      -1,    46,     3,    -1,   231,   233,   232,    -1,    64,   260,
       3,    -1,    64,    26,    -1,    -1,   233,   234,    -1,     3,
      -1,   237,    -1,   238,    -1,   239,    -1,   240,    -1,   241,
      -1,   242,    -1,   243,    -1,   244,    -1,   235,    -1,   236,
      -1,    86,     3,    -1,   258,    -1,    65,   136,     3,    -1,
      66,   136,     3,    -1,    67,   136,     3,    -1,    68,   136,
       3,    -1,    73,     3,    -1,   256,    -1,   257,    -1,    74,
     260,     3,    -1,   246,   251,   247,    -1,    83,   260,     3,
      -1,    83,    26,     3,    -1,   249,   251,   250,    -1,    82,
     260,     3,    -1,    82,    26,    -1,    -1,   251,   252,    -1,
       3,    -1,   253,    -1,   254,    -1,   255,    -1,   260,   136,
       3,    -1,   260,    67,     3,    -1,    85,     3,    -1,    32,
     261,     3,    -1,    33,   261,     3,    -1,    84,     7,   260,
       8,     3,    -1,    -1,   260,    -1,    99,    -1,   105,    -1,
     103,    -1,   102,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   467,   467,   472,   475,   476,   479,   480,   481,   482,
     483,   484,   485,   486,   487,   488,   489,   490,   491,   492,
     493,   494,   495,   496,   497,   498,   499,   500,   507,   510,
     517,   522,   523,   526,   527,   528,   529,   530,   531,   532,
     533,   534,   535,   536,   537,   543,   548,   552,   557,   562,
     567,   572,   577,   582,   587,   590,   591,   594,   595,   596,
     599,   604,   609,   616,   619,   624,   627,   628,   631,   635,
     639,   643,   648,   652,   656,   660,   665,   669,   673,   677,
     682,   686,   690,   694,   698,   703,   707,   714,   719,   720,
     723,   724,   725,   726,   727,   728,   729,   730,   731,   732,
     733,   734,   735,   736,   737,   738,   739,   740,   741,   742,
     743,   744,   745,   746,   747,   748,   749,   750,   751,   752,
     753,   754,   755,   756,   757,   758,   759,   760,   761,   762,
     763,   764,   770,   779,   785,   791,   796,   801,   806,   810,
     815,   820,   825,   830,   835,   840,   845,   850,   855,   860,
     865,   870,   875,   881,   886,   891,   897,   900,   903,   906,
     907,   910,   911,   912,   915,   920,   926,   931,   935,   940,
     944,   949,   954,   959,   964,   969,   974,   979,   984,   989,
     993,   997,  1002,  1007,  1012,  1017,  1023,  1028,  1033,  1038,
    1043,  1048,  1051,  1056,  1061,  1062,  1065,  1066,  1067,  1068,
    1069,  1070,  1073,  1080,  1087,  1093,  1099,  1104,  1110,  1114,
    1120,  1123,  1128,  1133,  1134,  1137,  1138,  1139,  1140,  1141,
    1142,  1143,  1144,  1147,  1152,  1162,  1167,  1177,  1187,  1192,
    1197,  1200,  1205,  1210,  1211,  1214,  1215,  1218,  1223,  1228,
    1233,  1237,  1241,  1245,  1249,  1254,  1258,  1264,  1269,  1272,
    1277,  1283,  1284,  1287,  1288,  1289,  1290,  1291,  1292,  1293,
    1294,  1295,  1296,  1297,  1300,  1306,  1313,  1318,  1323,  1328,
    1333,  1338,  1345,  1352,  1358,  1361,  1366,  1372,  1375,  1380,
    1385,  1386,  1389,  1390,  1391,  1392,  1395,  1400,  1405,  1410,
    1418,  1426,  1432,  1435,  1438,  1438,  1441,  1446
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "END_OF_FILE", "error", "$undefined", "EOS", "COMMA", "LEFT_SQ_BRACKET",
  "RIGHT_SQ_BRACKET", "LEFT_PAREN", "RIGHT_PAREN", "WILD", "TOK_COLLECTOR",
  "TOK_EXPORTER", "TOK_DNS_DEDUP", "TOK_DNS_DEDUP_ONLY", "TOK_NO_STATS",
  "TOK_PORT", "TOK_HOSTNAME", "TOK_PATH", "TOK_DELIM", "TOK_PRINT_HEADER",
  "TOK_MOVE", "TOK_DELETE", "TOK_LOCK", "TOK_UDP_TEMPLATE_TIMEOUT",
  "TOK_COLLECTOR_FILTER", "TOK_ROTATE_INTERVAL", "TOK_END", "TOK_FILTER",
  "TOK_LOG_FILE", "TOK_FLOW_ONLY", "TOK_DPI_ONLY", "TOK_POLL",
  "TOK_MAX_HIT_COUNT", "TOK_FLUSH_TIMEOUT", "TOK_LOG_LEVEL", "TOK_BASE_64",
  "TOK_LAST_SEEN", "TOK_REMOVE_EMPTY_FILES", "TOK_STATS_ONLY", "TOK_TABLE",
  "TOK_DPI_CONFIG", "TOK_MULTI_FILES", "TOK_NO_INDEX",
  "TOK_TIMESTAMP_FILES", "TOK_NO_FLOW_STATS", "TOK_PID_FILE",
  "TOK_MY_REMOVE", "TOK_MY_USER", "TOK_MY_PW", "TOK_MY_DB", "TOK_MY_HOST",
  "TOK_MY_TABLE", "TOK_FIELDS", "TOK_DPI_FIELD_LIST", "TOK_DPI_DELIMITER",
  "TOK_STATS_TIMEOUT", "TOK_USERIE", "TOK_AND_FILTER", "TOK_ESCAPE",
  "TOK_DNSRR_ONLY", "TOK_FULL", "TOK_LOG_DIR", "TOK_RECORDS",
  "TOK_DNSRESPONSE_ONLY", "TOK_SSL_CONFIG", "TOK_ISSUER", "TOK_SUBJECT",
  "TOK_OTHER", "TOK_EXTENSIONS", "TOK_DEDUP_PER_FLOW", "TOK_DEDUP_CONFIG",
  "TOK_FILE_PREFIX", "TOK_MERGE_TRUNCATED", "TOK_SSL_DEDUP",
  "TOK_CERT_FILE", "TOK_SSL_DEDUP_ONLY", "TOK_MD5", "TOK_SHA1", "TOK_GZIP",
  "TOK_DNSRR", "TOK_DEDUP_ONLY", "TOK_NO_FLOW", "TOK_OBID_MAP",
  "TOK_VLAN_MAP", "TOK_MAP", "TOK_DISCARD", "TOK_ADD_EXPORTER_NAME",
  "TOK_DECOMPRESS_DIRECTORY", "TOK_METADATA_EXPORT", "TOK_GEN_TOMBSTONE",
  "TOK_TOMBSTONE_CONFIGURED_ID", "TOK_TOMBSTONE_CONFIG",
  "TOK_PRESERVE_OBDOMAIN", "TOK_REWRITE_SSL_CERTS", "TOK_DISABLE",
  "TOK_INVARIANT", "TOK_MAX_BYTES", "TOK_MAX_SECONDS", "TOK_IPSET_FILE",
  "VAL_ATOM", "VAL_DATETIME", "VAL_DOUBLE", "VAL_HEXADECIMAL",
  "VAL_INTEGER", "VAL_IP", "VAL_QSTRING", "VAL_TRANSPORT",
  "VAL_EXPORT_FORMAT", "VAL_OPER", "VAL_FIELD", "VAL_LOGLEVEL",
  "VAL_CERT_DIGEST", "$accept", "mediatorConfFile", "mediatorConf",
  "stmtList", "stmt", "collectorBlock", "collectorBegin", "collectorEnd",
  "collectorStmtList", "collectorStmt", "col_port", "col_host", "col_path",
  "col_polling_interval", "col_decompress", "col_lock", "col_move_path",
  "col_delete", "filterBlock", "filterStmtList", "filterStmt",
  "filterBegin", "filterEnd", "filter_and_filter", "valueList",
  "valueListStart", "valueListEnd", "valueListItems", "valueListItem",
  "filter_comparison", "exporterBlock", "exporterBegin", "exporterEnd",
  "exporterStmtList", "exporterStmt", "exp_invariant", "exp_inv_max_bytes",
  "exp_inv_max_seconds", "exp_cert_digest", "exp_move_path", "exp_port",
  "exp_host", "exp_path", "exp_delim", "exp_dpi_delim", "exp_lock",
  "exp_rotate", "exp_udp_timeout", "exp_flow_only", "exp_dpi_only",
  "exp_no_stats", "exp_stats_only", "exp_remove_empty", "exp_multi_files",
  "exp_no_flow_stats", "statsConfig", "preserveObDomainConfig",
  "rewriteSslCertsConfig", "tombstoneConfig", "tombstoneBegin",
  "tombstoneEnd", "tombstoneStmtList", "tombstoneStmt",
  "genTombstoneConfig", "tombstoneIdConfig", "statsTimeout",
  "exp_dns_dedup", "exp_ssl_dedup", "exp_no_flow", "exp_dedup_only",
  "exp_print_headers", "exp_no_index", "exp_escape", "exp_dedup_flow",
  "exp_timestamp", "exp_dns_rr", "exp_dns_resp_only", "exp_gzip_files",
  "exp_metadata_export", "exp_disable_metadata_export", "logConfig",
  "logDirConfig", "logLevelConfig", "pidConfig", "ipsetConfig",
  "dedupConfigBlock", "dedupConfigBegin", "dedupConfigEnd",
  "dedupStmtList", "dedupStmt", "dedupHitConfig", "dedupFlushConfig",
  "dedupAddExporterName", "dedupMergeTruncated", "dedupFileStmt",
  "dnsDedupBlock", "dnsDedupBegin", "dnsDedupEnd", "dnsDedupStmtList",
  "dnsDedupStmt", "dnsDedupRecordList", "dnsDedupMapStmt",
  "dnsDedupAddExporterName", "dnsDedupHitConfig", "dnsDedupFlushConfig",
  "dnsDedupBase64Config", "dnsDedupLastSeenConfig", "dpiConfigBlock",
  "dpiConfigBegin", "dpiConfigEnd", "dpiConfigStmtList", "dpiConfigStmt",
  "tableStmt", "exp_fields", "exp_dpiFieldList", "exp_mysqlConfig",
  "userIE", "exp_remove_uploaded", "sslConfigBlock", "sslConfigBegin",
  "sslConfigEnd", "sslConfigStmtList", "sslConfigStmt",
  "ssldedupAddExporterName", "sslMapStmt", "sslIssuerList",
  "sslSubjectList", "sslOtherList", "sslExtensionList", "sslCertDedup",
  "sslDedupHitConfig", "sslDedupFlushConfig", "sslCertFile",
  "vlanMapBlock", "vlanMapBegin", "vlanMapEnd", "obidMapBlock",
  "obidMapBegin", "obidMapEnd", "voMapStmtList", "voMapStmt",
  "voMapStmtItem", "voMapStmtOther", "voMapStmtDiscard", "maxHitCount",
  "flushSeconds", "mapStmt", "optionalName", "atomOrQstring",
  "numericValue", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,   360,   361,   362,   363,   364,
     365,   366
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint16 yyr1[] =
{
       0,   112,   113,   114,   115,   115,   116,   116,   116,   116,
     116,   116,   116,   116,   116,   116,   116,   116,   116,   116,
     116,   116,   116,   116,   116,   116,   116,   116,   117,   118,
     119,   120,   120,   121,   121,   121,   121,   121,   121,   121,
     121,   121,   121,   121,   121,   122,   123,   123,   124,   125,
     126,   127,   128,   129,   130,   131,   131,   132,   132,   132,
     133,   134,   135,   136,   137,   138,   139,   139,   140,   140,
     140,   140,   140,   140,   140,   140,   141,   141,   141,   141,
     141,   141,   141,   141,   141,   142,   143,   144,   145,   145,
     146,   146,   146,   146,   146,   146,   146,   146,   146,   146,
     146,   146,   146,   146,   146,   146,   146,   146,   146,   146,
     146,   146,   146,   146,   146,   146,   146,   146,   146,   146,
     146,   146,   146,   146,   146,   146,   146,   146,   146,   146,
     146,   146,   147,   148,   149,   150,   151,   152,   153,   153,
     154,   155,   156,   157,   158,   159,   160,   161,   162,   163,
     164,   165,   166,   167,   168,   169,   170,   171,   172,   173,
     173,   174,   174,   174,   175,   176,   177,   178,   178,   179,
     179,   180,   181,   182,   183,   184,   185,   186,   187,   187,
     187,   187,   188,   189,   190,   191,   192,   193,   194,   195,
     196,   197,   198,   199,   200,   200,   201,   201,   201,   201,
     201,   201,   202,   203,   204,   205,   206,   206,   206,   206,
     207,   208,   209,   210,   210,   211,   211,   211,   211,   211,
     211,   211,   211,   212,   213,   214,   215,   216,   217,   218,
     219,   220,   221,   222,   222,   223,   223,   224,   225,   226,
     227,   227,   227,   227,   227,   228,   228,   229,   230,   231,
     232,   233,   233,   234,   234,   234,   234,   234,   234,   234,
     234,   234,   234,   234,   235,   236,   237,   238,   239,   240,
     241,   242,   243,   244,   245,   246,   247,   248,   249,   250,
     251,   251,   252,   252,   252,   252,   253,   254,   255,   256,
     257,   258,   259,   259,   260,   260,   261,   261
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     2,     1,     0,     2,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     3,     4,
       3,     0,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     2,     3,     3,     3,     3,     3,
       3,     2,     3,     2,     3,     0,     2,     1,     1,     1,
       2,     3,     2,     3,     1,     1,     1,     3,     1,     1,
       1,     1,     1,     1,     1,     1,     4,     4,     4,     4,
       4,     4,     4,     4,     4,     3,     5,     3,     0,     2,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     2,     2,     3,     3,     2,     3,     3,     3,     3,
       3,     3,     3,     2,     3,     3,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     3,     2,     3,     0,
       2,     1,     1,     1,     2,     3,     3,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     3,
       2,     3,     2,     2,     2,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     0,     2,     1,     1,     1,     1,
       1,     1,     1,     1,     2,     2,     5,     4,     9,     8,
       3,     3,     2,     0,     2,     1,     1,     1,     1,     1,
       1,     1,     1,     3,     1,     2,     1,     1,     2,     2,
       3,     3,     3,     0,     2,     1,     1,     4,     3,     3,
       3,     3,     3,     3,     3,     4,     5,     2,     3,     3,
       2,     0,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     2,     1,     3,     3,     3,     3,
       2,     1,     1,     3,     3,     3,     3,     3,     3,     2,
       0,     2,     1,     1,     1,     1,     3,     3,     2,     3,
       3,     5,     0,     1,     1,     1,     1,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint16 yydefact[] =
{
       4,     0,     0,     3,     1,     2,     6,     0,     0,   292,
       0,     0,     0,     0,   292,     0,     0,     0,     0,     0,
     292,     0,     0,     0,     0,     0,     0,    27,     5,     7,
      31,     8,    55,     9,    88,    10,    11,    12,    13,   159,
      23,    14,    16,    15,    17,    18,    22,   194,    19,   213,
      20,   233,    24,    21,   251,    25,   280,    26,   280,   292,
       0,   294,   295,     0,   293,   153,    60,     0,     0,     0,
       0,   297,   296,     0,     0,     0,     0,     0,     0,     0,
     157,   154,   155,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   292,   211,   186,   188,   231,
     189,   166,     0,   187,   249,   192,   278,   275,   190,    33,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   294,    28,    32,    34,    35,    36,    37,    41,    38,
      39,    40,    43,    42,     0,    57,     0,    56,    54,    59,
      58,    90,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   294,     0,   111,
     110,    85,    89,   128,   129,   130,   121,   123,    91,    92,
      93,    95,    96,    94,    97,    98,    99,   100,   101,   102,
     104,   106,   109,   117,   120,   124,   125,   105,   107,   116,
     103,   108,   118,   119,   122,   126,   127,   112,   113,   114,
     115,   161,     0,     0,     0,   156,   160,   162,   163,   196,
       0,     0,     0,     0,     0,     0,   191,   195,   197,   198,
     201,   200,   199,   202,   203,   215,     0,     0,     0,     0,
       0,     0,   210,   214,   220,   221,   222,   216,   217,   218,
     219,   226,   227,   224,   235,     0,     0,   230,   234,   236,
     253,     0,     0,     0,     0,     0,     0,     0,     0,   248,
     252,   262,   263,   254,   255,   256,   257,   258,   259,   260,
     261,   271,   272,   265,   282,     0,     0,   274,   281,   283,
     284,   285,     0,     0,   277,    29,     0,   245,     0,     0,
       0,     0,     0,     0,     0,    53,    51,     0,     0,    62,
       0,    44,     0,     0,     0,   168,   167,   148,     0,     0,
       0,     0,     0,   173,     0,   143,     0,     0,   146,   147,
     150,   149,   151,   174,   177,   152,   247,     0,     0,     0,
       0,     0,    64,     0,     0,     0,     0,   175,   178,     0,
     182,   176,   170,   169,   183,   180,     0,   172,   171,   184,
       0,   132,     0,     0,   131,   135,   164,     0,     0,     0,
       0,     0,     0,   205,   204,   212,   228,   229,     0,     0,
     225,     0,     0,   250,     0,     0,     0,     0,   270,     0,
     264,     0,   288,     0,     0,   279,    86,   246,    30,    45,
      47,    46,    48,    52,     0,    49,    50,     0,     0,     0,
       0,     0,     0,     0,     0,    61,    87,   137,   139,   138,
     140,   141,   136,   145,   144,   240,   241,   242,   243,   244,
     238,    75,    68,    69,    72,    71,    70,    73,    74,     0,
      66,   239,   142,   179,   181,   185,   133,   134,   165,   158,
     289,   290,   193,     0,     0,     0,   223,     0,     0,   232,
     266,   267,   268,   269,   273,   276,   287,   286,    84,    76,
      83,    80,    79,    78,    82,    81,    77,     0,    65,    63,
       0,     0,     0,   207,     0,   237,    67,     0,     0,   206,
     291,     0,     0,     0,     0,   209,     0,   208
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,     2,     3,    28,    29,    30,   122,    84,   123,
     124,   125,   126,   127,   128,   129,   130,   131,    31,    85,
     137,    32,   138,   132,   363,   364,   499,   459,   460,   133,
      33,    34,   191,    86,   192,   193,   194,   195,   196,   197,
     198,   199,   200,   201,   202,   203,   204,   205,   206,   207,
     208,   209,   210,   211,   212,    35,    36,    37,    38,    39,
     235,    87,   236,   237,   238,    40,   213,   214,   215,   216,
     217,   218,   219,   220,   221,   222,   223,   224,   225,   226,
      41,    42,    43,    44,    45,    46,    47,   246,    88,   247,
     248,   249,   250,   251,   252,    48,    49,   262,    89,   263,
     264,   265,   266,   267,   268,   269,   270,    50,    51,   277,
      90,   278,   279,   227,   228,   229,    52,   230,    53,    54,
     289,    91,   290,   291,   292,   293,   294,   295,   296,   297,
     298,   299,   300,    55,    56,   307,    57,    58,   314,    92,
     308,   309,   310,   311,   253,   254,   273,    63,    64,    73
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -297
static const yytype_int16 yypact[] =
{
    -297,    18,    26,   282,  -297,  -297,  -297,   -85,   -69,   -64,
      44,    62,   -64,   -44,   -64,   -64,   -45,   -45,   -64,   -64,
     -64,   -64,   -64,    64,    65,    68,   -64,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,   -64,
     -29,  -297,  -297,    75,  -297,  -297,  -297,    76,    80,    82,
      83,  -297,  -297,    84,   -64,    85,    90,    94,   100,   104,
    -297,  -297,  -297,   107,    12,    13,   192,     5,   323,   327,
      10,   318,    21,    39,   116,   -64,  -297,  -297,  -297,  -297,
    -297,  -297,    20,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
      99,   -45,   -74,   -64,   -64,   124,   125,    22,   -45,   126,
     -64,   128,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,    24,  -297,   108,  -297,  -297,  -297,
    -297,  -297,   131,   139,   155,   157,   -45,   -60,   -64,   -64,
     158,   -64,   159,   -45,   -45,   161,   171,   172,   173,   174,
     175,   176,   177,   178,   -64,   -64,   -64,   -64,   -64,   179,
     179,   -64,   180,    -1,   182,   183,   184,   185,   186,    16,
     187,   188,   189,   105,   191,   -45,   -45,   193,   194,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,   195,   -45,   156,  -297,  -297,  -297,  -297,  -297,
     -45,   -45,   198,   -64,   196,   197,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,   199,   210,   215,   179,
     212,   223,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,   -64,   211,  -297,  -297,  -297,
    -297,   221,   179,   179,   179,   179,   245,   -64,   249,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,   227,   251,  -297,  -297,  -297,
    -297,  -297,    15,   230,  -297,  -297,   254,  -297,   255,   256,
     257,   259,   261,   263,   265,  -297,  -297,   -64,   266,  -297,
     271,  -297,    46,   273,   274,  -297,  -297,  -297,   275,   276,
     278,   279,   280,  -297,   281,  -297,   287,   292,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,   295,   296,   297,
     298,   299,  -297,   301,    66,   303,   304,  -297,  -297,   305,
    -297,  -297,  -297,  -297,  -297,  -297,   308,  -297,  -297,  -297,
     309,  -297,   310,   311,  -297,  -297,  -297,   314,   315,   316,
     317,   320,     0,  -297,  -297,  -297,  -297,  -297,   321,   -64,
    -297,   179,   322,  -297,   325,   326,   328,   329,  -297,   330,
    -297,   331,  -297,   332,   333,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,   337,  -297,  -297,   338,   341,   344,
     345,   346,   350,   351,   354,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,    42,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,   359,     7,   355,  -297,   353,   364,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,    66,  -297,  -297,
     -64,   361,   366,  -297,   367,  -297,  -297,   363,   -64,  -297,
    -297,   179,   368,   369,   179,  -297,   374,  -297
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,   -25,  -169,  -297,  -297,  -297,  -296,   -22,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,
    -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,  -297,   144,
    -297,  -297,  -297,  -297,   -37,   -36,   288,    -3,   -12,   -13
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const yytype_uint16 yytable[] =
{
      67,   365,   368,    70,    74,   362,    75,    76,   231,    78,
      79,    69,   362,   274,    83,   109,   135,    77,     4,   375,
     362,    59,   110,   317,   304,    61,     5,   111,   112,   113,
     321,    62,   114,   115,   116,    61,   117,   117,    60,    61,
     136,    62,   304,   118,   339,    62,   497,    65,   498,   275,
     276,   362,   271,   272,   301,   302,    94,    71,    72,   369,
     139,   189,   102,   140,   190,    66,    68,    80,    81,   119,
     119,    82,   134,   134,   134,   451,   376,    95,    96,    97,
     312,   312,   413,    98,   473,    99,   100,   101,   103,   318,
     398,   501,   316,   104,   232,   233,   234,   105,   320,   120,
     322,   323,   324,   106,   305,   328,   306,   107,   330,   474,
     108,   121,    61,   404,   405,   406,   407,    62,    62,   315,
      61,   313,    71,    72,   306,   319,    62,   325,   326,   329,
     327,   331,   332,   338,   333,   340,   341,   342,    61,   344,
     346,   347,   335,   414,    62,   427,   428,   429,   430,   431,
     432,   433,   357,   358,   359,   360,   361,   334,   336,   366,
     337,   343,   345,   434,   348,   452,   453,   454,   455,   456,
     457,   458,   382,   383,   349,   350,   351,   352,   353,   354,
     355,   356,   388,   367,   362,   370,   371,   372,   373,   374,
     377,   378,   379,   380,   381,   141,   384,   385,   386,   393,
     394,   506,    93,   142,   143,   144,   145,   146,   147,   148,
     149,   150,   151,   396,   152,   153,   117,   154,   397,   399,
     387,   155,   156,   475,   391,   395,   400,   389,   390,   157,
     158,   392,   478,   159,   160,   161,   162,   402,   163,   164,
     165,   166,   167,   168,   169,   170,   171,   403,   408,   119,
     172,   173,   410,   411,   412,   174,   415,   416,   417,   418,
     419,   175,   420,   401,   421,   176,   422,   177,   423,   425,
     178,   179,   180,   181,   426,   409,   435,   436,   437,   438,
     182,   439,   440,   441,   442,     6,   183,   184,   185,   186,
     443,   187,     7,     8,     9,   444,    10,    62,   445,   446,
     447,   448,   449,   188,   450,   502,   461,   462,   463,    11,
      12,   464,   465,   466,   467,   424,    13,   468,   469,   470,
     471,   280,    14,   472,   476,   479,   239,    15,   480,   481,
     255,   482,   483,   484,   485,   486,   487,    16,    17,   256,
     488,   489,   513,    18,   490,   516,    19,   491,   492,   493,
     240,   241,    20,   494,   495,   240,   241,   496,   503,   240,
     241,   504,   257,   258,    21,    22,   500,   505,   508,   509,
     510,   511,   515,    23,    24,    25,   514,   517,     0,   303,
      26,    27,   281,   282,   283,   284,   285,   477,     0,   259,
       0,   286,   287,   242,   243,   244,     0,     0,     0,     0,
       0,     0,   260,     0,   288,     0,     0,     0,     0,   245,
       0,   260,     0,   261,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   507,     0,
       0,     0,     0,     0,     0,     0,   512
};

static const yytype_int16 yycheck[] =
{
      12,   170,     3,    15,    17,     5,    18,    19,     3,    21,
      22,    14,     5,     3,    26,     3,     3,    20,     0,     3,
       5,   106,    10,     3,     3,    99,     0,    15,    16,    17,
     104,   105,    20,    21,    22,    99,    24,    24,   107,    99,
      27,   105,     3,    31,   104,   105,     4,     3,     6,    39,
      40,     5,    89,    89,    91,    91,    59,   102,   103,    60,
      85,    86,    74,    85,    86,     3,   110,     3,     3,    57,
      57,     3,    84,    85,    86,     9,    60,   106,     3,     3,
      92,    93,    67,     3,    84,     3,     3,     3,     3,   102,
     259,    84,    95,     3,    89,    90,    91,     3,   111,    87,
     112,   113,   114,     3,    83,   118,    85,     3,   120,   109,
       3,    99,    99,   282,   283,   284,   285,   105,   105,     3,
      99,    82,   102,   103,    85,    26,   105,     3,     3,     3,
     108,     3,   108,   146,    26,   147,   148,   149,    99,   151,
     153,   154,     3,   312,   105,    99,   100,   101,   102,   103,
     104,   105,   164,   165,   166,   167,   168,    26,     3,   171,
       3,     3,     3,   332,     3,    99,   100,   101,   102,   103,
     104,   105,   185,   186,     3,     3,     3,     3,     3,     3,
       3,     3,    26,     3,     5,     3,     3,     3,     3,     3,
       3,     3,     3,    88,     3,     3,     3,     3,     3,     3,
       3,   497,    58,    11,    12,    13,    14,    15,    16,    17,
      18,    19,    20,     3,    22,    23,    24,    25,     3,     7,
     233,    29,    30,   392,    26,    26,     3,   240,   241,    37,
      38,   243,   401,    41,    42,    43,    44,    26,    46,    47,
      48,    49,    50,    51,    52,    53,    54,    26,     3,    57,
      58,    59,     3,    26,     3,    63,    26,     3,     3,     3,
       3,    69,     3,   275,     3,    73,     3,    75,     3,     3,
      78,    79,    80,    81,     3,   287,     3,     3,     3,     3,
      88,     3,     3,     3,     3,     3,    94,    95,    96,    97,
       3,    99,    10,    11,    12,     3,    14,   105,     3,     3,
       3,     3,     3,   111,     3,   474,     3,     3,     3,    27,
      28,     3,     3,     3,     3,   327,    34,     3,     3,     3,
       3,     3,    40,     3,     3,     3,     3,    45,     3,     3,
       3,     3,     3,     3,     3,     3,     3,    55,    56,    12,
       3,     3,   511,    61,     3,   514,    64,     3,     3,     3,
      32,    33,    70,     3,     3,    32,    33,     3,     3,    32,
      33,     8,    35,    36,    82,    83,     7,     3,     7,     3,
       3,     8,     3,    91,    92,    93,     8,     3,    -1,    91,
      98,    99,    64,    65,    66,    67,    68,   399,    -1,    62,
      -1,    73,    74,    70,    71,    72,    -1,    -1,    -1,    -1,
      -1,    -1,    84,    -1,    86,    -1,    -1,    -1,    -1,    86,
      -1,    84,    -1,    86,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   500,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   508
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint16 yystos[] =
{
       0,   113,   114,   115,     0,     0,     3,    10,    11,    12,
      14,    27,    28,    34,    40,    45,    55,    56,    61,    64,
      70,    82,    83,    91,    92,    93,    98,    99,   116,   117,
     118,   130,   133,   142,   143,   167,   168,   169,   170,   171,
     177,   192,   193,   194,   195,   196,   197,   198,   207,   208,
     219,   220,   228,   230,   231,   245,   246,   248,   249,   106,
     107,    99,   105,   259,   260,     3,     3,   260,   110,   259,
     260,   102,   103,   261,   261,   260,   260,   259,   260,   260,
       3,     3,     3,   260,   120,   131,   145,   173,   200,   210,
     222,   233,   251,   251,   259,   106,     3,     3,     3,     3,
       3,     3,   260,     3,     3,     3,     3,     3,     3,     3,
      10,    15,    16,    17,    20,    21,    22,    24,    31,    57,
      87,    99,   119,   121,   122,   123,   124,   125,   126,   127,
     128,   129,   135,   141,   260,     3,    27,   132,   134,   135,
     141,     3,    11,    12,    13,    14,    15,    16,    17,    18,
      19,    20,    22,    23,    25,    29,    30,    37,    38,    41,
      42,    43,    44,    46,    47,    48,    49,    50,    51,    52,
      53,    54,    58,    59,    63,    69,    73,    75,    78,    79,
      80,    81,    88,    94,    95,    96,    97,    99,   111,   135,
     141,   144,   146,   147,   148,   149,   150,   151,   152,   153,
     154,   155,   156,   157,   158,   159,   160,   161,   162,   163,
     164,   165,   166,   178,   179,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,   190,   191,   225,   226,   227,
     229,     3,    89,    90,    91,   172,   174,   175,   176,     3,
      32,    33,    70,    71,    72,    86,   199,   201,   202,   203,
     204,   205,   206,   256,   257,     3,    12,    35,    36,    62,
      84,    86,   209,   211,   212,   213,   214,   215,   216,   217,
     218,   256,   257,   258,     3,    39,    40,   221,   223,   224,
       3,    64,    65,    66,    67,    68,    73,    74,    86,   232,
     234,   235,   236,   237,   238,   239,   240,   241,   242,   243,
     244,   256,   257,   258,     3,    83,    85,   247,   252,   253,
     254,   255,   260,    82,   250,     3,   259,     3,   261,    26,
     261,   104,   260,   260,   260,     3,     3,   108,   261,     3,
     260,     3,   108,    26,    26,     3,     3,     3,   261,   104,
     260,   260,   260,     3,   260,     3,   261,   261,     3,     3,
       3,     3,     3,     3,     3,     3,     3,   260,   260,   260,
     260,   260,     5,   136,   137,   136,   260,     3,     3,    60,
       3,     3,     3,     3,     3,     3,    60,     3,     3,     3,
      88,     3,   261,   261,     3,     3,     3,   261,    26,   261,
     261,    26,   260,     3,     3,    26,     3,     3,   136,     7,
       3,   260,    26,    26,   136,   136,   136,   136,     3,   260,
       3,    26,     3,    67,   136,    26,     3,     3,     3,     3,
       3,     3,     3,     3,   260,     3,     3,    99,   100,   101,
     102,   103,   104,   105,   136,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     9,    99,   100,   101,   102,   103,   104,   105,   139,
     140,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,    84,   109,   136,     3,   260,   136,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     4,     6,   138,
       7,    84,   136,     3,     8,     3,   140,   260,     7,     3,
       3,     8,   260,   136,     8,     3,   136,     3
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *bottom, yytype_int16 *top)
#else
static void
yy_stack_print (bottom, top)
    yytype_int16 *bottom;
    yytype_int16 *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule)
#else
static void
yy_reduce_print (yyvsp, yyrule)
    YYSTYPE *yyvsp;
    int yyrule;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      fprintf (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       );
      fprintf (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yymsg, yytype, yyvaluep)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  YYUSE (yyvaluep);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
	break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */



/* The look-ahead symbol.  */
int yychar;

/* The semantic value of the look-ahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;



/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
  
  int yystate;
  int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Look-ahead token as an internal (translated) token number.  */
  int yytoken = 0;
#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  yytype_int16 yyssa[YYINITDEPTH];
  yytype_int16 *yyss = yyssa;
  yytype_int16 *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  YYSTYPE *yyvsp;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;


      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     look-ahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to look-ahead token.  */
  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a look-ahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid look-ahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the look-ahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 468 "mediator_config_parse.y"
    {
    validateConfFile();
}
    break;

  case 27:
#line 501 "mediator_config_parse.y"
    {
    /* match an unknown token */
    ++lineNumber;
    mediator_config_error("Unknown keyword %s", (yyvsp[(1) - (1)].str));
}
    break;

  case 29:
#line 511 "mediator_config_parse.y"
    {
    mdCollectionMethod_t colMethod;
    parseTransportAsMethod((yyvsp[(2) - (4)].transport), &colMethod, NULL);
    parseCollectorBegin(colMethod, (yyvsp[(3) - (4)].str));
}
    break;

  case 30:
#line 518 "mediator_config_parse.y"
    {
    parseCollectorEnd();
}
    break;

  case 44:
#line 538 "mediator_config_parse.y"
    {
    /* prevent lone unknown token from being considered start of a filter */
    mediator_config_error("Unknown keyword %s", (yyvsp[(1) - (2)].str));
}
    break;

  case 45:
#line 544 "mediator_config_parse.y"
    {
    parseCollectorPort((yyvsp[(2) - (3)].integer));
}
    break;

  case 46:
#line 549 "mediator_config_parse.y"
    {
    parseCollectorHost((yyvsp[(2) - (3)].str));
}
    break;

  case 47:
#line 553 "mediator_config_parse.y"
    {
    parseCollectorHost((yyvsp[(2) - (3)].str));
}
    break;

  case 48:
#line 558 "mediator_config_parse.y"
    {
    parseCollectorPath((yyvsp[(2) - (3)].str));
}
    break;

  case 49:
#line 563 "mediator_config_parse.y"
    {
    parseCollectorPollingInterval((yyvsp[(2) - (3)].integer));
}
    break;

  case 50:
#line 568 "mediator_config_parse.y"
    {
    parseCollectorDecompressDirectory((yyvsp[(2) - (3)].str));
}
    break;

  case 51:
#line 573 "mediator_config_parse.y"
    {
    parseCollectorNoLockedFiles();
}
    break;

  case 52:
#line 578 "mediator_config_parse.y"
    {
    parseCollectorMovePath((yyvsp[(2) - (3)].str));
}
    break;

  case 53:
#line 583 "mediator_config_parse.y"
    {
    parseCollectorDelete(TRUE);
}
    break;

  case 60:
#line 600 "mediator_config_parse.y"
    {
    parseFilterBegin();
}
    break;

  case 61:
#line 605 "mediator_config_parse.y"
    {
    parseFilterEnd();
}
    break;

  case 62:
#line 610 "mediator_config_parse.y"
    {
    andFilter = TRUE;
}
    break;

  case 64:
#line 620 "mediator_config_parse.y"
    {
    resetValueListTemp();
}
    break;

  case 68:
#line 632 "mediator_config_parse.y"
    {
    parseValueListItems((yyvsp[(1) - (1)].str), VAL_ATOM);
}
    break;

  case 69:
#line 636 "mediator_config_parse.y"
    {
    parseValueListItems((yyvsp[(1) - (1)].str), VAL_DATETIME);
}
    break;

  case 70:
#line 640 "mediator_config_parse.y"
    {
    parseValueListItems((yyvsp[(1) - (1)].str), VAL_INTEGER);
}
    break;

  case 71:
#line 644 "mediator_config_parse.y"
    {
    /* numericValue is limited to 32 bits, use VAL_HEXADECIMAL instead */
    parseValueListItems((yyvsp[(1) - (1)].str), VAL_HEXADECIMAL);
}
    break;

  case 72:
#line 649 "mediator_config_parse.y"
    {
    parseValueListItems((yyvsp[(1) - (1)].str), VAL_DOUBLE);
}
    break;

  case 73:
#line 653 "mediator_config_parse.y"
    {
    parseValueListItems((yyvsp[(1) - (1)].str), VAL_IP);
}
    break;

  case 74:
#line 657 "mediator_config_parse.y"
    {
    parseValueListItems((yyvsp[(1) - (1)].str), VAL_QSTRING);
}
    break;

  case 75:
#line 661 "mediator_config_parse.y"
    {
    valueListTemp.wild = TRUE;
}
    break;

  case 76:
#line 666 "mediator_config_parse.y"
    {
    parseComparison((yyvsp[(1) - (4)].str), (yyvsp[(2) - (4)].oper), (yyvsp[(3) - (4)].str), VAL_ATOM);
}
    break;

  case 77:
#line 670 "mediator_config_parse.y"
    {
    parseComparison((yyvsp[(1) - (4)].str), (yyvsp[(2) - (4)].oper), NULL, VAL_ATOM);
}
    break;

  case 78:
#line 674 "mediator_config_parse.y"
    {
    parseComparison((yyvsp[(1) - (4)].str), (yyvsp[(2) - (4)].oper), (yyvsp[(3) - (4)].str), VAL_INTEGER);
}
    break;

  case 79:
#line 678 "mediator_config_parse.y"
    {
    /* numericValue is limited to 32 bits, use VAL_HEXADECIMAL instead */
    parseComparison((yyvsp[(1) - (4)].str), (yyvsp[(2) - (4)].oper), (yyvsp[(3) - (4)].str), VAL_HEXADECIMAL);
}
    break;

  case 80:
#line 683 "mediator_config_parse.y"
    {
    parseComparison((yyvsp[(1) - (4)].str), (yyvsp[(2) - (4)].oper), (yyvsp[(3) - (4)].str), VAL_DOUBLE);
}
    break;

  case 81:
#line 687 "mediator_config_parse.y"
    {
    parseComparison((yyvsp[(1) - (4)].str), (yyvsp[(2) - (4)].oper), (yyvsp[(3) - (4)].str), VAL_QSTRING);
}
    break;

  case 82:
#line 691 "mediator_config_parse.y"
    {
    parseComparison((yyvsp[(1) - (4)].str), (yyvsp[(2) - (4)].oper), (yyvsp[(3) - (4)].str), VAL_IP);
}
    break;

  case 83:
#line 695 "mediator_config_parse.y"
    {
    parseComparison((yyvsp[(1) - (4)].str), (yyvsp[(2) - (4)].oper), (yyvsp[(3) - (4)].str), VAL_DATETIME);
}
    break;

  case 84:
#line 699 "mediator_config_parse.y"
    {
    parseComparison(NULL, (yyvsp[(2) - (4)].oper), (yyvsp[(3) - (4)].str), TOK_COLLECTOR_FILTER);
}
    break;

  case 86:
#line 708 "mediator_config_parse.y"
    {
    mdExportMethod_t expMethod;
    parseTransportAsMethod((yyvsp[(3) - (5)].transport), NULL, &expMethod);
    parseExporterBegin((yyvsp[(2) - (5)].exportFormat), expMethod, (yyvsp[(4) - (5)].str));
}
    break;

  case 87:
#line 715 "mediator_config_parse.y"
    {
    parseExporterEnd();
}
    break;

  case 131:
#line 765 "mediator_config_parse.y"
    {
    /* prevent lone unknown token from being considered start of a filter */
    mediator_config_error("Unknown keyword %s", (yyvsp[(1) - (2)].str));
}
    break;

  case 132:
#line 771 "mediator_config_parse.y"
    {
    mediator_config_error(
        "Invariant support is disabled in this version");

    /* REQUIRE_NOTNULL(expToBuild); */
    /* expToBuild->invariant = TRUE; */
}
    break;

  case 133:
#line 780 "mediator_config_parse.y"
    {
    REQUIRE_NOTNULL(expToBuild);
    expToBuild->invState.maxFileSize = (yyvsp[(2) - (3)].integer);
}
    break;

  case 134:
#line 786 "mediator_config_parse.y"
    {
    REQUIRE_NOTNULL(expToBuild);
    expToBuild->invState.maxTimeMillisec = (yyvsp[(2) - (3)].integer) * 1000;
}
    break;

  case 135:
#line 792 "mediator_config_parse.y"
    {
    parseExporterCertDigest((yyvsp[(1) - (2)].certDigest));
}
    break;

  case 136:
#line 797 "mediator_config_parse.y"
    {
    parseExporterMovePath((yyvsp[(2) - (3)].str));
}
    break;

  case 137:
#line 802 "mediator_config_parse.y"
    {
    parseExporterPort((yyvsp[(2) - (3)].integer));
}
    break;

  case 138:
#line 807 "mediator_config_parse.y"
    {
    parseExporterHost((yyvsp[(2) - (3)].str));
}
    break;

  case 139:
#line 811 "mediator_config_parse.y"
    {
    parseExporterHost((yyvsp[(2) - (3)].str));
}
    break;

  case 140:
#line 816 "mediator_config_parse.y"
    {
    parseExporterFile((yyvsp[(2) - (3)].str));
}
    break;

  case 141:
#line 821 "mediator_config_parse.y"
    {
    parseExporterTextDelimiter((yyvsp[(2) - (3)].str));
}
    break;

  case 142:
#line 826 "mediator_config_parse.y"
    {
    parseExporterDPIDelimiter((yyvsp[(2) - (3)].str));
}
    break;

  case 143:
#line 831 "mediator_config_parse.y"
    {
    parseExporterLock();
}
    break;

  case 144:
#line 836 "mediator_config_parse.y"
    {
    parseExporterRotateSeconds((yyvsp[(2) - (3)].integer));
}
    break;

  case 145:
#line 841 "mediator_config_parse.y"
    {
    parseExporterUDPTimeout((yyvsp[(2) - (3)].integer));
}
    break;

  case 146:
#line 846 "mediator_config_parse.y"
    {
    parseExporterFlowOnly();
}
    break;

  case 147:
#line 851 "mediator_config_parse.y"
    {
    parseExporterDPIOnly();
}
    break;

  case 148:
#line 856 "mediator_config_parse.y"
    {
    parseExporterNoStats();
}
    break;

  case 149:
#line 861 "mediator_config_parse.y"
    {
    parseExporterAddStats();
}
    break;

  case 150:
#line 866 "mediator_config_parse.y"
    {
    parseExporterRemoveEmpty();
}
    break;

  case 151:
#line 871 "mediator_config_parse.y"
    {
    parseExporterMultiFiles();
}
    break;

  case 152:
#line 876 "mediator_config_parse.y"
    {
    parseExporterNoFlowStats();
}
    break;

  case 153:
#line 882 "mediator_config_parse.y"
    {
    parseStatisticsConfig();
}
    break;

  case 154:
#line 887 "mediator_config_parse.y"
    {
    parsePreserveObDomainConfig();
}
    break;

  case 155:
#line 892 "mediator_config_parse.y"
    {
    parseRewriteSslCertsConfig();
}
    break;

  case 164:
#line 916 "mediator_config_parse.y"
    {
    parseGenTombstoneConfig();
}
    break;

  case 165:
#line 921 "mediator_config_parse.y"
    {
    parseTombstoneIdConfig((yyvsp[(2) - (3)].integer));
}
    break;

  case 166:
#line 927 "mediator_config_parse.y"
    {
    parseStatsTimeout((yyvsp[(2) - (3)].integer));
}
    break;

  case 167:
#line 932 "mediator_config_parse.y"
    {
    parseExporterDnsDedup(TRUE);
}
    break;

  case 168:
#line 936 "mediator_config_parse.y"
    {
    parseExporterDnsDedup(FALSE);
}
    break;

  case 169:
#line 941 "mediator_config_parse.y"
    {
    parseExporterSslDedup(TRUE);
}
    break;

  case 170:
#line 945 "mediator_config_parse.y"
    {
    parseExporterSslDedup(FALSE);
}
    break;

  case 171:
#line 950 "mediator_config_parse.y"
    {
    parseExporterNoFlow();
}
    break;

  case 172:
#line 955 "mediator_config_parse.y"
    {
    parseExporterDedupOnly();
}
    break;

  case 173:
#line 960 "mediator_config_parse.y"
    {
    parseExporterPrintHeader();
}
    break;

  case 174:
#line 965 "mediator_config_parse.y"
    {
    parseExporterNoIndex();
}
    break;

  case 175:
#line 970 "mediator_config_parse.y"
    {
    parseExporterEscapeChars();
}
    break;

  case 176:
#line 975 "mediator_config_parse.y"
    {
    parseExporterDedupPerFlow();
}
    break;

  case 177:
#line 980 "mediator_config_parse.y"
    {
    parseExporterTimestamp();
}
    break;

  case 178:
#line 985 "mediator_config_parse.y"
    {
    /* first boolean reflects ONLY, second reflects FULL */
    parseExporterDnsRR(TRUE, FALSE);
}
    break;

  case 179:
#line 990 "mediator_config_parse.y"
    {
    parseExporterDnsRR(TRUE, TRUE);
}
    break;

  case 180:
#line 994 "mediator_config_parse.y"
    {
    parseExporterDnsRR(FALSE, FALSE);
}
    break;

  case 181:
#line 998 "mediator_config_parse.y"
    {
    parseExporterDnsRR(FALSE, TRUE);
}
    break;

  case 182:
#line 1003 "mediator_config_parse.y"
    {
    parseExporterDnsResponseOnly();
}
    break;

  case 183:
#line 1008 "mediator_config_parse.y"
    {
    parseExporterGzipFiles();
}
    break;

  case 184:
#line 1013 "mediator_config_parse.y"
    {
    parseExporterMetadataExport();
}
    break;

  case 185:
#line 1018 "mediator_config_parse.y"
    {
    parseExporterDisableMetadataExport();
}
    break;

  case 186:
#line 1024 "mediator_config_parse.y"
    {
    parseLogConfig((yyvsp[(2) - (3)].str));
}
    break;

  case 187:
#line 1029 "mediator_config_parse.y"
    {
    parseLogDir((yyvsp[(2) - (3)].str));
}
    break;

  case 188:
#line 1034 "mediator_config_parse.y"
    {
    mdLoggerSetLevel((yyvsp[(2) - (3)].log_level));
}
    break;

  case 189:
#line 1039 "mediator_config_parse.y"
    {
    parsePidFile((yyvsp[(2) - (3)].str));
}
    break;

  case 190:
#line 1044 "mediator_config_parse.y"
    {
    parseIpsetFile((yyvsp[(2) - (3)].str));
}
    break;

  case 192:
#line 1052 "mediator_config_parse.y"
    {
    parseDedupConfigBegin((yyvsp[(2) - (3)].str));
}
    break;

  case 193:
#line 1057 "mediator_config_parse.y"
    {
    etemp = NULL;
}
    break;

  case 202:
#line 1074 "mediator_config_parse.y"
    {
    /* TOK_MAX_HIT_COUNT */
    REQUIRE_NOTNULL(etemp);
    md_dedup_configure_state(etemp->dedup, (yyvsp[(1) - (1)].integer), 0, FALSE, FALSE);
}
    break;

  case 203:
#line 1081 "mediator_config_parse.y"
    {
    /* TOK_FLUSH_TIMEOUT */
    REQUIRE_NOTNULL(etemp);
    md_dedup_configure_state(etemp->dedup, 0, (yyvsp[(1) - (1)].integer), FALSE, FALSE);
}
    break;

  case 204:
#line 1088 "mediator_config_parse.y"
    {
    REQUIRE_NOTNULL(etemp);
    md_dedup_configure_state(etemp->dedup, 0, 0, FALSE, TRUE);
}
    break;

  case 205:
#line 1094 "mediator_config_parse.y"
    {
    REQUIRE_NOTNULL(etemp);
    md_dedup_configure_state(etemp->dedup, 0, 0, TRUE, FALSE);
}
    break;

  case 206:
#line 1100 "mediator_config_parse.y"
    {
    /* PREFIX "name" {SIP|DIP|FLOWKEYHASH} [ IE, IE, ... ] */
    parseFileList((yyvsp[(2) - (5)].str), (yyvsp[(3) - (5)].field), NULL);
}
    break;

  case 207:
#line 1105 "mediator_config_parse.y"
    {
    /* PREFIX "name" [ IE, IE, ... ] */
    /* uses SIP by default */
    parseFileList((yyvsp[(2) - (4)].str), SIP_V4, NULL);
}
    break;

  case 208:
#line 1111 "mediator_config_parse.y"
    {
    /* PREFIX "name" {SIP|DIP|FLOWKEYHASH} MAP ( "name" ) [ IE, IE, ... ] */
    parseFileList((yyvsp[(2) - (9)].str), (yyvsp[(3) - (9)].field), (yyvsp[(6) - (9)].str));
}
    break;

  case 209:
#line 1115 "mediator_config_parse.y"
    {
    /* PREFIX "name" MAP ( "name" ) [ IE, IE, ... ] */
    parseFileList((yyvsp[(2) - (8)].str), SIP_V4, (yyvsp[(5) - (8)].str));
}
    break;

  case 211:
#line 1124 "mediator_config_parse.y"
    {
    cfg_dns_dedup.temp_name = (yyvsp[(2) - (3)].str);
}
    break;

  case 212:
#line 1129 "mediator_config_parse.y"
    {
    parseDNSDedupConfigEnd();
}
    break;

  case 223:
#line 1148 "mediator_config_parse.y"
    {
    parseDNSDedupRecordTypeList();
}
    break;

  case 224:
#line 1153 "mediator_config_parse.y"
    {
    /* MAP("name") */
    if (cfg_dns_dedup.map) {
        mediator_config_error(
            "MAP already defined for this DNS_DEDUP config block.");
    }
    cfg_dns_dedup.map = (yyvsp[(1) - (1)].fieldMap);
}
    break;

  case 225:
#line 1163 "mediator_config_parse.y"
    {
    cfg_dns_dedup.exportname = TRUE;
}
    break;

  case 226:
#line 1168 "mediator_config_parse.y"
    {
    /* TOK_MAX_HIT_COUNT */
    if ((yyvsp[(1) - (1)].integer) > (int)UINT16_MAX) {
        mediator_config_error("MAX_HIT_COUNT is above maximum of %u",
                              UINT16_MAX);
    }
    cfg_dns_dedup.max_hit = (yyvsp[(1) - (1)].integer);
}
    break;

  case 227:
#line 1178 "mediator_config_parse.y"
    {
    /* TOK_FLUSH_TIMEOUT */
    if ((yyvsp[(1) - (1)].integer) > (int)UINT16_MAX) {
        mediator_config_error("FLUSH_TIMEOUT is above maximum of %u",
                              UINT16_MAX);
    }
    cfg_dns_dedup.flush_timeout = (yyvsp[(1) - (1)].integer);
}
    break;

  case 228:
#line 1188 "mediator_config_parse.y"
    {
    md_config.dns_base64_encode = TRUE;
}
    break;

  case 229:
#line 1193 "mediator_config_parse.y"
    {
    cfg_dns_dedup.lastseen = TRUE;
}
    break;

  case 231:
#line 1201 "mediator_config_parse.y"
    {
    parseTableListBegin((yyvsp[(2) - (3)].str));
}
    break;

  case 232:
#line 1206 "mediator_config_parse.y"
    {
    resetValueListTemp();
}
    break;

  case 237:
#line 1219 "mediator_config_parse.y"
    {
    parseTableList((yyvsp[(2) - (4)].str));
}
    break;

  case 238:
#line 1224 "mediator_config_parse.y"
    {
    parseExporterFields();
}
    break;

  case 239:
#line 1229 "mediator_config_parse.y"
    {
    parseExporterDpiFieldList();
}
    break;

  case 240:
#line 1234 "mediator_config_parse.y"
    {
    parseMySQLParams((yyvsp[(2) - (3)].str), NULL, NULL, NULL, NULL);
}
    break;

  case 241:
#line 1238 "mediator_config_parse.y"
    {
    parseMySQLParams(NULL, (yyvsp[(2) - (3)].str), NULL, NULL, NULL);
}
    break;

  case 242:
#line 1242 "mediator_config_parse.y"
    {
    parseMySQLParams(NULL, NULL, (yyvsp[(2) - (3)].str), NULL, NULL);
}
    break;

  case 243:
#line 1246 "mediator_config_parse.y"
    {
    parseMySQLParams(NULL, NULL, NULL, (yyvsp[(2) - (3)].str), NULL);
}
    break;

  case 244:
#line 1250 "mediator_config_parse.y"
    {
    parseMySQLParams(NULL, NULL, NULL, NULL, (yyvsp[(2) - (3)].str));
}
    break;

  case 245:
#line 1255 "mediator_config_parse.y"
    {
    parseUserInfoElement((yyvsp[(2) - (4)].integer), (yyvsp[(3) - (4)].str), NULL);
}
    break;

  case 246:
#line 1259 "mediator_config_parse.y"
    {
    int app = (yyvsp[(4) - (5)].integer);
    parseUserInfoElement((yyvsp[(2) - (5)].integer), (yyvsp[(3) - (5)].str), &app);
}
    break;

  case 247:
#line 1265 "mediator_config_parse.y"
    {
    parseExporterRemoveUploaded();
}
    break;

  case 249:
#line 1273 "mediator_config_parse.y"
    {
    parseSSLConfigBegin((yyvsp[(2) - (3)].str));
}
    break;

  case 250:
#line 1278 "mediator_config_parse.y"
    {
    etemp = NULL;
    resetValueListTemp();
}
    break;

  case 264:
#line 1301 "mediator_config_parse.y"
    {
    REQUIRE_NOTNULL(etemp);
    md_ssl_dedup_configure_state(etemp->ssl_dedup, 0, 0, NULL, NULL, TRUE);
}
    break;

  case 265:
#line 1307 "mediator_config_parse.y"
    {
    /* MAP("name") */
    REQUIRE_NOTNULL(etemp);
    md_ssl_dedup_configure_state(etemp->ssl_dedup, 0, 0, NULL, (yyvsp[(1) - (1)].fieldMap), FALSE);
}
    break;

  case 266:
#line 1314 "mediator_config_parse.y"
    {
    parseSSLConfigTypeList(MD_SSLCONFIG_ISSUER);
}
    break;

  case 267:
#line 1319 "mediator_config_parse.y"
    {
    parseSSLConfigTypeList(MD_SSLCONFIG_SUBJECT);
}
    break;

  case 268:
#line 1324 "mediator_config_parse.y"
    {
    parseSSLConfigTypeList(MD_SSLCONFIG_OTHER);
}
    break;

  case 269:
#line 1329 "mediator_config_parse.y"
    {
    parseSSLConfigTypeList(MD_SSLCONFIG_EXTENSIONS);
}
    break;

  case 270:
#line 1334 "mediator_config_parse.y"
    {
    parseSSLCertDedup();
}
    break;

  case 271:
#line 1339 "mediator_config_parse.y"
    {
    /* TOK_MAX_HIT_COUNT */
    REQUIRE_NOTNULL(etemp);
    md_ssl_dedup_configure_state(etemp->ssl_dedup, (yyvsp[(1) - (1)].integer), 0, NULL, NULL, FALSE);
}
    break;

  case 272:
#line 1346 "mediator_config_parse.y"
    {
    /* TOK_FLUSH_TIMEOUT */
    REQUIRE_NOTNULL(etemp);
    md_ssl_dedup_configure_state(etemp->ssl_dedup, 0, (yyvsp[(1) - (1)].integer), NULL, NULL, FALSE);
}
    break;

  case 273:
#line 1353 "mediator_config_parse.y"
    {
    parseSSLCertFile((yyvsp[(2) - (3)].str));
}
    break;

  case 275:
#line 1362 "mediator_config_parse.y"
    {
    parseMapBegin(VLAN, (yyvsp[(2) - (3)].str));
}
    break;

  case 276:
#line 1367 "mediator_config_parse.y"
    {
    parseMapEnd(VLAN);
}
    break;

  case 278:
#line 1376 "mediator_config_parse.y"
    {
    parseMapBegin(OBDOMAIN, (yyvsp[(2) - (3)].str));
}
    break;

  case 279:
#line 1381 "mediator_config_parse.y"
    {
    parseMapEnd(OBDOMAIN);
}
    break;

  case 286:
#line 1396 "mediator_config_parse.y"
    {
    parseMapLine((yyvsp[(1) - (3)].str));
}
    break;

  case 287:
#line 1401 "mediator_config_parse.y"
    {
    parseMapOther((yyvsp[(1) - (3)].str));
}
    break;

  case 288:
#line 1406 "mediator_config_parse.y"
    {
    parseMapDiscard();
}
    break;

  case 289:
#line 1411 "mediator_config_parse.y"
    {
    if (((yyvsp[(2) - (3)].integer)) < 1) {
        mediator_config_error("MAX_HIT_COUNT must be a positive integer");
    }
    (yyval.integer) = (yyvsp[(2) - (3)].integer);
}
    break;

  case 290:
#line 1419 "mediator_config_parse.y"
    {
    if (((yyvsp[(2) - (3)].integer)) < 1) {
        mediator_config_error("FLUSH_TIMEOUT must be a positive integer");
    }
    (yyval.integer) = (yyvsp[(2) - (3)].integer);
}
    break;

  case 291:
#line 1427 "mediator_config_parse.y"
    {
    (yyval.fieldMap) = parseMapStmt((yyvsp[(3) - (5)].str));
}
    break;

  case 292:
#line 1432 "mediator_config_parse.y"
    {
    (yyval.str) = NULL;
}
    break;

  case 296:
#line 1442 "mediator_config_parse.y"
    {
    /* parse into a signed 32 bit integer */
    (yyval.integer) = parseNumericValue((yyvsp[(1) - (1)].str), 10);
}
    break;

  case 297:
#line 1447 "mediator_config_parse.y"
    {
    /* parse into a signed 32 bit integer */
    (yyval.integer) = parseNumericValue((yyvsp[(1) - (1)].str), 16);
}
    break;


/* Line 1267 of yacc.c.  */
#line 3566 "mediator_config_parse.c"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;


  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (yymsg);
	  }
	else
	  {
	    yyerror (YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse look-ahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse look-ahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  *++yyvsp = yylval;


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEOF && yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}


#line 1452 "mediator_config_parse.y"


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

