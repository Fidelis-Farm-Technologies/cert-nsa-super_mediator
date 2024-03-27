/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

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
/* Line 1529 of yacc.c.  */
#line 285 "mediator_config_parse.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

