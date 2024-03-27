%{
/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_config_lex.l
 *
 *  Lexical analyzer for mediator.conf configuration files.
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

#include <stdint.h>
#include <ctype.h>
#include "mediator_structs.h"
#include "mediator_config.h"
#include "mediator_config_parse.h"

int  lineNumber = 1;

/* configuration file name set by mdConfigfileParse() */
static const char *config_file = NULL;

#define BUF_SIZE 2048
static char  pipeconf_buf[BUF_SIZE];
static char *pipeconf_buf_end = pipeconf_buf + BUF_SIZE - 1;
static char *pipeconf_buf_ptr;

#define STRING_CHECK                             \
    if (pipeconf_buf_ptr >= pipeconf_buf_end) {  \
        *pipeconf_buf_end = '\0';                \
        mediator_config_warn("String too long"); \
        BEGIN(ST_STRING_ERR);                    \
    }

/*  Tell uncrustify to ignore the next part of the file */
/*  *INDENT-OFF* */
%}

%option never-interactive nounput noinput

%x ST_STRING

    /* state to use when a quoted string is too long */

%x ST_STRING_ERR

%x ST_TOKEN_ERR

     /* character classes */

wschar      [ \t\r]

wsopt       {wschar}*

ws          {wschar}+

comment     {wsopt}#.*\n

nl          {wsopt}\n

sp_         [ _]

eol         {nl}|{comment}

    /* Atoms (symbols) without quotes */

atomchar    [-_/@A-Za-z0-9]
atom        {atomchar}+

    /* numbers */

number      [0-9]+
exponent    [Ee][-+]?{number}

hexnumber   0[xX][0-9a-fA-F]+

    /* various forms for IP addresses */

ip4         [0-9]+\.[0-9]+\.[0-9\.]+
ip6         [0-9a-fA-F:]*:[0-9a-fA-F:]*:[0-9a-fA-F\.\:]*

ip          {ip4}|{ip6}

    /* date / time -- FIXME: Either parse this or get rid of it. */

timestr     [0-9]+[-/][0-9]+[-/][0-9Tt:.]+

%%

{eol}                   {lineNumber++; return EOS;}

{ws}                    ;

    /* symbols that are not operators */
"["                     {return LEFT_SQ_BRACKET;}
"]"                     {return RIGHT_SQ_BRACKET;}
"("                     {return LEFT_PAREN;}
")"                     {return RIGHT_PAREN;}
","                     {return COMMA;}
"*"                     {return WILD;}

    /* operators (fieldOperator_t), used in comparisons */
"=="                    {yylval.oper = EQUAL; return VAL_OPER;}
"!="                    {yylval.oper = NOT_EQUAL; return VAL_OPER;}
"<"                     {yylval.oper = LESS_THAN; return VAL_OPER;}
"<="                    {yylval.oper = LESS_THAN_OR_EQUAL; return VAL_OPER;}
">"                     {yylval.oper = GREATER_THAN; return VAL_OPER;}
">="                    {yylval.oper = GREATER_THAN_OR_EQUAL; return VAL_OPER;}
IN_LIST                 {yylval.oper = IN_LIST; return VAL_OPER;}
NOT_IN_LIST             {yylval.oper = NOT_IN_LIST; return VAL_OPER;}

    /* fields (mdAcceptFilterField_t) */
DIP                     {yylval.field = DIP_ANY; return VAL_FIELD;}
dip                     {yylval.field = DIP_ANY; return VAL_FIELD;}
DIP{sp_}V4              {yylval.field = DIP_V4; return VAL_FIELD;}
FLOWKEYHASH             {yylval.field = FLOWKEYHASH; return VAL_FIELD;}
flowkeyhash             {yylval.field = FLOWKEYHASH; return VAL_FIELD;}
OBDOMAIN                {yylval.field = OBDOMAIN; return VAL_FIELD;}
obdomain                {yylval.field = OBDOMAIN; return VAL_FIELD;}
SIP                     {yylval.field = SIP_ANY; return VAL_FIELD;}
sip                     {yylval.field = SIP_ANY; return VAL_FIELD;}
SIP{sp_}V4              {yylval.field = SIP_V4; return VAL_FIELD;}
VLAN                    {yylval.field = VLAN; return VAL_FIELD;}
vlan                    {yylval.field = VLAN; return VAL_FIELD;}

    /* transport for collectors and exporters (mdConfTransport_t) */
DIRECTORY_POLL          {yylval.transport = MD_CONF_TPORT_DIRECTORY_POLL;
                         return VAL_TRANSPORT;}
ROTATING{sp_}FILES      {yylval.transport = MD_CONF_TPORT_ROTATING_FILES;
                         return VAL_TRANSPORT;}
SINGLE{sp_}FILE         {yylval.transport = MD_CONF_TPORT_SINGLE_FILE;
                         return VAL_TRANSPORT;}
TCP                     {yylval.transport = MD_CONF_TPORT_TCP;
                         return VAL_TRANSPORT;}
UDP                     {yylval.transport = MD_CONF_TPORT_UDP;
                         return VAL_TRANSPORT;}

    /* exporter format (mdExportFormat_t) */
IPFIX                   {yylval.exportFormat = EF_IPFIX;
                         return VAL_EXPORT_FORMAT;}
JSON                    {yylval.exportFormat = EF_JSON;
                         return VAL_EXPORT_FORMAT;}
TEXT                    {yylval.exportFormat = EF_TEXT;
                         return VAL_EXPORT_FORMAT;}

    /* log levels (mdLogLevel_t) */
DEBUG                   {yylval.log_level = MD_DEBUG; return VAL_LOGLEVEL;}
MESSAGE                 {yylval.log_level = MESSAGE; return VAL_LOGLEVEL;}
QUIET                   {yylval.log_level = QUIET; return VAL_LOGLEVEL;}
WARNING                 {yylval.log_level = WARNING; return VAL_LOGLEVEL;}
ERROR                   {yylval.log_level = ERROR; return VAL_LOGLEVEL;}

    /* TLS/SSL certifcate hashing/digest methods */
SSL{sp_}CERT{sp_}HASH{sp_}MD5       {yylval.certDigest = SM_DIGEST_MD5;
                                     return VAL_CERT_DIGEST;}
SSL{sp_}CERT{sp_}HASH{sp_}SHA1      {yylval.certDigest = SM_DIGEST_SHA1;
                                     return VAL_CERT_DIGEST;}

    /* keyword terminals, sorted by return value */

ADD_EXPORT                      {return TOK_ADD_EXPORTER_NAME;}
ADD_EXPORT_NAME                 {return TOK_ADD_EXPORTER_NAME;}
ADD{sp_}EXPORTER                {return TOK_ADD_EXPORTER_NAME;}
ADD{sp_}EXPORTER{sp_}NAME       {return TOK_ADD_EXPORTER_NAME;}
AND{sp_}FILTERS?                {return TOK_AND_FILTER;}
BASE64{sp_}ENCODE               {return TOK_BASE_64;}
CERT{sp_}FILE                   {return TOK_CERT_FILE;}
COLLECTOR                       {return TOK_COLLECTOR;}
collector                       {return TOK_COLLECTOR_FILTER;}
DECOMPRESS{sp_}DIRECTORY        {return TOK_DECOMPRESS_DIRECTORY;}
DEDUP{sp_}CONFIG                {return TOK_DEDUP_CONFIG;}
DEDUP{sp_}ONLY                  {return TOK_DEDUP_ONLY;}
DEDUP{sp_}PER{sp_}FLOW          {return TOK_DEDUP_PER_FLOW;}
DELETE                          {return TOK_DELETE;}
DELIM                           {return TOK_DELIM;}
DELIMITER                       {return TOK_DELIM;}
DISABLE                         {return TOK_DISABLE;}
DISCARD                         {return TOK_DISCARD;}
DISCARD{sp_}OTHER               {return TOK_DISCARD;}
DNS{sp_}RESPONSE{sp_}ONLY       {return TOK_DNSRESPONSE_ONLY;}
DNS{sp_}RR                      {return TOK_DNSRR;}
DNS{sp_}RR{sp_}ONLY             {return TOK_DNSRR_ONLY;}
DNS{sp_}DEDUP                   {return TOK_DNS_DEDUP;}
DNS{sp_}DEDUP{sp_}ONLY          {return TOK_DNS_DEDUP_ONLY;}
DPI{sp_}CONFIG                  {return TOK_DPI_CONFIG;}
DPI_DELIMITER                   {return TOK_DPI_DELIMITER;}
DPI{sp_}FIELD{sp_}LIST          {return TOK_DPI_FIELD_LIST;}
DPI{sp_}ONLY                    {return TOK_DPI_ONLY;}
END                             {return TOK_END;}
ESCAPE                          {return TOK_ESCAPE;}
ESCAPE{sp_}CHARACTERS           {return TOK_ESCAPE;}
ESCAPE{sp_}CHARS                {return TOK_ESCAPE;}
EXPORTER                        {return TOK_EXPORTER;}
EXTENSIONS?                     {return TOK_EXTENSIONS;}
FIELDS                          {return TOK_FIELDS;}
FILE{sp_}PREFIX                 {return TOK_FILE_PREFIX;}
PREFIX                          {return TOK_FILE_PREFIX;}
FILTER                          {return TOK_FILTER;}
FLOW{sp_}ONLY                   {return TOK_FLOW_ONLY;}
FLUSH_TIMEOUT                   {return TOK_FLUSH_TIMEOUT;}
FLUSH{sp_}TIME                  {return TOK_FLUSH_TIMEOUT;}
FULL                            {return TOK_FULL;}
GEN{sp_}TOMBSTONE               {return TOK_GEN_TOMBSTONE;}
GZIP                            {return TOK_GZIP;}
GZIP{sp_}FILES                  {return TOK_GZIP;}
HOSTNAME                        {return TOK_HOSTNAME;}
IP{sp_}ADDRESS                  {return TOK_HOSTNAME;}
INVARIANT                       {return TOK_INVARIANT;}
IPSET{sp_}FILE                  {return TOK_IPSET_FILE;}
ISSUER                          {return TOK_ISSUER;}
LAST{sp_}SEEN                   {return TOK_LAST_SEEN;}
LOCK                            {return TOK_LOCK;}
LOG{sp_}DIR                     {return TOK_LOG_DIR;}
LOG{sp_}DIRECTORY               {return TOK_LOG_DIR;}
LOG                             {return TOK_LOG_FILE;}
LOG{sp_}FILE                    {return TOK_LOG_FILE;}
LOGLEVEL                        {return TOK_LOG_LEVEL;}
LOG{sp_}LEVEL                   {return TOK_LOG_LEVEL;}
MAP                             {return TOK_MAP;}
MAX{sp_}BYTES                   {return TOK_MAX_BYTES;}
MAX{sp_}HIT{sp_}COUNT           {return TOK_MAX_HIT_COUNT;}
MAX{sp_}SECONDS                 {return TOK_MAX_SECONDS;}
MERGE{sp_}TRUNCATED             {return TOK_MERGE_TRUNCATED;}
METADATA_EXPORT                 {return TOK_METADATA_EXPORT;}
MOVE                            {return TOK_MOVE;}
MOVE{sp_}PATH                   {return TOK_MOVE;}
MULTI                           {return TOK_MULTI_FILES;}
MULTI{sp_}FILES                 {return TOK_MULTI_FILES;}
MYSQL_DB                        {return TOK_MY_DB;}
MYSQL{sp_}DATABASE              {return TOK_MY_DB;}
MYSQL{sp_}HOST                  {return TOK_MY_HOST;}
MYSQL_PASS                      {return TOK_MY_PW;}
MYSQL{sp_}PASSWORD              {return TOK_MY_PW;}
REMOVE{sp_}UPLOADED             {return TOK_MY_REMOVE;}
MYSQL{sp_}TABLE                 {return TOK_MY_TABLE;}
MYSQL{sp_}USER                  {return TOK_MY_USER;}
NO{sp_}FLOW                     {return TOK_NO_FLOW;}
NO{sp_}FLOW{sp_}STATS           {return TOK_NO_FLOW_STATS;}
NO{sp_}INDEX                    {return TOK_NO_INDEX;}
NO{sp_}STATS                    {return TOK_NO_STATS;}
OBID{sp_}MAP                    {return TOK_OBID_MAP;}
OTHER                           {return TOK_OTHER;}
FILE                            {return TOK_PATH;}
PATH                            {return TOK_PATH;}
PIDFILE                         {return TOK_PID_FILE;}
PID{sp_}FILE                    {return TOK_PID_FILE;}
POLL                            {return TOK_POLL;}
PORT                            {return TOK_PORT;}
PRESERVE{sp_}OBDOMAIN           {return TOK_PRESERVE_OBDOMAIN;}
PRINT{sp_}HEADER                {return TOK_PRINT_HEADER;}
RECORDS                         {return TOK_RECORDS;}
REMOVE{sp_}EMPTY{sp_}FILES      {return TOK_REMOVE_EMPTY_FILES;}
REWRITE_SSL_CERTS               {return TOK_REWRITE_SSL_CERTS;}
ROTATE{sp_}INTERVAL             {return TOK_ROTATE_INTERVAL;}
SSL{sp_}CONFIG                  {return TOK_SSL_CONFIG;}
SSL{sp_}CERT{sp_}DEDUP          {return TOK_SSL_DEDUP;}
SSL{sp_}DEDUP                   {return TOK_SSL_DEDUP;}
SSL{sp_}DEDUP{sp_}ONLY          {return TOK_SSL_DEDUP_ONLY;}
STATS{sp_}ONLY                  {return TOK_STATS_ONLY;}
STATS{sp_}TIMEOUT               {return TOK_STATS_TIMEOUT;}
SUBJECT                         {return TOK_SUBJECT;}
TABLE                           {return TOK_TABLE;}
TIMESTAMP{sp_}FILES             {return TOK_TIMESTAMP_FILES;}
TOMBSTONE_CONFIG                {return TOK_TOMBSTONE_CONFIG;}
TOMBSTONE_CONFIGURED_ID         {return TOK_TOMBSTONE_CONFIGURED_ID;}
UDP{sp_}TEMPLATE{sp_}TIMEOUT    {return TOK_UDP_TEMPLATE_TIMEOUT;}
USER{sp_}IE                     {return TOK_USERIE;}
VLAN{sp_}MAP                    {return TOK_VLAN_MAP;}

    /* Error when old SM1 tokens are seen to give a better error */
FILEHANDLER             {
    ++lineNumber;
    mediator_config_error("FILEHANDLER is not supported in super_mediator-2");
}

{ip}                    {yylval.str = strdup(yytext); return VAL_IP;}

{number}"."{number}     {yylval.str = strdup(yytext); return VAL_DOUBLE;}
"."{number}             {yylval.str = strdup(yytext); return VAL_DOUBLE;}
{number}"."             {yylval.str = strdup(yytext); return VAL_DOUBLE;}
{number}"."{number}{exponent}  {yylval.str = strdup(yytext);return VAL_DOUBLE;}
"."{number}{exponent}   {yylval.str = strdup(yytext); return VAL_DOUBLE;}
{number}"."{exponent}   {yylval.str = strdup(yytext); return VAL_DOUBLE;}

{number}                {yylval.str = strdup(yytext); return VAL_INTEGER;}
{hexnumber}             {yylval.str = strdup(yytext); return VAL_HEXADECIMAL;}

{atom}                  {yylval.str = strdup(yytext); return VAL_ATOM;}

    /* FIXME: Change string parsing to support hexadecimal or unicode escapes
     * return a GString so it may contain embedded NUL characters for matching
     * to MAC addresses and other octetArrays. */

\"                     {BEGIN(ST_STRING); pipeconf_buf_ptr = pipeconf_buf;}

<ST_STRING>\\n         {*pipeconf_buf_ptr++ = '\n'; STRING_CHECK;}
<ST_STRING>\\t         {*pipeconf_buf_ptr++ = '\t'; STRING_CHECK;}
<ST_STRING>\\r         {*pipeconf_buf_ptr++ = '\r'; STRING_CHECK;}
<ST_STRING>\\b         {*pipeconf_buf_ptr++ = '\b'; STRING_CHECK;}
<ST_STRING>\\f         {*pipeconf_buf_ptr++ = '\f'; STRING_CHECK;}
<ST_STRING>\\\n        {*pipeconf_buf_ptr++ = '\n'; STRING_CHECK;}
<ST_STRING>\\.         {*pipeconf_buf_ptr++ = yytext[1]; STRING_CHECK;}

<ST_STRING>[^\\\n\"]+  {if ((pipeconf_buf_ptr + yyleng) < pipeconf_buf_end ) {
                            memcpy(pipeconf_buf_ptr, yytext, yyleng);
                            pipeconf_buf_ptr += yyleng;
                        } else {
                            memcpy(pipeconf_buf_ptr, yytext,
                                   pipeconf_buf_end - pipeconf_buf_ptr);
                            *pipeconf_buf_end = '\0';
                            mediator_config_warn("String too long");
                            BEGIN(ST_STRING_ERR);
                        } }

<ST_STRING>\n          {BEGIN(INITIAL);
                        yyless(0);
                        mediator_config_warn("String missing closing \"");
                        *pipeconf_buf_ptr = '\0';
                        yylval.str = strdup(pipeconf_buf);
                        return VAL_QSTRING; }

<ST_STRING>\"          {BEGIN(INITIAL);
                        *pipeconf_buf_ptr = '\0';
                        yylval.str = strdup(pipeconf_buf);
                        return VAL_QSTRING; }

    /* ST_STRING_ERR state: Entered when a string is too long.
     * Accepts everything up to closing quote or the end of the
     * line. */

<ST_STRING_ERR>[^\\\n\"]+  ;
<ST_STRING_ERR>\\.         ;
<ST_STRING_ERR>\"      {BEGIN(INITIAL);
                        yylval.str = strdup(pipeconf_buf);
                        return VAL_QSTRING; }
<ST_STRING_ERR>\n      {BEGIN(INITIAL);
                        yyless(0);
                        mediator_config_warn("String missing closing \"");
                        yylval.str = strdup(pipeconf_buf);
                        return VAL_QSTRING; }

    /* Handle unknown keyword */

.                           {yyless(0); BEGIN(ST_TOKEN_ERR);}

<ST_TOKEN_ERR>[^ \t\r\n]+   {mediator_config_warn("Unrecognized token '%s'",
                                                  yytext);
                             BEGIN(INITIAL); }

%%

/*  Reenable uncrustify */
/*  *INDENT-ON* */

int
yywrap(
    void)
{
    return 1;
}

int
mediator_config_error(
    const char  *fmt,
    ...)
{
    va_list  ap;

    va_start(ap, fmt);
    fprintf(stderr, "Error at %s:%d: ", config_file, lineNumber - 1);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(-1);
}

void
mediator_config_warn(
    const char  *fmt,
    ...)
{
    va_list  ap;

    va_start(ap, fmt);
    fprintf(stderr, "Warning at %s:%d: ", config_file, lineNumber - 1);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}


gboolean
mdConfigfileParse(
    const char  *path,
    GError     **err)
{
    const char *env;

    env = getenv("SM_TRACE_PARSER");
    if (env && (*env == '1')) {
        yydebug = 1;
    }

    config_file = path;

    yyin = fopen(config_file, "r");
    if (!yyin) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Could not open configuration file \"%s\" for reading: %s",
                    config_file, strerror(errno));
        return FALSE;
    }

    while (!feof(yyin)) {
        (void)yyparse();
    }
    return TRUE;
}
