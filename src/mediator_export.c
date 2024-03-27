/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_export.c
 *
 *  All exporting related functions, bulk of the code.
 *
 *  ------------------------------------------------------------------------
 *  Authors: Emily Sarneso, Matt Coates
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


/* define this value to define extern variables in the headers */
#define  MEDIATOR_EXPORT_SOURCE 1

#include <sys/time.h>
#include <sys/resource.h>
#include "mediator_autohdr.h"
#include "mediator_structs.h"
#include "mediator_inf.h"
#include "mediator_core.h"
#include "mediator_filter.h"
#include "mediator_util.h"
#include "templates.h"
#include "specs.h"
#include "mediator_dns.h"
#include "mediator_dedup.h"
#include "mediator_ssl.h"
#include "mediator_stat.h"
#include "mediator_print.h"
#include "mediator_json.h"

#ifdef HAVE_OPENSSL
#include <openssl/md5.h>
#include <openssl/sha.h>
#endif
#ifdef HAVE_MYSQL
#include <mysql.h>
#endif


#define ROTATE_IF_NEEDED(_exp_, _time_, _err_)                      \
    if (_exp_->rotateInterval) {                                    \
        if (_exp_->activeWriter->lastRotate) {                      \
            if ((_time_ - _exp_->activeWriter->lastRotate) >        \
                _exp_->rotateInterval) {                            \
                if (_exp_->exportFormat == EF_IPFIX) {              \
                    if (!mdIpfixFileRotate(_exp_, _time_, _err_)) { \
                        return FALSE;                               \
                    }                                               \
                } else {                                            \
                    if (!mdTextFileRotate(_exp_, _time_, _err_)) {  \
                        return FALSE;                               \
                    }                                               \
                }                                                   \
            }                                                       \
        } else {                                                    \
            _exp_->activeWriter->lastRotate = _time_;               \
        }                                                           \
    }

#define INSTALL_DEFAULT_FILE_WRITER(_exp_) \
    _exp_->activeWriter = _exp_->defaultWriter;

#define INSTALL_THIS_FILE_WRITER(_exp_, _thisWriter_) \
    _exp_->activeWriter = _thisWriter_;

#define REQUIRE_EXPORTFORMAT_TEXT_OR_JSON(_exp_, _err_)                 \
    if (EXPORTFORMAT_IS_TEXT_OR_JSON((_exp_)->exportFormat)) {          \
        /* ok */                                                        \
    } else {                                                            \
        g_set_error((_err_), MD_ERROR_DOMAIN, MD_ERROR_SETUP,           \
                    "Only allowed for a TEXT or JSON exporter");        \
        return FALSE;                                                   \
    }

#define REQUIRE_EXPORTFORMAT_TEXT(_exp_, _err_)                         \
    if (EF_TEXT == (_exp_)->exportFormat) { /* ok */ } else {           \
        g_set_error((_err_), MD_ERROR_DOMAIN, MD_ERROR_SETUP,           \
                    "Only allowed for a TEXT exporter");                \
        return FALSE;                                                   \
    }

#define REQUIRE_EXPORTFORMAT_IPFIX(_exp_, _err_)                        \
    if (EF_IPFIX == (_exp_)->exportFormat) { /* ok */ } else {          \
        g_set_error((_err_), MD_ERROR_DOMAIN, MD_ERROR_SETUP,           \
                    "Only allowed for an IPFIX exporter");              \
        return FALSE;                                                   \
    }


static fbTemplateInfo_t *
mdNewTemplateInfo(
    const mdExporter_t *exporter,
    const char         *name,
    uint16_t            appLabel,
    uint16_t            parentTid)
{
    fbTemplateInfo_t *mdInfo;

    if (!exporter->metadataExportTemplates) {
        return NULL;
    }
    mdInfo = fbTemplateInfoAlloc();
    if (!fbTemplateInfoInit(mdInfo, name, "", appLabel, parentTid)) {
        g_error("Couldn't initialize info for %s", name);
    }
    return mdInfo;
}

static gboolean
mdExporterPassTemplateToInvariantProcessors(
    mdExporter_t  *exporter,
    uint16_t       tid,
    fbTemplate_t  *tmpl,
    GError       **err);

/* a struct to keep track of table/file names for  DPI output */
typedef struct mdTableInfo_st {
    char      *table_name;
    FILE      *table_file;
    char      *file_name;
    uint64_t   last_rotate_ms;
    uint8_t    serial;
} mdTableInfo_t;

static mdTableInfo_t  **table_info = NULL;
static int              num_tables = 0;
static GHashTable      *table_hash = NULL;

static unsigned int     num_exporters = 0;


/*
 *  If the exporter is configured to generate output, set `err` and return
 *  TRUE; otherwise return FALSE.
 *
 *  Note that the return value of this function is the opposite of GLib the
 *  convention.
 */
static gboolean
mdExporterGeneratingAnything(
    const mdExporter_t *exporter,
    GError            **err)
{
    const char *setting = NULL;

    if (exporter->generateDnsDedup) {
        setting = "DNS_DEDUP";
    } else if (exporter->generateSslDedup) {
        setting = "SSL_DEDUP";
    } else if (exporter->generateDnsRR) {
        setting = "DNS_RR";
    } else if (exporter->generateGeneralDedup) {
        setting = "DEDUP_ONLY";
    }

    if (setting) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Exporter previously configured for %s", setting);
        return TRUE;
    }
    return FALSE;
}


/*  Set all allow<TYPE> and generate<TYPE> values to FALSE. */
static void
mdExporterDisableAllOutputs(
    mdExporter_t   *exporter)
{
    exporter->allowDnsDedup       = FALSE;
    exporter->allowDnsRR          = FALSE;
    exporter->allowFlow           = FALSE;
    exporter->allowSslCert        = FALSE;
    exporter->allowSslDedup       = FALSE;
    exporter->allowTombstone      = FALSE;
    exporter->allowYafStats       = FALSE;

    exporter->flowDpiRequired     = FALSE;
    exporter->flowDpiStrip        = FALSE;

    exporter->generateDnsDedup     = FALSE;
    exporter->generateDnsRR        = FALSE;
    exporter->generateGeneralDedup = FALSE;
    exporter->generateSslDedup     = FALSE;
}


/*
 *  Fill `err` with a message about some feature of the exporter already being
 *  enabled.  This should be called then an allow<TYPE> is false; the error
 *  message will say what setting has (most likely) set allow<TYPE> to FALSE.
 */
static void
mdExporterFillRecordTypeConflictError(
    const mdExporter_t *exporter,
    GError            **err)
{
    const char *setting = "";

    if (exporter->generateDnsDedup) {
        setting = "DNS_DEDUP_ONLY";
    } else if (exporter->generateDnsRR) {
        setting = "DNS_RR_ONLY";
    } else if (exporter->generateGeneralDedup) {
        setting = "DEDUP_ONLY";
    } else if (exporter->generateSslDedup) {
        setting = "SSL_DEDUP_ONLY";
    } else if (exporter->flowDpiStrip) {
        setting = "FLOW_ONLY";
    } else {
        g_error("Programmer error; record type conflict not handled");
    }

    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                "Exporter was previously configured for %s", setting);
}


static void
mdCloseAndUnlock(
    mdExporter_t  *exporter,
    FILE          *fp,
    char          *filename,
    char          *table);

/**
 * mdNewTable
 *
 *
 * create a new table to keep track of the table or file names
 * for DPI to CSV output
 *
 * @param table name of table
 */
void *
mdNewTable(
    const char *table)
{
    if (!table_info) {
        table_info =
            (mdTableInfo_t **)g_malloc(MAX_VALUE_LIST *
                                       sizeof(mdTableInfo_t *));
    }

    if (num_tables > 0 && (num_tables % MAX_VALUE_LIST)) {
        table_info =
            (mdTableInfo_t **)g_realloc(table_info,
                                        ((MAX_VALUE_LIST + num_tables) *
                                         sizeof(mdTableInfo_t *)));
    }

    table_info[num_tables] = g_slice_new0(mdTableInfo_t);
    table_info[num_tables]->table_name = g_strdup(table);
    table_info[num_tables]->serial = 0;
    num_tables++;

    return (void *)table_info[num_tables - 1];
}


void *
mdGetTableByApplication(
    int   id)
{
    const char    *newID;

    /* associate app label with known info element */
    switch (id) {
      case 80:
        newID = "httpServerString";
        break;
      case 21:
        newID = "ftpReturn";
        break;
      case 25:
        newID = "smtpHello";
        break;
      case 53:
        newID = "dns_1";
        break;
      case 143:
        newID = "imapCapability";
        break;
      case 554:
        newID = "rtspURL";
        break;
      case 5060:
        newID = "sipInvite";
        break;
      case 22:
        newID = "sshVersion";
        break;
      default:
        return NULL;
    }

    return (void *)g_hash_table_lookup(table_hash, (gconstpointer)newID);
}

gboolean
mdTableHashEnabled(
    void)
{
    return !!(table_hash);
}

/**
 * mdInsertTableItem
 *
 *
 * Insert an Info Element ID/mdTableInfo struct into the hash table
 * for quick lookup.
 *
 */
gboolean
mdInsertTableItem(
    void        *table_name,
    const char  *val)
{
    gpointer rc;

    if (!table_hash) {
        table_hash = g_hash_table_new((GHashFunc)g_str_hash,
                                      (GEqualFunc)g_str_equal);
        if (table_hash == NULL) {
            return FALSE;
        }
    }

    rc = g_hash_table_lookup(table_hash, (gconstpointer)val);
    if (rc) {
        return FALSE;
    }

    g_hash_table_insert(table_hash, (gpointer)val, table_name);

    return TRUE;
}


/**
 * mdBuildDefaultTableHash
 *
 * if the user doesn't give us names for the files,
 * we need to create the hash table with all the default ones.
 *
 */
void
mdBuildDefaultTableHash(
    void)
{
    mdTableInfo_t *tab = NULL;

    tab = mdNewTable(FLOW_STATS_DEFAULT);
    mdInsertTableItem(tab, "stats");

    tab = mdNewTable(YAF_STATS_DEFAULT);
    mdInsertTableItem(tab, "yaf_stats");

    tab = mdNewTable(FTP_DEFAULT);
    mdInsertTableItem(tab, "ftpReturn");
    mdInsertTableItem(tab, "ftpUser");
    mdInsertTableItem(tab, "ftpPass");
    mdInsertTableItem(tab, "ftpType");
    mdInsertTableItem(tab, "ftpRespCode");

    tab = mdNewTable(SSH_DEFAULT);
    mdInsertTableItem(tab, "sshVersion");
    mdInsertTableItem(tab, "sshServerVersion");
    mdInsertTableItem(tab, "sshKeyExchangeAlgorithm");
    mdInsertTableItem(tab, "sshHostKeyAlgorithm");
    mdInsertTableItem(tab, "sshServerHostKey");
    mdInsertTableItem(tab, "sshCipher");
    mdInsertTableItem(tab, "sshMacAlgorithm");
    mdInsertTableItem(tab, "sshCompressionMethod");
    mdInsertTableItem(tab, "sshHassh");
    mdInsertTableItem(tab, "sshServerHassh");
    mdInsertTableItem(tab, "sshHasshAlgorithms");
    mdInsertTableItem(tab, "sshServerHasshAlgorithms");

    tab = mdNewTable(SMTP_DEFAULT);
    mdInsertTableItem(tab, "smtpHello");
    mdInsertTableItem(tab, "smtpFrom");
    mdInsertTableItem(tab, "smtpTo");
    mdInsertTableItem(tab, "smtpContentType");
    mdInsertTableItem(tab, "smtpSubject");
    mdInsertTableItem(tab, "smtpFilename");
    mdInsertTableItem(tab, "smtpContentDisposition");
    mdInsertTableItem(tab, "smtpResponse");
    mdInsertTableItem(tab, "smtpEnhanced");
    mdInsertTableItem(tab, "smtpSize");
    mdInsertTableItem(tab, "smtpDate");
    mdInsertTableItem(tab, "smtpKey");
    mdInsertTableItem(tab, "smtpValue");
    mdInsertTableItem(tab, "smtpURL");

    /* TODO: Standardize dns like the rest */
    tab = mdNewTable(DNS_DEFAULT);
    mdInsertTableItem(tab, "dns_1");
    mdInsertTableItem(tab, "dns_2");
    mdInsertTableItem(tab, "dns_5");
    mdInsertTableItem(tab, "dns_6");
    mdInsertTableItem(tab, "dns_12");
    mdInsertTableItem(tab, "dns_15");
    mdInsertTableItem(tab, "dns_16");
    mdInsertTableItem(tab, "dns_28");
    mdInsertTableItem(tab, "dns_33");
    mdInsertTableItem(tab, "dns_43");
    mdInsertTableItem(tab, "dns_47");
    mdInsertTableItem(tab, "dns_48");
    mdInsertTableItem(tab, "dns_50");
    mdInsertTableItem(tab, "dns_51");
    mdInsertTableItem(tab, "dns_53");

    tab = mdNewTable(TFTP_DEFAULT);
    mdInsertTableItem(tab, "tftpFilename");
    mdInsertTableItem(tab, "tftpMode");

    tab = mdNewTable(HTTP_DEFAULT);
    mdInsertTableItem(tab, "httpServerString");
    mdInsertTableItem(tab, "httpUserAgent");
    mdInsertTableItem(tab, "httpGet");
    mdInsertTableItem(tab, "httpConnection");
    mdInsertTableItem(tab, "httpVersion");
    mdInsertTableItem(tab, "httpReferer");
    mdInsertTableItem(tab, "httpLocation");
    mdInsertTableItem(tab, "httpHost");
    mdInsertTableItem(tab, "httpContentLength");
    mdInsertTableItem(tab, "httpAge");
    mdInsertTableItem(tab, "httpAccept");
    mdInsertTableItem(tab, "httpAcceptLanguage");
    mdInsertTableItem(tab, "httpContentType");
    mdInsertTableItem(tab, "httpResponse");
    mdInsertTableItem(tab, "httpCookie");
    mdInsertTableItem(tab, "httpSetCookie");
    mdInsertTableItem(tab, "httpAuthorization");
    mdInsertTableItem(tab, "httpVia");
    mdInsertTableItem(tab, "httpXForwardedFor");
    mdInsertTableItem(tab, "httpExpires");
    mdInsertTableItem(tab, "httpRefresh");
    mdInsertTableItem(tab, "httpIMEI");
    mdInsertTableItem(tab, "httpIMSI");
    mdInsertTableItem(tab, "httpMSISDN");
    mdInsertTableItem(tab, "httpSubscriber");
    mdInsertTableItem(tab, "httpAcceptCharset");
    mdInsertTableItem(tab, "httpAcceptEncoding");
    mdInsertTableItem(tab, "httpAllow");
    mdInsertTableItem(tab, "httpDate");
    mdInsertTableItem(tab, "httpExpect");
    mdInsertTableItem(tab, "httpFrom");
    mdInsertTableItem(tab, "httpProxyAuthentication");
    mdInsertTableItem(tab, "httpUpgrade");
    mdInsertTableItem(tab, "httpWarning");
    mdInsertTableItem(tab, "httpDNT");
    mdInsertTableItem(tab, "httpXForwardedProto");
    mdInsertTableItem(tab, "httpXForwardedHost");
    mdInsertTableItem(tab, "httpXForwardedServer");
    mdInsertTableItem(tab, "httpXDeviceId");
    mdInsertTableItem(tab, "httpXProfile");
    mdInsertTableItem(tab, "httpLastModified");
    mdInsertTableItem(tab, "httpContentEncoding");
    mdInsertTableItem(tab, "httpContentLanguage");
    mdInsertTableItem(tab, "httpContentLocation");
    mdInsertTableItem(tab, "httpXUaCompatible");

    tab = mdNewTable(IMAP_DEFAULT);
    mdInsertTableItem(tab, "imapCapability");
    mdInsertTableItem(tab, "imapLogin");
    mdInsertTableItem(tab, "imapStartTLS");
    mdInsertTableItem(tab, "imapAuthenticate");
    mdInsertTableItem(tab, "imapCommand");
    mdInsertTableItem(tab, "imapExists");
    mdInsertTableItem(tab, "imapRecent");

    tab = mdNewTable(IRC_DEFAULT);
    mdInsertTableItem(tab, "ircTextMessage");

    tab = mdNewTable(SIP_DEFAULT);
    mdInsertTableItem(tab, "sipInvite");
    mdInsertTableItem(tab, "sipCommand");
    mdInsertTableItem(tab, "sipVia");
    mdInsertTableItem(tab, "sipMaxForwards");
    mdInsertTableItem(tab, "sipAddress");
    mdInsertTableItem(tab, "sipContentLength");
    mdInsertTableItem(tab, "sipUserAgent");

    tab = mdNewTable(MYSQL_DEFAULT);
    mdInsertTableItem(tab, "mysqlUsername");
    mdInsertTableItem(tab, "mysqlCommandCode");
    mdInsertTableItem(tab, "mysqlCommandText");

    tab = mdNewTable(SLP_DEFAULT);
    mdInsertTableItem(tab, "slpVersion");
    mdInsertTableItem(tab, "slpMessageType");
    mdInsertTableItem(tab, "slpString");

    tab = mdNewTable(POP3_DEFAULT);
    mdInsertTableItem(tab, "pop3TextMessage");

    tab = mdNewTable(RTSP_DEFAULT);
    mdInsertTableItem(tab, "rtspURL");
    mdInsertTableItem(tab, "rtspVersion");
    mdInsertTableItem(tab, "rtspReturnCode");
    mdInsertTableItem(tab, "rtspContentLength");
    mdInsertTableItem(tab, "rtspCommand");
    mdInsertTableItem(tab, "rtspContentType");
    mdInsertTableItem(tab, "rtspTransport");
    mdInsertTableItem(tab, "rtspCSeq");
    mdInsertTableItem(tab, "rtspLocation");
    mdInsertTableItem(tab, "rtspPacketsReceived");
    mdInsertTableItem(tab, "rtspUserAgent");
    mdInsertTableItem(tab, "rtspJitter");

    tab = mdNewTable(NNTP_DEFAULT);
    mdInsertTableItem(tab, "nntpResponse");
    mdInsertTableItem(tab, "nntpCommand");

    tab = mdNewTable(SSL_DEFAULT);
    mdInsertTableItem(tab, "sslClientVersion");
    mdInsertTableItem(tab, "sslServerCipher");
    mdInsertTableItem(tab, "sslCompressionMethod");
    mdInsertTableItem(tab, "sslCertVersion");
    mdInsertTableItem(tab, "sslCertSignature");
    mdInsertTableItem(tab, "sslCertIssuerCountryName");
    mdInsertTableItem(tab, "sslCertIssuerOrgName");
    mdInsertTableItem(tab, "sslCertIssuerOrgUnitName");
    mdInsertTableItem(tab, "sslCertIssuerZipCode");
    mdInsertTableItem(tab, "sslCertIssuerState");
    mdInsertTableItem(tab, "sslCertIssuerCommonName");
    mdInsertTableItem(tab, "sslCertIssuerLocalityName");
    mdInsertTableItem(tab, "sslCertIssuerStreetAddress");
    /* TODO: Inaccurate? mdInsertTableItem(tab, 199); */
    mdInsertTableItem(tab, "sslCertSubjectCountryName");
    mdInsertTableItem(tab, "sslCertSubjectOrgName");
    mdInsertTableItem(tab, "sslCertSubjectOrgUnitName");
    mdInsertTableItem(tab, "sslCertSubjectZipCode");
    mdInsertTableItem(tab, "sslCertSubjectState");
    mdInsertTableItem(tab, "sslCertSubjectCommonName");
    mdInsertTableItem(tab, "sslCertSubjectLocalityName");
    mdInsertTableItem(tab, "sslCertSubjectStreetAddress");
    mdInsertTableItem(tab, "sslCertSerialNumber");
    mdInsertTableItem(tab, "sslObjectType");
    mdInsertTableItem(tab, "sslObjectValue");
    mdInsertTableItem(tab, "sslCertValidityNotBefore");
    mdInsertTableItem(tab, "sslCertValidityNotAfter");
    mdInsertTableItem(tab, "sslPublicKeyAlgorithm");
    mdInsertTableItem(tab, "sslPublicKeyLength");
    mdInsertTableItem(tab, "sslRecordVersion");
    mdInsertTableItem(tab, "sslServerName");
    mdInsertTableItem(tab, "sslCertificateHash");
    mdInsertTableItem(tab, "sslCertificate");
    mdInsertTableItem(tab, "sslCertificateSHA1");
    mdInsertTableItem(tab, "sslCertificateMD5");
    mdInsertTableItem(tab, "sslClientJA3");
    mdInsertTableItem(tab, "sslServerJA3S");
    mdInsertTableItem(tab, "sslClientJA3Fingerprint");
    mdInsertTableItem(tab, "sslServerJA3SFingerprint");

    /* Holdover for mdExporterTextNewSSLCertPrint and
     *              mdExporterTextRewrittenSSLCertPrint*/
    mdInsertTableItem(tab, "ssl");

    tab = mdNewTable(INDEX_DEFAULT);
    mdInsertTableItem(tab, "flow");

    tab = mdNewTable(DHCP_DEFAULT);
    mdInsertTableItem(tab, "dhcpFingerprint");
    mdInsertTableItem(tab, "dhcpVendorCode");
    mdInsertTableItem(tab, "dhcpOption");

    tab = mdNewTable(P0F_DEFAULT);
    mdInsertTableItem(tab, "osName");
    mdInsertTableItem(tab, "osVersion");
    mdInsertTableItem(tab, "osFingerprint");
    mdInsertTableItem(tab, "reverseOsName");
    mdInsertTableItem(tab, "reverseOsVersion");
    mdInsertTableItem(tab, "reverseOsFingerprint");

    tab = mdNewTable(RTP_DEFAULT);
    mdInsertTableItem(tab, "rtpPayloadType");

    tab = mdNewTable(DNP_DEFAULT);
    mdInsertTableItem(tab, "dnp3ObjectData");

    tab = mdNewTable(MODBUS_DEFAULT);
    mdInsertTableItem(tab, "modbusData");

    tab = mdNewTable(ENIP_DEFAULT);
    mdInsertTableItem(tab, "enipData");
}

static gboolean
mdExporterExpandBuf(
    mdExporter_t  *exporter)
{
    g_debug("Expanding output buffer for exporter %s", exporter->name);

//    /* free the old buffer */
//    g_slice_free1(exporter->buf->buflen, exporter->buf->buf);
//    /* double the size */
//    exporter->buf->buflen = (exporter->buf->buflen * 2);
//    exporter->buf->buf = g_slice_alloc(exporter->buf->buflen);
//    if (exporter->buf->buf == NULL) {
//        return FALSE;
//    }
//    exporter->buf->cp = exporter->buf->buf;
    return TRUE;
}


/**
 * mdGetTableItem
 *
 * retrieve the name of the table or file associated with this info element
 * id as given by the user, or by default.
 *
 */
char *
mdGetTableItem(
    const char  *id)
{
    mdTableInfo_t *ret = NULL;

    if (!table_hash) {
        mdBuildDefaultTableHash();
    }

    ret = (mdTableInfo_t *)g_hash_table_lookup(table_hash, (gconstpointer)id);
    if (ret) {
        return ret->table_name;
    }

    return NULL;
}


/**
 * mdNewExporter
 *
 *
 */
mdExporter_t *
mdNewExporter(
    mdExportFormat_t   exportFormat,
    mdExportMethod_t   exportMethod,
    const char        *name)
{
    mdExporter_t *exporter;

    if (UINT8_MAX == num_exporters) {
        g_warning("Maximum number of exporters reached");
        return NULL;
    }

    exporter = g_slice_new0(mdExporter_t);
    exporter->exportFormat = exportFormat;
    exporter->exportMethod = exportMethod;

    exporter->mysql                 = NULL;

    /* initialize the fbConnSpec to empty */
    exporter->spec.host             = NULL;
    exporter->spec.svc              = NULL;
    exporter->spec.ssl_ca_file      = NULL;
    exporter->spec.ssl_cert_file    = NULL;
    exporter->spec.ssl_key_file     = NULL;
    exporter->spec.ssl_key_pass     = NULL;
    exporter->spec.vai              = NULL;
    exporter->spec.vssl_ctx         = NULL;

    if (exportMethod == EM_UDP) {
        exporter->spec.transport = FB_UDP;
    } else if (exportMethod == EM_TCP) {
        exporter->spec.transport = FB_TCP;
    }

    exporter->delimiter             = '|';
    exporter->dpi_delimiter         = 0;
    exporter->timestamp_files       = FALSE;

    /* zero out all writer information */
    exporter->defaultWriter = g_slice_new0(mdFileWriter_t);

    exporter->defaultWriter->exporter = exporter;

    if (EXPORTFORMAT_IS_TEXT_OR_JSON(exportFormat)) {
        exporter->buf = g_string_sized_new(MD_MSGLEN_STD);
        if (exportFormat == EF_JSON) {
            exporter->json = TRUE;
            exporter->escape_chars = TRUE;
            exporter->delimiter = ',';
        }
    }

    exporter->dpi_field_table = NULL;

    /* by default, all records types are allowed
     * which means flowNoDPI and flowsOnlyWithDPI are set to FALSE */
    exporter->metadataExportTemplates         = TRUE;
    exporter->metadataExportElements          = TRUE;
    exporter->allowFlow                       = TRUE;
    exporter->flowDpiStrip                    = FALSE;
    exporter->flowDpiRequired                 = FALSE;
    exporter->allowDnsDedup                   = TRUE;
    exporter->allowSslDedup                   = TRUE;
    exporter->allowDnsRR                      = TRUE;
    exporter->allowSslCert                    = TRUE;
    exporter->allowGeneralDedup               = TRUE;
    exporter->allowYafStats                   = TRUE;
    exporter->allowTombstone                  = TRUE;
    // FIXME: Nothing reads this value
    //exporter->allowUnknownRecords             = TRUE;
    exporter->flowStatsAllowedInTextExporters   = TRUE;

    /* all of the generates and config booleans are false from memset */

    exporter->id = num_exporters + 1;
    if (name) {
        exporter->name = g_strdup(name);
    } else {
        exporter->name = g_strdup_printf("E%d", exporter->id);
    }

    exporter->invState.minFileSize      = 0;
    exporter->invState.maxFileSize      = UINT64_MAX;
    exporter->invState.minTimeMillisec  = 0;
    exporter->invState.maxTimeMillisec  = UINT64_MAX;

    return exporter;
}

/* all sessions
 * does not make a new session if one exists
 * Only called by openIpfixFileExport, openTextfileExport, openSocketExport
 * CORRECT ONE - druef
 */
static gboolean
mdExporterInitSession(
    mdExporter_t  *exporter,
    GError       **err)
{
    fbSession_t      *session     = NULL;
    fbInfoModel_t    *model       = mdInfoModel();
    fbTemplateInfo_t *mdInfo      = NULL;
    fbTemplate_t     *tmpl;
    uint16_t          tid;

    if (exporter->activeWriter->session) {
        return TRUE;
    }

    exporter->infoModel = model;

    session = fbSessionAlloc(model);

    if (exporter->metadataExportElements &&
        !fbSessionSetMetadataExportElements(
            session, TRUE, YAF_TYPE_METADATA_TID, err))
    {
        return FALSE;
    }
    if (exporter->metadataExportTemplates &&
        !fbSessionSetMetadataExportTemplates(
            session, TRUE, YAF_TEMPLATE_METADATA_TID, FB_TID_AUTO, err))
    {
        g_error("Failed to set metadata export templates: %s",
                (*err)->message);
    }

    if (exporter->cfg->gen_tombstone) {
        if (!mdExporterAddTombstoneTemplates(exporter, session, err)) {
            return FALSE;
        }
    }

    if (exporter->generateDnsDedup) {
        fbTemplate_t *dnsDedupTmplA       = NULL;
        fbTemplate_t *dnsDedupTmplAAAA    = NULL;
        fbTemplate_t *dnsDedupTmplO       = NULL;
        fbTemplate_t *dnsDedupTmplInt     = NULL;
        uint16_t      aRecTid             = 0;
        uint16_t      aaaaRecTid          = 0;
        uint16_t      oRecTid             = 0;
        uint16_t      aRecLSTid           = 0;
        uint16_t      aaaaRecLSTid        = 0;
        uint16_t      oRecLSTid           = 0;
        uint16_t      dnsIntTid           = 0;
        uint32_t      specFlags;

        dnsDedupTmplA      = fbTemplateAlloc(model);
        dnsDedupTmplAAAA   = fbTemplateAlloc(model);
        dnsDedupTmplO      = fbTemplateAlloc(model);
        dnsDedupTmplInt    = fbTemplateAlloc(model);

        /* internal template gets everything */
        mdTemplateAppendSpecArray(dnsDedupTmplInt, mdDNSDedupTmplSpec, ~0);

        dnsIntTid = mdSessionAddTemplate(session, TRUE,
                                         FB_TID_AUTO,
                                         dnsDedupTmplInt,
                                         NULL);

        if (md_dns_dedup_get_print_lastseen(exporter->dns_dedup)) {
            specFlags = MD_DNS_DD_LAST_SEEN;
            if (md_dns_dedup_get_add_exporter_name(exporter->dns_dedup)) {
                specFlags |= MD_DNS_DD_XPTR_NAME;
            }

            /* AREC_LS setup */
            mdTemplateAppendSpecArray(
                dnsDedupTmplA, mdDNSDedupTmplSpec, MD_DNS_DD_AREC | specFlags);

            mdInfo = mdNewTemplateInfo(
                exporter, MD_DNS_AREC_LS_NAME, 0, FB_TMPL_MD_LEVEL_0);

            aRecLSTid = mdSessionAddTemplate(session, FALSE,
                                             MD_DNS_DEDUP_AREC | specFlags,
                                             dnsDedupTmplA, mdInfo);

            /* OREC_LS setup */
            mdTemplateAppendSpecArray(
                dnsDedupTmplO, mdDNSDedupTmplSpec, MD_DNS_DD_OREC | specFlags);

            mdInfo = mdNewTemplateInfo(
                exporter, MD_DNS_OREC_LS_NAME, 0, FB_TMPL_MD_LEVEL_0);

            oRecLSTid = mdSessionAddTemplate(session, FALSE,
                                             MD_DNS_DEDUP_OREC | specFlags,
                                             dnsDedupTmplO, mdInfo);

            /* AAAAREC_LS setup */
            mdTemplateAppendSpecArray(
                dnsDedupTmplAAAA, mdDNSDedupTmplSpec, MD_DNS_DD_AAAAREC | specFlags);

            mdInfo = mdNewTemplateInfo(
                exporter, MD_DNS_AAAAREC_LS_NAME, 0, FB_TMPL_MD_LEVEL_0);

            aaaaRecLSTid = mdSessionAddTemplate(session, FALSE,
                                             MD_DNS_DEDUP_AAAAREC | specFlags,
                                             dnsDedupTmplAAAA, mdInfo);
        } else {
            specFlags = 0;
            if (md_dns_dedup_get_add_exporter_name(exporter->dns_dedup)) {
                specFlags |= MD_DNS_DD_XPTR_NAME;
            }

            /* AREC setup */
            mdTemplateAppendSpecArray(
                dnsDedupTmplA, mdDNSDedupTmplSpec, MD_DNS_DD_AREC | specFlags);
            mdInfo = mdNewTemplateInfo(
                exporter, MD_DNS_AREC_NAME, 0, FB_TMPL_MD_LEVEL_0);
            aRecTid = mdSessionAddTemplate(session, FALSE,
                                           MD_DNS_DEDUP_AREC | specFlags,
                                           dnsDedupTmplA, mdInfo);

            /* OREC setup */
            mdTemplateAppendSpecArray(
                dnsDedupTmplO, mdDNSDedupTmplSpec, MD_DNS_DD_OREC | specFlags);
            mdInfo = mdNewTemplateInfo(
                exporter, MD_DNS_OREC_NAME, 0, FB_TMPL_MD_LEVEL_0);
            oRecTid = mdSessionAddTemplate(session, FALSE,
                                           MD_DNS_DEDUP_OREC | specFlags,
                                           dnsDedupTmplO, mdInfo);

            /* AAAAREC setup */
            mdTemplateAppendSpecArray(dnsDedupTmplAAAA, mdDNSDedupTmplSpec,
                                      MD_DNS_DD_AAAAREC | specFlags);
            mdInfo = mdNewTemplateInfo(
                exporter, MD_DNS_AREC_NAME, 0, FB_TMPL_MD_LEVEL_0);
            aaaaRecTid = mdSessionAddTemplate(session, FALSE,
                                              MD_DNS_DEDUP_AAAAREC | specFlags,
                                              dnsDedupTmplAAAA, mdInfo);
        }

        if (!(aRecTid || aRecLSTid) || !(oRecTid || oRecLSTid)
            || !(aaaaRecTid || aaaaRecLSTid) || !dnsIntTid)
        {
            g_error("dns dedup template didn't work");
        }

        exporter->genTids.dnsDedupArecExtTid        = aRecTid;
        exporter->genTids.dnsDedupAAAArecExtTid     = aaaaRecTid;
        exporter->genTids.dnsDedupOrecExtTid        = oRecTid;
        exporter->genTids.dnsDedupArecLSExtTid      = aRecLSTid;
        exporter->genTids.dnsDedupAAAArecLSExtTid   = aaaaRecLSTid;
        exporter->genTids.dnsDedupOrecLSExtTid      = oRecLSTid;
        exporter->dnsDedupIntTid            = dnsIntTid;
    }

    if (exporter->generateSslDedup) {
        tmpl = fbTemplateAlloc(model);
        mdTemplateAppendSpecArray(tmpl, mdSSLDedupSpec, 0);
        mdInfo = mdNewTemplateInfo(
            exporter, MD_SSL_DEDUP_NAME, 0, FB_TMPL_MD_LEVEL_0);

        exporter->genTids.sslDedupTid = mdSessionAddTemplate(session, TRUE,
                                                             MD_SSL_TID,
                                                             tmpl,
                                                             mdInfo);
        exporter->genTids.sslDedupTid = mdSessionAddTemplate(session, FALSE,
                                                             MD_SSL_TID,
                                                             tmpl,
                                                             mdInfo);
    }

    if (exporter->generateDnsRR) {
        /* internal template uses all elements in the spec */
        tmpl = fbTemplateAlloc(model);
        mdTemplateAppendSpecArray(tmpl, mdDnsRRSpec, ~0);
        if (!(tid = fbSessionAddTemplate(session, TRUE, FB_TID_AUTO,
                                         tmpl, NULL, err)))
        {
            return FALSE;
        }
        exporter->dnsRRIntTid = tid;

        if (exporter->dnsRRFull) {
            /* full IPv4 external template */
            tmpl = fbTemplateAlloc(model);
            mdTemplateAppendSpecArray(
                tmpl, mdDnsRRSpec, MD_DNSRR_FULL | MD_DNSRR_IP4);
            mdInfo = mdNewTemplateInfo(
                exporter, MD_DNSRR_IPV4_FULL_NAME, 0, FB_TMPL_MD_LEVEL_0);
            if (!(tid = fbSessionAddTemplate(session, FALSE, MD_DNSRR_IPV4_FULL,
                                             tmpl, mdInfo, err)))
            {
                return FALSE;
            }
            exporter->genTids.dnsRR4FullExtTid = tid;

            /* full IPv6 external template */
            tmpl = fbTemplateAlloc(model);
            mdTemplateAppendSpecArray(
                tmpl, mdDnsRRSpec, MD_DNSRR_FULL | MD_DNSRR_IP6);
            mdInfo = mdNewTemplateInfo(
                exporter, MD_DNSRR_IPV6_FULL_NAME, 0, FB_TMPL_MD_LEVEL_0);
            if (!(tid = fbSessionAddTemplate(session, FALSE, MD_DNSRR_IPV6_FULL,
                                             tmpl, mdInfo, err)))
            {
                return FALSE;
            }
            exporter->genTids.dnsRR6FullExtTid = tid;
        } else {
            /* non-full external template */
            tmpl = fbTemplateAlloc(model);
            mdTemplateAppendSpecArray(tmpl, mdDnsRRSpec, 0);
            mdInfo = mdNewTemplateInfo(
                exporter, MD_DNSRR_NAME, 0, FB_TMPL_MD_LEVEL_0);
            if (!(tid = fbSessionAddTemplate(session, FALSE, MD_DNSRR,
                                             tmpl, mdInfo, err)))
            {
                return FALSE;
            }
            exporter->genTids.dnsRRExtTid = tid;
        }
    }

    if (exporter->generateGeneralDedup) {
        /* setup general dedup */
/*        if (!mdAddTmpl(session, md_dedup_spec, MD_DEDUP_FULL, FALSE,
 *                 "md_dedup_full", NULL, err))
 *          {
 *          return NULL;
 *          }*/
    }
    exporter->activeWriter->session = session;

    return TRUE;
}


/*
 *  Add the Tombstone Main and Access templates needed by GEN_TOMBSTONE to
 *  `session` that is associated with `exporter`.
 *
 *  This is public so that mdProcessTombstoneV1() can add the V2 templates to
 *  the exporter should it export V1 tombstone records.
 *
 *  FIXME: This should check that an existing unrelated template is not being
 *  removed from the exporter when called by mdProcessTombstoneV1().
 */
gboolean
mdExporterAddTombstoneTemplates(
    mdExporter_t  *exporter,
    fbSession_t   *session,
    GError       **err)
{
    fbTemplate_t     *tmpl;
    uint16_t          tid;

    MD_UNUSED_PARAM(err);

    /* main tombstone template */
    tmpl = fbTemplateAlloc(fbSessionGetInfoModel(session));
    mdTemplateAppendSpecArray(tmpl, mdEmSpecTombstoneMainV2, 0);
    fbTemplateSetOptionsScope(tmpl, MD_TOMBSTONE_MAIN_SCOPE);
    tid = mdSessionAddTemplate(session, TRUE, MD_TOMBSTONE_MAIN_TID,
                               tmpl, NULL);
    exporter->genTids.tombstoneV2MainTid = tid;

    tid = mdSessionAddTemplate(session, FALSE, MD_TOMBSTONE_MAIN_TID,
                               tmpl, NULL);

    /* tombstone access list template */
    tmpl = fbTemplateAlloc(fbSessionGetInfoModel(session));
    mdTemplateAppendSpecArray(tmpl, mdEmSpecTombstoneAccessV2, 0);
#if MD_TOMBSTONE_ACCESS_SCOPE > 0
    fbTemplateSetOptionsScope(tmpl, MD_TOMBSTONE_ACCESS_SCOPE);
#endif
    tid = mdSessionAddTemplate(session, TRUE, MD_TOMBSTONE_ACCESS_TID,
                               tmpl, NULL);
    exporter->genTids.tombstoneV2AccessTid = tid;
    tid = mdSessionAddTemplate(session, FALSE, MD_TOMBSTONE_ACCESS_TID,
                               tmpl, NULL);

    return TRUE;
}


/**
 * mdInsertDPIFieldItem
 *
 *  Returns TRUE unless this is the first call for `exporter` and its format
 *  is not TEXT or JSON.
 *
 */
gboolean
mdExporterInsertDPIFieldItem(
    mdExporter_t  *exporter,
    int            ie,
    GError       **err)
{
    int on = 1;

    if (exporter->dpi_field_table == NULL) {
        REQUIRE_EXPORTFORMAT_TEXT_OR_JSON(exporter, err);
        exporter->dpi_field_table =
            g_hash_table_new(g_direct_hash, g_direct_equal);
    }
    g_hash_table_insert(exporter->dpi_field_table, GUINT_TO_POINTER(ie),
                        GUINT_TO_POINTER(on));
    return TRUE;
}


/**
 * mdGetDPIItem
 *
 * simple wrapper around g_hash_table_lookup_extended
 * Returns TRUE if id is present in table as a key
 */
gboolean
mdGetDPIItem(
    GHashTable  *table,
    uint16_t     id)
{
    gboolean rc;
    void    *key = NULL;
    gpointer value = NULL;

    rc = g_hash_table_lookup_extended(table,
                                      GUINT_TO_POINTER((unsigned int)id),
                                      key, &value);

    return rc;
}

/**
 * mdExporterSetPort
 *
 * Called by config parser and mediator_main for command line
 *
 */
gboolean
mdExporterSetPort(
    mdExporter_t  *exporter,
    const char    *port,
    GError       **err)
{
    int p = atoi(port);

    if (!EXPORTMETHOD_IS_SOCKET(exporter->exportMethod)) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Exporter port only allowed for TCP or UDP exporters");
        return FALSE;
    }
    if (p < 1024 || p > UINT16_MAX) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Invalid Port %s. Valid range of Exporter output port "
                    "is 1024-65535", port);
        return FALSE;
    }
    if (exporter->spec.svc) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "The Exporter has already been assigned the port %s",
                    exporter->spec.svc);
        return FALSE;
    }

    exporter->spec.svc = g_strdup(port);
    return TRUE;
}

/**
 * mdExporterSetHost
 *
 * Called by config parser and mediator_main for command line
 *
 */
gboolean
mdExporterSetHost(
    mdExporter_t  *exporter,
    const char    *host,
    GError       **err)
{
    if (!EXPORTMETHOD_IS_SOCKET(exporter->exportMethod)) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Exporter host only allowed for TCP or UDP exporters");
        return FALSE;
    }
    if (exporter->spec.host) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "The Exporter has already been assigned the host \"%s\"",
                    exporter->spec.host);
        return FALSE;
    }

    exporter->spec.host = g_strdup(host);
    return TRUE;
}

/**
 * mdExporterSetRotateInterval
 *
 * Called by config parser and mediator_main for command line
 *
 */
gboolean
mdExporterSetRotateInterval(
    mdExporter_t  *exporter,
    int            seconds,
    GError       **err)
{
    /* FIXME: Do we allow it for SINGLE_FILE exporters or do MUTLI_FILES
     * exporters need to be ROTATING_FILES?  For now, allow for SINGLE_FILE
     * exporters. */

    if (EXPORTMETHOD_IS_SOCKET(exporter->exportMethod)) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Rotate interval only allowed for file-based exporters");
        return FALSE;
    }
    if (seconds <= 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Rotate interval must be greater than 0");
        return FALSE;
    }

    exporter->rotateInterval = (uint64_t)seconds * 1000;
    return TRUE;
}

/**
 * mdExporterSetFileSpec
 *
 * Called by config parser and mediator_main for command line
 * Use defaultWriter in setup
 *
 */
gboolean
mdExporterSetFileSpec(
    mdExporter_t  *exporter,
    const char    *spec,
    GError       **err)
{
    if (EXPORTMETHOD_IS_SOCKET(exporter->exportMethod)) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Export path is not allowed for TCP or UDP exporters");
        return FALSE;
    }
    if (exporter->defaultWriter->outspec) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "The Exporter has already been assigned the output \"%s\"",
                    exporter->defaultWriter->outspec);
        return FALSE;
    }
    /* Difficult to check anything else at this time.  `spec` may be a single
     * file, a filename-template in rotating-ipfix mode, or a directory in
     * MULTI_FILES mode */

    exporter->defaultWriter->outspec = g_strdup(spec);
    return TRUE;
}

/**
 * mdExporterSetDelimiters
 *
 *   Sets regular delimiter and dpi delimiter.  If value is NULL, it is
 *   ignored.
 */
gboolean
mdExporterSetDelimiters(
    mdExporter_t  *exporter,
    const char    *delim,
    const char    *dpi_delim,
    GError       **err)
{
    if (EF_TEXT != exporter->exportFormat) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "May set delimiter only for TEXT exporters");
        return FALSE;
    }
    if (delim) {
        if (strlen(delim) != 1) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Delimiter must be a single character;"
                        " \"%s\" is invalid", delim);
            return FALSE;
        }
        exporter->delimiter = *delim;
    }
    if (dpi_delim) {
        if (strlen(dpi_delim) != 1) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Delimiter must be a single character;"
                        " \"%s\" is invalid", dpi_delim);
            return FALSE;
        }
        exporter->dpi_delimiter = *dpi_delim;
    }
    return TRUE;
}

/**
 * mdExporterSetMovePath
 *
 * Called by config parser. Use default writer
 *
 */
gboolean
mdExporterSetMovePath(
    mdExporter_t  *exporter,
    const char    *path,
    GError       **err)
{
    if (EXPORTMETHOD_IS_SOCKET(exporter->exportMethod)) {
        g_set_error(
            err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
            "MOVE is allowed only for file and directory based Exporters");
        return FALSE;
    }
    if (!g_file_test(path, G_FILE_TEST_IS_DIR)) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Move destination is not a directory \"%s\"", path);
        return FALSE;
    }
    g_free(exporter->defaultWriter->mvPath);
    exporter->defaultWriter->mvPath = g_strdup(path);
    return TRUE;
}

/*
 *  Set the UDP Template Timeout which is not actually used anywhere.
 *
 *  This function expects the value to be in seconds.  If 0, use the default
 *  of 600 seconds (10 minutes).
 *
 *  For whatever reason, the man page for the config file says MINUTES, not
 *  SECONDS.  The man page for the program says seconds.
 *
 *  In addition, in the config file the option is parsed in the context of an
 *  exporter, but there is a single global value.
 */
gboolean
mdExporterSetUdpTemplateTimeout(
    mdExporter_t   *exporter,
    int             udpTimeout,
    GError        **err)
{
    MD_UNUSED_PARAM(exporter);

    if (udpTimeout < 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "UDP Template Timeout (%d) must be non-negative",
                    udpTimeout);
        return FALSE;
    }
    if (0 == udpTimeout) {
        udpTimeout = 600;
    }

    /* Convert to milliseonds */
    md_config.udp_template_timeout = udpTimeout * 1000;
    return TRUE;
}

/**
 * mdExporterSetNoFlow
 *
 *
 */
void
mdExporterSetNoFlow(
    mdExporter_t  *exporter)
{
    exporter->allowFlow = FALSE;
}

/**
 * mdExporterSetFlowExportLock
 *
 *
 */
gboolean
mdExporterEnableLocks(
    mdExporter_t  *exporter,
    GError       **err)
{
    if (EXPORTMETHOD_IS_SOCKET(exporter->exportMethod)) {
        g_set_error(
            err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
            "LOCK is allowed only for file and directory based Exporters");
        return FALSE;
    }

    exporter->lock = TRUE;
    return TRUE;
}

/**
 * mdExporterGZIPFiles
 *
 */
gboolean
mdExporterSetGZIPFiles(
    mdExporter_t  *exporter,
    GError       **err)
{
    if (EXPORTMETHOD_IS_SOCKET(exporter->exportMethod)) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "GZIP_FILES is allowed only for"
                    " file and directory based Exporters");
        return FALSE;
    }

    exporter->gzip = TRUE;
    return TRUE;
}

gboolean
mdExporterEnableDedupPerFlow(
    mdExporter_t  *exporter,
    GError       **err)
{
    REQUIRE_EXPORTFORMAT_TEXT_OR_JSON(exporter, err);

    // FIXME: Nothing reads this value
    //exporter->dedup_per_flow = TRUE;
    return TRUE;
}


/**
 *  Updates the exporter to handle a template.
 *
 *  Assumes it is only called with a locked log mutex.
 */
static void
mdExporterInstallFirstUseOfColTmpl(
    mdExporter_t              *exporter,
    const mdCollector_t       *collector,
    uint16_t                   collTid,
    fbTemplate_t              *intTmpl,
    uint16_t                   extTid,
    const fbTemplateInfo_t    *mdInfo,
    fbTemplate_t              *exporterExpTmpl,
    mdUtilTemplateType_t       templateType,
    mdUtilTemplateContents_t   templateContents,
    const GString             *msgPref,
    GError                   **err)
{
    fbTemplateInfo_t       *thisMdInfo  = NULL;
    uint16_t intTid      = 0;
    mdExpFlowTmplCtx_t     *intTmplCtx  = NULL;
    fbTemplate_t           *extTmpl     = NULL;
    GString *thisPref    = NULL;

    thisPref = g_string_new(msgPref->str);
    g_string_append_printf(thisPref, "FirstUse");

    /* use wrapper add template to update invariant export sessions */
    intTid = mdSessionAddTemplate(exporter->activeWriter->session,
                                  TRUE, /* internal */
                                  collTid,
                                  intTmpl, NULL);

    if (0 == extTid) {
        if (exporterExpTmpl && exporterExpTmpl != intTmpl) {
            extTmpl = exporterExpTmpl;
        } else {
            extTmpl = fbTemplateCopy(intTmpl, 0);
        }
        thisMdInfo = ((mdInfo) ? fbTemplateInfoCopy(mdInfo) : NULL);

        extTid = mdSessionAddTemplate(exporter->activeWriter->session,
                                      FALSE,
                                      collTid,
                                      extTmpl,
                                      thisMdInfo);
    }

    g_string_free(thisPref, TRUE);

    /* templates are in */
    intTmplCtx = g_slice_new0(mdExpFlowTmplCtx_t);
    fbTemplateSetContext(intTmpl, intTmplCtx, NULL, templateCtxFree);

    intTmplCtx->defCtx.contextType      = TCTX_TYPE_EXPORTER;
    intTmplCtx->defCtx.associatedExtTid = extTid;
    intTmplCtx->defCtx.templateType     = templateType;
    intTmplCtx->defCtx.templateContents = templateContents;

    mdTemplateContextSetListOffsets(&intTmplCtx->defCtx, intTmpl);

    exporter->collInfoById[collector->id].id = collector->id;
    exporter->collInfoById[collector->id].expIntTmplByColIntTid[collTid] =
        intTmpl;
    exporter->collInfoById[collector->id].expIntTidByColIntTid[collTid] =
        intTid;

    /* add full installed internal template to invariant fbWriters */
    mdExporterPassTemplateToInvariantProcessors(exporter, intTid, intTmpl, err);
}


/* only called with a locked log_mutex*/
static gboolean
processPotentialSpecialDPITemplate(
    mdExporter_t              *exporter,
    mdUtilTemplateContents_t   tc,
    uint16_t                  *tidToUse,
    fbTemplate_t             **tmplToUse,
    const fbTemplateInfo_t   **mdInfoToUse,
    uint8_t                    collectorId,
    const GString             *msgPref)
{
    uint16_t          sslL2ParentTid  = 0;
    const fbTemplateInfo_t *mdInfo          = *mdInfoToUse;
    fbTemplateInfo_t *newMdInfo;
    GError           *err             = NULL;
    const fbTemplateField_t *field           = NULL;

    MD_UNUSED_PARAM(collectorId);

    /* returning TRUE tells the calling function to install the template
     * that was received. Returning false says don't install it */

    switch (tc.specCase.dpi) {
      case TC_APP_DPI_SSL_L1:
      case TC_APP_DPI_SSL_L1_CERT_LIST:
        if (tc.yafVersion == TC_YAF_VERSION_2) {
            field = fbTemplateFindFieldByIdent(*tmplToUse, 0, 292, NULL, 0);
            if (!field) { /* an orig stl...cert list */
                g_error("No STL in SSL Level 1");
            }
            exporter->rwSSLLevel2STLOffset = field->offset;
        } else if (tc.yafVersion == TC_YAF_VERSION_3) {
            field = fbTemplateFindFieldByIdent(*tmplToUse, 6871, 425, NULL, 0);
            if (!field) {
                g_error("No STL in SSL Level 1");
            }
            exporter->rwSSLLevel2STLOffset = field->offset;
        } else {
            /* todo, move to sanity check */
            g_error("Yaf version required for ssl level 1");
        }
        g_message("%s Adding new template", msgPref->str);
        return TRUE; /* add template as is to exporter session with ctx */

      case TC_APP_DPI_SSL_L2:
        //if (exporter->generateSslDedup && exporter->flattenSSLCerts) {
        //    g_error("Cannot do ssl dedup and flatten SSL...yet");
        //}
        //if (exporter->recvdTids.flattenedSSLTid) {
        //    g_warning("Exporter got both flattened and unflatted SSL L2");
        //}

        if (exporter->generateSslDedup) {
            fbTemplate_t *tmpl;

            tmpl = md_ssl_make_full_cert_template(*tmplToUse, &err);
            if (!tmpl) {
                g_error("couldn't create full cert template: %s", err->message);
            }
            exporter->genTids.fullCertFromSSLDedupTid = mdSessionAddTemplate(
                exporter->activeWriter->session,
                TRUE,
                MD_SSL_FULL_CERT_LEVEL_2,
                tmpl,
                NULL);

            tmpl = fbTemplateCopy(tmpl, FALSE);
            newMdInfo = mdNewTemplateInfo(
                exporter, MD_SSL_DEDUP_CERT_NAME, 0, FB_TMPL_MD_LEVEL_0);
            /* NO BL to add for Level 2 */

            exporter->genTids.fullCertFromSSLDedupTid = mdSessionAddTemplate(
                exporter->activeWriter->session,
                FALSE,
                MD_SSL_FULL_CERT_LEVEL_2,
                tmpl,
                newMdInfo);
            g_message("%s Adding new template", msgPref->str);
            g_message("Also generating SSL DEDUP CERT Level 2 tid: %#x",
                      exporter->genTids.fullCertFromSSLDedupTid);
        }

        if (exporter->flattenSSLCerts) {
            /* do not add this template to session */
            /* add the rewrite cert template, and use that
             * use pieces of incoming TMD, notably parentTid
             * if rewriting, then we know ssl L2 orig is available,
             * check for rewritten cert available and do nothing */
            fbTemplateInfo_t *mdinfo;
            if (exporter->genTids.flattenedSSLTid) {
                /* Already did this processing, ignore it all */
                return FALSE;
            }

            *tmplToUse = mdUtilMakeSslFlatCertTmpl(*tmplToUse, NULL, 0, &err);
            if (!*tmplToUse) {
                g_error("Failed to create flattened SSL Cert Template: %s",
                        err->message);
            }

            /* set tmplToUse and mdInfoToUse, and tidToUse for installation*/

            *tidToUse = MD_SSL_CERTIFICATE_TID;
            exporter->genTids.flattenedSSLTid = MD_SSL_CERTIFICATE_TID;

            if (exporter->metadataExportTemplates) {
                /* TODO BLs for template info */
                newMdInfo = fbTemplateInfoAlloc();
                *mdInfoToUse = newMdInfo;
                if (!mdInfo) {
                    g_warning("Creating flattened SSL template info without "
                              "parentTid as no mdInfo received for SSL L2");
                    fbTemplateInfoInit(newMdInfo,
                                       MD_SSL_CERTIFICATE_NAME,
                                       "", 0, FB_TMPL_MD_LEVEL_NA);
                } else {
                    sslL2ParentTid = fbTemplateInfoGetParentTid(mdInfo);
                    if (sslL2ParentTid == FB_TMPL_MD_LEVEL_NA) {
                        g_warning("SSL L2 had NA parent Tid, so will flattened"
                                  " SSL template");
                    }

                    fbTemplateInfoInit(newMdInfo,
                                       MD_SSL_CERTIFICATE_NAME,
                                       "", 0, sslL2ParentTid);
                    /* TODO add BL info for rewritten certs */
                }
            }

#if 0
            if (!exporter->generateSslDedup) {
                g_message("%s Ignoring Level 2 due to flattening",
                          msgPref->str);
                /* redundant check at this point as we're not allowed to do
                 * both, but eventually we will be and this should be noted */
            }
#endif  /* 0 */

            g_message("Generated flattened SSL Level 2 tid: %#x", *tidToUse);
            return TRUE;
        }
        g_message("%s Adding new template", msgPref->str);
        return TRUE;

      case TC_APP_DPI_SSL_L3:
        if (exporter->flattenSSLCerts) {
            g_message("%s Ignoring SSL Level 3 as we are rewriting CERTs",
                      msgPref->str);
            return FALSE; /* do not add this template */
        }
        break;

      case TC_APP_DPI_SSL_RW_L2:
        if (exporter->flattenSSLCerts) {
            g_warning("SSL already rewritten, but rewritessl enabled");
            exporter->flattenSSLCerts = FALSE;
        }
        if (exporter->recvdTids.sslLevel2Tid) {
            g_warning("Exporter got both flattened and unflatted SSL L2");
        }
        break;

      case TC_APP_DPI_TCP_REV:
      case TC_APP_DPI_TCP_FWD:
        /* nothing to do */
        break;

      case TC_APP_UNKNOWN:
      case TC_APP_DPI_DNS:
        /* dns already recorded in known templates elsewhere */
        /* nothing to do */
        break;
    }

    g_message("%s Adding new template", msgPref->str);

    return TRUE;
}

static void
invFbWritersAddSingleTemplate(
    mdExporter_t    *exporter,
    uint16_t         intTid,
    fbTemplate_t    *intTmplToCopy,
    mdFileWriter_t  *fbWriter,
    GError         **err)
{
    uint16_t            extTid          = 0;

    fbTemplate_t       *extTmplToCopy   = NULL;
    mdExpFlowTmplCtx_t *origCtx         = NULL;
    const fbTemplateInfo_t *origMdInfo      = NULL;
    fbSession_t        *origSession     = exporter->defaultWriter->session;

    fbTemplate_t       *intCopiedTmpl   = NULL;
    fbTemplate_t       *extCopiedTmpl   = NULL;
    mdExpFlowTmplCtx_t *newCtx          = NULL;
    fbTemplateInfo_t   *newMdInfo       = NULL;
    fbSession_t        *recvSession     = fbWriter->session;

    mdUtilTemplateContents_t templateContents = MD_TC_INIT;

    origCtx = fbTemplateGetContext(intTmplToCopy);

    if (!origCtx) { /* TMD or IE or mistake, ignore */
        g_message("Ignoring TID %#x in FbWritersAddTemplate", intTid);
        return;
    }

    /* First check the template contents. Only pass FLOW, DPI,
     * and UNKNOWN_DATA. No options records */

    templateContents = origCtx->defCtx.templateContents;
    switch (templateContents.general) {
      case TC_UNKNOWN_DATA: /* could be DPI if no TMD ocming in */
      case TC_FLOW:
      case TC_DPI:
        /* all good, move forward */
        break;
      default:
        g_message("Ignoring TID %#x which is %s in fbWritersAdd", intTid,
                  mdUtilDebugTemplateContents(templateContents)->str);
        return;
    }

    /* we now know we have all that we need and that we want to add this tmpl
     * */
    extTid = origCtx->defCtx.associatedExtTid;
    if (!extTid) {
        g_error("No associated ext tid for int tid %#x", intTid);
    }

    if (fbSessionGetTemplate(recvSession, TRUE, intTid, NULL)) {
        g_message("Already have an internal template for tid %#x in session %p",
                  intTid, recvSession);
    }

    if (fbSessionGetTemplate(recvSession, FALSE, extTid, NULL)) {
        g_message("Already have an external template for tid %#x in session %p",
                  extTid, recvSession);
    }

    /* now that we have the external TID, and we know it exists, get the
     * template info for that template */
    origMdInfo = fbSessionGetTemplateInfo(origSession, extTid);

    extTmplToCopy = fbSessionGetTemplate(origSession, FALSE, extTid, err);
    if (!extTmplToCopy) {
        g_error("No associated external template for tid %#x in session %p",
                extTid, origSession);
    }

    /* at this point, memory is starting to be allocated */

    intCopiedTmpl = fbTemplateCopy(intTmplToCopy, 0);
    if (!intCopiedTmpl) {
        g_error("Failed to copy int template in fbWriter add template");
    }

    /* make a copy of the original context for the internal template */
    newCtx = (mdExpFlowTmplCtx_t *)templateCtxCopy(
        (mdDefaultTmplCtx_t *)origCtx,
        intCopiedTmpl);
    if (!newCtx) {
        g_error("Error getting new context copy");
    }
    /* set the context on the template */
    fbTemplateSetContext(intCopiedTmpl, newCtx, NULL, templateCtxFree);

    extCopiedTmpl = fbTemplateCopy(extTmplToCopy, 0);
    if (!extCopiedTmpl) {
        g_error("Failed to copy ext template in fbWriter add template");
    }

    /* add internal template. mdInfo is NULL for internal */
    intTid = mdSessionAddTemplate(recvSession, TRUE, intTid, intCopiedTmpl,
                                  NULL);

    /* get the template info if the exporter is exporting it */
    if (exporter->metadataExportTemplates && origMdInfo) {
        newMdInfo = fbTemplateInfoCopy(origMdInfo);
        if (!newMdInfo) {
            g_error("Could not get copy of template info for tid %#x", intTid);
        }
    }

    /* add the external template, including template info */
    extTid = mdSessionAddTemplate(recvSession, FALSE, extTid, extCopiedTmpl,
                                  newMdInfo);
}

typedef struct invPassTemplateForeachData_st {
    mdExporter_t  *exporter;
    fbTemplate_t  *templateToCopy;
    uint16_t       tid;
    GError       **err;
} invPassTemplateForeachData_t;

static void
invFbWritersAddTemplateForeach(
    gpointer   key,  /* tuple */
    gpointer   value,  /*mdFbWriter_t */
    gpointer   user_data)
{
    mdFileWriter_t *fbWriter        = (mdFileWriter_t *)value;
    invPassTemplateForeachData_t *passData        =
        (invPassTemplateForeachData_t *)user_data;

    MD_UNUSED_PARAM(key);

    invFbWritersAddSingleTemplate(passData->exporter, passData->tid,
                                  passData->templateToCopy, fbWriter,
                                  passData->err);
}

static gboolean
mdExporterPassTemplateToInvariantProcessors(
    mdExporter_t  *exporter,
    uint16_t       tid,
    fbTemplate_t  *tmpl,
    GError       **err)
{
    invPassTemplateForeachData_t passData;

    if (!exporter->invState.fileWritersTable) {
        return TRUE;
    }

    passData.exporter       = exporter;
    passData.templateToCopy = tmpl;
    passData.tid            = tid;
    passData.err            = err;

    g_hash_table_foreach(exporter->invState.fileWritersTable,
                         invFbWritersAddTemplateForeach,
                         (gpointer) & passData);

    return TRUE;
}


/*
 *  `intTmpl` is the template for the Exporter to use as its internal
 *  template.  It must be a fresh template copy that the Exporter can claim
 *  ownership of.
 *
 *  `exporterExpTmpl` is the Export template for the Exporter.  If it is
 *  NULL, the export template should be based on `intTmpl`.  When
 *  `exporterExpTmpl` is non-NULL, it must be a fresh template copy the
 *  Exporter can claim ownership of.
 */
static void
mdExporterTemplateCallback(
    mdExporter_t              *exporter,
    const mdCollector_t       *collector,
    uint16_t                   collTid,
    fbTemplate_t              *intTmpl,
    const fbTemplateInfo_t    *mdInfo,
    fbTemplate_t              *exporterExpTmpl,
    mdUtilTemplateType_t       templateType,
    mdUtilTemplateContents_t   tc)
{
    fbTemplate_t     *extTmpl             = NULL;
    fbTemplate_t     *curIntTmplForTid    = NULL;
    fbTemplate_t     *curExtTmplForTid    = NULL;
    uint16_t          extTid              = 0;
    GError           *err                 = NULL;
    uint8_t           collectorId         = collector->id;
    fbSession_t      *session             = NULL;
    gboolean          intTemplatesAreEqual = FALSE;
    gboolean          extTemplatesAreEqual = FALSE;
    gboolean          intTidAvailable     = FALSE;
    gboolean          extTidAvailable     = FALSE;
    gboolean          usedIncomingTemplate = FALSE;
    fbTemplateInfo_t *thisMdInfo          = NULL;
    GString          *msgPref             = g_string_new(NULL);

    g_assert(intTmpl);

    if (mdInfo) {
        g_string_printf(msgPref, "EXP %s(%d) TID %s (%#x):",
                        exporter->name,
                        exporter->id,
                        fbTemplateInfoGetName(mdInfo),
                        collTid);
    } else {
        g_string_printf(msgPref, "EXP %s(%d) TID %#x:",
                        exporter->name,
                        exporter->id,
                        collTid);
    }

    /* template id sanity check, may need to rethink */
    mdUtilUpdateKnownTemplates(msgPref, tc, collTid, &(exporter->recvdTids));

    pthread_mutex_lock(&(exporter->cfg->log_mutex));
    if (0 == fbTemplateCountElements(intTmpl)) {
        /* can we ignore revocations? */
        g_warning("template revocations %#x", collTid);
        pthread_mutex_unlock(&(exporter->cfg->log_mutex));
        return;
    }

    session = exporter->activeWriter->session;
    if (!session) {
        g_error("%s No session created but templates received", msgPref->str);
    }

    /* we have the assumption we have a single yaf version for all data */
    setExporterYafVersion(exporter, tc.yafVersion);

    /* If `exporterExpTmpl` is NULL, set it to `intTmpl` for convenience,
     * noting that we may need to copy intTmpl at some point. */
    if (NULL == exporterExpTmpl) {
        exporterExpTmpl = intTmpl;
    }

    /* look to see if we already have this TID in our session as internal */
    curIntTmplForTid = fbSessionGetTemplate(session, TRUE, collTid, NULL);
    if (curIntTmplForTid) {
        /* mthomas.2021.08.23 If we used the template we were given instead
         * of copying, it we could simply compare the template pointers. */
        /* if so, is it the same template? */
        if (fbTemplatesAreEqual(intTmpl, curIntTmplForTid)) {
            intTemplatesAreEqual = TRUE;
        } else {
            intTemplatesAreEqual = FALSE;
        }
    } else {
        /* it's ok if there isn't a template */
        /* haven't seen this one yet */
        intTidAvailable = TRUE;
    }

    /* look to see if we already have this TID in our session as external */
    curExtTmplForTid = fbSessionGetTemplate(session, FALSE, collTid, NULL);
    if (curExtTmplForTid) {
        /* if so, is it the same template? */
        if (fbTemplatesAreEqual(exporterExpTmpl, curExtTmplForTid)) {
            extTemplatesAreEqual = TRUE;
        } else {
            extTemplatesAreEqual = FALSE;
        }
    } else {
        /* it's ok if there isn't a template */
        /* haven't seen this one yet */
        extTidAvailable = TRUE;
    }

    /* by assuming the same YAF versions, we assume templates with same TIDs
     * are the same */
    if (!intTidAvailable && !intTemplatesAreEqual) {
        g_error("%s Different collectors use the same TID %#06x"
                " to refer to different templates",
                msgPref->str, collTid);
    }

    /* check to see that TID and template matches for external template,
     * unless this is a flowNoDPI template. If so, we wouldn't changed the
     * external template, meaning this template received wouldn't match */
    if (!exporter->flowDpiStrip) {
        /* flows without DPI is the only reason to change an external tmpl
         * while keeping the same TID */
        if (!extTidAvailable && !extTemplatesAreEqual) {
            g_error("%s Collection TID %#06x is in use by this exporter"
                    " and refers to a different external template",
                    msgPref->str, collTid);
        }
    }

    if (exporter->metadataExportTemplates && !mdInfo) {
        g_message("%s Metadata export turned on, no metadata info received",
                  msgPref->str);
    }

    /* at this point templates and tids are fine */

    switch (tc.general) {
      case TC_NUM_TYPES:
        g_error("%s Num Types template in exporter callback", msgPref->str);
        break;
      case TC_UNKNOWN:
        g_warning("%s Unknown template in exporter callback", msgPref->str);
        break;

      case TC_FLOW:
        if (!exporter->allowFlow) {
            g_message("%s Ignoring template. No flow allowed", msgPref->str);
            break;
        }
        if (!intTidAvailable) {
            /* already got this tmpl */
            /* use existing templates in place */
            /* make sure the info per collector is updated in case the existing
             * template and TID pair came from another collector */
            exporter->collInfoById[collectorId].id = collectorId;
            exporter->collInfoById[collectorId].expIntTmplByColIntTid[collTid] =
                curIntTmplForTid;
            exporter->collInfoById[collectorId].expIntTidByColIntTid[collTid] =
                collTid;
            g_message("%s Reuse template", msgPref->str);
        } else {
            /* first flow template of this TID */
            if (exporter->flowDpiStrip) {
                /* remove any lists */
                const fbTemplateField_t *field;
                fbInfoElementSpecId_t    flowIEToAdd;
                fbTemplateIter_t         tmplIter;

                /* start with a blank template, loop through received
                 * template adding anything that isn't a list */
                extTmpl = fbTemplateAlloc(fbSessionGetInfoModel(session));
                fbTemplateIterInit(&tmplIter, exporterExpTmpl);
                while ((field = fbTemplateIterNext(&tmplIter))) {
                    if (!fbInfoElementIsList(fbTemplateFieldGetIE(field))) {
                        flowIEToAdd.ident.enterprise_id =
                            fbTemplateFieldGetPEN(field);
                        flowIEToAdd.ident.element_id =
                            fbTemplateFieldGetId(field);
                        flowIEToAdd.len_override = fbTemplateFieldGetLen(field);
                        flowIEToAdd.flags = 0;
                        mdTemplateAppendOneSpecId(extTmpl, &flowIEToAdd, 0);
                    }
                }

                if (exporterExpTmpl != intTmpl) {
                    fbTemplateFreeUnused(exporterExpTmpl);
                    exporterExpTmpl = NULL;
                }

                /* copy the metadata info */
                thisMdInfo = ((mdInfo) ? fbTemplateInfoCopy(mdInfo) : NULL);

                /* use wrapper to update invariant exporters */
                extTid = mdSessionAddTemplate(session,
                                              FALSE,
                                              collTid,
                                              extTmpl,
                                              thisMdInfo);

                /* install the modified external template and the internal
                 * template in the exporter */
                mdExporterInstallFirstUseOfColTmpl(exporter,
                                                   collector,
                                                   collTid,
                                                   intTmpl,
                                                   extTid,
                                                   thisMdInfo,
                                                   NULL,
                                                   templateType,
                                                   tc,
                                                   msgPref,
                                                   &err);
                g_message("%s Adding new template removing lists",
                          msgPref->str);
            } else {
                /* "install" the template as is */
                mdExporterInstallFirstUseOfColTmpl(exporter,
                                                   collector,
                                                   collTid,
                                                   intTmpl,
                                                   0,
                                                   mdInfo,
                                                   exporterExpTmpl,
                                                   templateType,
                                                   tc,
                                                   msgPref,
                                                   &err);
                g_message("%s Adding new template", msgPref->str);
                exporterExpTmpl = NULL;
            }

            usedIncomingTemplate = TRUE;
        }
        break;

      case TC_DNS_DEDUP:
        if (!exporter->allowDnsDedup) {
            usedIncomingTemplate = FALSE;
            break;
        }
        /* already got an incoming dns dedup and used it, not generating our
         * own */
        if (!intTidAvailable) {
            if (exporter->generateDnsDedup) {
                g_warning("Doing DNS dedup, but using received dedup template");
            }
            exporter->collInfoById[collectorId].id = collectorId;
            exporter->collInfoById[collectorId].expIntTmplByColIntTid[collTid] =
                curIntTmplForTid;
            exporter->collInfoById[collectorId].expIntTidByColIntTid[collTid] =
                collTid;
            g_message("%s Reuse template", msgPref->str);
            break;
        }

        /* haven't gotten this incoming tid yet, check to see if we
         * added it yet */

        extTid = 0;
        extTmpl = NULL;
        switch (tc.specCase.dnsDedup) {
          case TC_DNS_DEDUP_AREC:
            if (exporter->genTids.dnsDedupArecExtTid) {
                extTid = exporter->genTids.dnsDedupArecExtTid;
                g_message("%s Found existing AREC ext tid %#x",
                          msgPref->str, extTid);
            }
            break;
          case TC_DNS_DEDUP_AAAAREC:
            if (exporter->genTids.dnsDedupAAAArecExtTid) {
                extTid = exporter->genTids.dnsDedupAAAArecExtTid;
                g_message("%s Found existing AAAAREC ext tid %#x",
                          msgPref->str, extTid);
            }
            break;
          case TC_DNS_DEDUP_OREC:
            if (exporter->genTids.dnsDedupOrecExtTid) {
                extTid = exporter->genTids.dnsDedupOrecExtTid;
                g_message("%s Found existing OREC ext tid %#x",
                          msgPref->str, extTid);
            }
            break;
          case TC_DNS_DEDUP_LS_AREC_V1:
            if (exporter->genTids.dnsDedupArecLSExtTid) {
                extTid = exporter->genTids.dnsDedupArecLSExtTid;
                g_message("%s Found existing AREC LS V1 ext tid %#x",
                          msgPref->str, extTid);
            }
            break;
          case TC_DNS_DEDUP_LS_AAAAREC_V1:
            if (exporter->genTids.dnsDedupAAAArecLSExtTid) {
                extTid = exporter->genTids.dnsDedupAAAArecLSExtTid;
                g_message("%s Found existing AAAAREC LS V1 ext tid %#x",
                          msgPref->str, extTid);
            }
            break;
          case TC_DNS_DEDUP_LS_OREC_V1:
            if (exporter->genTids.dnsDedupOrecLSExtTid) {
                extTid = exporter->genTids.dnsDedupOrecLSExtTid;
                g_message("%s Found existing OREC LS V1 ext tid %#x",
                          msgPref->str, extTid);
            }
            break;
          case TC_DNS_DEDUP_LS_AREC_V2:
            if (exporter->genTids.dnsDedupArecLSExtTid) {
                extTid = exporter->genTids.dnsDedupArecLSExtTid;
                g_message("%s Found existing AREC LS V2 ext tid %#x",
                          msgPref->str, extTid);
            }
            break;
          case TC_DNS_DEDUP_LS_AAAAREC_V2:
            if (exporter->genTids.dnsDedupAAAArecLSExtTid) {
                extTid = exporter->genTids.dnsDedupAAAArecLSExtTid;
                g_message("%s Found existing AAAAREC LS V2 ext tid %#x",
                          msgPref->str, extTid);
            }
            break;
          case TC_DNS_DEDUP_LS_OREC_V2:
            if (exporter->genTids.dnsDedupOrecLSExtTid) {
                extTid = exporter->genTids.dnsDedupOrecLSExtTid;
                g_message("%s Found existing OREC LS V2 ext tid %#x",
                          msgPref->str, extTid);
            }
            break;
          case TC_DNS_DEDUP_NOT_SET:
          case TC_DNS_DEDUP_LS_V1:
          case TC_DNS_DEDUP_LS_V2:
          default:
            g_error("%s Got other spec case dns dedup %d",
                    msgPref->str, tc.specCase.dnsDedup);
        }
        if (extTid) {
            usedIncomingTemplate = FALSE;
            extTmpl = fbSessionGetTemplate(session, FALSE, extTid, NULL);
            if (!extTmpl) {
                g_error("%s DNS dedup tid regiestered no tmpl tid %#x reg %#x",
                        msgPref->str, collTid, extTid);
            }

            /* only use the existing template if it's a perfect match */
            if (mdUtilDetermineRelative(extTmpl, exporterExpTmpl)
                != TC_EXACT)
            {
                g_warning("%s DNS Dedup incoming template does not match "
                          "registered template, creating new one",
                          msgPref->str);
                extTid = 0;
                usedIncomingTemplate = TRUE;
            }
        } else {
            usedIncomingTemplate = TRUE;
            g_message("%s Adding new template", msgPref->str);
        }
        mdExporterInstallFirstUseOfColTmpl(exporter,
                                           collector,
                                           collTid,
                                           intTmpl,
                                           extTid,
                                           mdInfo,
                                           exporterExpTmpl,
                                           templateType,
                                           tc,
                                           msgPref,
                                           &err);
        exporterExpTmpl = NULL;

        /* compare to existing DNS dedup templates added
         * if !dedup...ignore */
        break;

      case TC_SSL_DEDUP:
        if (!exporter->allowSslDedup) {
            usedIncomingTemplate = FALSE;
            break;
        }
        extTid = 0;
        extTmpl = NULL;
        if (exporter->genTids.sslDedupTid) {
            extTid = exporter->genTids.sslDedupTid;
            g_message("%s Found existing SSL DEDUP tid %#x", msgPref->str,
                      extTid);
            extTmpl = fbSessionGetTemplate(session, FALSE, extTid, NULL);
            if (!extTmpl) {
                g_error("%s SSL dedup tid regiestered no tmpl tid %#x reg %#x",
                        msgPref->str, collTid, extTid);
            }

            /* only use the existing template if it's a perfect match */
            if (mdUtilDetermineRelative(extTmpl, intTmpl) != TC_EXACT) {
                g_warning("%s SSL Dedup incoming template does not match "
                          "registered template, creating new one",
                          msgPref->str);
                extTid = 0;
            }
            usedIncomingTemplate = FALSE;
        }
        if (!extTid) {
            g_message("%s Adding new template", msgPref->str);
            usedIncomingTemplate = TRUE;
        }
        mdExporterInstallFirstUseOfColTmpl(exporter,
                                           collector,
                                           collTid,
                                           intTmpl,
                                           extTid,
                                           mdInfo,
                                           exporterExpTmpl,
                                           templateType,
                                           tc,
                                           msgPref,
                                           &err);
        /* compare to existing...*/
        break;

      case TC_GENERAL_DEDUP:
        if (!exporter->allowGeneralDedup) {
            usedIncomingTemplate = FALSE;
            break;
        }
        /* compare to existing */
        if (extTid) {
            usedIncomingTemplate = FALSE;
            extTmpl = fbSessionGetTemplate(session, FALSE, extTid, NULL);
            if (!extTmpl) {
                g_error("%s GEN DEDUP tid regiestered no tmpl tid %#x reg %#x",
                        msgPref->str, collTid, extTid);
            }

            /* only use the existing template if it's a perfect match */
            if (mdUtilDetermineRelative(extTmpl,exporterExpTmpl) != TC_EXACT)
            {
                g_warning("%s GEN DEDUP incoming template does not match "
                          "registered template, creating new one",
                          msgPref->str);
                extTid = 0;
                usedIncomingTemplate = TRUE;
            }
        } else {
            usedIncomingTemplate = TRUE;
            g_message("%s Adding new template", msgPref->str);
        }
        mdExporterInstallFirstUseOfColTmpl(exporter,
                                           collector,
                                           collTid,
                                           intTmpl,
                                           extTid,
                                           mdInfo,
                                           exporterExpTmpl,
                                           templateType,
                                           tc,
                                           msgPref,
                                           &err);
        exporterExpTmpl = NULL;
        break;

      case TC_DNS_RR:
        if (!exporter->allowDnsRR) {
            break;
        }
        /* compare to existing */
        switch (tc.specCase.dnsRR) {
          case TC_DNS_RR_FULL_4:
            if (exporter->genTids.dnsRR4FullExtTid) {
                extTid = exporter->genTids.dnsRR4FullExtTid;
                g_message("%s Found existing DNS RR Full IPv4 ext tid %#x",
                          msgPref->str,
                          extTid);
            }
            break;
          case TC_DNS_RR_FULL_6:
            if (exporter->genTids.dnsRR6FullExtTid) {
                extTid = exporter->genTids.dnsRR6FullExtTid;
                g_message("%s Found existing DNS RR Full IPv6 ext tid %#x",
                          msgPref->str,
                          extTid);
            }
            break;
          case 0: /* not full */
            if (exporter->genTids.dnsRRExtTid) {
                extTid = exporter->genTids.dnsRRExtTid;
                g_message("%s Found existing DNS RR ext tid %#x",
                          msgPref->str,
                          extTid);
            }
            break;
        }

        if (extTid) {
            usedIncomingTemplate = FALSE;
            extTmpl = fbSessionGetTemplate(session, FALSE, extTid, NULL);
            if (!extTmpl) {
                g_error("%s DNS RR tid regiestered no tmpl tid %#x reg %#x",
                        msgPref->str, collTid, extTid);
            }

            /* only use the existing template if it's a perfect match */
            if (mdUtilDetermineRelative(extTmpl,exporterExpTmpl) != TC_EXACT)
            {
                g_warning("%s DNS RR incoming template does not match "
                          "registered template, creating new one",
                          msgPref->str);
                extTid = 0;
                usedIncomingTemplate = TRUE;
            }
        } else {
            usedIncomingTemplate = TRUE;
            g_message("%s Adding new template", msgPref->str);
        }
        mdExporterInstallFirstUseOfColTmpl(exporter,
                                           collector,
                                           collTid,
                                           intTmpl,
                                           extTid,
                                           mdInfo,
                                           exporterExpTmpl,
                                           templateType,
                                           tc,
                                           msgPref,
                                           &err);
        exporterExpTmpl = NULL;
        break;

      case TC_YAF_STATS:
        if (!exporter->allowYafStats &&
            !exporter->statsAddedToFlowOnlyOrDPIOnly)
        {
            break;
        }
        if (!intTidAvailable) {
            /* already got a yaf stats tmpl */
            /* use existing templates in place */
            exporter->collInfoById[collectorId].id = collectorId;
            exporter->collInfoById[collectorId].expIntTmplByColIntTid[collTid] =
                curIntTmplForTid;
            exporter->collInfoById[collectorId].expIntTidByColIntTid[collTid] =
                collTid;
            g_message("%s Reuse template", msgPref->str);
        } else {
            /* first yaf stats */
            g_message("%s Adding new template", msgPref->str);
            usedIncomingTemplate = TRUE;
            mdExporterInstallFirstUseOfColTmpl(exporter,
                                               collector,
                                               collTid,
                                               intTmpl,
                                               extTid,
                                               mdInfo,
                                               exporterExpTmpl,
                                               templateType,
                                               tc,
                                               msgPref,
                                               &err);
            exporterExpTmpl = NULL;
        }
        break;

      case TC_TOMBSTONE:
        if (!exporter->allowYafStats && !exporter->allowTombstone &&
            !exporter->statsAddedToFlowOnlyOrDPIOnly)
        {
            break;
        }
        if (!intTidAvailable) {
            /* already got a tombstone tmpl */
            /* use existing templates in place */
            exporter->collInfoById[collectorId].id = collectorId;
            exporter->collInfoById[collectorId].expIntTmplByColIntTid[collTid] =
                curIntTmplForTid;
            exporter->collInfoById[collectorId].expIntTidByColIntTid[collTid] =
                collTid;
            g_message("%s Reuse template", msgPref->str);
        } else {
            /* If GEN_TOMBSTONE is active and the incoming tombstone tmpl
             * matches the existing one, use the incoming template as the
             * internal and the existing as the export template. */
            if (tc.specCase.tombstone == TC_TOMBSTONE_V2 &&
                exporter->genTids.tombstoneV2MainTid)
            {
                extTid = exporter->genTids.tombstoneV2MainTid;
                g_message("%s Found existing Tombstone Main tid %#06x",
                          msgPref->str, extTid);
                extTmpl = fbSessionGetTemplate(session, FALSE,
                                               extTid, NULL);
                if (!extTmpl) {
                    g_error("%s Tombstone Main TID defined as %#06x"
                            " but template not found in session",
                            msgPref->str, extTid);
                }

                /* only use the existing template if it's a match */
                if (mdUtilDetermineRelative(extTmpl, exporterExpTmpl)
                    == TC_EXACT)
                {
                    exporterExpTmpl = NULL;
                    mdExporterInstallFirstUseOfColTmpl(exporter,
                                                       collector,
                                                       collTid,
                                                       intTmpl,
                                                       extTid,
                                                       mdInfo,
                                                       exporterExpTmpl,
                                                       templateType,
                                                       tc,
                                                       msgPref,
                                                       &err);
                    usedIncomingTemplate = TRUE;
                    break;
                } else {
                    g_warning("%s TOMBSTONE Main incoming template %#06x "
                              "does not match registered template, "
                              "creating new one", msgPref->str, extTid);
                    extTid = 0;
                    usedIncomingTemplate = TRUE;
                }
            } else if (tc.specCase.tombstone == TC_TOMBSTONE_ACCESS_V2 &&
                       exporter->genTids.tombstoneV2AccessTid)
            {
                extTid = exporter->genTids.tombstoneV2AccessTid;
                g_message("%s Found existing Tombstone Access tid %#06x",
                          msgPref->str, extTid);
                extTmpl = fbSessionGetTemplate(session, FALSE,
                                               extTid, NULL);
                if (!extTmpl) {
                    g_error("%s Tombstone Access TID defined as %#06x"
                            " but template not found in session",
                            msgPref->str, extTid);
                }

                /* only use the existing template if it's a match */
                if (mdUtilDetermineRelative(extTmpl, exporterExpTmpl)
                    == TC_EXACT)
                {
                    exporterExpTmpl = NULL;
                    mdExporterInstallFirstUseOfColTmpl(exporter,
                                                       collector,
                                                       collTid,
                                                       intTmpl,
                                                       extTid,
                                                       mdInfo,
                                                       exporterExpTmpl,
                                                       templateType,
                                                       tc,
                                                       msgPref,
                                                       &err);
                    usedIncomingTemplate = TRUE;
                    break;
                } else {
                    g_warning("%s TOMBSTONE Access incoming template %#06x "
                              "does not match registered template, "
                              "creating new one", msgPref->str, extTid);
                    extTid = 0;
                    usedIncomingTemplate = TRUE;
                }
                if (extTid) {
                    fbSessionAddTemplatePair(
                        session, exporter->genTids.tombstoneV2AccessTid,
                        extTid);
                }
            } else {
                g_message("%s Adding new template", msgPref->str);
                usedIncomingTemplate = TRUE;
            }
            mdExporterInstallFirstUseOfColTmpl(exporter,
                                               collector,
                                               collTid,
                                               intTmpl,
                                               extTid,
                                               mdInfo,
                                               exporterExpTmpl,
                                               templateType,
                                               tc,
                                               msgPref,
                                               &err);
            exporterExpTmpl = NULL;
        }
        break;

      case TC_TMD_OR_IE:
        g_error("%s Got TMD or IE in Exporter callback", msgPref->str);
        break;

      case TC_DPI:
      case TC_UNKNOWN_DATA: /* could be DPI */
        /* if it's flow only, ignore for sure DPI */
        /* flowonly means no dpi, no dedup, no rewrite, no stats, etc
         * it also means that any unknown data gets blocked too */
        if (exporter->flowDpiStrip) {
            g_message("%s Ignoring DPI template, FLOW ONLY", msgPref->str);
            break;
        }

        if (!intTidAvailable) {
            /* already got this tmpl */
            /* use existing templates in place */
            exporter->collInfoById[collectorId].id = collectorId;
            exporter->collInfoById[collectorId].expIntTmplByColIntTid[collTid] =
                curIntTmplForTid;
            exporter->collInfoById[collectorId].expIntTidByColIntTid[collTid] =
                collTid;
            g_message("%s Reuse template", msgPref->str);
        } else {
            /* setup anything useful for potential DPI templates,
             * main dns template, and all ssl templates */
            uint16_t        tidToUse = collTid;
            fbTemplate_t   *tmplToUse = intTmpl;
            const fbTemplateInfo_t *mdInfoToUse = mdInfo;

            /* if sslrewriting, ssl 2 and ssl3 will never be available */
            if (processPotentialSpecialDPITemplate(exporter, tc, &tidToUse,
                                                   &tmplToUse, &mdInfoToUse,
                                                   collectorId, msgPref))
            {
                if (intTmpl != tmplToUse && exporterExpTmpl == intTmpl) {
                    /* if we changed the `tmplToUse` and if
                     * `exporterExpTmpl` was initially `intTmpl`, change
                     * `exporterExpTmpl` to reflect the change */
                    exporterExpTmpl = tmplToUse;
                }
                /* add things */
                mdExporterInstallFirstUseOfColTmpl(exporter,
                                                   collector,
                                                   tidToUse,
                                                   (fbTemplate_t *)tmplToUse,
                                                   0,
                                                   mdInfoToUse,
                                                   exporterExpTmpl,
                                                   templateType,
                                                   tc,
                                                   msgPref,
                                                   &err);
                exporterExpTmpl = NULL;

                if (tmplToUse == intTmpl) {
                    usedIncomingTemplate = TRUE;
                } else {
                    /* tmplToUse got used, not copied */
                    /* free the original incoming one though */
                    fbTemplateInfoFree((fbTemplateInfo_t *)mdInfoToUse);
                }
            }
        }
        break;

      case TC_UNKNOWN_OPTIONS:
        /* stats, tombstone, or other */
        if (!exporter->allowYafStats && !exporter->allowTombstone &&
            !exporter->flowStatsAllowedInTextExporters)
        {
            break;
        }

        if (!intTidAvailable) {
            /* already got this tmpl */
            /* use existing templates in place */
            g_message("%s Reuse template", msgPref->str);
            exporter->collInfoById[collectorId].id = collectorId;
            exporter->collInfoById[collectorId].expIntTmplByColIntTid[collTid] =
                curIntTmplForTid;
            exporter->collInfoById[collectorId].expIntTidByColIntTid[collTid] =
                collTid;
        } else { /* first instance */
            mdExporterInstallFirstUseOfColTmpl(exporter,
                                               collector,
                                               collTid,
                                               intTmpl,
                                               0,
                                               mdInfo,
                                               exporterExpTmpl,
                                               templateType,
                                               tc,
                                               msgPref,
                                               &err);
            g_message("%s Adding new template", msgPref->str);

            exporterExpTmpl = NULL;
            usedIncomingTemplate = TRUE;
        }
        break;
    }

    pthread_mutex_unlock(&(exporter->cfg->log_mutex));
    if (exporterExpTmpl != intTmpl && exporterExpTmpl != NULL) {
        fbTemplateFreeUnused(exporterExpTmpl);
    }
    if (!usedIncomingTemplate) {
        fbTemplateFreeUnused(intTmpl);
    }

    g_string_free(msgPref, TRUE);
}

/*
 *  `tmpl` is the template this exporter should use as its internal template.
 *  'exporterExpTmpl` is the template this exporter should use as the export
 *  template unless it is NULL, in which case `tmpl` is also the export
 *  template.  `collTid` is the template ID the exporter should use when
 *  adding the template(s) to the session on both the internal and export
 *  sides.
 */
void
mdExporterCallTemplateCallback(
    mdExporter_t              *exporter,
    const mdCollector_t       *collector,
    uint16_t                   collTid,
    fbTemplate_t              *tmpl,
    const fbTemplateInfo_t    *mdInfo,
    fbTemplate_t              *exporterExpTmpl,
    mdUtilTemplateType_t       templateType,
    mdUtilTemplateContents_t   templateContents)
{
    uint16_t newMaxSize;

    mdExporterTemplateCallback(exporter,
                               collector,
                               collTid,
                               tmpl,
                               mdInfo,
                               exporterExpTmpl,
                               templateType,
                               templateContents);

    /* update max record size if needed */
    newMaxSize = fbSessionGetLargestInternalTemplateSize(
        exporter->activeWriter->session);
    if (newMaxSize > exporter->largestRecTemplateSize) {
        exporter->largestRecTemplateSize = newMaxSize;
    }
}


/**
 * mdExporterEnableBasicFlowsOnly
 *
 *
 */
gboolean
mdExporterEnableBasicFlowsOnly(
    mdExporter_t  *exporter,
    GError       **err)
{
    if (!exporter->allowFlow) {
        mdExporterFillRecordTypeConflictError(exporter, err);
        return FALSE;
    }
    if (exporter->flowDpiRequired) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Exporter was previously configured for DPI_ONLY");
        return FALSE;
    }
    if (mdExporterGeneratingAnything(exporter, err)) {
        return FALSE;
    }

    mdExporterDisableAllOutputs(exporter);

    exporter->allowFlow           = TRUE;
    exporter->flowDpiStrip        = TRUE;

    return TRUE;
}


/**
 * mdExporterEnableFlowsWithDpiOnly
 *
 *
 */
gboolean
mdExporterEnableFlowsWithDpiOnly(
    mdExporter_t  *exporter,
    GError       **err)
{
    if (!exporter->allowFlow) {
        mdExporterFillRecordTypeConflictError(exporter, err);
        return FALSE;
    }
    if (exporter->flowDpiStrip) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Exporter was previously configured for FLOW_ONLY");
        return FALSE;
    }

    mdExporterDisableAllOutputs(exporter);

    exporter->allowFlow           = TRUE;
    exporter->flowDpiRequired     = TRUE;
    exporter->flowDpiStrip        = FALSE;

    return TRUE;
}

/**
 * mdExporterSetStats
 *
 *  mode == 1 disables export of yaf stats (NO_STATS in sm.conf)
 *  mode == 2 enables export of yaf stats (STATS_ONLY in sm.conf)
 *
 *  Since stats are allowed by default, mode==2 does not toggle the values.
 */
void
mdExporterSetStats(
    mdExporter_t  *exporter,
    uint8_t        mode)
{
    if (mode == 1) {
        exporter->allowYafStats   = FALSE;
        exporter->allowTombstone  = FALSE;
    } else if (mode == 2) {
        if (exporter->flowDpiStrip || exporter->flowDpiRequired) {
            exporter->statsAddedToFlowOnlyOrDPIOnly = TRUE;
            exporter->allowYafStats   = FALSE;
            exporter->allowTombstone  = FALSE;
        }
    } else {
        g_error("Programmer error: Invalid mode %u", mode);
    }
}


/**
 * mdExporterEnableSslDedup
 *
 *
 */
gboolean
mdExporterEnableSslDedup(
    mdExporter_t   *exporter,
    gboolean        only,
    GError        **err)
{
    if (!exporter->allowSslDedup) {
        /* a previous *_ONLY disabled this */
        mdExporterFillRecordTypeConflictError(exporter, err);
        return FALSE;
    }
    if (only) {
        /* check for previous generation statement */
        if (mdExporterGeneratingAnything(exporter, err)) {
            return FALSE;
        }
        mdExporterDisableAllOutputs(exporter);
    }

    exporter->allowSslDedup     = TRUE;
    exporter->generateSslDedup  = TRUE;
    exporter->allowSslCert      = TRUE;

    if (!exporter->ssl_dedup) {
        exporter->ssl_dedup = md_ssl_dedup_new_state();
    }

    exporter->no_index = TRUE;

    return TRUE;
}

/**
 * mdExporterEnableGeneralDedup
 *
 * 'only' should be TRUE when DEDUP_ONLY is used in an EXPORTER and FALSE when
 * the DEDUP_CONFIG block is used.
 */
gboolean
mdExporterEnableGeneralDedup(
    mdExporter_t   *exporter,
    gboolean        only,
    GError        **err)
{
    if (!exporter->allowGeneralDedup) {
        /* a previous *_ONLY disabled this */
        mdExporterFillRecordTypeConflictError(exporter, err);
        return FALSE;
    }
    if (only) {
        /* check for previous generation statement */
        if (mdExporterGeneratingAnything(exporter, err)) {
            return FALSE;
        }
        mdExporterDisableAllOutputs(exporter);
    }

    exporter->allowGeneralDedup     = TRUE;
    exporter->generateGeneralDedup  = TRUE;
    exporter->usedGeneralDedupConfig = TRUE;

    exporter->no_index = TRUE;

    return TRUE;
}


/**
 * mdExporterSetPrintHeader
 *
 *
 */
gboolean
mdExporterSetPrintHeader(
    mdExporter_t  *exporter,
    GError       **err)
{
    REQUIRE_EXPORTFORMAT_TEXT(exporter, err);

    exporter->print_header = TRUE;
    return TRUE;
}

/**
 * mdExporterSetEscapeChars
 *
 *
 */
gboolean
mdExporterSetEscapeChars(
    mdExporter_t  *exporter,
    GError       **err)
{
    REQUIRE_EXPORTFORMAT_TEXT(exporter, err);

    exporter->escape_chars = TRUE;
    return TRUE;
}

/**
 * mdExporterCompareNames
 *
 */
gboolean
mdExporterCompareNames(
    const mdExporter_t *exporter,
    const char         *name)
{
    return (0 == g_strcmp0(exporter->name, name));
}

gboolean
mdExporterSetSSLConfig(
    mdExporter_t  *exporter,
    uint8_t       *list,
    unsigned int   type,
    GError       **err)
{
    if (EF_IPFIX == exporter->exportFormat) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Cannot choose SSL fields in an IPFIX Exporter;"
                    " remove ISSUER, SUBJECT, OTHER, EXTENSIONS keyword(s)");
        return FALSE;
    }

    if (!exporter->ssl_config) {
        exporter->ssl_config = g_slice_new0(mdSSLConfig_t);
    }

    switch (type) {
      case MD_SSLCONFIG_ISSUER:
      case MD_SSLCONFIG_SUBJECT:
      case MD_SSLCONFIG_EXTENSIONS:
        if (exporter->ssl_config->enabled[type]) {
            g_free(exporter->ssl_config->enabled[type]);
        }
        exporter->ssl_config->enabled[type] = list;
        break;

      case MD_SSLCONFIG_OTHER:
        if (exporter->ssl_config->enabled[type]) {
            g_free(exporter->ssl_config->enabled[type]);
        }
        exporter->ssl_config->enabled[type] = list;
        /* if there's a DPI field list - add any item from the SSL OTHER list
         * to the DPI field list as well */
        if (exporter->dpi_field_table) {
            unsigned int i;
            for (i = 0; i < mdSSLConfigArraySize[type]; i++) {
                if (list[i] == 1) {
                    mdExporterInsertDPIFieldItem(exporter, i, NULL);
                }
            }
        }
        break;

      default:
        g_error("Invalid SSL_CONFIG type value %u", type);
    }

    return TRUE;
}


/**
 * mdExporterEnableDnsDedup
 *
 *
 */
gboolean
mdExporterEnableDnsDedup(
    mdExporter_t  *exporter,
    gboolean       only,
    GError       **err)
{
    if (!exporter->allowDnsDedup) {
        mdExporterFillRecordTypeConflictError(exporter, err);
        return FALSE;
    }
    if (only) {
        /* check for previous generation statement */
        if (mdExporterGeneratingAnything(exporter, err)) {
            return FALSE;
        }
        mdExporterDisableAllOutputs(exporter);
    }

    if (!exporter->dns_dedup) {
        exporter->dns_dedup = md_new_dns_dedup_state();
    }

    exporter->allowDnsDedup       = TRUE;
    exporter->generateDnsDedup    = TRUE;

    return TRUE;
}

gboolean
mdExporterGetDnsDedupStatus(
    mdExporter_t  *exporter)
{
    return exporter->generateDnsDedup;
}

const char *
mdExporterGetName(
    mdExporter_t  *exporter)
{
    return exporter->name;
}

//||gboolean
//||mdExporterGetJson(
//||    mdExporter_t  *exporter)
//||{
//||    return exporter->json;
//||}

void
mdExporterSetRemoveEmpty(
    mdExporter_t  *exporter)
{
    exporter->remove_empty = TRUE;
}

gboolean
mdExporterSetNoIndex(
    mdExporter_t  *exporter,
    gboolean       val,
    GError       **err)
{
    /* FIXME: Is no_index valid for JSON exporters or only TEXT? */
    if (TRUE == val) {
        REQUIRE_EXPORTFORMAT_TEXT_OR_JSON(exporter, err);
    }

    exporter->no_index = val;
    return TRUE;
}

gboolean
mdExporterSetTimestampFiles(
    mdExporter_t  *exporter,
    GError       **err)
{
    REQUIRE_EXPORTFORMAT_TEXT_OR_JSON(exporter, err);

    exporter->timestamp_files = TRUE;
    return TRUE;
}

void
mdExporterSetRemoveUploaded(
    mdExporter_t  *exporter)
{
    exporter->remove_uploaded = TRUE;
}

/**
 * mdExporterSetNoFlowStats
 *
 */
void
mdExporterSetNoFlowStats(
    mdExporter_t  *exporter)
{
    exporter->flowStatsAllowedInTextExporters = FALSE;
}


static void
mdExporterFreeCustomList(
    mdExporter_t   *exporter)
{
    mdFieldEntry_t *e;

    while (exporter->customFieldList) {
        detachHeadOfSLL((mdSLL_t **)&(exporter->customFieldList),
                        (mdSLL_t **)&e);
        g_slice_free(mdFieldEntry_t, e);
    }
}


/**
 * mdExportCustomList
 *
 *
 */
gboolean
mdExporterSetCustomList(
    mdExporter_t    *exporter,
    mdFieldEntry_t  *list,
    GError         **err)
{
    REQUIRE_EXPORTFORMAT_TEXT_OR_JSON(exporter, err);

    /* delete any existing list */
    mdExporterFreeCustomList(exporter);

    exporter->customFieldList = list;
    exporter->allowYafStats = FALSE;
    exporter->allowTombstone = FALSE;
    return TRUE;
}

void
mdExporterCustomListDPI(
    mdExporter_t  *exporter)
{
    exporter->custom_list_dpi = TRUE;
    exporter->no_index = TRUE;
}

/**
 * mdExporterEnableDnsRR
 *
 */
gboolean
mdExporterEnableDnsRR(
    mdExporter_t   *exporter,
    gboolean        only,
    gboolean        full,
    GError        **err)
{
    if (EF_IPFIX != exporter->exportFormat) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "%s available only for IPFIX Exporters",
                    ((only) ? "DNS_RR_ONLY" : "DNS_RR"));
        return FALSE;
    }
    if (!exporter->allowDnsRR) {
        mdExporterFillRecordTypeConflictError(exporter, err);
        return FALSE;
    }
    if (only) {
        /* check for previous generation statement */
        if (mdExporterGeneratingAnything(exporter, err)) {
            return FALSE;
        }
        mdExporterDisableAllOutputs(exporter);
    }

    exporter->generateDnsRR = TRUE;
    exporter->allowDnsRR    = TRUE;
    exporter->dnsRRFull     = full;

    return TRUE;
}

gboolean
mdExporterEnableCertDigest(
    mdExporter_t       *exporter,
    smCertDigestType_t  method,
    GError             **err)
{
    if (!EXPORTFORMAT_IS_TEXT_OR_JSON(exporter->exportFormat)) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Certificate hashing not allowed for an IPFIX exporter");
        return FALSE;
    }

    /* Note: mdExporterVerifySetup() repeats this test since the order of the
     * statements in the exporter block may affect this check. */
    if (!exporter->allowSslDedup || !exporter->allowSslCert) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Certificate hashing not allowed since exporter"
                    " has disabled certificate output");
        return FALSE;
    }

    switch (method) {
      case SM_DIGEST_MD5:
        exporter->hash_md5 = TRUE;
        break;
      case SM_DIGEST_SHA1:
        exporter->hash_sha1 = TRUE;
        break;
      default:
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Invalid digest type id %d", (int)method);
        return FALSE;
    }

#ifdef HAVE_OPENSSL
    return TRUE;
#else
    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                "super_mediator was built without OpenSSL support");
    return FALSE;
#endif  /* HAVE_OPENSSL */
}

/**
 * mdExporterSetDNSResponseOnly
 *
 */
void
mdExporterEnableDnsResponseOnly(
    mdExporter_t  *exporter)
{
    /* Only allowed when generating DNS_RR. Checked in
     * mdExporterVerifySetup() */
    exporter->dns_resp_only = TRUE;
}

/**
 * mdExporterAddMySQLInfo
 *
 *
 */
gboolean
mdExporterAddMySQLInfo(
    mdExporter_t  *exporter,
    const char    *user,
    const char    *password,
    const char    *db_name,
    const char    *db_host,
    const char    *table)
{
    if (exporter->mysql == NULL) {
        exporter->mysql = g_slice_new0(mdMySQLInfo_t);
    }
    if (user) {
        g_free(exporter->mysql->user);
        exporter->mysql->user = g_strdup(user);
    }
    if (password) {
        g_free(exporter->mysql->password);
        exporter->mysql->password = g_strdup(password);
    }
    if (db_name) {
        g_free(exporter->mysql->db_name);
        exporter->mysql->db_name = g_strdup(db_name);
    }
    if (db_host) {
        g_free(exporter->mysql->db_host);
        exporter->mysql->db_host = g_strdup(db_host);
    }
    if (table) {
        g_free(exporter->mysql->table);
        exporter->mysql->table = g_strdup(table);
    }

#ifdef HAVE_MYSQL
    if (exporter->mysql->user && exporter->mysql->password &&
        exporter->mysql->db_name)
    {
        my_bool reconnect = 1;
        exporter->mysql->conn = mysql_init(NULL);
        /* #if MYSQL_VERSION_ID >= 50013 */
        mysql_options(exporter->mysql->conn, MYSQL_OPT_RECONNECT, &reconnect);
        /* #endif */
        if (exporter->mysql->conn == NULL) {
            g_warning("Error Initializing Connection %u: %s\n",
                      mysql_errno(exporter->mysql->conn),
                      mysql_error(exporter->mysql->conn));
            return FALSE;
        }
        if (mysql_real_connect(exporter->mysql->conn, exporter->mysql->db_host,
                               exporter->mysql->user, exporter->mysql->password,
                               exporter->mysql->db_name, 0, NULL, 0) == NULL)
        {
            g_warning("Error Connection %u: %s",
                      mysql_errno(exporter->mysql->conn),
                      mysql_error(exporter->mysql->conn));
            return FALSE;
        }
    }
#else  /* if HAVE_MYSQL */
    g_warning("Invalid Keyword: super_mediator not configured for MySQL.");
#endif /* if HAVE_MYSQL */
    return TRUE;
}

/**
 * mdExporterSetMetadataExport
 *
 *
 */
gboolean
mdExporterSetMetadataExport(
    mdExporter_t *exporter,
    gboolean      describe_templates,
    gboolean      describe_elements,
    GError      **err)
{
    if (exporter->exportFormat != EF_IPFIX) {
        g_set_error(
            err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
            "Setting metadata export only applicable for IPFIX exporters");
        return FALSE;
    }

    exporter->metadataExportTemplates = describe_templates;
    exporter->metadataExportElements = describe_elements;
    return TRUE;
}

/**
 * mdLockFile
 *
 * "Locks" a file.  Really just prepends "." to the filename
 *
 */
static void
mdLockFile(
    GString  *path)
{
    char  *find = NULL;
    gssize pos;

    find = g_strrstr(path->str, "/");
    if (find) {
        pos = find - path->str + 1;
        g_string_insert_c(path, pos, '.');
    } else {
        g_string_prepend_c(path, '.');
    }
}

/**
 * mdUnlockFile
 *
 * "Unlocks" a file.  Really just renames the file.
 *
 */
static void
mdUnlockFile(
    const char  *path)
{
    GString *lock_name = NULL;
    char    *find = NULL;
    gssize   pos;

    lock_name = g_string_new(path);
    find = g_strrstr(lock_name->str, "/");
    if (find) {
        pos = find - lock_name->str + 1;
        g_string_insert_c(lock_name, pos, '.');
    } else {
        g_string_prepend_c(lock_name, '.');
    }
    g_debug("Unlocking File %s", path);

    if (g_rename(lock_name->str, path) != 0) {
        g_warning("Error renaming file from %s to %s",
                  lock_name->str, path);
    }
    g_string_free(lock_name, TRUE);
}



/**
 * mdExporterSetMultiFiles
 *
 * Called by config parser. Use defaultWriter
 *
 */
gboolean
mdExporterEnableMultiFiles(
    mdExporter_t   *exporter,
    GError        **err)
{
    static const char *firstExporter = NULL;
    int     offset;
    char   *hold_spec;

    REQUIRE_EXPORTFORMAT_TEXT(exporter, err);
    if (firstExporter) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "MULTI_FILES already enabled by %s and"
                    " only one exporter may use the MULTI_FILES feature",
                    firstExporter);
        return FALSE;
    }
    firstExporter = mdExporterGetName(exporter);

    exporter->multi_files = TRUE;
    exporter->allowSslDedup = FALSE;

    if (!g_file_test(exporter->defaultWriter->outspec, G_FILE_TEST_IS_DIR)) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "PATH must name a directory when using MULTI_FILES,"
                    " but \"%s\" is not",
                    exporter->defaultWriter->outspec);
        return FALSE;
    }

    /* ensure it ends with '/' */
    offset = strlen(exporter->defaultWriter->outspec);
    if (exporter->defaultWriter->outspec[offset - 1] != '/') {
        hold_spec = g_strconcat(exporter->defaultWriter->outspec, "/", NULL);
        g_free(exporter->defaultWriter->outspec);
        exporter->defaultWriter->outspec = hold_spec;
    }

    return TRUE;
}

/**
 * mdExporterFree
 *
 *
 */
void
mdExporterFree(
    mdExporter_t  *exporter)
{
    g_slice_free(mdExporter_t, exporter);
}

#ifdef HAVE_MYSQL
/**
 * mdLoadFile
 *
 * load a dpi file into the database.
 *
 */
static void
mdLoadFile(
    mdExporter_t  *exporter,
    const char    *table,
    const char    *filename)
{
    char           query[500];
    int            err;
    unsigned long  bid = 0;
    unsigned long  aid = 0;
    mdMySQLInfo_t *mysql = exporter->mysql;

    if (mysql->conn) {
        sprintf(query, "LOAD DATA LOCAL INFILE '%s' INTO TABLE %s.%s"
                " FIELDS TERMINATED BY '%c'", filename, mysql->db_name,
                table, exporter->delimiter);
        err = mysql_query(mysql->conn, query);

#if MYSQL_VERSION_ID >= 50013
        bid = mysql_thread_id(mysql->conn);
        mysql_ping(mysql->conn);
        aid = mysql_thread_id(mysql->conn);
#endif
        /* try again for specific errors */
        if (err) {
            if ((mysql_errno(mysql->conn) == 0) ||
                (mysql_errno(mysql->conn) == 1143))
            {
                g_debug("%s: Error importing local file %u: %s. "
                        "Trying query again without LOCAL keyword.",
                        exporter->name, mysql_errno(mysql->conn),
                        mysql_error(mysql->conn));
                sprintf(query, "LOAD DATA INFILE '%s' INTO TABLE %s"
                        " FIELDS TERMINATED BY '%c'", filename,
                        table, exporter->delimiter);
                err = mysql_query(mysql->conn, query);
            } else if (bid != aid) {
                g_message("%s: Reconnected to MySQL Database.", exporter->name);
                sprintf(query, "LOAD DATA LOCAL INFILE '%s' INTO TABLE %s"
                        " FIELDS TERMINATED BY '%c'", filename,
                        table, exporter->delimiter);
                err = mysql_query(mysql->conn, query);
            }
        }

        if (err) {
            g_warning("%s: Error loading data %u:%s", exporter->name,
                      mysql_errno(mysql->conn), mysql_error(mysql->conn));
        } else {
            g_debug("%s: Successfully imported file %s to table '%s'",
                    exporter->name, filename, table);
            if (exporter->remove_uploaded) {
                if (!g_remove(filename)) {
                    g_debug("%s: Removed Imported File '%s'", exporter->name,
                            filename);
                } else {
                    g_warning("%s: Error removing file: %d", exporter->name,
                              g_file_error_from_errno(errno));
                }
            }
        }
    }
}
#endif /* if HAVE_MYSQL */



/**
 * mdGetTableFile
 *
 * returns the file pointer for this element id.
 */
FILE *
mdGetTableFile(
    mdExporter_t  *exporter,
    const char    *id)
{
    mdTableInfo_t *ret = NULL;
    GString       *file_name;
    uint64_t       start_secs;

    if (!table_hash) {
        mdBuildDefaultTableHash();
    }
    ret = g_hash_table_lookup(table_hash, (gconstpointer)id);
    if (ret) {
        if (!ret->table_file ||
            (ret->last_rotate_ms &&
             (exporter->activeWriter->lastRotate != ret->last_rotate_ms)))
        {
            file_name = g_string_new(exporter->activeWriter->outspec);
            if (ret->table_file) {
                mdCloseAndUnlock(exporter, ret->table_file, ret->file_name,
                                 ret->table_name);
                /*if (exporter->lock) {
                 *  mdUnlockFile(ret->file_name);
                 * }
                 * fclose(ret->table_file);
                 * if (exporter->mysql) {
                 *  mdLoadFile(exporter, ret->table_name, ret->file_name);
                 * }
                 * g_free(ret->file_name);*/
            }
            start_secs = exporter->activeWriter->lastRotate / 1000;
            g_string_append_printf(file_name, "%s.txt", ret->table_name);
            if (exporter->timestamp_files) {
                md_util_time_append(file_name, start_secs, MD_TIME_FMT_YMDHMS);
            } else {
                g_string_append_printf(file_name, "%d", ret->serial);
            }
            ret->serial++;
            ret->file_name = g_strdup(file_name->str);
            if (exporter->lock) {
                mdLockFile(file_name);
            }
            ret->table_file = fopen(file_name->str, "w");
            ret->last_rotate_ms = exporter->activeWriter->lastRotate;
            if (ret->table_file == NULL) {
                g_warning("%s: Error Opening File %s", exporter->name,
                          file_name->str);
            }
            g_debug("%s: Opening Text File %s", exporter->name,
                    file_name->str);
            g_string_free(file_name, TRUE);
        }
        return ret->table_file;
    }

    return NULL;
}


/**
 * mdExporterVerifySetup
 *
 * verifies that the exporters are appropriately setup
 * and that all configuration parameters were used
 * correctly
 *
 * @param exp to be verified
 * @param err not really used
 * @return true if correct
 */
gboolean
mdExporterVerifySetup(
    mdExporter_t  *exporter,
    GError       **err)
{
    /* some of this is also checked in config file parsing, but because
     * this all can be done on the command, it must be checked here too.
     * Only things that are configurable from the command line AND the config
     * file are verified here */

    /* set the name first so it appears in error messages */
    if (!exporter->name) {
        exporter->name = g_strdup_printf("E%d", exporter->id);
    }

    /* first validate the export method has what it needs */
    switch (exporter->exportMethod) {
      case EM_SINGLE_FILE:
        /* single output file needs a filename */
        if (exporter->defaultWriter->outspec == NULL) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "SINGLE_FILE Exporter requires a PATH");
            return FALSE;
        }
        if (exporter->lock) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "LOCK Only valid with a ROTATING_FILES Exporter");
            return FALSE;
        }
        break;

      case EM_ROTATING_FILES:
        /* rotating files needs a path, and a rotating interval */
        if (exporter->defaultWriter->outspec == NULL) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "ROTATING_FILES Exporter requires a PATH");
            return FALSE;
        }
        if (!exporter->rotateInterval) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "ROTATING FILES Exporter requires a ROTATE_INTERVAL");
            return FALSE;
        }
        if (exporter->timestamp_files) {
            g_debug("Keyword TIMESTAMP_FILES is ignored for SINGLE_FILE "
                    "Exporters %s", exporter->name);
            exporter->timestamp_files = FALSE;
        }
        exporter->remove_empty = TRUE;
        break;

      case EM_TCP:
      case EM_UDP:
        if (exporter->spec.host == NULL) {
            exporter->spec.host = g_strdup("localhost");
        }
        if (exporter->spec.svc == NULL) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "TCP/UDP Exporter requires a PORT");
            return FALSE;
        }
        break;

      case EM_NONE:
      default:
        /* this really should never happen */
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Invalid Transport (%d) for Exporter %s",
                    exporter->exportMethod, exporter->name);
        return FALSE;
    }

    if (exporter->dns_resp_only && !exporter->generateDnsRR) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "DNS_RESPONSE_ONLY is only allowed when DNS_RR or"
                    " DNS_RR_ONLY is also specified");
        return FALSE;
    }

    /* FIXME: Need to confirm the DEDUP_CONFIG generation and the DEDUP_ONLY
     * setting within the exporter. */

    if (exporter->generateDnsDedup ^ (NULL != exporter->dns_dedup)) {
        g_error("Programmer error: generateDnsDedup and dns_dedup mismatch:"
                " generateDnsDedup = %d, dns_dedup = %d",
                exporter->generateDnsDedup, (NULL != exporter->dns_dedup));
    }
    if (exporter->generateSslDedup ^ (NULL != exporter->ssl_dedup)) {
        g_error("Programmer error: generateSslDedup and ssl_dedup mismatch:"
                " generateSslDedup = %d, ssl_dedup = %d",
                exporter->generateSslDedup, (NULL != exporter->ssl_dedup));
    }
    if (exporter->json ^ (EF_JSON == exporter->exportFormat)) {
        g_error("Programmer error: json and exportFormat mismatch:"
                " json = %d, exportFormat = %d",
                exporter->json, exporter->exportFormat);
    }

    if (EXPORTFORMAT_IS_TEXT_OR_JSON(exporter->exportFormat)) {
        if (exporter->exportMethod != EM_SINGLE_FILE &&
            exporter->exportMethod != EM_ROTATING_FILES)
        {
            g_error("Programmer error: Unsupported exportMethod %d for"
                    " a JSON or TEXT exporter", exporter->exportMethod);
        }

        /* FIXME: Provide a way to disable this */
        exporter->remove_empty = TRUE;

        if (exporter->defaultWriter->outspec == NULL) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "%s Exporter requires a FILE or DIRECTORY Path.",
                        mdUtilDebugExportFormat(exporter->exportFormat));
            return FALSE;
        }
        if (exporter->dpi_delimiter == 0) {
            /* not set by user */
            exporter->dpi_delimiter = exporter->delimiter;
        }

        /* LOCK and TIMESTAMP_FILES require a ROTATE_INTERVAL */
        if (!exporter->rotateInterval) {
            if (exporter->lock) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "LOCK Only valid with a ROTATING FILES Exporter");
                return FALSE;
            }
            if (exporter->timestamp_files) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "TIMESTAMP_FILES only valid with ROTATE");
                return FALSE;
            }
        }

        /* MULTI_FILES has many requirements */
        if (exporter->multi_files) {
            /* must be a TEXT exporter; should have been checked when
             * multi_files was enabled */
            if (FALSE != exporter->json) {
                g_error("Programmer error: JSON and MULTI_FILES are both TRUE");
            }
            if (!exporter->flowDpiRequired) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "MULTI_FILES requires DPI_ONLY");
                return FALSE;
            }
            if (exporter->allowDnsDedup) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "MULTI_FILES not compatible with DNS_DEDUP");
                return FALSE;
            }
            if (exporter->allowSslDedup) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "MULTI_FILES not compatible with SSL_DEDUP");
                return FALSE;
            }
            if (exporter->dpi_field_table) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "MULTI_FILES not compatible with DPI_FIELD_LIST. "
                            "Use DPI_CONFIG block to configure MULTI_FILES.");
                return FALSE;
            }
            if (table_hash) {
                /* only allow enabling of certificate hashes via DPI_CONFIG
                 * block, not the SSL_CERT_HASH_* tokens */
                if (exporter->hash_md5 || exporter->hash_sha1) {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                                "For MULTI_FILES USE 299 for MD5_HASH or"
                                " 298 for SHA1_HASH in the DPI_CONFIG block.");
                    return FALSE;
                }
                if (mdGetTableItem("sslCertificateMD5")) {
                    exporter->hash_md5 = TRUE;
                }
                if (mdGetTableItem("sslCertificateSHA1")) {
                    exporter->hash_sha1 = TRUE;
                }
            }
        }

        if (!exporter->allowSslDedup || !exporter->allowSslCert) {
            if (exporter->hash_md5 || exporter->hash_sha1) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "Certificate hashing not allowed since exporter"
                            " has disabled certificate output");
                return FALSE;
            }
        }

        if (!exporter->customFieldList && exporter->custom_list_dpi) {
            /* FIXME: Cannot actually create a field "none" since "none"
             * is not a valid IE. */
            mdFieldEntry_t *item = mdMakeFieldEntryFromName("none", TRUE,
                                                            NULL);
            mdExporterEnableFlowsWithDpiOnly(exporter, NULL);
            mdExporterSetCustomList(exporter, item, NULL);
        }
        if (exporter->usedGeneralDedupConfig && !exporter->json) {
            /* FIXME.2021.07.01.mthomas Calling mdExporterDedupOnly()
             * causes the program to abort; SM-1.x used to set the
             * exporter->generalDedupAllowed flag for this condition. We
             * need to determine why and if we still need to. */
            /* mdExporterDedupOnly(exporter); */
            exporter->allowYafStats = FALSE;
            exporter->allowTombstone = FALSE;
        }

        /* create a basic flow printing custom list */
        if (!exporter->customFieldList) {
            if (!exporter->multi_files && exporter->allowFlow) {
                /* if JSON - don't print payload */
                gboolean payload_on = exporter->json ? FALSE : TRUE;
                exporter->customFieldList = mdCreateBasicFlowList(
                    payload_on, (exporter->json));
                exporter->allowYafStats = TRUE;
                exporter->allowTombstone = TRUE;
                /* TODO: Possibly enable different printing via */
                /*       mdSetExportFieldListDecoratorBasic. */
                if (!exporter->flowDpiStrip) {
                    /* turn on DPI... */
                    exporter->basic_list_dpi = TRUE;
                }
            }
            if (exporter->flowDpiRequired) {
                mdExporterFreeCustomList(exporter);
                exporter->customFieldList = mdCreateIndexFlowList();
                exporter->custom_list_dpi = TRUE;
            }
        }

        if (exporter->customFieldList) {
            if (exporter->flowDpiRequired &&
                (!exporter->custom_list_dpi && !exporter->basic_list_dpi))
            {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "Specified 'DPI_ONLY' "
                            "but DPI not listed in custom FIELD list.");
                return FALSE;
            }
            if (exporter->flowDpiStrip && exporter->custom_list_dpi) {
                g_warning("FLOW_ONLY keyword for EXPORTER %s "
                          "is ignored due to DPI in custom FIELD list.",
                          exporter->name);
            }
        }
        if (exporter->flowDpiStrip && exporter->dpi_field_table) {
            g_warning("FLOW_ONLY keyword is present with DPI_FIELD_LIST. "
                      "Ignoring DPI_FIELD_LIST for EXPORTER %s",
                      exporter->name);
        }

        if (!exporter->multi_files && exporter->rotateInterval) {
            exporter->timestamp_files = TRUE;
        }
        /*if (exporter->dnsdeduponly) {
         *  if (exporter->custom_list) {
         *      g_warning("Warning: FIELD list is ignored due to"
         *                " presence of DNS_DEDUP_ONLY keyword in"
         *                " EXPORTER %s.", exporter->name);
         *  }
         * }*/


        /*        if (exporter->ssldeduponly) {
         *          if (exporter->custom_list) {
         *              g_warning("Warning: FIELD list is ignored due to"
         *                        " presence of SSL_DEDUP_ONLY keyword for
         * "
         *                        "EXPORTER %s", exporter->name);
         *          }
         *      }*/

        /*        if (exporter->mysql) {
         *          if (exporter->flowonly) {
         *              if (exporter->mysql->table == NULL) {
         *                  exporter->mysql->table =
         * g_strdup(INDEX_DEFAULT);
         *              }
         *          }
         *          if (exporter->dnsdeduponly) {
         *              if (exporter->mysql->table == NULL) {
         *                  exporter->mysql->table =
         * g_strdup(DNS_DEDUP_DEFAULT);
         *              }
         *          }
         *          if (exporter->no_stats == 2) {
         *              if (exporter->mysql->table == NULL) {
         *                  exporter->mysql->table =
         * g_strdup(YAF_STATS_DEFAULT);
         *              }
         *          }
         *          if (exporter->custom_list) {
         *              if (exporter->mysql->table == NULL) {
         *                  fprintf(stderr, "Error: Custom FIELD List with
         * MySQL import "
         *                          "requires MYSQL_TABLE name for EXPORTER
         * %s.",
         *                          exporter->name);
         *                  return FALSE;
         *              }
         *          }
         *      }*/

        if (exporter->usedGeneralDedupConfig && !exporter->json) {
            int   offset;
            char *hold_spec;

            if (!g_file_test(exporter->defaultWriter->outspec,
                             G_FILE_TEST_IS_DIR))
            {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "DEDUP_CONFIG requires PATH to be a File"
                            " Directory but \"%s\" is not",
                            exporter->defaultWriter->outspec);
                return FALSE;
            }
            offset = strlen(exporter->defaultWriter->outspec);
            if (exporter->defaultWriter->outspec[offset - 1] != '/') {
                hold_spec = g_strconcat(exporter->defaultWriter->outspec,
                                        "/", NULL);
                g_free(exporter->defaultWriter->outspec);
                exporter->defaultWriter->outspec = hold_spec;
            }
        }

        /* json and print_header may not both be true; should have been
         * checked when print_header enabled */
        if (exporter->print_header && exporter->json) {
            g_error("Programmer error: PRINT_HEADER and JSON are both true");
        }

        if (exporter->json) {
            exporter->escape_chars = TRUE;
        }
    }

/*    if (exporter->deduponly && !exporter->dedupconfig) {
 *      fprintf(stderr, "Error: DEDUP_ONLY was set for Exporter %s "
 *              "but no corresponding DEDUP_CONFIG block was found.\n",
 * exporter->name);
 *      return FALSE;
 *  }*/

    num_exporters++;

    return TRUE;
}


/**
 * mdCloseAndUnlock
 *
 * close a file, unlock it, possibly remove it.
 *
 */
static void
mdCloseAndUnlock(
    mdExporter_t  *exporter,
    FILE          *fp,
    char          *filename,
    char          *table)
{
    gboolean rm = FALSE;

    MD_UNUSED_PARAM(table);

    if (fp == NULL || filename == NULL) {
        return;
    }

    if (filename[0] != '-' && (strlen(filename) != 1)) {
        g_debug("%s: Closing File %s", exporter->name, filename);
    }

    if (exporter->remove_empty) {
        fseek(fp, 0L, SEEK_END);
        if (!ftell(fp)) {
            rm = TRUE;
        }
    }

    fclose(fp);

    if (exporter->lock) {
        mdUnlockFile(filename);
    }

    if (rm) {
        g_debug("%s: Removing Empty File %s", exporter->name, filename);
        g_remove(filename);
    } else {
/*        if (exporter->mysql) {
 *          if (exporter->flowonly || exporter->dnsdeduponly ||
 *              exporter->multi_files || exporter->no_stats == 2 ||
 *              exporter->custom_list)
 *          {
 *              char *table_name;
 *              table_name = table ? table : exporter->mysql->table;
 *              mdLoadFile(exporter, table_name, filename); */
        /* don't compress if already removed */
        /*if (exporter->remove_uploaded) {
         *  if (filename) {
         *      g_free(filename);
         *  }
         *  return;
         * }
         * }
         * } */

        if (exporter->gzip) {
            /* since compression is handled in a child process,
             * we must pass the destination directory and let
             * the compression process move it once compression is
             * complete.
             */
            md_util_compress_file(filename, exporter->activeWriter->mvPath);
        } else if (exporter->activeWriter->mvPath) {
            GString *mv_name;
            mv_name = sm_util_move_file(filename,
                                        exporter->activeWriter->mvPath);
            if (!mv_name) {
                g_warning("Unable to move file to %s",
                          exporter->activeWriter->mvPath);
            } else {
                g_string_free(mv_name, TRUE);
            }
        }
    }

    if (filename) {
        g_free(filename);
    }
}



/**
 * mdOpenIpfixFileExport
 *
 * open an IPFIX file, close the current IPFIX file
 *
 */
static gboolean
mdOpenIpfixFileExport(
    mdExporter_t  *exporter,
    const char    *path,
    GError       **err)
{
    if (!mdExporterInitSession(exporter, err)) {
        return FALSE;
    }

    if (path[0] == '-' && strlen(path) == 1) {
        if (isatty(fileno(stdout))) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Refusing to write to terminal on stdout");
            return FALSE;
        }
        g_debug("%s: Writing to stdout", exporter->name);
        exporter->activeWriter->lfp = stdout;
    } else {
        g_debug("%s: Opening File %s", exporter->name, path);
        exporter->activeWriter->lfp = fopen(path, "w");
    }

    if (exporter->activeWriter->lfp == NULL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "%s: Cannot open file \"%s\" for writing: %s",
                    exporter->name, path, strerror(errno));
        return FALSE;
    }

    exporter->activeWriter->fbExporter = fbExporterAllocFP(
        exporter->activeWriter->lfp);

    /* reset the existing fbuf's exporter or create a new fbuf */
    if (exporter->activeWriter->fbuf) {
        fBufSetExporter(exporter->activeWriter->fbuf,
                        exporter->activeWriter->fbExporter);
    } else {
        exporter->activeWriter->fbuf = fBufAllocForExport(
            exporter->activeWriter->session,
            exporter->activeWriter->fbExporter);
    }

    if (!fbSessionExportTemplates(exporter->activeWriter->session, err)) {
        return FALSE;
    }

    return TRUE;
}

/**
 * mdOpenTextFileExport
 *
 * open a new text file, close the current one
 *
 *
 */
static gboolean
mdOpenTextFileExport(
    mdExporter_t  *exporter,
    const char    *path,
    GError       **err)
{
    GString *str;
    size_t   rc;

    if (!mdExporterInitSession(exporter, err)) {
        return FALSE;
    }

    if (strlen(path) == 1 && path[0] == '-') {
        g_debug("%s: Writing Text to stdout", exporter->name);
        exporter->activeWriter->lfp = stdout;
    } else {
        g_debug("%s: Opening Text File: %s", exporter->name, path);
        exporter->activeWriter->lfp = fopen(path, "w+");
    }
    if (exporter->activeWriter->lfp == NULL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "%s: Cannot open file \"%s\" for writing: %s",
                    exporter->name, path, strerror(errno));
        return FALSE;
    }

    if (exporter->print_header) {
        str = g_string_new(NULL);
        mdPrintBasicHeader(exporter, str);
        rc = fwrite(str->str, 1, str->len, exporter->activeWriter->lfp);

        if (rc != str->len) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "%s: Error writing to file: %s\n", exporter->name,
                        strerror(errno));
            g_string_free(str, TRUE);
            return FALSE;
        }
        g_string_free(str, TRUE);
    }

    return TRUE;
}


/**
 * mdOutputClose
 *
 * emit the fbuf, and free it.
 *
 */
static gboolean
mdOutputClose(
    fBuf_t    *fbuf,
    gboolean   flush,
    GError   **err)
{
    gboolean ok = TRUE;

    if (fbuf == NULL) {
        return ok;
    }

    if (flush) {
        ok = fBufEmit(fbuf, err);
    }

    fBufFree(fbuf);
    fbuf = NULL;

    return ok;
}

/**
 * mdFileOpenRotater
 *
 * get a new filename for file rotaters in the format of
 * outspec-TIME-serial_no
 *
 */
static GString *
mdFileOpenRotater(
    mdExporter_t  *exporter)
{
    GString        *namebuf = NULL;
    static uint32_t serial = 0;
    time_t          cur_time = time(NULL);

    namebuf = g_string_new(NULL);

    if (EXPORTFORMAT_IS_TEXT_OR_JSON(exporter->exportFormat)) {
        g_string_printf(namebuf, "%s.", exporter->activeWriter->outspec);
    } else {
        g_string_printf(namebuf, "%s-", exporter->activeWriter->outspec);
    }

    if (exporter->timestamp_files) {
        uint64_t flow_secs = exporter->activeWriter->lastRotate / 1000;
        md_util_time_append(namebuf, flow_secs, MD_TIME_FMT_YMDHMS);
    } else {
        md_util_time_append(namebuf, cur_time, MD_TIME_FMT_YMDHMS);
    }

    if (!exporter->timestamp_files) {
        g_string_append_printf(namebuf, "-%05u", serial++);
    }

    return namebuf;
}

/**
 * mdOpenTextOutput
 *
 * open a new text exporter
 *
 */
static gboolean
mdOpenTextOutput(
    mdExporter_t  *exporter,
    GError       **err)
{
    GString *namebuf = NULL;
    gboolean rc;

    if (exporter->multi_files ||
        (exporter->usedGeneralDedupConfig && !exporter->json))
    {
        if (!mdExporterInitSession(exporter, err)) {
            return FALSE;
        }
        return TRUE;
    }

    /* STAT EXP filesWritten */
    exporter->expStats.filesWritten++;

    if (exporter->rotateInterval) {
        namebuf = mdFileOpenRotater(exporter);
        if (exporter->json) {
            g_string_append_printf(namebuf, ".json");
        } else {
            g_string_append_printf(namebuf, ".txt");
        }
        exporter->activeWriter->currentFname = g_strdup(namebuf->str);
        if (exporter->lock) {
            mdLockFile(namebuf);
        }
        rc = mdOpenTextFileExport(exporter, namebuf->str, err);
        g_string_free(namebuf, TRUE);
        return rc;
    }

    return mdOpenTextFileExport(exporter, exporter->activeWriter->outspec, err);
}

/**
 * mdTextFileRotate
 *
 * close the current text file, and get a new filename
 * for the new one
 *
 */
static gboolean
mdTextFileRotate(
    mdExporter_t  *exporter,
    uint64_t       cur_time,
    GError       **err)
{
    GString *namebuf;
    gboolean rc = FALSE;

    if (exporter->multi_files) {
        exporter->activeWriter->lastRotate = cur_time;
        return TRUE;
    }

    if (exporter->usedGeneralDedupConfig && !exporter->json) {
        return TRUE;
    }

    if (exporter->activeWriter->lastRotate == 0) {
        exporter->activeWriter->lastRotate = cur_time;
        return mdOpenTextOutput(exporter, err);
    }

    exporter->activeWriter->lastRotate = cur_time;

    if (exporter->activeWriter->lfp) {
        mdCloseAndUnlock(exporter, exporter->activeWriter->lfp,
                         exporter->activeWriter->currentFname,
                         NULL);
    }

    namebuf = mdFileOpenRotater(exporter);

    if (exporter->json) {
        g_string_append_printf(namebuf, ".json");
    } else {
        g_string_append_printf(namebuf, ".txt");
    }

    exporter->activeWriter->currentFname = g_strdup(namebuf->str);

    if (exporter->lock) {
        mdLockFile(namebuf);
    }

    rc = mdOpenTextFileExport(exporter, namebuf->str, err);

    g_string_free(namebuf, TRUE);

    return rc;
}

#if 0
/* currently unused. Need to use again. Use DefaultWriter */
static gboolean
mdVerifyRotatePath(
    mdExporter_t  *exporter,
    GError       **err)
{
    FILE    *tmp = NULL;
    GString *tmpname = NULL;
    /* test that path exists and file can be created */

    tmpname = mdFileOpenRotater(exporter);

    tmp = fopen(tmpname->str, "w+");
    if (tmp == NULL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "%s: Cannot open file \"%s\" for writing: %s",
                    exporter->name, exporter->defaultWriter->outspec,
                   strerror(errno));
        return FALSE;
    } else {
        /* close and remove empty temp file */
        fclose(tmp);
        g_remove(tmpname->str);
        g_string_free(tmpname, TRUE);
    }

    return TRUE;
}
#endif  /* 0 */

/**
 * mdIpfixFileRotate
 *
 * rotate IPFIX files, will have ".med" suffix
 *
 */
static gboolean
mdIpfixFileRotate(
    mdExporter_t  *exporter,
    uint64_t       cur_time,
    GError       **err)
{
    GString *namebuf;
    gboolean rv;

    exporter->activeWriter->lastRotate = cur_time;

    if (fBufGetExporter(exporter->activeWriter->fbuf)) {
        fBufEmit(exporter->activeWriter->fbuf, err);
        fbExporterClose(fBufGetExporter(exporter->activeWriter->fbuf));
    }

    if (exporter->activeWriter->lfp) {
        mdCloseAndUnlock(exporter, exporter->activeWriter->lfp,
                         exporter->activeWriter->currentFname,
                         NULL);
    }

    namebuf = mdFileOpenRotater(exporter);

    g_string_append_printf(namebuf, ".med");

    exporter->activeWriter->currentFname = g_strdup(namebuf->str);

    if (exporter->lock) {
        mdLockFile(namebuf);
    }

    rv = mdOpenIpfixFileExport(exporter, namebuf->str, err);

    g_string_free(namebuf, TRUE);

    return rv;
}

/**
 * mdOpenIpfixSocketExporter
 *
 * open a TCP/UDP Exporter
 *
 */
static gboolean
mdOpenIpfixSocketExporter(
    mdExporter_t  *exporter,
    GError       **err)
{
    /* use the active one for setting it up, which should be default one */
    if (!mdExporterInitSession(exporter, err)) {
        return FALSE;
    }

    exporter->activeWriter->fbExporter   = fbExporterAllocNet(
        &(exporter->spec));

    if (exporter->activeWriter->fbuf) {
        fBufSetExporter(exporter->activeWriter->fbuf,
                        exporter->activeWriter->fbExporter);
    } else {
        exporter->activeWriter->fbuf = fBufAllocForExport(
            exporter->activeWriter->session,
            exporter->activeWriter->fbExporter);
    }

    if (!fbSessionExportTemplates(exporter->activeWriter->session, err)) {
        return FALSE;
    }

    return TRUE;
}


/**
 * mdIpfixOutputOpen - druef-new
 *
 * allocate session
 * allocate exporter
 * configure the new exporter
 * allocate and configure fbuf
 *
 * Run on activeWriter. Always called after defaultWriter is installed
 *
 */
static gboolean
mdIpfixOutputOpen(
    mdConfig_t    *cfg,
    mdExporter_t  *exporter,
    GError       **err)
{
    if (EXPORTMETHOD_IS_SOCKET(exporter->exportMethod)) {
        return mdOpenIpfixSocketExporter(exporter, err);
    }

    /* STAT EXP filesWritten */
    exporter->expStats.filesWritten++;
    if (exporter->rotateInterval) {
        return mdIpfixFileRotate(exporter, cfg->ctime, err);
    }

    return mdOpenIpfixFileExport(exporter, exporter->activeWriter->outspec,
                                 err);
}


/*
 *  This function is primarily used when GEN_TOMBSTONE is TRUE to send a
 *  tombstone record generated by SM.
 *
 *  This may also be used when reading YAF-2.10 data that uses the
 *  Tombstone-V1 templates.
 */
gboolean
mdExporterFormatAndSendOrigTombstone(
    mdConfig_t      *cfg,
    mdExporter_t    *exporter,
    mdGenericRec_t  *mdRec,
    GError         **err)
{
    size_t bytes = 0;
    tombstoneMainV2Rec_t *rec = (tombstoneMainV2Rec_t *)mdRec->fbRec->rec;
    int lineno = -1;

    /* tombstone records go out default writer, which should be active */
    if (!exporter->allowTombstone) {
        return TRUE;
    }

    mdRec->intTid   = exporter->genTids.tombstoneV2MainTid;
    mdRec->extTid   = exporter->genTids.tombstoneV2MainTid;

    if (!exporter->active) {
        if (cfg->ctime - exporter->last_restart_ms > MD_RESTART_MS) {
            if (!mdExporterRestart(cfg, exporter, err)) {
                g_message("Error restarting exporter %s: %s",
                          exporter->name, (*err)->message);
                g_clear_error(err);
                return TRUE;
            }
        } else {
            return TRUE;
        }
    }

    /* guaranteed to be V2, and guaranteed to only have one entry in STL */
    rec->accessList.tmplID = exporter->genTids.tombstoneV2AccessTid;

    if (exporter->exportFormat == EF_IPFIX) {
        fBufSetInternalTemplate(exporter->activeWriter->fbuf,
                                mdRec->intTid, err);
        fBufSetExportTemplate(exporter->activeWriter->fbuf, mdRec->extTid, err);

        if (!(fBufAppend(exporter->activeWriter->fbuf,
                         mdRec->fbRec->rec,
                         mdRec->fbRec->recsize,
                         err)))
        {
            lineno = __LINE__;
            goto err;
        }
    } else {
        ROTATE_IF_NEEDED(exporter, cfg->ctime, err);

        if (exporter->json) {
            bytes = mdPrintJsonTombstone(
                (tombstoneMainV2Rec_t *)mdRec->fbRec->rec,
                cfg->collector_name, exporter->activeWriter->lfp,
                err);
            if (!bytes) {
                lineno = __LINE__;
                goto err;
            }
        }
    }

    return TRUE;

  err:
    if (err && !*err) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "FIX THE CODE!!! Function near %s:%d did not set GError",
                    __FILE__, lineno);
    }
    g_warning("Error writing created tombstone record: %s", (*err)->message);
    g_clear_error(err);
    g_warning("Deactivating Exporter %s.", exporter->name);
    exporter->active = FALSE;
    if (!mdExporterRestart(cfg, exporter, err)) {
        g_warning("Error restarting exporter %s: %s",
                  exporter->name, (*err)->message);
        g_clear_error(err);
    }
    return TRUE;
}

static gboolean
mdExporterSendIPFIXRecord(
    const mdGenericRec_t  *mdRec,
    mdExporter_t          *exporter,
    GError               **err)
{
    uint16_t            expIntTid = 0;
    uint16_t            expExtTid = 0;
    fbTemplate_t       *expIntTmpl  = NULL;
    mdFlowExporterCollectorInfo_t *collInfo = NULL;
    mdExpFlowTmplCtx_t *intTmplCtx = NULL;

    /* send IPFIX record to active writer */

    collInfo = &(exporter->collInfoById[mdRec->collector->id]);

    expIntTid = collInfo->expIntTidByColIntTid[mdRec->intTid];
    expIntTmpl = collInfo->expIntTmplByColIntTid[mdRec->intTid];
    intTmplCtx = fbTemplateGetContext(expIntTmpl);
    expExtTid = intTmplCtx->defCtx.associatedExtTid;

    fBufSetInternalTemplate(exporter->activeWriter->fbuf, expIntTid, err);
    fBufSetExportTemplate(exporter->activeWriter->fbuf, expExtTid, err);

    if (!(fBufAppend(exporter->activeWriter->fbuf,
                     mdRec->fbRec->rec,
                     mdRec->fbRec->recsize,
                     err)))
    {
        return FALSE;
    }

    /* STAT EXP bytesWritten */
    exporter->expStats.bytesWritten += fbExporterGetOctetCountAndReset(
        exporter->activeWriter->fbExporter);

    return TRUE;
}

/**
 * mdExporterWriteOptions
 *
 * write an IPFIX Options Record
 *
 * @param cfg - mediator configuration options
 * @param exporter - exporter to write to
 * @param tid - template id
 * @param rec - the options record to write
 * @param rec_length - length of record to write
 * @param err
 * @return TRUE if no errors
 */
gboolean
mdExporterWriteOptions(
    mdConfig_t      *cfg,
    mdExporter_t    *exporter,
    mdGenericRec_t  *mdRec,
    GError         **err)
{
    size_t bytes = 0;
    const mdDefaultTmplCtx_t *intTmplCtx;
    mdUtilTemplateContents_t  tc;
    int lineno = -1;

    intTmplCtx  = mdRec->intTmplCtx;
    tc          = intTmplCtx->templateContents;

    /* TODO: break out yaf stats and tombstone into new functions */

    /* options records are written to default writer which should be active */
    if (!exporter->allowYafStats && !exporter->allowTombstone &&
        !exporter->statsAddedToFlowOnlyOrDPIOnly)
    {
        /* STAT EXP recordsIgnoredByType */
        exporter->expStats.recordsIgnoredByType[tc.general]++;
        return TRUE;
    }

    /* STAT EXP recordsForwardedByType */
    exporter->expStats.recordsForwardedByType[tc.general]++;

    if (!exporter->active) {
        if (cfg->ctime - exporter->last_restart_ms > MD_RESTART_MS) {
            if (!mdExporterRestart(cfg, exporter, err)) {
                g_message("Error restarting exporter %s: %s",
                          exporter->name, (*err)->message);
                g_clear_error(err);
                return TRUE;
            }
        } else {
            return TRUE;
        }
    }

    if (exporter->exportFormat == EF_IPFIX) {
        if (!mdExporterSendIPFIXRecord(mdRec, exporter, err)) {
            g_warning("couldn't write options %s\n", (*err)->message);
            lineno = __LINE__;
            goto err;
        }
        bytes = mdRec->fbRec->recsize;
    } else {
        ROTATE_IF_NEEDED(exporter, cfg->ctime, err);

        if (tc.general == TC_YAF_STATS) {
            if (exporter->json) {
                bytes = mdPrintJsonStats(mdRec, cfg->collector_name,
                                         exporter->activeWriter->lfp, err);
            } else {
                if (exporter->multi_files) {
                    FILE *fp = mdGetTableFile(exporter, "yaf_stats");
                    if (fp == NULL) {
                        lineno = __LINE__;
                        goto err;
                    }
                    bytes = mdPrintStats(
                        (yafStatsV2Rec_t *)(mdRec->fbRec->rec),
                        cfg->collector_name,
                        fp,
                        exporter->delimiter,
                        exporter->allowYafStats,
                        exporter->statsAddedToFlowOnlyOrDPIOnly,
                        err);
                } else {
                    bytes = mdPrintStats(
                        (yafStatsV2Rec_t *)(mdRec->fbRec->rec),
                        cfg->collector_name,
                        exporter->activeWriter->lfp,
                        exporter->delimiter,
                        exporter->allowYafStats,
                        exporter->statsAddedToFlowOnlyOrDPIOnly,
                        err);
                }
            }
            if (!bytes) {
                lineno = __LINE__;
                goto err;
            }
        }

        if (tc.general == TC_TOMBSTONE) {
            if (exporter->json) {
                bytes = mdPrintJsonTombstone(
                    (tombstoneMainV2Rec_t *)(mdRec->fbRec->rec),
                    cfg->collector_name,
                    exporter->activeWriter->lfp, err);
                if (!bytes) {
                    lineno = __LINE__;
                    goto err;
                }
            }
        }
    }

    return TRUE;

  err:
    if (err && !*err) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "FIX THE CODE!!! Function near %s:%d did not set GError",
                    __FILE__, lineno);
    }
    g_warning("Error writing option record: %s", (*err)->message);
    g_clear_error(err);
    g_warning("Deactivating Exporter %s.", exporter->name);
    exporter->active = FALSE;
    if (!mdExporterRestart(cfg, exporter, err)) {
        g_warning("Error restarting exporter %s: %s",
                  exporter->name, (*err)->message);
        g_clear_error(err);
    }
    return TRUE;
}

/**
 *  Processes the type-value (yaf_ssl_subcert_t) records in 'srcStl' and
 *  copies them into 'dstRec'.  'stlCount' denotes which STL is in 'srcStl'
 *  (0=issuer, 1=subject, 2=extensions).
 */
void
mdExporterSslProcessTypeValueList(
    md_ssl_certificate_t  *dstRec,
    fbSubTemplateList_t   *srcStl,
    const unsigned int     stlCount)
{
    yaf_ssl_subcert_t *type_val_rec = NULL;
    fbBasicList_t     *bl;
    fbVarfield_t      *vf;
    fbVarfield_t      *srcvf;
    unsigned int       key;

    while ((type_val_rec = fbSTLNext(yaf_ssl_subcert_t, srcStl, type_val_rec)))
    {
        key = type_val_rec->sslObjectType;
        srcvf = &type_val_rec->sslObjectValue;
        bl = NULL;
        vf = NULL;

        /* Issuer or Subject */
        if (stlCount < 2) {
            switch (key) {
              case 3:
                /* id-at-commonName {id-at 3} */
                bl = ((0 == stlCount)
                      ? &dstRec->sslCertIssuerCommonNameList
                      : &dstRec->sslCertSubjectCommonNameList);
                break;

              case 6:
                /* id-at-countryName {id-at 6} */
                vf = ((0 == stlCount)
                      ? &dstRec->sslCertIssuerCountryName
                      : &dstRec->sslCertSubjectCountryName);
                break;

              case 7:
                /* id-at-localityName {id-at 7} */
                vf = ((0 == stlCount)
                      ? &dstRec->sslCertIssuerLocalityName
                      : &dstRec->sslCertSubjectLocalityName);
                break;

              case 8:
                /* id-at-stateOrProvinceName {id-at 8} */
                vf = ((0 == stlCount)
                      ? &dstRec->sslCertIssuerState
                      : &dstRec->sslCertSubjectState);
                break;

              case 9:
                /* id-at-streetAddress {id-at 9} */
                bl = ((0 == stlCount)
                      ? &dstRec->sslCertIssuerStreetAddressList
                      : &dstRec->sslCertSubjectStreetAddressList);
                break;

              case 10:
                /* id-at-organizationName {id-at 10} */
                bl = ((0 == stlCount)
                      ? &dstRec->sslCertIssuerOrgNameList
                      : &dstRec->sslCertSubjectOrgNameList);
                break;

              case 11:
                /* id-at-organizationalUnitName {id-at 11} */
                bl = ((0 == stlCount)
                      ? &dstRec->sslCertIssuerOrgUnitNameList
                      : &dstRec->sslCertSubjectOrgUnitNameList);
                break;

              case 17:
                /* id-at-postalCode {id-at 17} */
                vf = ((0 == stlCount)
                      ? &dstRec->sslCertIssuerZipCode
                      : &dstRec->sslCertSubjectZipCode);
                break;

              case 12:
                /* id-at-title {id-at 12} */
                vf = ((0 == stlCount)
                      ? &dstRec->sslCertIssuerTitle
                      : &dstRec->sslCertSubjectTitle);
                break;

              case 41:
                /* id-at-name {id-at 41} */
                vf = ((0 == stlCount)
                      ? &dstRec->sslCertIssuerName
                      : &dstRec->sslCertSubjectName);
                break;

              case 1:
                /* pkcs-9-emailAddress {pkcs-9 1} */
                vf = ((0 == stlCount)
                      ? &dstRec->sslCertIssuerEmailAddress
                      : &dstRec->sslCertSubjectEmailAddress);
                break;

              case 25:
                /* 0.9.2342.19200300.100.1.25 {dc 25} */
                bl = ((0 == stlCount)
                      ? &dstRec->sslCertIssuerOrgUnitNameList
                      : &dstRec->sslCertSubjectOrgUnitNameList);
                break;
            }
        } else {
            /**** Extentions ****/
            g_assert(2 == stlCount);

            switch (key) {
              case 14:
                /* id-ce-subjectKeyIdentifier {id-ce 14} */
                vf = &dstRec->sslCertExtSubjectKeyIdent;
                break;

              case 15:
                /* id-ce-keyUsage {id-ce 15} */
                vf = &dstRec->sslCertExtKeyUsage;
                break;

              case 16:
                /* id-ce-privateKeyUsagePeriod {id-ce 16} */
                vf = &dstRec->sslCertExtPrivKeyUsagePeriod;
                break;

              case 17:
                /* id-ce-subjectAltName {id-ce 17} */
                vf = &dstRec->sslCertExtSubjectAltName;
                break;

              case 18:
                /* id-ce-issuerAltName {id-ce 18} */
                vf = &dstRec->sslCertExtIssuerAltName;
                break;

              case 29:
                /* id-ce-certificateIssuer {id-ce 29} */
                vf = &dstRec->sslCertExtCertIssuer;
                break;

              case 31:
                /* id-ce-cRLDistributionPoints {id-ce 31} */
                vf = &dstRec->sslCertExtCrlDistribution;
                break;

              case 32:
                /* id-ce-certificatePolicies {id-ce 32} */
                vf = &dstRec->sslCertExtCertPolicies;
                break;

              case 35:
                /* id-ce-authorityKeyIdentifier {id-ce 35} */
                vf = &dstRec->sslCertExtAuthorityKeyIdent;
                break;

              case 37:
                /* id-ce-extKeyUsage {id-ce 37} */
                vf = &dstRec->sslCertExtExtendedKeyUsage;
                break;
            }
        }

        if (vf) {
            g_assert(NULL == bl);
            memcpy(vf, srcvf, sizeof(*vf));
        } else if (bl) {
            vf = fbBasicListAddNewElements(bl, 1);
            memcpy(vf, srcvf, sizeof(fbVarfield_t));
        }
    }
}

typedef struct mdSSLRWLevel2_st {
    /* Array of fbSubTemplateList_t */
    GArray               *stlArray;
    const fbTemplate_t   *sslFlatTmpl;
    GError               *err;
    uint16_t              stlOffset;
    uint16_t              stlIter;
} mdSSLRWLevel2_t;

static int
flatten_ssl_rewrite_level_2_callback(
    const fbRecord_t  *record,
    void              *v_level2State)
{
    mdSSLRWLevel2_t     *level2State = (mdSSLRWLevel2_t *)v_level2State;
    fbSubTemplateList_t *recStl;
    fbSubTemplateList_t *tmpStl;
    fbRecord_t recRec;
    fbRecord_t tmpRec;
    unsigned int i;

    recStl = (fbSubTemplateList_t *)(record->rec + level2State->stlOffset);

    g_array_append_vals(level2State->stlArray, recStl, 1);
    tmpStl = &g_array_index(level2State->stlArray, fbSubTemplateList_t,
                            level2State->stlIter);

    memset(recStl, 0, sizeof(*recStl));
    fbSubTemplateListInit(recStl, fbSubTemplateListGetSemantic(tmpStl),
                          MD_SSL_CERTIFICATE_TID, level2State->sslFlatTmpl,
                          fbSubTemplateListCountElements(tmpStl));

    tmpRec.tmpl = fbSubTemplateListGetTemplate(tmpStl);

    recRec.tmpl = level2State->sslFlatTmpl;
    recRec.tid = MD_SSL_CERTIFICATE_TID;
    recRec.reccapacity = fbTemplateGetIELenOfMemBuffer(recRec.tmpl);

    for (i = 0; i < fbSubTemplateListCountElements(tmpStl); ++i) {
        tmpRec.rec = fbSubTemplateListGetIndexedDataPtr(tmpStl, i);
        recRec.rec = fbSubTemplateListGetIndexedDataPtr(recStl, i);
        if (!mdUtilFlattenOneSslCertificate(&tmpRec, &recRec, NULL,
                                            &level2State->err))
        {
            return -1;
        }
    }

    ++level2State->stlIter;
    return 0;
}


fbTemplate_t *
mdUtilMakeSslFlatCertTmpl(
    const fbTemplate_t         *srcTmpl,
    const fbInfoElementSpec_t  *addlSpecs,
    uint32_t                    addlSpecFlags,
    GError                    **err)
{
    fbTemplate_t *newTmpl;
    fbTemplateIter_t iter;
    const fbTemplateField_t *field;
    fbInfoElementSpec_t *elems;
    mdDefaultTmplCtx_t *defCtx;
    unsigned int i;

    newTmpl = fbTemplateAlloc(fbTemplateGetInfoModel(srcTmpl));

    /* append elements that hold the "flattened" values that get pulled from
     * type/object STL */
    mdTemplateAppendSpecArray(newTmpl, mdSSLRWCertLevel2Spec, ~0);

    /* append any additional elements */
    if (addlSpecs &&
        !fbTemplateAppendSpecArray(newTmpl, addlSpecs, addlSpecFlags, err))
    {
        fbTemplateFreeUnused(newTmpl);
        return NULL;
    }

    /*
     * When writing an TLS CERT as TEXT, the code currently casts it to a
     * either a YAF2 style struct or a flattened struct, and which struct is
     * determined by examining its template context.  Create a context and set
     * it to the value for a flattened cert.  If the writing code were to
     * examine the template directly, this context setting would (probably)
     * not be needed.
     */
    defCtx = g_slice_new0(mdDefaultTmplCtx_t);
    fbTemplateSetContext(newTmpl, defCtx, NULL, templateCtxFree);

    defCtx->contextType      = TCTX_TYPE_EXPORTER;
    defCtx->associatedExtTid = MD_SSL_TID;
    defCtx->templateType     = TT_TOP_OTHER;
    defCtx->templateContents.general      = TC_UNKNOWN_DATA;
    defCtx->templateContents.specCase.dpi = TC_APP_DPI_SSL_RW_L2;
    defCtx->templateContents.relative     = TC_EXACT_DEF;
    defCtx->templateContents.yafVersion   = TC_YAF_ALL_VERSIONS;

    elems = g_new0(fbInfoElementSpec_t, fbTemplateCountElements(srcTmpl) + 1);

    /* find all elements from incoming template whose type is not STL */
    i = 0;
    fbTemplateIterInit(&iter, srcTmpl);
    while ((field = fbTemplateIterNext(&iter))) {
        if (FB_SUB_TMPL_LIST == fbTemplateFieldGetType(field)) {
            continue;
        }
        elems[i].name = fbTemplateFieldGetName(field);
        elems[i].len_override = fbTemplateFieldGetLen(field);
        ++i;
    }

    /* append those elements */
    if (!fbTemplateAppendSpecArray(newTmpl, elems, ~0, err)) {
        fbTemplateFreeUnused(newTmpl);
        g_free(elems);
        return NULL;
    }

    g_free(elems);

    return newTmpl;
}


int
mdUtilFlattenOneSslCertificate(
    const fbRecord_t           *origRecord,
    fbRecord_t                 *flatRecord,
    const mdDefaultTmplCtx_t   *origRecTmplCtx,
    GError                    **err)
{
    static const fbInfoElement_t *sslCertIssuerCommonName;
    static const fbInfoElement_t *sslCertIssuerStreetAddress;
    static const fbInfoElement_t *sslCertIssuerOrgName;
    static const fbInfoElement_t *sslCertIssuerOrgUnitName;
    static const fbInfoElement_t *sslCertIssuerDomainComponent;
    static const fbInfoElement_t *sslCertSubjectCommonName;
    static const fbInfoElement_t *sslCertSubjectStreetAddress;
    static const fbInfoElement_t *sslCertSubjectOrgName;
    static const fbInfoElement_t *sslCertSubjectOrgUnitName;
    static const fbInfoElement_t *sslCertSubjectDomainComponent;
    const fbTemplateField_t *origBLField;
    const fbBasicList_t     *origBL;
    const fbTemplateField_t *flatBLField;
    fbBasicList_t           *flatBL;
    md_ssl_certificate_t    *flatRec;
    void     *data;
    uint16_t  i, j;

    if (NULL == origRecTmplCtx) {
        origRecTmplCtx = fbTemplateGetContext(origRecord->tmpl);
    }

    if (NULL == sslCertIssuerCommonName) {
        /* get handles to the IEs used by the basic lists in the
         * md_ssl_certificate_t */
        fbInfoModel_t *model = mdInfoModel();
        sslCertIssuerCommonName = fbInfoModelGetElementByName(
            model, "sslCertIssuerCommonName");
        sslCertSubjectCommonName = fbInfoModelGetElementByName(
            model, "sslCertSubjectCommonName");
        sslCertIssuerStreetAddress = fbInfoModelGetElementByName(
            model, "sslCertIssuerStreetAddress");
        sslCertSubjectStreetAddress = fbInfoModelGetElementByName(
            model, "sslCertSubjectStreetAddress");
        sslCertIssuerOrgName = fbInfoModelGetElementByName(
            model, "sslCertIssuerOrgName");
        sslCertSubjectOrgName = fbInfoModelGetElementByName(
            model, "sslCertSubjectOrgName");
        sslCertIssuerOrgUnitName = fbInfoModelGetElementByName(
            model, "sslCertIssuerOrgUnitName");
        sslCertSubjectOrgUnitName = fbInfoModelGetElementByName(
            model, "sslCertSubjectOrgUnitName");
        sslCertIssuerDomainComponent = fbInfoModelGetElementByName(
            model, "sslCertIssuerDomainComponent");
        sslCertSubjectDomainComponent = fbInfoModelGetElementByName(
            model, "sslCertSubjectDomainComponent");
    }

    if (!fbRecordCopyToTemplate(
            origRecord, flatRecord, flatRecord->tmpl, flatRecord->tid, err))
    {
        return FALSE;
    }

    /* CopyToTemplate does not copy the data for any basicLists, so do that
     * manually (e.g., sslBinaryCertificateList) */
    i = 0;
    j = 0;
    while ((origBLField = (fbTemplateFindFieldByDataType(
                               origRecord->tmpl, FB_BASIC_LIST, &i, 0))))
    {
        if (0 == j) {
            /* Move to the final basicList in the rewritten template.  We know
             * there are 10 basicLists, so skip 9 to land on the final one. */
            /* FIXME: Assumes that the full cert exported by SSL_DEDUP does
             * not include any basic lists. */
            flatBLField = fbTemplateFindFieldByDataType(
                flatRecord->tmpl, FB_BASIC_LIST, &j, 9);
            if (NULL == flatBLField) {
                g_error("BAD");
            }
        }
        flatBLField = fbTemplateFindFieldByDataType(
            flatRecord->tmpl, FB_BASIC_LIST, &j, 0);
        origBL = (fbBasicList_t *)origRecord->rec + origBLField->offset;
        flatBL = (fbBasicList_t *)flatRecord->rec + flatBLField->offset;
        g_assert(fbBasicListGetInfoElement(origBL) ==
                 fbBasicListGetInfoElement(flatBL));
        data = fbBasicListResize(flatBL, fbBasicListCountElements(origBL));
        memcpy(data, fbBasicListGetDataPtr(origBL), origBL->dataLength);
    }


    flatRec = (md_ssl_certificate_t *)flatRecord->rec;

    /* Initialize all the basic lists */
    fbBasicListInit(&flatRec->sslCertIssuerCommonNameList,
                    FB_LIST_SEM_ALL_OF, sslCertIssuerCommonName, 0);
    fbBasicListInit(&flatRec->sslCertSubjectCommonNameList,
                    FB_LIST_SEM_ALL_OF, sslCertSubjectCommonName, 0);

    fbBasicListInit(&flatRec->sslCertIssuerStreetAddressList,
                    FB_LIST_SEM_ALL_OF, sslCertIssuerStreetAddress, 0);
    fbBasicListInit(&flatRec->sslCertSubjectStreetAddressList,
                    FB_LIST_SEM_ALL_OF, sslCertSubjectStreetAddress, 0);

    fbBasicListInit(&flatRec->sslCertIssuerOrgNameList,
                    FB_LIST_SEM_ALL_OF, sslCertIssuerOrgName, 0);
    fbBasicListInit(&flatRec->sslCertSubjectOrgNameList,
                    FB_LIST_SEM_ALL_OF, sslCertSubjectOrgName, 0);

    fbBasicListInit(&flatRec->sslCertIssuerOrgUnitNameList,
                    FB_LIST_SEM_ALL_OF, sslCertIssuerOrgUnitName, 0);
    fbBasicListInit(&flatRec->sslCertSubjectOrgUnitNameList,
                    FB_LIST_SEM_ALL_OF, sslCertSubjectOrgUnitName, 0);

    fbBasicListInit(&flatRec->sslCertIssuerDomainComponentList,
                    FB_LIST_SEM_ALL_OF, sslCertIssuerDomainComponent, 0);
    fbBasicListInit(&flatRec->sslCertSubjectDomainComponentList,
                    FB_LIST_SEM_ALL_OF, sslCertSubjectDomainComponent, 0);

    /* Process the STLs */
    for (i = 0; i < origRecTmplCtx->stlCount && i < 3; ++i) {
        mdExporterSslProcessTypeValueList(
            flatRec,
            ((fbSubTemplateList_t *)
             (origRecord->rec + origRecTmplCtx->stlOffsets[i])),
            i);
    }

    return TRUE;
}

static int
flatten_ssl_put_back_orig_callback(
    const fbRecord_t  *record,
    void              *v_level2State)
{
    mdSSLRWLevel2_t      *level2State = (mdSSLRWLevel2_t *)v_level2State;
    fbSubTemplateList_t  *recStl;
    fbSubTemplateList_t  *tmpStl;
    md_ssl_certificate_t *dstRec;

    recStl = (fbSubTemplateList_t *)(record->rec +level2State->stlOffset);
    tmpStl = &g_array_index(level2State->stlArray, fbSubTemplateList_t,
                            level2State->stlIter);

    /* dstRec is a md_ssl_certificate_t in the record's STL */
    dstRec = NULL;

    while ((dstRec = fbSTLNext(md_ssl_certificate_t, recStl, dstRec))) {
        /* clear the basicLists */
        fbBasicListClear(&dstRec->sslCertIssuerCommonNameList);
        fbBasicListClear(&dstRec->sslCertSubjectCommonNameList);
        fbBasicListClear(&dstRec->sslCertIssuerStreetAddressList);
        fbBasicListClear(&dstRec->sslCertSubjectStreetAddressList);
        fbBasicListClear(&dstRec->sslCertIssuerOrgNameList);
        fbBasicListClear(&dstRec->sslCertSubjectOrgNameList);
        fbBasicListClear(&dstRec->sslCertIssuerOrgUnitNameList);
        fbBasicListClear(&dstRec->sslCertSubjectOrgUnitNameList);
        fbBasicListClear(&dstRec->sslCertIssuerDomainComponentList);
        fbBasicListClear(&dstRec->sslCertSubjectDomainComponentList);
    }

    /* clear the STL on the record */
    fbSubTemplateListClear(recStl);

    /* copy the old STL back onto the record */
    memcpy(recStl, tmpStl, sizeof(*recStl));

    level2State->stlIter++;
    return 0;
}

/**
 *  For each yafSSLDPICert_t record in the STML entry stored on 'flow',
 *  converts its subTemplateList of yaf_newssl_cert_t records to an
 *  md_ssl_certificate_t which "flattens" the certificate and stores many
 *  values in separate IEs, appends the record to the exporter's fbuf, and
 *  then restores the record so no other processing is affected.
 *
 *  The return status is the result of fBufAppend().
 */
static int
mdExporterFlattenAndWriteSslCerts(
    mdExporter_t   *exporter,
    mdFullFlow_t   *flow,
    const GString  *prefixString,
    GError        **err)
{
    int             rc;
    mdSSLRWLevel2_t rwLevel2State;

    memset(&rwLevel2State, 0, sizeof(rwLevel2State));

    /* send to active writer which was already installed */

    /* For each incoming STL holding yafSSLDPICert_t records, the STL is
     * copied to a temporary location, its old location is filled with a new
     * STL holding the flattened certificate records, the top-level record is
     * written, and then the STL from the temporary location is
     * copied back into place. */

    /* where to store the STLs */
    rwLevel2State.stlArray = g_array_new(FALSE, FALSE,
                                         sizeof(fbSubTemplateList_t));

    /* active session, as this doesn't care which writer it is */
    rwLevel2State.sslFlatTmpl = fbSessionGetTemplate(
        exporter->activeWriter->session, TRUE,
        exporter->genTids.flattenedSSLTid,
        err);

    /* The offset in the SSL L1 template of the STL that holds the TLS/SSL
     * certificates */
    rwLevel2State.stlOffset = exporter->rwSSLLevel2STLOffset;

    if (fbRecordFindAllSubRecords(flow->fbRec,
                                  exporter->recvdTids.sslLevel1Tid, 0,
                                  flatten_ssl_rewrite_level_2_callback,
                                  &rwLevel2State))
    {
        g_error("Error returned while flattening SSL certificate record: %s",
                rwLevel2State.err->message);
    }

    if (exporter->exportFormat == EF_IPFIX) {
        rc = fBufAppend(exporter->activeWriter->fbuf, flow->fbRec->rec,
                        exporter->largestRecTemplateSize, err);
    } else {
        rc = mdExporterDPIFlowPrint(exporter, flow, prefixString, err);
    }

    /* Change the flattened record back to its original state */
    rwLevel2State.stlIter = 0;
    if (fbRecordFindAllSubRecords(flow->fbRec, exporter->recvdTids.sslLevel1Tid,
                                  0,
                                  flatten_ssl_put_back_orig_callback,
                                  &rwLevel2State))
    {
        g_error("Error returned while restoring flattened record: %s",
                rwLevel2State.err->message);
    }

    g_array_free(rwLevel2State.stlArray, TRUE);

    return rc;
}


static mdFileWriter_t *
handleInvariant(
    mdExporter_t  *exporter,
    mdFullFlow_t  *flow)
{
    time_t          timestamp           = 0;
    invariants_t    invs;
    struct tm       ltr;
    struct tm      *localTimeResult     = &ltr;
    invariants_t   *keyInvs             = NULL;
    mdFileWriter_t *fbWriter            = NULL;
    mdFileWriter_t *writerToClose       = NULL;
    uint16_t        tid                 = 0;
    fbTemplate_t   *tmpl                = NULL;
    GError         *err                 = NULL;
    mdDefaultTmplCtx_t *defCtx              = NULL;

    timestamp = flow->flowStartMilliseconds / 1000;
    localTimeResult = gmtime_r(&timestamp, localTimeResult);

    invs.observationDomain = *(flow->observationDomain);
    invs.vlanId             = flow->vlanId;
    invs.silkAppLabel       = flow->silkAppLabel;
    invs.year               = localTimeResult->tm_year + 1900;
    invs.month              = localTimeResult->tm_mon + 1;
    invs.day                = localTimeResult->tm_mday;
    invs.hour               = localTimeResult->tm_hour;

    fbWriter = g_hash_table_lookup(exporter->invState.fileWritersTable,
                                   &invs);
    if (!fbWriter) {
        /* need all new sessions, exporter, fbuf */
        fbWriter = g_slice_new0(mdFileWriter_t);

        fbWriter->outspec = g_strdup_printf(
            "%s-inv-year-%d-month-%d-day-%02d-hour-%02d"
            "-observationDomainId-%d-vlanId-%d-silkAppLabel-%02d.med",
            exporter->defaultWriter->outspec,
            invs.year, invs.month, invs.day, invs.hour,
            invs.observationDomain, invs.vlanId, invs.silkAppLabel);

        fbWriter->exporter = exporter;

        fbWriter->bytesWrittenSinceLastRotate = 0;
        fbWriter->lastRotate = exporter->cfg->ctime;

        /* if rotate...call mdIpfixFileRotate
         * if not...call mdOpenIpfixFileExport */

        INSTALL_THIS_FILE_WRITER(exporter, fbWriter);

        /* prepare to open the file. Check that we have room in max FPs */
        if (exporter->invState.currentFPs == exporter->invState.maxFPs) {
            /* need to flush the oldest one, and close it */
            writerToClose = detachFromEndOfDLL(
                (mdDLL_t **)&(exporter->invState.head),
                (mdDLL_t **)&(exporter->invState.tail));

            if (!writerToClose) {
                g_error("No writer at tail...something is very wrong");
            }

            if (fBufGetExporter(writerToClose->fbuf)) {
                fBufEmit(writerToClose->fbuf, &err);
                fbExporterClose(fBufGetExporter(writerToClose->fbuf));
                writerToClose->fbuf = NULL;
            }

            if (writerToClose->lfp) {
                mdCloseAndUnlock(exporter, writerToClose->lfp,
                                 writerToClose->currentFname,
                                 NULL);
            }

            g_hash_table_remove(exporter->invState.fileWritersTable,
                                writerToClose->key);
        } else {
            exporter->invState.currentFPs++;
        }

        if (exporter->rotateInterval) {
            mdIpfixFileRotate(exporter, exporter->cfg->ctime, &err);
        } else {
            mdOpenIpfixFileExport(exporter, exporter->activeWriter->outspec,
                                  &err);
        }

        keyInvs = g_slice_new0(invariants_t);
        memcpy(keyInvs, &invs, sizeof(invariants_t));
        g_hash_table_insert(exporter->invState.fileWritersTable,
                            keyInvs, fbWriter);

        exporter->activeWriter->key = (uint8_t *)keyInvs;

        /* save the key after we save the writer so it's not overwritten */
        fbWriter->key = (uint8_t *)keyInvs;

        /* need to get all of the templates out of the default session, and
         * into this one */

        for (tid = 1; tid < UINT16_MAX; tid++) {
            tmpl = fbSessionGetTemplate(exporter->defaultWriter->session, TRUE,
                                        tid, NULL);
            if (tmpl) {
                defCtx = fbTemplateGetContext(tmpl);
                if (!defCtx) {
                    continue;
                }

                switch (defCtx->templateContents.general) {
                  case TC_UNKNOWN_DATA:
                  case TC_FLOW:
                  case TC_DPI:
                    invFbWritersAddSingleTemplate(exporter, tid, tmpl, fbWriter,
                                                  &err);
                    break;
                  default:
                    break;
                }
            }
        }

        if (exporter->metadataExportElements &&
            !fbSessionSetMetadataExportElements(
                fbWriter->session, TRUE, YAF_TYPE_METADATA_TID, &err))
        {
            g_error("Failed to set IE metadata template: %s", err->message);
        }
        if (exporter->metadataExportTemplates &&
            !fbSessionSetMetadataExportTemplates(
                fbWriter->session, TRUE, YAF_TEMPLATE_METADATA_TID,
                FB_TID_AUTO, &err))
        {
            g_error("Failed to set metadata export templates: %s",
                    err->message);
        }
        if (!fbSessionExportTemplates(fbWriter->session, &err)) {
            g_error("Couldn't export templates after creating writer: %s",
                    err->message);
        }

        attachHeadToDLL((mdDLL_t **)&(exporter->invState.head),
                        (mdDLL_t **)&(exporter->invState.tail),
                        (mdDLL_t *)fbWriter);
    } else {
        INSTALL_THIS_FILE_WRITER(exporter, fbWriter);

        if (exporter->invState.head != fbWriter) {
            detachThisEntryOfDLL((mdDLL_t **)&(exporter->invState.head),
                                 (mdDLL_t **)&(exporter->invState.tail),
                                 (mdDLL_t *)fbWriter);

            attachHeadToDLL((mdDLL_t **)&(exporter->invState.head),
                            (mdDLL_t **)&(exporter->invState.tail),
                            (mdDLL_t *)fbWriter);
        }
    }

    return fbWriter;
}


/**
 * mdExporterWriteFlow
 *
 *
 * write a mediator flow record
 *
 * @param cfg - mediator configuration options
 * @param exporter - exporter to write to
 * @param flow - a full mediator flow
 * @param err
 * @return 1 if flow is successfully written, 0 if flow is ignored but no
 * error is set, -1 on error with Gerror being set.
 */
int
mdExporterWriteFlow(
    mdConfig_t    *cfg,
    mdExporter_t  *exporter,
    mdFullFlow_t  *flow,
    GError       **err)
{
    gboolean      rc;
    int           ret;
    uint16_t      expIntTid               = 0;
    uint16_t      expExtTid               = 0;
    fbTemplate_t *expIntTmpl              = NULL;
    mdFlowExporterCollectorInfo_t *collInfo                = NULL;
    mdExpFlowTmplCtx_t            *intTmplCtx              = NULL;
    mdFileWriter_t *writerUsedByInvariant   = NULL;
    /* filled no matter exporter type, adding to stats at end */
    uint64_t        bytesWritten            = 0;
    int lineno = -1;

    if (!exporter->allowFlow) {
        /* STAT EXP recordsIgnoredByType */
        exporter->expStats.recordsIgnoredByType[TC_FLOW]++;
        return 0;
    }

    if (exporter->flowDpiStrip) {
        if (flow->flowEndReason == YAF_END_UDPFORCE) {
            /* STAT EXP recordsIgnoredByType */
            exporter->expStats.recordsIgnoredByType[TC_FLOW]++;
            /* ignore dns records */
            return 0;
        }
    }

    if (!exporter->active) {
        if (cfg->ctime - exporter->last_restart_ms > MD_RESTART_MS) {
            if (!mdExporterRestart(cfg, exporter, err)) {
                g_message("Error restarting exporter %s: %s",
                          exporter->name, (*err)->message);
                g_clear_error(err);
                return 0;
            }
        } else {
            return 0;
        }
    }

    /* STAT EXP recordsForwardedBy Type */
    exporter->expStats.recordsForwardedByType[TC_FLOW]++;
    /* STAT EXP flowsByAppLabel */
    exporter->expStats.flowsByAppLabel[flow->silkAppLabel]++;

    if (exporter->exportFormat == EF_IPFIX) {
        if (exporter->flowDpiRequired) {
            if (flow->silkAppLabel == 0) {
                return 0;
            }
        }

        /* rotating invariant writers will happen in handleInvariant */
        if (exporter->invariant) {
            writerUsedByInvariant = handleInvariant(exporter, flow);
        } else {
            ROTATE_IF_NEEDED(exporter, cfg->ctime, err);
        }

        /* at this point, activeWriter is the one to reference / update */

        /* TODO - turn into function or macro */
        /* need to figure out rewriting SSL certs first */
        collInfo = &(exporter->collInfoById[flow->collector->id]);

        expIntTid = collInfo->expIntTidByColIntTid[flow->intTid];
        expIntTmpl = collInfo->expIntTmplByColIntTid[flow->intTid];
        intTmplCtx = fbTemplateGetContext(expIntTmpl);
        expExtTid = intTmplCtx->defCtx.associatedExtTid;

        fBufSetInternalTemplate(exporter->activeWriter->fbuf, expIntTid, err);
        fBufSetExportTemplate(exporter->activeWriter->fbuf, expExtTid, err);

        if (cfg->usec_sleep) {
            usleep(cfg->usec_sleep);
        }

        if (exporter->flattenSSLCerts && flow->silkAppLabel == 443 &&
            !exporter->flowDpiStrip)
        {
            /* export a record where the SSL certificates list has
             * been flattened */
            rc = mdExporterFlattenAndWriteSslCerts(exporter, flow, NULL, err);
        } else {
            /* this includes the case of already flattened certs */
            rc = fBufAppend(exporter->activeWriter->fbuf,
                            (uint8_t *)flow->fbRec->rec,
                            exporter->largestRecTemplateSize, err);
        }

        if (!rc) {
            g_warning("append failed %s", (*err)->message);
            lineno = __LINE__;
            goto err;
#if 0
        } else {
            /* TODO: do we really need to emit here? */
            fBufEmit(exporter->activeWriter->fbuf, err);
#endif  /* 0 */
        }

        /* we have successfully written to the fbuf, get the bytes written */
        bytesWritten += fbExporterGetOctetCountAndReset(
            exporter->activeWriter->fbExporter);
        exporter->activeWriter->bytesWrittenSinceLastRotate += bytesWritten;

        /* if there was an invariant, store any changes back in that writer
         * and install the default one
         * otherwise, the active writer is still default so no work needed
         */
        if (exporter->invariant) {
            if (exporter->activeWriter->bytesWrittenSinceLastRotate >
                exporter->invState.maxFileSize)
            {
                /* rotate this file */
                /* do not need to count this FP, as one was closed and one
                 * was opened...net zero */
                mdIpfixFileRotate(exporter, cfg->ctime, err);
                exporter->activeWriter->bytesWrittenSinceLastRotate = 0;
            } else if ((cfg->ctime - exporter->activeWriter->lastRotate)
                       > exporter->invState.maxTimeMillisec)
            {
                /* rotate this file */
                /* do not need to count this FP, as one was closed and one
                 * was opened...net zero */
                mdIpfixFileRotate(exporter, cfg->ctime, err);
                exporter->activeWriter->bytesWrittenSinceLastRotate = 0;
            }

            INSTALL_DEFAULT_FILE_WRITER(exporter);
        }
    } else {
        /* TODO capture bytes written */
        ROTATE_IF_NEEDED(exporter, cfg->ctime, err);

        ret = mdCustomFlowPrint(exporter->customFieldList, flow, exporter, err);
        if (ret == 1) {
            return 0;
        }

        if (ret < 0) {
            lineno = __LINE__;
            goto err;
        } else if (ret == 0) {
            /* FIXME: REmove this block; with new GString output buffer, this
             * should never occur. */
            /* realloc bigger buffer and try again */
            if (!mdExporterExpandBuf(exporter)) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_MEM,
                            "Error allocating memory for exporter %s",
                            exporter->name);
                return -1;
            }
            ret = mdCustomFlowPrint(exporter->customFieldList, flow, exporter,
                                    err);
            if (ret < 0) {
                lineno = __LINE__;
                goto err;
            } else if (ret == 0) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                            "Error writing to buffer for exporter %s",
                            exporter->name);
                lineno = __LINE__;
                goto err;
            }
        }
    } /* TEXT type exporter */

    /* STAT EXP bytesWritten */
    exporter->expStats.bytesWritten += bytesWritten;

    return 1;

  err:
    if (err && !*err) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "FIX THE CODE!!! Function near %s:%d did not set GError",
                    __FILE__, lineno);
    }
    g_warning("Error writing flow: %s", (*err)->message);
    g_clear_error(err);
    g_warning("Deactivating Exporter %s.", exporter->name);
    exporter->active = FALSE;
    if (!mdExporterRestart(cfg, exporter, err)) {
        g_warning("Error restarting exporter %s: %s",
                  exporter->name, (*err)->message);
        g_clear_error(err);
    }
    return 1;
}

/**
 * mdExporterWriteDNSDedupRecord
 *
 * write a DNS de-duplicated record to the given exporter
 *
 * @param cfg - mediator configuration options
 * @param exporter - exporter to write to
 * @param mdRec - the record to write
 * @param err
 * @return TRUE if no errors
 */
gboolean
mdExporterWriteDNSDedupRecord(
    mdConfig_t      *cfg,
    mdExporter_t    *exporter,
    mdGenericRec_t  *mdRec,
    GError         **err)
{
    ssize_t  bytes = 0;
    gboolean print_last_seen = FALSE;
    int lineno = -1;

    /* DNS Dedup only goes to default writer which should be active */

    if (exporter == NULL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "Exporter Node Exists, but No Type");
        return FALSE;
    }

    if (!exporter->active) {
        if (cfg->ctime - exporter->last_restart_ms > MD_RESTART_MS) {
            if (!mdExporterRestart(cfg, exporter, err)) {
                g_message("Error restarting exporter %s: %s",
                          exporter->name, (*err)->message);
                g_clear_error(err);
                return TRUE;
            }
        } else {
            return TRUE;
        }
    }

    if (exporter->exportFormat == EF_IPFIX) {
        if (mdRec->generated) {
            fBufSetInternalTemplate(exporter->activeWriter->fbuf,
                                    mdRec->intTid, err);
            if (!fBufSetExportTemplate(exporter->activeWriter->fbuf,
                                       mdRec->extTid, err))
            {
                g_warning("couldn't set export template DNS DEDUP %#x %s",
                          mdRec->extTid,
                          (*err)->message);
            }
            if (!(fBufAppend(exporter->activeWriter->fbuf,
                             mdRec->fbRec->rec,
                             mdRec->fbRec->recsize,
                             err)))
            {
                g_warning("couldn't fbuf append generated dns dedup");

                lineno = __LINE__;
                goto err;
            }
            bytes = mdRec->fbRec->recsize;
        } else {
            if (!mdExporterSendIPFIXRecord(mdRec, exporter, err)) {
                lineno = __LINE__;
                goto err;
            }
            bytes = mdRec->fbRec->recsize;
        }
    } else {
        ROTATE_IF_NEEDED(exporter, cfg->ctime, err);

        if (exporter->json) {
            bytes = mdJsonifyDNSDedupRecord(exporter->activeWriter->lfp,
                                            exporter->buf, mdRec,
                                            print_last_seen,
                                            cfg->dns_base64_encode, err);
        } else {
            bytes = mdPrintDNSDedupRecord(exporter->activeWriter->lfp,
                                          exporter->buf,
                                          exporter->delimiter, mdRec,
                                          cfg->dns_base64_encode,
                                          print_last_seen,
                                          exporter->escape_chars, err);
        }

        if (bytes < 0) {
            lineno = __LINE__;
            goto err;
        } else if (bytes == 0) {
            /* realloc bigger buffer and try again */
            if (!mdExporterExpandBuf(exporter)) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_MEM,
                            "Error allocating memory for exporter %s",
                            exporter->name);
                return FALSE;
            }
            if (exporter->json) {
                bytes = mdJsonifyDNSDedupRecord(exporter->activeWriter->lfp,
                                                exporter->buf,
                                                mdRec, print_last_seen,
                                                cfg->dns_base64_encode, err);
            } else {
                bytes = mdPrintDNSDedupRecord(exporter->activeWriter->lfp,
                                              exporter->buf,
                                              exporter->delimiter, mdRec,
                                              cfg->dns_base64_encode,
                                              print_last_seen,
                                              exporter->escape_chars,
                                              err);
            }

            if (bytes < 0) {
                lineno = __LINE__;
                goto err;
            } else if (bytes == 0) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                            "Error writing to buffer for exporter %s",
                            exporter->name);
                lineno = __LINE__;
                goto err;
            }
        }
    }

    return TRUE;

  err:
    if (err && !*err) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "FIX THE CODE!!! Function near %s:%d did not set GError",
                    __FILE__, lineno);
    }
    g_warning("Error writing DNS Record: %s", (*err)->message);
    g_clear_error(err);
    g_warning("Deactivating Exporter %s.", exporter->name);
    exporter->active = FALSE;
    if (!mdExporterRestart(cfg, exporter, err)) {
        g_warning("Error restarting exporter %s: %s",
                  exporter->name, (*err)->message);
        g_clear_error(err);
    }

    return TRUE;
}


static void
mdHashSimpleFreeInv(
    gpointer   ptr)
{
    g_slice_free1(sizeof(invariants_t), ptr);
}

static void
mdHashFreeFileWriter(
    gpointer   ptr)
{
    mdFileWriter_t *fWriter     = (mdFileWriter_t *)ptr;
    fBuf_t         *thisFBuf    = fWriter->fbuf;
    GError         *err = NULL;

    if (thisFBuf) {
        /* make sure everything appended it written before we close */
        if (fBufGetExporter(thisFBuf)) {
            fBufEmit(thisFBuf, &err);
            fbExporterClose(fBufGetExporter(thisFBuf));
            fBufFree(fWriter->fbuf);
            fWriter->fbuf = NULL;
            fWriter->fbExporter = NULL;
            fWriter->session    = NULL;
        }

        if (fWriter->lfp) {
            mdCloseAndUnlock(fWriter->exporter, fWriter->lfp,
                             fWriter->currentFname,
                             NULL);
            fWriter->lfp = NULL;
        }
    }

    /* can ignore next and prev */
    g_free(fWriter->outspec);
    /*g_free(fWriter->currentFname);*/

    g_slice_free1(sizeof(mdFileWriter_t), fWriter);
}

/**
 * mdExportersInit
 *
 * cycle through exporters and open their output methods
 *
 */
gboolean
mdExportersInit(
    mdConfig_t    *cfg,
    mdExporter_t  *firstExp,
    GError       **err)
{
    mdExporter_t *exporter = NULL;
    uint16_t      numInvs = 0;

    if (NULL == firstExp) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Error: No Exporter Defined.\n");
        return FALSE;
    }

    for (exporter = firstExp; exporter; exporter = exporter->next) {
        if (exporter->invariant) {
            numInvs++;
        }
    }

    for (exporter = firstExp; exporter; exporter = exporter->next) {
        exporter->cfg = cfg;
        exporter->flattenSSLCerts = cfg->rewrite_ssl_certs;

        if (exporter->invariant) {
            /* inUseFPs is the number of file pointers assumed to be used by
             * the collectors, the other exporters, and the shared libraries
             * used by super_mediator */
            const long     inUseFPs = 20;
            struct rlimit  rlp;
            smHashTable_t *smht;

            smht = smCreateHashTable(sizeof(invariants_t),
                                     mdHashSimpleFreeInv,
                                     mdHashFreeFileWriter);
            exporter->invState.fileWritersTable = smht->table;
            g_slice_free(smHashTable_t, smht);

            if (0 != getrlimit(RLIMIT_NOFILE, &rlp)) {
                g_error("Unable to get max number file files: %s",
                        strerror(errno));
            }
            if ((long)rlp.rlim_cur <= numInvs + inUseFPs) {
                g_error("Max number of file files (%ld) is too low;"
                        " need at least %ld",
                        (long)rlp.rlim_cur, numInvs + inUseFPs);
            }
            exporter->invState.maxFPs = (rlp.rlim_cur - inUseFPs) / numInvs;
            if (exporter->invState.maxFPs < 1) {
                g_error("Computed less than 1 file pointer per exporter: %ld",
                        exporter->invState.maxFPs);
            }
            g_message("maxFP per exporter = %ld", exporter->invState.maxFPs);
        }

        INSTALL_DEFAULT_FILE_WRITER(exporter);

        if (EXPORTFORMAT_IS_TEXT_OR_JSON(exporter->exportFormat)) {
            if (!mdOpenTextOutput(exporter, err)) {
                return FALSE;
            }
        } else {
            /* this structure is OK */
            if (!mdIpfixOutputOpen(cfg, exporter, err)) {
                pthread_mutex_lock(&(cfg->log_mutex));
                g_warning("Error connecting to exporter: %s", (*err)->message);
                pthread_mutex_unlock(&(cfg->log_mutex));
                g_clear_error(err);
                exporter->active = FALSE;
                continue;
                /*return FALSE;*/
            }

            if (exporter->dedup) {
                /* dedup only deals with default writers */
                if (!md_dedup_add_templates(exporter->dedup,
                                            exporter->defaultWriter->fbuf,
                                            err))
                {
                    pthread_mutex_lock(&(cfg->log_mutex));
                    g_warning("Error adding dedup templates: %s",
                              (*err)->message);
                    pthread_mutex_unlock(&(cfg->log_mutex));
                    exporter->active = FALSE;
                    continue;
                }
            }

            /* just try to emit, there will be an error if not connected */
            if (!fBufEmit(exporter->activeWriter->fbuf, err)) {
                pthread_mutex_lock(&(cfg->log_mutex));
                g_warning("Error connecting to exporter: %s", (*err)->message);
                pthread_mutex_unlock(&(cfg->log_mutex));
                g_clear_error(err);
                exporter->active = FALSE;
                continue;
                /*return FALSE;*/
            }
        }

        pthread_mutex_lock(&(cfg->log_mutex));
        g_message("%s: Exporter Active.", exporter->name);
        pthread_mutex_unlock(&(cfg->log_mutex));
        exporter->active = TRUE;
    }

    return TRUE;
}

gboolean
mdExporterRestart(
    mdConfig_t    *cfg,
    mdExporter_t  *exporter,
    GError       **err)
{
    if (NULL == exporter) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Error: No Exporter Defined.\n");
        return FALSE;
    }

    exporter->last_restart_ms = cfg->ctime;

    exporter->expStats.restarts++;

    if (exporter->exportFormat == EF_TEXT) {
        if (!exporter->rotateInterval) {
            if (!mdOpenTextOutput(exporter, err)) {
                return FALSE;
            }
        } else {
            if ((cfg->ctime - exporter->activeWriter->lastRotate) >
                exporter->rotateInterval)
            {
                if (!mdTextFileRotate(exporter, cfg->ctime, err)) {
                    exporter->activeWriter->lastRotate = 0;
                    return FALSE;
                }
            }
        }
    } else {
        /* TODO...handle invariant */
        INSTALL_DEFAULT_FILE_WRITER(exporter);
        if (!mdIpfixOutputOpen(cfg, exporter, err)) {
            return FALSE;
        }
        if (!fBufEmit(exporter->defaultWriter->fbuf, err)) {
            return FALSE;
        }
    }

    /* TODO...update */
    g_debug("%s: Total Flows Exported Before Restart: %" PRIu64,
            exporter->name, exporter->expStats.recordsForwardedByType[TC_FLOW]);
    g_message("%s: Exporter successfully restarted. Now active.",
              exporter->name);
    /* reset counters */
    exporter->active = TRUE;
    exporter->last_restart_ms = 0;
    /* note that exporter was restarted */ // FIXME: Value never read
    //exporter->time_started = g_timer_elapsed(mdStatGetTimer(), NULL);
    return TRUE;
}

/*void mdLogExporterStats(
 *  mdConfig_t     *cfg,
 *  gboolean        dedup,
 *  md_stats_t     *expSummary)
 * {
 *  mdExporter_t *exporter = NULL;
 *  uint64_t         seconds = g_timer_elapsed(mdStatGetTimer(), NULL);
 *
 *  memset(expSummary, 0, sizeof(md_stats_t));
 *
 *  if (!seconds) seconds = 1;
 *
 *  for (exporter = cfg->firstExp; exporter; exporter = exporter->next) {
 *
 *
 *      if (exporter->dedup) {
 *          if (dedup) {
 *              md_dedup_print_stats(exporter->dedup, exporter->name);
 *          }
 *          continue;
 *      }
 *
 *      pthread_mutex_lock(&(cfg->log_mutex));
 *      if (exporter->exp_flows) {
 *          g_message("Exporter %s: %"PRIu64" records, %"PRIu64" stats, "
 *                    "%.4f Mbps, %.2f bytes per record",
 *                    exporter->name, exporter->exp_flows,
 *                    exporter->exp_stats,
 *                    ((((double)exporter->exp_bytes * 8.0) / 1000000) /
 *                     seconds),
 *                    ((double)exporter->exp_bytes / exporter->exp_flows));
 *      } else {
 *          g_message("Exporter %s: %"PRIu64" records, %"PRIu64" stats",
 *                    exporter->name, exporter->exp_flows,
 *                    exporter->exp_stats);
 *      }
 *      pthread_mutex_unlock(&(cfg->log_mutex));
 *
 *      if (exporter->dns_dedup && dedup) {
 *          md_dns_dedup_print_stats(exporter->dns_dedup, exporter->name);
 *      }
 *
 *  }
 * }*/

/**
 * mdExporterDestroy
 *
 * loop through exporter list and remove the exporters
 * flush the DNS close queue, and destroy tables
 *
 * Frees default writer, done writing, so no active writer
 *
 */
gboolean
mdExporterDestroy(
    mdContext_t  *ctx,
    GError      **err)
{
    mdExporter_t *exporter = NULL;
    int           loop;
    mdConfig_t   *cfg = ctx->cfg;

    mdStatLogExporters(ctx);

    while (cfg->firstExp) {
        detachHeadOfSLL((mdSLL_t **)&(cfg->firstExp), (mdSLL_t **)&exporter);

        if (exporter->invariant) {
            g_hash_table_destroy(exporter->invState.fileWritersTable);
        }

        if (exporter->dns_dedup) {
            md_dns_dedup_flush_all_tab(exporter->dns_dedup, cfg->ctime, TRUE);
            if (!md_dns_dedup_flush_queue(exporter, cfg, err)) {
                return FALSE;
            }
            /* print final stats */
            md_dns_dedup_print_stats(exporter->dns_dedup, exporter->name);
            if (!md_dns_dedup_free_state(cfg, exporter, err)) {
                return FALSE;
            }
        }

        if (exporter->dedup) {
            md_dedup_flush_alltab(exporter, cfg->ctime, TRUE);
            if (!md_dedup_flush_queue(exporter, cfg, err)) {
                return FALSE;
            }
            md_dedup_print_stats(exporter->dedup, exporter->name);
            if (!md_dedup_free_state(cfg, exporter, err)) {
                return FALSE;
            }
            if (exporter->exportFormat == EF_TEXT && !exporter->json) {
                /* otherwise it will be freed below */
                g_free(exporter->defaultWriter->outspec);
            }
        }

        if (exporter->ssl_dedup) {
            md_ssl_dedup_flush_tab(exporter->ssl_dedup, cfg->ctime, TRUE);
            if (!md_ssl_dedup_flush_queue(exporter, cfg, err)) {
                return FALSE;
            }
            md_ssl_dedup_print_stats(exporter->ssl_dedup, exporter->name);
            if (!md_ssl_dedup_free_state(cfg, exporter, err)) {
                return FALSE;
            }
        }

        if (exporter->defaultWriter->fbuf && exporter->active) {
            if (!mdOutputClose(exporter->defaultWriter->fbuf, TRUE, err)) {
                return FALSE;
            }
        }

        if (exporter->spec.host) {
            g_free(exporter->spec.host);
        }

        if (exporter->spec.svc) {
            g_free(exporter->spec.svc);
        }

        if (exporter->ssl_config) {
            for (loop = 0; loop <= MD_SSLCONFIG_TYPE_MAX; ++loop) {
                g_free(exporter->ssl_config->enabled[loop]);
            }
            g_slice_free(mdSSLConfig_t, exporter->ssl_config);
        }

        if (exporter->multi_files) {
            for (loop = 0; loop < num_tables; loop++) {
                if (table_info[loop]->table_file) {
                    mdCloseAndUnlock(exporter, table_info[loop]->table_file,
                                     table_info[loop]->file_name,
                                     table_info[loop]->table_name);
                    /*fclose(table_info[loop]->table_file);
                     * if (exporter->lock) {
                     *  mdUnlockFile(table_info[loop]->file_name);
                     * }
                     * if (exporter->mysql) {
                     *  mdLoadFile(exporter->exp, table_info[loop]->table_name,
                     *             table_info[loop]->file_name);
                     * }
                     * g_free(table_info[loop]->file_name);*/
                }
                g_free(table_info[loop]->table_name);
                g_slice_free(mdTableInfo_t, table_info[loop]);
            }

            if (table_info) {
                g_free(table_info);
                g_hash_table_destroy(table_hash);
                num_tables = 0;
            }

            g_free(exporter->defaultWriter->outspec);
        } else if (exporter->defaultWriter->lfp) {
            if (exporter->defaultWriter->currentFname) {
                mdCloseAndUnlock(exporter, exporter->defaultWriter->lfp,
                                 exporter->defaultWriter->currentFname, NULL);
                if (exporter->defaultWriter->outspec) {
                    g_free(exporter->defaultWriter->outspec);
                }
            } else {
                mdCloseAndUnlock(exporter, exporter->defaultWriter->lfp,
                                 exporter->defaultWriter->outspec, NULL);
            }
        }

        mdExporterFreeCustomList(exporter);

        if (exporter->mysql) {
            g_free(exporter->mysql->user);
            g_free(exporter->mysql->password);
            g_free(exporter->mysql->db_name);
            g_free(exporter->mysql->db_host);
            g_free(exporter->mysql->table);
#ifdef HAVE_MYSQL
            if (exporter->mysql->conn) {
                mysql_close(exporter->mysql->conn);
            }
#endif
            g_slice_free(mdMySQLInfo_t, exporter->mysql);
        }

        /* free exporter name */
        g_free((char *)exporter->name);
        exporter->name = NULL;

        if (EXPORTFORMAT_IS_TEXT_OR_JSON(exporter->exportFormat)) {
            g_string_free(exporter->buf, TRUE);
            //g_slice_free1(exporter->buf->buflen, exporter->buf->buf);
            //g_slice_free(mdBuf_t, exporter->buf);
            fbSessionFree(exporter->defaultWriter->session);
        }

        mdFilterDestroy(exporter->filter);

        if (exporter->defaultWriter) {
            g_slice_free(mdFileWriter_t, exporter->defaultWriter);
            exporter->defaultWriter = NULL;
        }

        mdExporterFree(exporter);
    }

    return TRUE;
}


/**
 * mdExporterConnectionReset
 *
 * when a connection is reset via TCP, flush the DNS tables
 * and buffer so we don't hang on to records too long.
 * this also gets called every 5 minutes if we're not receiving
 * anything
 *
 */
gboolean
mdExporterConnectionReset(
    mdConfig_t  *cfg,
    GError     **err)
{
    mdExporter_t *exporter = NULL;

    for (exporter = cfg->firstExp; exporter; exporter = exporter->next) {
        if (!exporter->active) {
            continue;
        }

        INSTALL_DEFAULT_FILE_WRITER(exporter);

        if (exporter->dns_dedup) {
            md_dns_dedup_flush_all_tab(exporter->dns_dedup, cfg->ctime, FALSE);
            if (!md_dns_dedup_flush_queue(exporter, cfg, err)) {
                return FALSE;
            }
        }

        if (exporter->dedup) {
            md_dedup_flush_alltab(exporter, cfg->ctime, FALSE);
            if (!md_dedup_flush_queue(exporter, cfg, err)) {
                return FALSE;
            }
        }

        if (exporter->ssl_dedup) {
            md_ssl_dedup_flush_tab(exporter->ssl_dedup, cfg->ctime, FALSE);
            if (!md_ssl_dedup_flush_queue(exporter, cfg, err)) {
                return FALSE;
            }
        }

        if (exporter->exportFormat == EF_IPFIX) {
            /* TODO...fix me when type and format are sane */
            if (!fBufEmit(exporter->activeWriter->fbuf, err)) {
                pthread_mutex_lock(&(cfg->log_mutex));
                g_warning("Error emitting buffer: %s", (*err)->message);
                g_warning("Deactivating Exporter %s.", exporter->name);
                pthread_mutex_unlock(&(cfg->log_mutex));
                exporter->active = FALSE;
                g_clear_error(err);
            }

            if (exporter->rotateInterval) {
                if (exporter->activeWriter->lastRotate == 0) {
                    exporter->activeWriter->lastRotate = cfg->ctime;
                } else if ((cfg->ctime - exporter->activeWriter->lastRotate) >
                           exporter->rotateInterval)
                {
                    if (!mdIpfixFileRotate(exporter, cfg->ctime, err)) {
                        pthread_mutex_lock(&(cfg->log_mutex));
                        g_warning("Error rotating file: %s", (*err)->message);
                        g_warning("Deactivating Exporter %s.", exporter->name);
                        pthread_mutex_unlock(&(cfg->log_mutex));
                        exporter->active = FALSE;
                        g_clear_error(err);
                    }
                }
            }
        }

        /* flush out whatever is in the file pointer, no matter the type
         * of file */
        if (exporter->activeWriter->lfp) {
            fflush(exporter->activeWriter->lfp);
        }

        if (EXPORTFORMAT_IS_TEXT_OR_JSON(exporter->exportFormat)) {
            if (exporter->rotateInterval) {
                if ((cfg->ctime - exporter->activeWriter->lastRotate) >
                    exporter->rotateInterval)
                {
                    if (!mdTextFileRotate(exporter, cfg->ctime, err)) {
                        exporter->activeWriter->lastRotate = 0;
                        pthread_mutex_lock(&(cfg->log_mutex));
                        g_warning("Error rotating file: %s", (*err)->message);
                        g_warning("Deactivating Exporter %s.", exporter->name);
                        pthread_mutex_unlock(&(cfg->log_mutex));
                        exporter->active = FALSE;
                        g_clear_error(err);
                    }
                }
            }
        }
    }

    return TRUE;
}


/**
 * mdCustomFlowPrint
 *
 *
 */
int
mdCustomFlowPrint(
    mdFieldEntry_t  *list,
    mdFullFlow_t    *flow,
    mdExporter_t    *exporter,
    GError         **err)
{
    mdFieldEntry_t *fLNode = NULL;
    GString        *buf = exporter->buf;
    size_t          rc = 0;
    int             dpi_ret = 0;
    GString        *dpiPrefixString = g_string_new(NULL);

    /* FIXME: In TEXT mode, the fields of the flow record include a delimiter
     * after the last field; that is inconsistent with SM-v1.x and it does not
     * match the PRINT_HEADER line */

    if (!exporter->no_index && exporter->flowDpiRequired) {
        if (!exporter->json) {
            g_string_append_printf(buf, "flow%c%u%c", exporter->delimiter,
                                   *(flow->flowKeyHash), exporter->delimiter);
        }
        g_string_append_printf(dpiPrefixString, "%u%c%" PRIu64 "%c%d%c",
                               *(flow->flowKeyHash), exporter->delimiter,
                               flow->flowStartMilliseconds,
                               exporter->delimiter,
                               *(flow->observationDomain),
                               exporter->delimiter);
    }

    if (exporter->json) {
        g_string_append(buf, "{\"flows\":{");
    }

    for (fLNode = list; fLNode; fLNode = fLNode->next) {
        mdPrintFieldEntry(flow, exporter, buf, fLNode, exporter->json);
        rc++;
    }
    if (!exporter->json && !exporter->multi_files &&
        !(exporter->no_index && exporter->flowDpiRequired))
    {
        g_string_append_c(buf, '\n');
    }

    if (exporter->multi_files) {
        FILE *fp = mdGetTableFile(exporter, "flow");
        if (fp == NULL) {
            g_warning("Error retrieving file for flow records");
            g_string_free(dpiPrefixString, TRUE);
            return TRUE;
        }
        rc = md_util_write_buffer(fp, buf, exporter->name, err);
        if (!rc) {
            g_warning("Error writing flow records");
            g_string_free(dpiPrefixString, TRUE);
            return FALSE;
        }
    }

    /* TODO: This print could be brought back inside mdExporterDPIFlowPrint
             if a bit more logic is implemented regarding when DPI exists
             and if the trailing comma from above is removed when it doesn't */
    if (exporter->json) {
        g_string_append(buf, "\"dpi\": [");
    }
    if (!exporter->flowDpiStrip) {
        if (exporter->no_index && exporter->flowDpiRequired) {
            /* assume buf contains no embedded nuls */
            g_string_assign(dpiPrefixString, buf->str);
            g_string_truncate(buf, 0);
        }

        if (exporter->flattenSSLCerts && flow->silkAppLabel == 443)
        {
            /* export a record where the SSL certificates list has
             * been flattened */
            dpi_ret = mdExporterFlattenAndWriteSslCerts(
                exporter, flow, dpiPrefixString, err);
        } else {
            dpi_ret = mdExporterDPIFlowPrint(
                exporter, flow, dpiPrefixString, err);
        }
    }
    if (exporter->json) {
        g_string_append(buf, "]}}\n");
    }

    if (!exporter->flowDpiRequired || dpi_ret > 0) {
        rc = md_util_write_buffer(exporter->activeWriter->lfp, buf,
                                  exporter->name, err);
    }

    g_string_free(dpiPrefixString, TRUE);

    g_string_truncate(buf, 0);
    if (!rc) {
        return -1;
    }

    return rc;
}


#if 0
/**
 * mdExportFlowStats
 *
 */
static gboolean
mdExportFlowStats(
    mdExporter_t     *exporter,
    md_text_stats_t  *stats,
    const char       *index_str,
    size_t            index_len,
    const char       *label,
    uint8_t           rev)
{
    char     delim = exporter->delimiter;
    GString *buf = exporter->buf;
    size_t   bufstart = buf->len;
    GError  *err = NULL;

    if (!exporter->flowStatsAllowedInTextExporters) {
        return TRUE;
    }

    if (!exporter->no_index) {
        g_string_append_printf(buf, "%s%c", label, delim);
    }

    g_string_append_len(buf, index_str, index_len);

    g_string_append_printf(buf, "%u%c%u%c%u%c%" PRIu64,
                           stats->tcpUrgTotalCount, delim,
                           stats->smallPacketCount, delim,
                           stats->nonEmptyPacketCount, delim,
                           stats->dataByteCount);
    g_string_append_printf(buf, "%c%" PRIu64 "%c%d%c%d%c%d%c", delim,
                           stats->averageInterarrivalTime, delim,
                           stats->firstNonEmptyPacketSize, delim,
                           stats->largePacketCount, delim,
                           stats->maxPacketSize, delim);
    g_string_append_printf(buf, "%02x%c%d%c%" PRIu64 "%c",
                           stats->firstEightNonEmptyPacketDirections, delim,
                           stats->standardDeviationPayloadLength, delim,
                           stats->standardDeviationInterarrivalTime, delim);
    if (stats->nonEmptyPacketCount) {
        g_string_append_printf(buf, "%" PRIu64 "%c",
                       stats->dataByteCount / stats->nonEmptyPacketCount,
                       delim);
    } else {
        g_string_append_c(buf, '0');
        g_string_append_c(buf, delim);
    }

    if (rev) {
        g_string_append_printf(buf, "%u%c%u%c%u%c%" PRIu64,
                       stats->reverseTcpUrgTotalCount, delim,
                       stats->reverseSmallPacketCount, delim,
                       stats->reverseNonEmptyPacketCount, delim,
                       stats->reverseDataByteCount);
        g_string_append_printf(buf, "%c%" PRIu64 "%c%d%c%d%c%d%c", delim,
                       stats->reverseAverageInterarrivalTime, delim,
                       stats->reverseFirstNonEmptyPacketSize, delim,
                       stats->reverseLargePacketCount, delim,
                       stats->reverseMaxPacketSize, delim);
        g_string_append_printf(buf, "%d%c%" PRIu64 "%c",
                       stats->reverseStandardDeviationPayloadLength,
                       delim,
                       stats->reverseStandardDeviationInterarrivalTime,
                       delim);
        if (stats->reverseNonEmptyPacketCount) {
            g_string_append_printf(buf, "%" PRIu64,
                           stats->reverseDataByteCount /
                           stats->reverseNonEmptyPacketCount);
        } else {
            g_string_append_c(buf, '0');
        }
    } else {
        g_string_append_printf(buf, "0%c0%c0%c0%c0%c0%c0%c0%c0%c0%c0%c0",
                       delim, delim, delim, delim, delim, delim, delim,
                       delim, delim, delim, delim);
    }

    g_string_append_c(buf, '\n');

    if (exporter->multi_files) {
        FILE  *fp = mdGetTableFile(exporter, "stats");
        size_t rc;
        if (fp == NULL) {
            g_string_truncate(buf, bufstart);
            return TRUE;
        }

        rc = md_util_write_buffer(fp, buf, exporter->name, &err);

        if (!rc) {
            g_warning("Error writing file for flowstats: %s",
                      err->message);
            g_clear_error(&err);
            return FALSE;
        }

/*        exporter->exp_bytes += rc;*/
    }

    return TRUE;
}
#endif  /* 0 */

#if 0
static gboolean
mdJsonizeFlowStats(
    mdExporter_t     *exporter,
    md_text_stats_t  *stats,
    char             *index_str,
    size_t            index_len,
    uint8_t           rev)
{
    GString *buf = exporter->buf;

    if (!exporter->flowStatsAllowedInTextExporters) {
        return TRUE;
    }

    if (exporter->no_index) {
        g_string_append_len(buf, index_str, index_len);
    }

    g_string_append_printf(buf, "\"tcpUrgTotalCount\":%u,",
                   stats->tcpUrgTotalCount);
    g_string_append_printf(buf, "\"smallPacketCount\":%u,",
                   stats->smallPacketCount);
    g_string_append_printf(buf, "\"nonEmptyPacketCount\":%u,",
                   stats->nonEmptyPacketCount);
    g_string_append_printf(buf, "\"dataByteCount\":%" PRIu64 ",",
                   stats->dataByteCount);
    g_string_append_printf(buf, "\"averageInterarrivalTime\":%" PRIu64 ",",
                   stats->averageInterarrivalTime);
    g_string_append_printf(buf, "\"firstNonEmptyPacketSize\":%d,",
                   stats->firstNonEmptyPacketSize);
    g_string_append_printf(buf, "\"largePacketCount\":%d,",
                   stats->largePacketCount);
    g_string_append_printf(buf, "\"maxPacketSize\":%d,",
                   stats->maxPacketSize);
    g_string_append_printf(
        buf, "\"firstEightNonEmptyPacketDirections\":\"%02x\",",
        stats->firstEightNonEmptyPacketDirections);
    g_string_append_printf(buf, "\"standardDeviationPayloadLength\":%u,",
                           stats->standardDeviationPayloadLength);
    g_string_append_printf(
        buf, "\"standardDeviationInterarrivalTime\":%" PRIu64 ",",
        stats->standardDeviationInterarrivalTime);

    if (stats->nonEmptyPacketCount) {
        g_string_append_printf(buf, "\"bytesPerPacket\":%" PRIu64 ",",
                               stats->dataByteCount /
                               stats->nonEmptyPacketCount);
        }

    if (rev) {
        g_string_append_printf(buf, "\"reverseTcpUrgTotalCount\":%u,",
                               stats->reverseTcpUrgTotalCount);
        g_string_append_printf(buf, "\"reverseSmallPacketCount\":%u,",
                               stats->reverseSmallPacketCount);
        g_string_append_printf(buf, "\"reverseNonEmptyPacketCount\":%u,",
                               stats->reverseNonEmptyPacketCount);
        g_string_append_printf(buf, "\"reverseDataByteCount\":%" PRIu64 ",",
                               stats->reverseDataByteCount);
        g_string_append_printf(
            buf, "\"reverseAverageInterarrivalTime\":%" PRIu64 ",",
            stats->reverseAverageInterarrivalTime);
        g_string_append_printf(buf, "\"reverseFirstNonEmptyPacketSize\":%d,",
                               stats->reverseFirstNonEmptyPacketSize);
        g_string_append_printf(buf, "\"reverseLargePacketCount\":%d,",
                               stats->reverseLargePacketCount);
        g_string_append_printf(buf, "\"reverseMaxPacketSize\":%d,",
                               stats->reverseMaxPacketSize);
        g_string_append_printf(
            buf, "\"reverseStandardDeviationPayloadLength\":%u,",
            stats->reverseStandardDeviationPayloadLength);
        g_string_append_printf(
            buf, "\"reverseStandardDeviationInterarrivalTime\":%" PRIu64 ",",
            stats->reverseStandardDeviationInterarrivalTime);

        if (stats->reverseNonEmptyPacketCount) {
            g_string_append_printf(
                buf, "\"reverseBytesPerPacket\":%" PRIu64 ",",
                stats->reverseDataByteCount /
                stats->reverseNonEmptyPacketCount);
        }
    }
    return TRUE;
}
#endif  /* 0 */

#if 0
/**
 * mdJsonizeVLElement
 *
 *  Writes the name and value of a CERT info element to 'exporter'.  The
 *  element's ID is 'id' and its value is in 'buf' having length is 'buflen'.
 *  If the type of the IE indicates it is a number, it is printed without
 *  quotation marks.  When 'hex' is TRUE, the value is printed as a string of
 *  hexadecimal values.
 */
gboolean
mdJsonizeVLElement(
    mdExporter_t  *exporter,
    uint8_t       *buf,
    char          *label,
    char          *index_str,
    size_t         index_len,
    uint16_t       id,
    size_t         buflen,
    gboolean       hex)
{
    const fbInfoElement_t *ie = NULL;
    GString *mdbuf = exporter->buf;

    /* unused */
    MD_UNUSED_PARAM(label);
    MD_UNUSED_PARAM(index_str);
    MD_UNUSED_PARAM(index_len);

    if (exporter->dpi_field_table) {
        if (!mdGetDPIItem(exporter->dpi_field_table, id)) {
            return TRUE;
        }
    }

    /* Get the IE name from fixbuf */

    ie = fbInfoModelGetElementByID(exporter->infoModel, id, CERT_PEN);

    if (ie->type != 0 && ie->type < 11) {
        /* use fixbuf 1.4 to get type information, and if integer, don't quote
         * the value: (0 is octet array, 1-10 are integers, floats) */
        g_string_append_printf(mdbuf, "\"%s\":", ie->name);

        if (!mdPrintVariableLength(mdbuf, buf, buflen, '"', hex,
                                   exporter->escape_chars, TRUE))
        {
            return FALSE;
        }
    } else {
        /* quote because it's an octet array, string, or other */

        g_string_append_printf(mdbuf, "\"%s\":\"", ie->name);
        if (hex) {
            md_util_hexdump_append(mdbuf, buf, buflen);
        } else {
            mdJsonifyEscapeCharsGStringAppend(mdbuf, buf, buflen);
        }
        g_string_append_c(mdbuf, '\"');
    }

    g_string_append_c(mdbuf, ',');

    return TRUE;
}
#endif  /* 0 */

static int
mdExporterSSLCertHash(
    mdExporter_t  *exporter,
    fbVarfield_t  *ct,
    const GString *index_str,
    int            cert_no)
{
#ifdef HAVE_OPENSSL
    GString      *buf = exporter->buf;
    char          delim = exporter->dpi_delimiter;
    unsigned char digest[EVP_MAX_MD_SIZE] = "";
    unsigned int  len = 0;

    if (exporter->json) {
        /* remove '},' */
        g_string_truncate(buf, buf->len - 2);
        //buf->cp -= 2;
        //brem += 2;
        if (exporter->hash_md5 ||
            mdExporterCheckSSLConfig(exporter, 299, MD_SSLCONFIG_OTHER))
        {
            smCertDigestCompute(ct->buf, ct->len, digest, &len, SM_DIGEST_MD5);
            g_string_append(buf, ",\"sslCertificateMD5\":\"");
            md_util_hexdump_append_nospace(buf, digest, len);
            g_string_append_c(buf, '"');
        }
        if (exporter->hash_sha1 ||
            mdExporterCheckSSLConfig(exporter, 298, MD_SSLCONFIG_OTHER))
        {
            smCertDigestCompute(ct->buf, ct->len, digest, &len, SM_DIGEST_SHA1);
            g_string_append(buf, ",\"sslCertificateSHA1\":\"");
            md_util_hexdump_append_nospace(buf, digest, len);
            g_string_append_c(buf, '"');
        }

        g_string_append(buf, "},");
    } else {
        GString *ssl_buffer = g_string_sized_new(256);

        if (exporter->hash_md5 ||
            mdExporterCheckSSLConfig(exporter, 299, MD_SSLCONFIG_OTHER))
        {
            smCertDigestCompute(ct->buf, ct->len, digest, &len, SM_DIGEST_MD5);
            g_string_printf(ssl_buffer, "I%c%d%c",
                            delim, cert_no, delim);
            md_util_hexdump_append(ssl_buffer, digest, len);
            exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer->str,
                                 SSL_DEFAULT, index_str->str, index_str->len,
                                 299, ssl_buffer->len, FALSE);
        }
        if (exporter->hash_sha1 ||
            mdExporterCheckSSLConfig(exporter, 298, MD_SSLCONFIG_OTHER))
        {
            smCertDigestCompute(ct->buf, ct->len, digest, &len, SM_DIGEST_SHA1);
            g_string_printf(ssl_buffer, "I%c%d%c",
                            delim, cert_no, delim);
            md_util_hexdump_append(ssl_buffer, digest, len);
            exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer->str,
                                 SSL_DEFAULT, index_str->str, index_str->len,
                                 298, ssl_buffer->len, FALSE);
        }
        g_string_free(ssl_buffer, TRUE);
    }

#endif /* HAVE_OPENSSL */

    return 1;
}

/**
 * mdExporterSSLBase64Encode
 *
 */
static gboolean
mdExporterSSLBase64Encode(
    mdExporter_t  *exporter,
    fbVarfield_t  *ct,
    const GString *index_str,
    int            cert_no)
{
    GString *ssl_buffer = g_string_sized_new(256);
    char   delim = exporter->dpi_delimiter;
    gchar *base1;

    base1 = g_base64_encode((const guchar *)ct->buf, ct->len);

    g_string_append_printf(ssl_buffer, "I%c%d%c%s",
                           delim, cert_no, delim, base1);
    exporter->VLprint_fn(exporter, (uint8_t *)ssl_buffer->str,
                         SSL_DEFAULT, index_str->str, index_str->len, 296,
                         ssl_buffer->len, FALSE);
    g_free(base1);
    g_string_free(ssl_buffer, TRUE);

    return TRUE;
}



static gboolean
isDPIv2(
    uint16_t   tid)
{
    return (((tid & 0xFF00) >= 0xC200) && ((tid & 0xFF00) <= 0xCF00));
}

/**
 * mdExporterDPIFlowPrint
 *
 * writes all the DPI data to the given FILE.
 *
 */
int
mdExporterDPIFlowPrint(
    mdExporter_t  *exporter,
    mdFullFlow_t  *flow,
    const GString *prefixString,
    GError       **err)
{
    GString   *buf = exporter->buf;
    size_t     bufstart = buf->len;
    char       delim = exporter->dpi_delimiter;
    fbRecord_t subrec;
    fbSubTemplateList_t *tempSTL = NULL;
    fbSubTemplateMultiListEntry_t *tempSTMLE = NULL;
    gboolean   first = TRUE;

    MD_UNUSED_PARAM(err);

    /* Get DPI template*/
    if (!flow->dpiListPtr) {
        return -1;
    }

    if (flow->intTmplCtx->defCtx.templateContents.yafVersion ==
        TC_YAF_VERSION_3)
    {
        tempSTL = (fbSubTemplateList_t *)(flow->dpiListPtr);
        subrec.rec = fbSubTemplateListGetDataPtr(tempSTL);
        subrec.tmpl = fbSubTemplateListGetTemplate(tempSTL);
        subrec.tid = fbSubTemplateListGetTemplateID(tempSTL);
        subrec.recsize = subrec.reccapacity = fbTemplateGetIELenOfMemBuffer(
            subrec.tmpl);
    } else if (flow->intTmplCtx->defCtx.templateContents.yafVersion ==
               TC_YAF_VERSION_2)
    {
        tempSTMLE = fbSubTemplateMultiListGetFirstEntry(
            (fbSubTemplateMultiList_t *)(flow->dpiListPtr));
        while (tempSTMLE && !isDPIv2(fbSubTemplateMultiListEntryGetTemplateID(
                                         tempSTMLE)))
        {
            tempSTMLE = fbSubTemplateMultiListGetNextEntry(
                (fbSubTemplateMultiList_t *)(flow->dpiListPtr),
                tempSTMLE);
        }
        if (tempSTMLE) {
            subrec.rec = fbSubTemplateMultiListEntryGetDataPtr(tempSTMLE);
            subrec.tmpl = fbSubTemplateMultiListEntryGetTemplate(tempSTMLE);
            subrec.tid = fbSubTemplateMultiListEntryGetTemplateID(tempSTMLE);
            subrec.recsize = subrec.reccapacity = fbTemplateGetIELenOfMemBuffer(
                subrec.tmpl);
        } else {
            return -1;
        }
    } else {
        return -1;
    }

    while (subrec.rec != NULL) {
        /* TODO: Will not do p0f, dhcp, or fullcert */

        if (exporter->json) {
            if (!first) {
                g_string_append_c(buf, ',');
            } else {
                first = FALSE;
            }

            g_string_append_c(buf, '{');
        }

        if (exporter->json) {
            mdPrintDPIRecord(exporter, &subrec, prefixString, buf, delim,
                             exporter->escape_chars, exporter->json);
        } else {
            /* Special cases for DNS and SSL because they are a pain. */
            if (subrec.tid == YAF_NEWSSL_TID) {
                /* TODO: proper prefix string */
                if (!mdExporterTextNewSSLPrint(exporter, &subrec,
                                               prefixString))
                {
                    return -1;
                }
            } else if (subrec.tid == YAF_DNSQR_TID) {
                mdExporterTextDNSPrint(exporter, (yafDnsQR_t *)(subrec.rec),
                                       prefixString);
            } else {
                mdPrintDPIRecord(exporter, &subrec, prefixString, buf,
                                 delim, exporter->escape_chars, exporter->json);
            }
        }

        if (flow->intTmplCtx->defCtx.templateContents.yafVersion ==
            TC_YAF_VERSION_3)
        {
            subrec.rec = fbSTLNext(uint8_t, tempSTL, subrec.rec);
        } else if (flow->intTmplCtx->defCtx.templateContents.yafVersion ==
                   TC_YAF_VERSION_2)
        {
            subrec.rec = fbSTMLEntryNext(uint8_t, tempSTMLE, subrec.rec);
        } else {
            return -1;
        }

        if (exporter->json) {
            g_string_append_c(buf, '}');
        }
    }

    if (exporter->multi_files) {
        return -1;
    }

    // Return the number of characters added to the buffer
    return ((buf->len <= bufstart) ? 0 : (buf->len - bufstart));
}

/**
 * mdExporterTextDNSPrint
 *
 * Returns DNS elements from DPI suitable for text output
 *
 */
gboolean
mdExporterTextDNSPrint(
    mdExporter_t      *exporter,
    const yafDnsQR_t  *dns,
    const GString     *prefixString)
{
    char     delim = exporter->dpi_delimiter;
    GString *buf = exporter->buf;
    uint16_t uid;

    uid = dns->dnsRRType > 51 ? 53 : dns->dnsRRType;

    if (exporter->dns_resp_only) {
        if (dns->dnsQueryResponse == 0) {return FALSE;}
    }

    if (exporter->dpi_field_table) {
        if (!mdGetDPIItem(exporter->dpi_field_table, uid)) {
            return FALSE;
        }
    }

    g_string_append_printf(buf, "%s%c%s%c",
                           prefixString->str, delim,
                           DNS_DEFAULT, delim);
    g_string_append_printf(buf, "%c%c%d%c%d%c",
                           ((dns->dnsQueryResponse) ? 'R' : 'Q'), delim,
                           dns->dnsId, delim,
                           dns->dnsSection, delim);
    g_string_append_printf(buf, "%d%c%d%c",
                           dns->dnsResponseCode, delim,
                           ((dns->dnsAuthoritative) ? 1 : 0), delim);
    g_string_append_printf(buf, "%d%c%u%c",
                           dns->dnsRRType, delim,
                           dns->dnsTTL, delim);

    if (dns->dnsName.buf) {
        if (!md_util_append_varfield(buf, &(dns->dnsName))) {
            return FALSE;
        }
    } /* else - query may be for the root server which is NULL*/

    if (dns->dnsQueryResponse == 0) {
        g_string_append_printf(buf, "%c\n", delim);
        return TRUE;
    }

    g_string_append_c(buf, delim);

    switch (dns->dnsRRType) {
      case 1:
        {
            const yaf_dnsA_t *a = NULL;
            char        ipaddr[20];
            while ((a = fbSTLNext(yaf_dnsA_t, &(dns->dnsRRList), a))) {
                if (a->dnsA) {
                    md_util_print_ip4_addr(ipaddr, a->dnsA);
                    g_string_append_printf(buf, "%s", ipaddr);
                }
            }
            g_string_append_c(buf, '\n');
            break;
        }
      case 2:
        {
            const yaf_dnsNS_t *ns = NULL;
            while ((ns = fbSTLNext(yaf_dnsNS_t, &(dns->dnsRRList), ns))) {
                mdPrintVariableLength(buf, ns->dnsNSDName.buf,
                                      ns->dnsNSDName.len, delim, 0,
                                      exporter->escape_chars, FALSE);
            }
            g_string_append_c(buf, '\n');
            break;
        }
      case 5:
        {
            const yaf_dnsCNAME_t *c = NULL;
            while ((c = fbSTLNext(yaf_dnsCNAME_t, &(dns->dnsRRList), c))) {
                mdPrintVariableLength(buf, c->dnsCNAME.buf,
                                      c->dnsCNAME.len, delim, 0,
                                      exporter->escape_chars, FALSE);
            }
            g_string_append_c(buf, '\n');
            break;
        }
      case 6:
        {
            const yaf_dnsSOA_t *soa = NULL;
            while ((soa = fbSTLNext(yaf_dnsSOA_t, &(dns->dnsRRList), soa))) {
                mdPrintVariableLength(buf, soa->dnsSOAMName.buf,
                                      soa->dnsSOAMName.len, delim, 0,
                                      exporter->escape_chars, FALSE);
                /*g_string_append_len(str, soa->rname.buf,
                 * soa->rname.len);
                 * g_string_append_printf(str,
                 * "%u%c%u%c%u%c%u%c%u",
                 * soa->serial, delim,
                 * soa->refresh, delim,
                 * soa->retry, delim,
                 * soa->expire, delim,
                 * soa->minimum);*/
            }
            g_string_append_c(buf, '\n');
            break;
        }
      case 12:
        {
            const yaf_dnsPTR_t *ptr = NULL;
            while ((ptr = fbSTLNext(yaf_dnsPTR_t, &(dns->dnsRRList), ptr))) {
                mdPrintVariableLength(buf, ptr->dnsPTRDName.buf,
                                      ptr->dnsPTRDName.len, delim, 0,
                                      exporter->escape_chars, FALSE);
            }
            g_string_append_c(buf, '\n');
            break;
        }
      case 15:
        {
            const yaf_dnsMX_t *mx = NULL;
            while ((mx = fbSTLNext(yaf_dnsMX_t, &(dns->dnsRRList), mx))) {
                mdPrintVariableLength(buf, mx->dnsMXExchange.buf,
                                      mx->dnsMXExchange.len, delim, 0,
                                      exporter->escape_chars, FALSE);
            }
            g_string_append_c(buf, '\n');
            break;
        }
      case 16:
        {
            const yaf_dnsTXT_t *txt = NULL;
            while ((txt = fbSTLNext(yaf_dnsTXT_t, &(dns->dnsRRList), txt))) {
                mdPrintVariableLength(buf, txt->dnsTXTData.buf,
                                      txt->dnsTXTData.len, delim, 0,
                                      exporter->escape_chars, FALSE);
            }
            g_string_append_c(buf, '\n');
            break;
        }
      case 28:
        {
            const yaf_dnsAAAA_t *aa = NULL;
            char           ipaddr[40];
            while ((aa = fbSTLNext(yaf_dnsAAAA_t, &(dns->dnsRRList), aa))) {
                md_util_print_ip6_addr(ipaddr, (uint8_t *)&(aa->dnsAAAA));
                g_string_append_printf(buf, "%s", ipaddr);
            }
            g_string_append_c(buf, '\n');
            break;
        }
      case 33:
        {
            const yaf_dnsSRV_t *srv = NULL;
            while ((srv = fbSTLNext(yaf_dnsSRV_t, &(dns->dnsRRList), srv))) {
                mdPrintVariableLength(buf, srv->dnsSRVTarget.buf,
                                      srv->dnsSRVTarget.len, delim, 0,
                                      exporter->escape_chars, FALSE);

                /*g_string_append_printf(str, "%c%d%c%d%c%d",
                 * delim, srv->dnsPriority,
                 * delim, srv->dnsWeight,
                 * delim, srv->dnsPort);*/
            }
            g_string_append_c(buf, '\n');
            break;
        }
      case 46:
        {
            const yaf_dnsRRSig_t *rr = NULL;
            while ((rr = fbSTLNext(yaf_dnsRRSig_t, &(dns->dnsRRList), rr))) {
                mdPrintVariableLength(buf, rr->dnsRRSIGSigner.buf,
                                      rr->dnsRRSIGSigner.len, delim, 0,
                                      exporter->escape_chars, FALSE);
            }
            g_string_append_c(buf, '\n');
            break;
        }
      case 47:
        {
            const yaf_dnsNSEC_t *nsec = NULL;
            while ((nsec = fbSTLNext(yaf_dnsNSEC_t, &(dns->dnsRRList),
                                                      nsec)))
            {
                mdPrintVariableLength(buf,
                                      nsec->dnsNSECNextDomainName.buf,
                                      nsec->dnsNSECNextDomainName.len, delim, 0,
                                      exporter->escape_chars, FALSE);
            }
            g_string_append_c(buf, '\n');
            break;
        }
      default:
        g_string_append_c(buf, '\n');
    }

    return TRUE;
}



gboolean
mdExporterWriteDNSRRRecord(
    mdConfig_t      *cfg,
    mdExporter_t    *exporter,
    mdGenericRec_t  *mdRec,
    GError         **err)
{
    static gboolean dns_rr_no_text_seen = FALSE;
    size_t bytes;
    int lineno = -1;

    g_assert(exporter);

    /* DNS RR records go out default writer which should be active */

    if (!exporter->allowDnsRR || exporter->multi_files) {
        return TRUE;
    }

    if (!exporter->active) {
        if (cfg->ctime - exporter->last_restart_ms > MD_RESTART_MS) {
            if (!mdExporterRestart(cfg, exporter, err)) {
                g_message("Error restarting exporter %s: %s",
                          exporter->name, (*err)->message);
                g_clear_error(err);
                return TRUE;
            }
        } else {
            return TRUE;
        }
    }

    if (exporter->exportFormat == EF_IPFIX) {
        if (mdRec->generated) {
            fBufSetInternalTemplate(exporter->activeWriter->fbuf,
                                    mdRec->intTid, err);
            if (!fBufSetExportTemplate(exporter->activeWriter->fbuf,
                                       mdRec->extTid, err))
            {
                g_warning("couldn't set export template generated DNS RR %#x %s",
                          mdRec->extTid,
                          (*err)->message);
            }

            if (!(fBufAppend(exporter->activeWriter->fbuf,
                             mdRec->fbRec->rec,
                             mdRec->fbRec->recsize,
                             err)))
            {
                g_warning("couldn't fbuf append generated dns rr");
                lineno = __LINE__;
                goto err;
            }
            bytes = mdRec->fbRec->recsize;
        } else {
            if (!mdExporterSendIPFIXRecord(mdRec, exporter, err)) {
                g_warning("Couldn't write dns RR ipfix %s", (*err)->message);
            }
        }
    } else if (exporter->exportFormat == EF_JSON) {
        /* TODO capture bytes written */
        ROTATE_IF_NEEDED(exporter, cfg->ctime, err);

        /* here will call printDNS function already implemented in JSON code */
        if (!mdJsonifyDNSRRRecord(mdRec, exporter->buf)) {
            lineno = __LINE__;
            goto err;
        }
        bytes = md_util_write_buffer(exporter->activeWriter->lfp,
                                     exporter->buf, exporter->name, err);
        if (!bytes) {
            lineno = __LINE__;
            goto err;
        }

    } else {
        if (!dns_rr_no_text_seen) {
            dns_rr_no_text_seen = TRUE;
            g_warning("DNS RR export only for IPFIX or JSON exporters");
        }
    }

#if 0
} else {
    if (exporter->rotateInterval) {
        if ((cfg->ctime - exporter->last_rotate_ms) >
            exporter->rotateInterval)
        {
            if (!mdTextFileRotate(exporter, cfg->ctime, err)) {
                exporter->last_rotate_ms = 0;
                lineno = __LINE__;
                goto err;
            }
        }
    }
    if (exporter->custom_list && !exporter->basic_list_dpi) {
        mdFullFlow_t         flow;
        /* TODO */
        /*md_main_template_t   mdrec;*/
        mdExportFieldList_t *fLNode = NULL;
        size_t buflen = MD_REM_MSG(exporter->buf);

        memset(&flow, 0, sizeof(mdFullFlow_t));
/*            memset(&mdrec, 0, sizeof(md_main_template_t));
 *
 *          mdrec.flowStartMilliseconds = dns->flowStartMilliseconds;
 *          mdrec.flowEndMilliseconds = dns->flowStartMilliseconds;
 *          if (dns->sourceIPv4Address || dns->destinationIPv4Address) {
 *              mdrec.sourceIPv4Address = dns->sourceIPv4Address;
 *              mdrec.destinationIPv4Address = dns->destinationIPv4Address;
 *          } else {
 *              memcpy(&(mdrec.sourceIPv6Address), dns->sourceIPv6Address, 16);
 *              memcpy(&(mdrec.destinationIPv6Address),
 * dns->destinationIPv6Address, 16);
 *          }
 *          mdrec.silkAppLabel = 53;
 *          mdrec.observationDomainId = dns->observationDomainId;
 *          mdrec.sourceTransportPort = dns->sourceTransportPort;
 *          mdrec.destinationTransportPort = dns->destinationTransportPort;
 *          mdrec.vlanId = dns->vlanId;
 *          mdrec.protocolIdentifier = dns->protocolIdentifier;
 *          flow.rec = &mdrec;*/

        for (fLNode = exporter->custom_list;
             fLNode;
             fLNode = fLNode->next)
        {
            if (!fLNode->print_fn(&flow, exporter->buf, &buflen,
                                  fLNode->decorator->str))
            {
                if (!expand) {
                    if (!mdExporterExpandBuf(exporter)) {
                        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_MEM,
                                    "Error allocating memory for exporter %s",
                                    exporter->name);
                        return FALSE;
                    }
                    expand = TRUE;
                    /* start over */
                    fLNode = exporter->custom_list;
                } else {
                    /* already tried this - ABORT! */
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                                "Error writing to buffer for exporter %s",
                                exporter->name);
                    lineno = __LINE__;
                    goto err;
                }
            }
        }
        g_string_truncate(buf, buf->len - 1);
        //exporter->buf->cp -= 1;
        //buflen += 1;
        g_string_append_c(exporter->buf, '\n');
        bytes = md_util_write_buffer(exporter->lfp, exporter->buf,
                                     exporter->name, err);
        if (!bytes) {
            lineno = __LINE__;
            goto err;
        }
    } else if (exporter->json) {
        /* here will call printDNS function already implemented in JSON code */
        if (!mdJsonifyDNSRRRecord(mdRec, exporter->buf)) {
            lineno = __LINE__;
            goto err;
        }
        bytes = md_util_write_buffer(exporter->lfp, exporter->buf,
                                     exporter->name, err);
        if (!bytes) {
            lineno = __LINE__;
            goto err;
        }
    } else {
        ret = mdPrintDNSRRRecord(exporter->buf, exporter->lfp,
                                 exporter->delimiter, mdRec,
                                 cfg->dns_base64_encode,
                                 exporter->escape_chars, err);
        if (ret < 0) {
            lineno = __LINE__;
            goto err;
        } else if (ret == 0) {
            if (!mdExporterExpandBuf(exporter)) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_MEM,
                            "Error allocating memory for exporter %s",
                            exporter->name);
                return FALSE;
            }
            ret = mdPrintDNSRRRecord(exporter->buf, exporter->lfp,
                                     exporter->delimiter, mdRec,
                                     cfg->dns_base64_encode,
                                     exporter->escape_chars, err);
            if (ret < 0) {
                lineno = __LINE__;
                goto err;
            } else if (ret == 0) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                            "Error writing to buffer for exporter %s",
                            exporter->name);
                lineno = __LINE__;
                goto err;
            }
        }
        bytes = ret;
    }
}
#endif /* if 0 */

    return TRUE;

  err:
    if (err && !*err) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "FIX THE CODE!!! Function near %s:%d did not set GError",
                    __FILE__, lineno);
    }
    g_warning("Error writing DNS Record: %s", (*err)->message);
    g_clear_error(err);
    g_warning("Deactivating Exporter %s.", exporter->name);
    exporter->active = FALSE;
    if (!mdExporterRestart(cfg, exporter, err)) {
        g_warning("Error restarting exporter %s: %s",
                  exporter->name, (*err)->message);
        g_clear_error(err);
    }

    return TRUE;
}

typedef struct md_dns_rr_build_ctx_st {
    mdFullFlow_t *fullFlow;
    mdGenericRec_t *mdRecToFill;
    md_dns_rr_t *dns;
    mdExporter_t *exporter;
    mdConfig_t *cfg;
    GError **err;
} md_dns_rr_build_ctx_t;

static int
exportDNSRRBuildRecordCallback(
    const fbRecord_t  *record,
    void              *ctx)
{
    yafDnsQR_t *dnsQR       = NULL;
    md_dns_rr_build_ctx_t *dnsRRCtx    = (md_dns_rr_build_ctx_t *)ctx;
    md_dns_rr_t *dnsRRRec    = dnsRRCtx->dns;
    mdFullFlow_t *flow        = dnsRRCtx->fullFlow;
    mdGenericRec_t *recToFill   = dnsRRCtx->mdRecToFill;
    mdExporter_t *exporter    = dnsRRCtx->exporter;
    mdConfig_t *cfg         = dnsRRCtx->cfg;
    mdDefaultTmplCtx_t *tmplCtx     = fbTemplateGetContext(record->tmpl);
    mdUtilTemplateContents_t templateContents = tmplCtx->templateContents;
    fbRecord_t copiedRecord;
    yafDnsQR_t copiedDnsQR;
    GError **err         = dnsRRCtx->err;

    /* these exact/super/sub are relative to yafDnsQR_t,
     *      * the assumption is that something else verified that
     *exp->dnsDPITid
     *           * has enough fields for DNS dedup
     *                */
    switch (templateContents.relative) {
      case TC_EXACT_DEF:
      case TC_EXACT:
        dnsQR = (yafDnsQR_t *)record->rec;
        break;
      case TC_SUPER:
      case TC_SUB:
      case TC_MIX:
        copiedRecord.rec            = (uint8_t *)&copiedDnsQR;
        copiedRecord.reccapacity    = sizeof(yafDnsQR_t);
        if (templateContents.yafVersion == TC_YAF_VERSION_2) {
            if (!fbRecordCopyToTemplate(record, &copiedRecord, yafDnsQRTmplV2,
                                        record->tid, err))
            {
                g_warning("failed to copy dns rec to new template %s\n",
                          (*err)->message);
            }
        } else if (templateContents.yafVersion == TC_YAF_VERSION_3) {
            if (!fbRecordCopyToTemplate(record, &copiedRecord, yafDnsQRTmplV3,
                                        record->tid, err))
            {
                g_warning("failed to copy dns rec to new template %s\n",
                          (*err)->message);
            }
        }

        dnsQR   = &copiedDnsQR;
        break;
    }

    /* dnsQR points to the incoming DNS record */
    dnsRRRec->rrname.buf        = dnsQR->dnsName.buf;
    dnsRRRec->rrname.len        = dnsQR->dnsName.len;
    dnsRRRec->dnsTTL            = dnsQR->dnsTTL;
    dnsRRRec->dnsRRType         = dnsQR->dnsRRType;
    dnsRRRec->dnsQueryResponse  = dnsQR->dnsQueryResponse;
    dnsRRRec->dnsAuthoritative  = dnsQR->dnsAuthoritative;
    dnsRRRec->dnsResponseCode   = dnsQR->dnsResponseCode;
    dnsRRRec->dnsSection        = dnsQR->dnsSection;
    dnsRRRec->dnsId             = dnsQR->dnsId;

    if (exporter->dns_resp_only) {
        if (dnsRRRec->dnsQueryResponse == 0) {return 0;}
    }

    if (flow->flowEndReason == YAF_END_UDPFORCE &&
        dnsRRRec->dnsQueryResponse == 1)
    {
        dnsRRRec->yafFlowKeyHash = md_util_rev_flow_key_hash(flow);
    }

    dnsRRRec->rrdata.buf = NULL;
    dnsRRRec->rrdata.len = 0;

    if (dnsRRRec->dnsQueryResponse) {
        switch (dnsQR->dnsRRType) {
          case 1:
            {
                const yaf_dnsA_t *a = NULL;
                while ((a = fbSTLNext(yaf_dnsA_t, &dnsQR->dnsRRList, a))) {
                    dnsRRRec->rrdata.buf = (uint8_t *)&(a->dnsA);
                    dnsRRRec->rrdata.len = 4;
                }
                break;
            }
          case 2:
            {
                const yaf_dnsNS_t *ns = NULL;
                while ((ns = fbSTLNext(yaf_dnsNS_t, &dnsQR->dnsRRList, ns))) {
                    dnsRRRec->rrdata.buf = ns->dnsNSDName.buf;
                    dnsRRRec->rrdata.len = ns->dnsNSDName.len;
                }
                break;
            }
          case 5:
            {
                const yaf_dnsCNAME_t *c = NULL;
                while ((c = fbSTLNext(yaf_dnsCNAME_t, &dnsQR->dnsRRList, c)))
                {
                    dnsRRRec->rrdata.buf = c->dnsCNAME.buf;
                    dnsRRRec->rrdata.len = c->dnsCNAME.len;
                }
                break;
            }
          case 6:
            {
                const yaf_dnsSOA_t *soa = NULL;
                while ((soa = fbSTLNext(yaf_dnsSOA_t, &dnsQR->dnsRRList, soa)))
                {
                    dnsRRRec->rrdata.buf = soa->dnsSOAMName.buf;
                    dnsRRRec->rrdata.len = soa->dnsSOAMName.len;
                }
                break;
            }
          case 12:
            {
                const yaf_dnsPTR_t *ptr = NULL;
                while ((ptr = fbSTLNext(yaf_dnsPTR_t, &dnsQR->dnsRRList, ptr)))
                {
                    dnsRRRec->rrdata.buf = ptr->dnsPTRDName.buf;
                    dnsRRRec->rrdata.len = ptr->dnsPTRDName.len;
                }
                break;
            }
          case 15:
            {
                const yaf_dnsMX_t *mx = NULL;
                while ((mx = fbSTLNext(yaf_dnsMX_t, &dnsQR->dnsRRList, mx)))
                {
                    dnsRRRec->rrdata.buf = mx->dnsMXExchange.buf;
                    dnsRRRec->rrdata.len = mx->dnsMXExchange.len;
                }
                break;
            }
          case 16:
            {
                const yaf_dnsTXT_t *txt = NULL;
                while ((txt = fbSTLNext(yaf_dnsTXT_t, &dnsQR->dnsRRList, txt)))
                {
                    dnsRRRec->rrdata.buf = txt->dnsTXTData.buf;
                    dnsRRRec->rrdata.len = txt->dnsTXTData.len;
                }
                break;
            }
          case 28:
            {
                const yaf_dnsAAAA_t *aa = NULL;
                while ((aa = fbSTLNext(yaf_dnsAAAA_t, &dnsQR->dnsRRList, aa)))
                {
                    dnsRRRec->rrdata.buf = (uint8_t *)&(aa->dnsAAAA);
                    dnsRRRec->rrdata.len = 16;
                }
                break;
            }
          case 33:
            {
                const yaf_dnsSRV_t *srv = NULL;
                while ((srv = fbSTLNext(yaf_dnsSRV_t, &dnsQR->dnsRRList, srv)))
                {
                    dnsRRRec->rrdata.buf = srv->dnsSRVTarget.buf;
                    dnsRRRec->rrdata.len = srv->dnsSRVTarget.len;
                }
                break;
            }
          case 46:
            {
                const yaf_dnsRRSig_t *rr = NULL;
                while ((rr = fbSTLNext(yaf_dnsRRSig_t, &dnsQR->dnsRRList, rr)))
                {
                    dnsRRRec->rrdata.buf = rr->dnsRRSIGSigner.buf;
                    dnsRRRec->rrdata.len = rr->dnsRRSIGSigner.len;
                }
                break;
            }
          case 47:
            {
                const yaf_dnsNSEC_t *nsec = NULL;
                while ((nsec = fbSTLNext(yaf_dnsNSEC_t, &dnsQR->dnsRRList,
                                                          nsec)))
                {
                    dnsRRRec->rrdata.buf = nsec->dnsNSECNextDomainName.buf;
                    dnsRRRec->rrdata.len = nsec->dnsNSECNextDomainName.len;
                }
                break;
            }
          default:
            dnsRRRec->rrdata.buf = NULL;
            dnsRRRec->rrdata.len = 0;
        }
    }

    recToFill->generated = TRUE;
    if (!mdExporterWriteDNSRRRecord(cfg, exporter, recToFill, err)) {
        return FALSE;
    }

    return 0;
}

gboolean
mdExportDNSRR(
    mdConfig_t    *cfg,
    mdExporter_t  *exporter,
    mdFullFlow_t  *flow,
    uint16_t       tid,
    GError       **err)
{
    md_dns_rr_t dns;
    mdGenericRec_t mdRec;
    fbRecord_t fbRec;
    md_dns_rr_build_ctx_t dnsRRCtx;

    MD_UNUSED_PARAM(cfg);
    MD_UNUSED_PARAM(tid);

    if (!exporter->allowDnsRR || exporter->multi_files) {
        return TRUE;
    }

    memset(&dns, 0, sizeof(dns));

    if (exporter->dnsRRFull) {
        /* check if flow is v4 or v6 */
        if (flow->ipv4) {
            dns.sourceIPv4Address = flow->sourceIPv4Address;
            dns.destinationIPv4Address = flow->destinationIPv4Address;
            mdRec.extTid    = exporter->genTids.dnsRR4FullExtTid;
        } else {
            memcpy(dns.sourceIPv6Address, flow->sourceIPv6Address, 16);
            memcpy(dns.destinationIPv6Address,
                   flow->destinationIPv6Address, 16);
            mdRec.extTid    = exporter->genTids.dnsRR6FullExtTid;
        }
        dns.sourceTransportPort = flow->sourceTransportPort;
        dns.destinationTransportPort = flow->destinationTransportPort;
        dns.vlanId = flow->vlanId;
        dns.protocolIdentifier = flow->protocolIdentifier;
    } else {
        mdRec.extTid = exporter->genTids.dnsRRExtTid;
    }

    mdRec.fbRec     = &fbRec;
    fbRec.rec       = (uint8_t *)&dns;
    fbRec.tid       = exporter->dnsRRIntTid;
    fbRec.recsize   = sizeof(md_dns_rr_t);
    mdRec.intTid    = fbRec.tid;

    dns.yafFlowKeyHash          = *(flow->flowKeyHash);
    dns.flowStartMilliseconds   = flow->flowStartMilliseconds;
    dns.observationDomainId     = *flow->observationDomain;

    dnsRRCtx.fullFlow       = flow;
    dnsRRCtx.dns            = &dns;
    dnsRRCtx.mdRecToFill    = &mdRec;
    dnsRRCtx.exporter       = exporter;
    dnsRRCtx.err            = err;

    if (fbRecordFindAllSubRecords(flow->fbRec, exporter->recvdTids.dnsDPITid, 0,
                                  exportDNSRRBuildRecordCallback,
                                  &dnsRRCtx))
    {
        /* unlike most of these, returning false is allowed */
        return FALSE;
    }

    return TRUE;
}

void
mdExporterDedupFileClose(
    mdExporter_t  *exporter,
    FILE          *fp,
    char          *last_file)
{
    mdCloseAndUnlock(exporter, fp, last_file, NULL);
    /*if (fp) {
     *  fclose(fp);
     *  }
     *
     * if (last_file) {
     *  if (exporter->lock) {
     *      mdUnlockFile(last_file);
     *  }
     *  g_free(last_file);
     *
     * }*/
}

gboolean
mdExporterDedupFileOpen(
    mdConfig_t    *cfg,
    mdExporter_t  *exporter,
    FILE         **file,
    char         **last_file,
    char          *prefix,
    uint64_t      *rotate,
    GError       **err)
{
    GString *file_name;
    uint64_t start_secs;
    FILE *fp = *file;

    if (exporter->exportFormat == EF_IPFIX) {
        return TRUE;
    }

    /* if it's JSON...use the main export file, not a special one */
    if (exporter->json) {
        fp = exporter->activeWriter->lfp;
    }

    /* only use a dedup file if we're rotating */
    if (fp && !exporter->rotateInterval) {
        return TRUE;
    }

    if (fp && exporter->rotateInterval) {
        if ((cfg->ctime - *rotate) < exporter->rotateInterval) {
            return TRUE;
        } else {
            if (exporter->json) { /* use main json file for this output */
                mdExporterDedupFileClose(exporter, fp,
                                         exporter->activeWriter->currentFname);
            } else {
                mdExporterDedupFileClose(exporter, fp, *last_file);
            }
        }
    }

    file_name = g_string_new(NULL);

    if (exporter->usedGeneralDedupConfig) {
        g_string_assign(file_name, exporter->activeWriter->outspec);
    }

    if (exporter->rotateInterval) {
        start_secs = cfg->ctime / 1000;

        if (!exporter->json) {
            /* 1 FILE for JSON */
            g_string_append_printf(file_name, "%s.", prefix);
        }
        md_util_time_append(file_name, start_secs, MD_TIME_FMT_YMDHMS);

        if (exporter->json) {
            g_string_append_printf(file_name, ".json");
        } else {
            g_string_append_printf(file_name, ".txt");
        }
    } else if (!exporter->json) {
        if (!exporter->usedGeneralDedupConfig) {
            g_string_append_printf(file_name, "%s", prefix);
        } else {
            g_string_append_printf(file_name, "%s.txt", prefix);
        }
    }

    if (exporter->json) {
        exporter->activeWriter->currentFname = g_strdup(file_name->str);
    } else {
        *last_file = g_strdup(file_name->str);
    }
    if (exporter->lock) {
        mdLockFile(file_name);
    }

    fp = fopen(file_name->str, "w");
    if (fp == NULL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "%s: Error Opening File \"%s\": %s",
                    exporter->name, file_name->str, strerror(errno));
        return FALSE;
    }
    g_debug("%s: Opening Text File: %s", exporter->name, file_name->str);
    g_string_free(file_name, TRUE);

    if (exporter->rotateInterval) {
        *rotate = cfg->ctime;
    }
    if (exporter->json) {
        exporter->activeWriter->lfp = fp;
    } else {
        *file = fp;
    }

    return TRUE;
}

gboolean
mdExporterWriteGeneralDedupRecord(
    mdConfig_t      *cfg,
    mdExporter_t    *exporter,
    FILE            *fp,
    mdGenericRec_t  *mdRec,
    const char      *prefix,
    GError         **err)
{
    md_dedup_t *rec = (md_dedup_t *)mdRec->fbRec->rec;
    int ret = 0;
    int lineno = -1;

    /* DEDUP records go out default, which should be active */

    if (exporter == NULL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "Exporter Node Exists, but No Type\n");
        return FALSE;
    }

    if (!exporter->allowGeneralDedup || exporter->multi_files) {
        return TRUE;
    }

    if (!exporter->active) {
        if (cfg->ctime - exporter->last_restart_ms > MD_RESTART_MS) {
            if (!mdExporterRestart(cfg, exporter, err)) {
                g_message("Error restarting exporter %s: %s",
                          exporter->name, (*err)->message);
                g_clear_error(err);
                return TRUE;
            }
        } else {
            return TRUE;
        }
    }

    if (exporter->exportFormat == EF_IPFIX) {
        if (!mdRec->generated) {
            if (!mdExporterSendIPFIXRecord(mdRec, exporter, err)) {
                g_warning("couldn't write dedup %s\n", (*err)->message);
                lineno = __LINE__;
                goto err;
            }
        } else {
            fBufSetInternalTemplate(exporter->activeWriter->fbuf,
                                    mdRec->intTid, err);
            if (!fBufSetExportTemplate(exporter->activeWriter->fbuf,
                                       mdRec->extTid, err))
            {
                g_warning("Could not set export template for generated"
                          " general DEDUP %#x %s",
                          mdRec->extTid, (*err)->message);
                lineno = __LINE__;
                goto err;
            }

            if (!(fBufAppend(exporter->activeWriter->fbuf,
                             mdRec->fbRec->rec,
                             mdRec->fbRec->recsize,
                             err)))
            {
                g_warning("couldn't fbuf append generated dns rr");
                lineno = __LINE__;
                goto err;
            }
        }

/*        if (int_tid == 0) {
 *          int_tid = MD_DEDUP_FULL;
 *      }
 *
 *      if (!mdExporterfBufSetup(cfg, exporter, NULL, err,
 *                               mdInitExporterSessionDedupOnly,
 *                               int_tid, ext_tid))
 *      {*/
        /* if this fails, it's probably because the internal dedup
         * templates have not been added to the session.  Add them
         * and try again */
/*
 *          if (!g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_TMPL)) {
 *              return FALSE;
 *          }
 *
 *          g_clear_error(err);
 *          if (!md_dedup_add_templates(exporter->dedup, exporter->fbuf, err))
 * {
 *              return FALSE;
 *          }
 *          if (!mdExporterfBufSetup(cfg, exporter, NULL, err,
 *                                   mdInitExporterSessionDedupOnly,
 *                                   int_tid, ext_tid))
 *          {
 *              return FALSE;
 *          }
 *      }
 *      if (!fBufAppend(exporter->fbuf, (uint8_t *)rec, rec_length, err)) {
 *           fBufFree(exporter->fbuf);
 *          lineno = __LINE__;
 *          goto err;
 *      }*/
    } else {
        if (!fp) {
            /* for collectors OR JSON exporters */
            fp = exporter->activeWriter->lfp;
        }

        if (exporter->json) {
            ret = mdJsonifyDedupRecord(fp, exporter->buf, prefix,
                                       rec, err);
        } else {
            ret = mdPrintDedupRecord(fp, exporter->buf, rec,
                                     exporter->delimiter, err);
        }

        if (ret < 0) {
            lineno = __LINE__;
            goto err;
        } else if (ret == 0) {
            if (!mdExporterExpandBuf(exporter)) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_MEM,
                            "Error allocating memory for exporter %s",
                            exporter->name);
                return FALSE;
            }

            if (exporter->json) {
                ret = mdJsonifyDedupRecord(fp, exporter->buf, prefix,
                                           rec, err);
            } else {
                ret = mdPrintDedupRecord(fp, exporter->buf, rec,
                                         exporter->delimiter, err);
            }

            if (ret < 0) {
                lineno = __LINE__;
                goto err;
            } else if (ret == 0) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                            "Error writing to buffer for exporter %s",
                            exporter->name);
                lineno = __LINE__;
                goto err;
            }
        }
    }

    return TRUE;

  err:
    if (err && !*err) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "FIX THE CODE!!! Function near %s:%d did not set GError",
                    __FILE__, lineno);
    }
    g_warning("Error writing Dedup Record: %s", (*err)->message);
    g_clear_error(err);
    g_warning("Deactivating Exporter %s.", exporter->name);
    exporter->active = FALSE;
    if (!mdExporterRestart(cfg, exporter, err)) {
        g_warning("Error restarting exporter %s: %s",
                  exporter->name, (*err)->message);
        g_clear_error(err);
    }

    return TRUE;
}

gboolean
mdExporterSSLCertRecord(
    mdConfig_t       *cfg,
    mdExporter_t     *exporter,
    FILE             *cert_file,
    mdGenericRec_t   *mdRec,
    yfSSLFullCert_t  *fullcert,
    const uint8_t    *issuer,
    size_t            issuer_len,
    uint8_t           cert_no,
    GError          **err)
{
    size_t rc;
    int lineno = -1;

    /* SSL Certs will go out default writer, which should be active */
    if (!exporter->allowSslCert || exporter->multi_files) {
        return TRUE;
    }

    if (!exporter->active) {
        if (cfg->ctime - exporter->last_restart_ms > MD_RESTART_MS) {
            if (!mdExporterRestart(cfg, exporter, err)) {
                g_message("Error restarting exporter %s: %s",
                          exporter->name, (*err)->message);
                g_clear_error(err);
                return TRUE;
            }
        } else {
            return TRUE;
        }
    }

    if (exporter->exportFormat == EF_IPFIX) {
        if (mdRec->generated) {
            if (!fBufSetInternalTemplate(exporter->activeWriter->fbuf,
                                         mdRec->intTid, err))
            {
                g_error("Unable to set internal template SSL CERT %#x: %s",
                        mdRec->intTid, (*err)->message);
            }
            if (!fBufSetExportTemplate(exporter->activeWriter->fbuf,
                                       mdRec->extTid, err))
            {
                g_error("Unable to set export template SSL CERT %#x: %s",
                        mdRec->extTid, (*err)->message);
            }
            if (!(fBufAppend(exporter->activeWriter->fbuf,
                             mdRec->fbRec->rec,
                             mdRec->fbRec->recsize,
                             err)))
            {
                g_error("Unable to append generated SSL CERT: %s",
                        (*err)->message);
                lineno = __LINE__;
                goto err;
            }
        } else {
            if (!mdExporterSendIPFIXRecord(mdRec, exporter, err)) {
                g_warning("Unable to write SSL CERT: %s", (*err)->message);
                lineno = __LINE__;
                goto err;
            }
        }
    } else {
        if (exporter->json) {
            GString *empty = g_string_new(NULL);
            g_string_append(exporter->buf, "{\"sslCert\":{");
            mdPrintDPIRecord(exporter, mdRec->fbRec, empty, exporter->buf,
                             exporter->delimiter, TRUE, TRUE);
            g_string_free(empty, TRUE);
            g_string_append(exporter->buf, "}}\n");
        } else {
            GString *prefix = g_string_new(NULL);
            gboolean index_config = exporter->no_index;
            const fbTemplateField_t *sslCertSerialNumber;
            fbVarfield_t vf;

            /* set temporarily */
            exporter->no_index = TRUE;

            /* FIXME: Cache this location */
            sslCertSerialNumber = fbTemplateFindFieldByIdent(
                mdRec->fbRec->tmpl, CERT_PEN, 244, NULL, 0);
            if (sslCertSerialNumber) {
                fbRecordCopyFieldValue(mdRec->fbRec, sslCertSerialNumber,
                                       (void *)&vf, sizeof(vf));
                md_util_hexdump_append_nospace(prefix, vf.buf, vf.len);
            }
            g_string_append_c(prefix, exporter->delimiter);

            if (issuer) {
                g_string_append_len(prefix, (gchar *)issuer, issuer_len);
            }
            g_string_append_c(prefix, exporter->delimiter);

            if (cfg->ctime) {
                md_util_millitime_append(prefix, cfg->ctime);
                g_string_append_c(prefix, exporter->delimiter);
            } else {
                g_string_append_c(prefix, exporter->delimiter);
            }
            if (TC_APP_DPI_SSL_RW_L2 ==
                mdRec->intTmplCtx->templateContents.specCase.dpi)
            {
                md_ssl_certificate_t *cert =
                    (md_ssl_certificate_t *)mdRec->fbRec->rec;
                mdExporterTextRewrittenSSLCertPrint(
                    exporter, cert, prefix, cert_no);
            } else {
                yafSSLDPICert_t *ssl = (yafSSLDPICert_t *)mdRec->fbRec->rec;
                mdExporterTextNewSSLCertPrint(exporter, ssl, prefix, cert_no);
            }
            if (fullcert &&
                (exporter->hash_md5 || exporter->hash_sha1 ||
                 mdExporterCheckSSLConfig(exporter, 299, MD_SSLCONFIG_OTHER) ||
                 mdExporterCheckSSLConfig(exporter, 298, MD_SSLCONFIG_OTHER) ||
                 mdExporterCheckSSLConfig(exporter, 296, MD_SSLCONFIG_OTHER)))
            {
                fbVarfield_t *ct =
                    fbBasicListGetIndexedDataPtr(&(fullcert->cert), cert_no);
                if (ct->len) {
                    mdExporterSSLCertHash(exporter, ct, prefix, cert_no);
                    if (mdExporterCheckSSLConfig(
                            exporter, 296, MD_SSLCONFIG_OTHER))
                    {
                        mdExporterSSLBase64Encode(
                            exporter, ct, prefix, cert_no);
                    }
                }
            }

            exporter->no_index = index_config;
            g_string_free(prefix, TRUE);
        }

        /* write to file */
        if (!cert_file) {
            ROTATE_IF_NEEDED(exporter, cfg->ctime, err);
        }
        if (exporter->buf->len == 0) {
            /* Nothing to write */
            return TRUE;
        }

        if (cert_file) {
            rc = md_util_write_buffer(cert_file, exporter->buf,
                                      exporter->name, err);
        } else {
            rc = md_util_write_buffer(exporter->activeWriter->lfp,
                                      exporter->buf,
                                      exporter->name, err);
        }

        if (!rc) {
            lineno = __LINE__;
            goto err;
        }
    }

    return TRUE;

  err:
    if (err && !*err) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "FIX THE CODE!!! Function near %s:%d did not set GError",
                    __FILE__, lineno);
    }
    g_warning("Error writing SSL CERT Record: %s", (*err)->message);
    g_clear_error(err);
    g_warning("Deactivating Exporter %s.", exporter->name);
    exporter->active = FALSE;
    if (!mdExporterRestart(cfg, exporter, err)) {
        g_warning("Error restarting exporter %s: %s",
                  exporter->name, (*err)->message);
        g_clear_error(err);
    }

    return TRUE;
}

/**
 * mdExporterWriteSSLDedupRecord
 *
 * write a SSL de-duplicated record to the given exporter
 *
 * @param cfg - mediator configuration options
 * @param exporter - exporter to write to
 * @param tid - template id
 * @param rec - the record to write
 * @param rec_length - length of record to write
 * @param err
 * @return TRUE if no errors
 */
gboolean
mdExporterWriteSSLDedupRecord(
    mdConfig_t      *cfg,
    mdExporter_t    *exporter,
    mdGenericRec_t  *mdRec,
    GError         **err)
{
    int ret;
    int lineno = -1;

    /* DEDUP records written to default, which is what active will be */

    if (exporter == NULL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "Exporter Node Exists, but No Type\n");
        return FALSE;
    }

    if (!exporter->allowSslDedup) {
        return TRUE;
    }

    if (!exporter->active) {
        if (cfg->ctime - exporter->last_restart_ms > MD_RESTART_MS) {
            if (!mdExporterRestart(cfg, exporter, err)) {
                g_message("Error restarting exporter %s: %s",
                          exporter->name, (*err)->message);
                g_clear_error(err);
                return TRUE;
            }
        } else {
            return TRUE;
        }
    }

    if (exporter->exportFormat == EF_IPFIX) {
        if (mdRec->generated) {
            if (!fBufSetInternalTemplate(exporter->activeWriter->fbuf,
                                         mdRec->intTid, err))
            {
                g_warning("Unable to set internal template SSL DEDUP %#x: %s",
                          mdRec->intTid, (*err)->message);
                goto err;
            }
            if (!fBufSetExportTemplate(exporter->activeWriter->fbuf,
                                       mdRec->extTid, err))
            {
                g_warning("Unable to set export template SSL DEDUP %#x: %s",
                          mdRec->extTid, (*err)->message);
                goto err;
            }
            if (!(fBufAppend(exporter->activeWriter->fbuf, mdRec->fbRec->rec,
                             mdRec->fbRec->recsize, err)))
            {
                g_warning("Unable to append generated SSL DEDUP: %s",
                          (*err)->message);
                lineno = __LINE__;
                goto err;
            }
        } else {
            if (!mdExporterSendIPFIXRecord(mdRec, exporter, err)) {
                lineno = __LINE__;
                goto err;
            }
        }
    } else {
        ROTATE_IF_NEEDED(exporter, cfg->ctime, err);

        if (exporter->json) {
            ret = mdJsonifySSLDedupRecord(exporter->activeWriter->lfp,
                                          exporter->buf,
                                          mdRec,
                                          err);
        } else {
            ret = mdPrintSSLDedupRecord(exporter->activeWriter->lfp,
                                        exporter->buf,
                                        mdRec,
                                        exporter->delimiter, err);
        }

        if (ret < 0) {
            lineno = __LINE__;
            goto err;
        } else if (ret == 0) {
            if (!mdExporterExpandBuf(exporter)) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_MEM,
                            "Error allocating memory for exporter %s",
                            exporter->name);
                return FALSE;
            }
            /* try again with expanded buffer */
            if (exporter->json) {
                ret = mdJsonifySSLDedupRecord(exporter->activeWriter->lfp,
                                              exporter->buf,
                                              mdRec, err);
            } else {
                ret = mdPrintSSLDedupRecord(exporter->activeWriter->lfp,
                                            exporter->buf,
                                            mdRec,
                                            exporter->delimiter, err);
            }
            if (ret < 0) {
                lineno = __LINE__;
                goto err;
            } else if (ret == 0) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                            "Error writing to buffer for exporter %s",
                            exporter->name);
                lineno = __LINE__;
                goto err;
            }
        }
    }

    return TRUE;

  err:
    if (err && !*err) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "FIX THE CODE!!! Function near %s:%d did not set GError",
                    __FILE__, lineno);
    }
    g_warning("Error writing SSL Dedup Record: %s", (*err)->message);
    g_clear_error(err);
    g_warning("Deactivating Exporter %s.", exporter->name);
    exporter->active = FALSE;
    if (!mdExporterRestart(cfg, exporter, err)) {
        g_warning("Error restarting exporter %s: %s",
                  exporter->name, (*err)->message);
        g_clear_error(err);
    }

    return TRUE;
}
