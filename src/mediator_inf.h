/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_inf.h
 *
 *  Yaf mediator for filtering, DNS deduplication, and other mediator-like
 *  things
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
#ifndef _MEDIATOR_INF_H
#define _MEDIATOR_INF_H

#include "templates.h"
#include "mediator_structs.h"
#include "mediator_util.h"
#ifdef ENABLE_SKIPSET
#include SKIPSET_HEADER_NAME
#ifdef HAVE_SILK_UTILS_H
#include <silk/utils.h>
#endif
#endif

#define FTP_DEFAULT   "ftp"
#define SSH_DEFAULT   "ssh"
#define SMTP_DEFAULT  "smtp"
#define DNS_DEFAULT   "dns"
#define TFTP_DEFAULT  "tftp"
#define HTTP_DEFAULT  "http"
#define IMAP_DEFAULT  "imap"
#define IRC_DEFAULT   "irc"
#define SIP_DEFAULT   "sip"
#define MYSQL_DEFAULT "mysql"
#define SLP_DEFAULT   "slp"
#define POP3_DEFAULT  "pop3"
#define RTSP_DEFAULT  "rtsp"
#define NNTP_DEFAULT  "nntp"
#define SSL_DEFAULT   "tls"
#define DHCP_DEFAULT  "dhcp"
#define P0F_DEFAULT   "p0f"
#define INDEX_DEFAULT "flow"
#define DNS_DEDUP_DEFAULT "dns"
#define FLOW_STATS_DEFAULT "flowstats"
#define YAF_STATS_DEFAULT "yaf_stats"
#define DNP_DEFAULT   "dnp"
#define RTP_DEFAULT   "rtp"
#define MODBUS_DEFAULT "modbus"
#define ENIP_DEFAULT   "enip"

gboolean
mdCoreInit(
    GError    **error);

mdExporter_t *
mdNewExporter(
    mdExportFormat_t    exportFormat,
    mdExportMethod_t    exportMethod,
    const char         *name);

mdCollector_t *
mdNewCollector(
    mdCollectionMethod_t    collectionMethod,
    const char             *name);

//||uint8_t mdCollectorGetId(
//||    mdCollector_t      *collector);
//||
//||void mdCollectorHasTimestampField(
//||    mdCollector_t      *collector);
//||
void
mdCollectorHasDataTimestampField(
    mdCollector_t      *collector);

void
mdCollectorHasSourceRuntimeTimestampField(
    mdCollector_t      *collector);

void
mdCollectorUpdateMaxRecord(
    mdCollector_t      *collector);

gboolean
mdCollectorsInit(
    mdConfig_t            *md,
    mdCollector_t         *collector,
    GError                **err);

void
mdInterruptListeners(
    mdConfig_t        *cfg);

gboolean
mdCollectorSetInSpec(
    mdCollector_t      *collector,
    const char         *inspec,
    GError            **err);

gboolean
mdCollectorSetDeleteFiles(
    mdCollector_t      *collector,
    gboolean            delete,
    GError            **err);

gboolean
mdCollectorSetPollingInterval(
    mdCollector_t      *collector,
    int                 pollingInterval,
    GError            **err);

gboolean
mdCollectorSetDecompressWorkingDir(
    mdCollector_t      *collector,
    const char         *path,
    GError            **err);

gboolean
mdCollectorSetMoveDir(
    mdCollector_t      *collector,
    const char         *move_dir,
    GError            **err);

void
mdCollectorSetNoLockedFilesMode(
    mdCollector_t      *collector);

gboolean
mdCollectorSetPort(
    mdCollector_t      *collector,
    const char         *port,
    GError            **err);

const char *
mdCollectorGetName(
    const mdCollector_t      *node);

uint8_t
mdCollectorGetID(
    const mdCollector_t      *node);

gboolean
mdCollectorVerifySetup(
    mdCollector_t      *collector,
    GError            **err);

void *
mdNewTable(
    const char *table);

void *
mdGetTableByApplication(
    int id);

void
mdBuildDefaultTableHash(
    void);

gboolean
mdInsertTableItem(
    void       *table_name,
    const char *val);

gboolean
mdExporterInsertDPIFieldItem(
    mdExporter_t   *exporter,
    int             ie,
    GError        **err);

gboolean
mdExporterSetPort(
    mdExporter_t  *exporter,
    const char    *port,
    GError       **err);

gboolean
mdExporterSetHost(
    mdExporter_t  *exporter,
    const char    *host,
    GError       **err);

gboolean
mdExporterSetFileSpec(
    mdExporter_t  *exporter,
    const char    *spec,
    GError       **err);

gboolean
mdExporterSetRotateInterval(
    mdExporter_t  *exporter,
    int            rotateIntervalSec,
    GError       **err);

gboolean
mdExporterSetDelimiters(
    mdExporter_t  *exporter,
    const char    *delim,
    const char    *dpi_delim,
    GError       **err);

gboolean
mdExporterSetUdpTemplateTimeout(
    mdExporter_t   *exporter,
    int             udpTimeout,
    GError        **err);

void
mdExporterFree(
    mdExporter_t *exporter);

gboolean
mdExporterEnableLocks(
    mdExporter_t  *exporter,
    GError       **err);

gboolean
mdExporterEnableDedupPerFlow(
    mdExporter_t *exporter,
    GError      **err);

void
mdExporterSetRemoveEmpty(
    mdExporter_t *exporter);

gboolean
mdExporterVerifySetup(
    mdExporter_t *exporter,
    GError      **err);

gboolean
mdExporterSetGZIPFiles(
    mdExporter_t *exporter,
    GError      **err);

gboolean
mdExporterEnableFlowsWithDpiOnly(
    mdExporter_t   *exporter,
    GError        **err);

gboolean
mdExporterEnableBasicFlowsOnly(
    mdExporter_t   *exporter,
    GError        **err);

//||void mdExporterSetTemplateCallback(
//||    mdExporter_t   *exporter);
//||

gboolean
mdExporterEnableGeneralDedup(
    mdExporter_t   *exporter,
    gboolean        only,
    GError        **err);

gboolean
mdExporterEnableSslDedup(
    mdExporter_t   *exporter,
    gboolean        only,
    GError        **err);

gboolean
mdExporterGetDnsDedupStatus(
    mdExporter_t   *exporter);

void
mdExporterEnableDnsResponseOnly(
    mdExporter_t   *exporter);

gboolean
mdExporterEnableDnsDedup(
    mdExporter_t   *exporter,
    gboolean        only,
    GError        **err);

void
mdExporterSetStats(
    mdExporter_t   *exporter,
    uint8_t         mode);

void
mdExporterSetNoFlowStats(
    mdExporter_t   *exporter);

gboolean
mdExporterSetNoIndex(
    mdExporter_t   *exporter,
    gboolean        val,
    GError        **err);

gboolean
mdExporterSetPrintHeader(
    mdExporter_t   *exporter,
    GError        **err);

gboolean
mdExporterSetEscapeChars(
    mdExporter_t   *exporter,
    GError        **err);

gboolean
mdExporterEnableMultiFiles(
    mdExporter_t   *exporter,
    GError        **err);

gboolean
mdExporterSetTimestampFiles(
    mdExporter_t   *exporter,
    GError        **err);

void
mdExporterSetRemoveUploaded(
    mdExporter_t   *exporter);

gboolean
mdExporterSetCustomList(
    mdExporter_t   *exporter,
    mdFieldEntry_t *list,
    GError        **err);

void
mdExporterCustomListDPI(
    mdExporter_t   *exporter);

//||void mdExporterSetId(
//||    mdExporter_t *exporter,
//||    uint8_t          id);
//||
gboolean
mdExporterCompareNames(
    const mdExporter_t *exporter,
    const char         *name);

gboolean
mdExporterSetSSLConfig(
    mdExporter_t   *exporter,
    uint8_t        *list,
    unsigned int    type,
    GError        **err);

gboolean
mdExporterEnableDnsRR(
    mdExporter_t   *exporter,
    gboolean        only,
    gboolean        full,
    GError        **err);

gboolean
mdExporterAddMySQLInfo(
    mdExporter_t   *exporter,
    const char     *user,
    const char     *password,
    const char     *db_name,
    const char     *db_host,
    const char     *table);

void
mdExporterCallTemplateCallback(
    mdExporter_t               *exporter,
    const mdCollector_t        *collector,
    uint16_t                    tid,
    fbTemplate_t               *tmpl,
    const fbTemplateInfo_t     *mdInfo,
    fbTemplate_t               *exporterExpTmpl,
    mdUtilTemplateType_t        templateType,
    mdUtilTemplateContents_t    templateContents);
//||
//||void mdInterruptFlowSource(
//||    mdConfig_t *md);
//||
gboolean
mdExporterFormatAndSendOrigTombstone(
    mdConfig_t         *cfg,
    mdExporter_t       *exporter,
    mdGenericRec_t     *mdRec,
    GError            **err);

int
mdExporterWriteFlow(
    mdConfig_t         *cfg,
    mdExporter_t       *exporter,
    mdFullFlow_t       *flow,
    GError            **err);

gboolean
mdSendTombstoneRecord(
    mdContext_t        *ctx,
    GError            **err);

gboolean
mdExporterWriteOptions(
    mdConfig_t         *cfg,
    mdExporter_t       *exporter,
    mdGenericRec_t     *genRec,
    GError            **err);

gboolean
mdExporterWriteDNSDedupRecord(
    mdConfig_t         *cfg,
    mdExporter_t       *exporter,
    mdGenericRec_t     *mdRec,
    GError            **err);

gboolean
mdExporterWriteGeneratedDNSDedupRecord(
    mdConfig_t         *cfg,
    mdExporter_t       *exporter,
    mdGenericRec_t     *mdRec,
    GError            **err);

gboolean
mdExportersInit(
    mdConfig_t         *cfg,
    mdExporter_t       *exporter,
    GError            **err);

gboolean
mdExporterRestart(
    mdConfig_t         *cfg,
    mdExporter_t       *exp,
    GError            **err);

gboolean
mdExporterWriteDNSRRRecord(
    mdConfig_t         *cfg,
    mdExporter_t       *exporter,
    mdGenericRec_t     *mdRec,
    GError            **err);

gboolean
mdExporterDestroy(
    mdContext_t        *ctx,
    GError            **err);

int
mdExporterDPIFlowPrint(
    mdExporter_t       *exporter,
    mdFullFlow_t       *flow,
    const GString      *prefixString,
    GError            **err);

gboolean
mdExporterTextDNSPrint(
    mdExporter_t       *exporter,
    const yafDnsQR_t   *dns,
    const GString      *prefixString);

//||GString *mdExporterJsonDNSPrint(
//||    mdExporter_t   *exporter,
//||    yafDnsQR_t     *dnsqrflow);
//||
gboolean
mdExporterConnectionReset(
    mdConfig_t         *cfg,
    GError            **err);

gboolean
mdExportDNSRR(
    mdConfig_t         *cfg,
    mdExporter_t       *exporter,
    mdFullFlow_t       *flow,
    uint16_t            tid,
    GError            **err);

/**
 *  Control what metadata is exported by IPFIX Exporters.  By default, an
 *  Exporter generates both Template description records and records the
 *  describe enterprise-specific information elements (RFC5610 records).
 *  Return TRUE unless `exporter` does not export IPFIX.
 *
 *  @param exporter            The Exporter to configure.
 *  @param describe_templates  If true, export Template Metadata; if false, do
 *                             not.
 *  @param describe_elements   If true, export RFC5610 IE Description records;
 *                             if false, do not.
 *  @param err                 An error that is filled when `exporter` does
 *                             not export IPFIX.
 */
gboolean
mdExporterSetMetadataExport(
    mdExporter_t *exporter,
    gboolean      describe_templates,
    gboolean      describe_elements,
    GError      **err);

gboolean
mdCollectorWait(
    mdContext_t *ctx,
    GError      **err);

gboolean
mdCollectorRestartListener(
    mdConfig_t         *md,
    mdCollector_t      *collector,
    GError             **err);

gboolean
mdCollectorStartListeners(
    mdConfig_t         *md,
    mdCollector_t      *collector,
    GError             **err);

void
mdCollectorListDestroy(
    mdConfig_t    *cfg,
    gboolean      active);

/** print functions */
int
mdCustomFlowPrint(
    mdFieldEntry_t     *list,
    mdFullFlow_t       *flow,
    mdExporter_t       *exporter,
    GError            **err);

gboolean
mdExporterDedupFileOpen(
    mdConfig_t          *cfg,
    mdExporter_t        *exporter,
    FILE                **file,
    char                **last_file,
    char                *prefix,
    uint64_t            *rotate,
    GError             **err);

char *
mdGetTableItem(
    const char *id);

FILE *
mdGetTableFile(
    mdExporter_t *exporter,
    const char   *id);

gboolean
mdGetDPIItem(
    GHashTable               *table,
    uint16_t                 id);

gboolean
mdTableHashEnabled(
    void);

gboolean
mdExporterAddTombstoneTemplates(
    mdExporter_t  *exporter,
    fbSession_t   *session,
    GError       **err);

void
mdExporterDedupFileClose(
    mdExporter_t *exporter,
    FILE             *fp,
    char             *last_file);

gboolean
mdExporterSSLCertRecord(
    mdConfig_t           *cfg,
    mdExporter_t         *exporter,
    FILE                 *cert_file,
    mdGenericRec_t       *mdRec,
    yfSSLFullCert_t      *fullcert,
    const uint8_t        *issuer_name,
    size_t               issuer_len,
    uint8_t              cert_no,
    GError               **err);

void
mdExporterSslProcessTypeValueList(
    md_ssl_certificate_t  *dstRec,
    fbSubTemplateList_t   *srcStl,
    const unsigned int     stlCount);

gboolean
mdExporterWriteSSLDedupRecord(
    mdConfig_t        *cfg,
    mdExporter_t  *exporter,
    mdGenericRec_t *mdRec,
    GError            **err);

gboolean
mdExporterWriteGeneralDedupRecord(
    mdConfig_t     *cfg,
    mdExporter_t   *enode,
    FILE           *fp,
    mdGenericRec_t *mdRec,
    const char     *prefix,
    GError        **err);

gboolean
mdExporterEnableCertDigest(
    mdExporter_t       *exporter,
    smCertDigestType_t  method,
    GError             **err);

const char *
mdExporterGetName(
    mdExporter_t *exporter);

gboolean
mdExporterSetMovePath(
    mdExporter_t  *exporter,
    const char    *path,
    GError       **err);

void
mdExporterSetNoFlow(
    mdExporter_t  *exporter);

//||gboolean mdExporterGetJson(
//||    mdExporter_t *exporter);

void
setExporterYafVersion(
    mdExporter_t   *exporter,
    uint8_t         yv);

void
setCollectorYafVersion(
    mdCollector_t      *collector,
    uint8_t             yv);

void
mdTemplateContextSetListOffsets(
    mdDefaultTmplCtx_t *tmplCtx,
    const fbTemplate_t *tmpl);

#endif  /* _MEDIATOR_INF_H */
