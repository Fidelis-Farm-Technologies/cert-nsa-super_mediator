/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file templates.h
 *
 *  contains all the templates the mediator needs to collect/export
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

#ifndef _MEDIATOR_TEMPLATES_H
#define _MEDIATOR_TEMPLATES_H

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
#include <fixbuf/public.h>

//||
//||/*#include "mediator_structs.h"
//||#include "mediator_util.h"*/
//||#ifdef HAVE_OPENSSL
//||#include <openssl/md5.h>
//||#include <openssl/sha.h>
//||#endif
//||
//||/* Special dimensions */
//||#define YTF_TOTAL       0x0001
//||#define YTF_PAD         0x0002
//||#define YTF_MPLS        0x0004
//||#define YTF_REV         0x0010
//||#define YTF_TCP         0x0020
//||#define YTF_DAGIF       0x0040
//||#define YTF_DELTA       0x0080
//||#define YTF_LIST        0x0100
//||#define YTF_IP4         0x0200
//||#define YTF_IP6         0x0400
//||#define YTF_MPLS        0x0004
//||#define YTF_NDPI        0x0008
//||
//||#define MD_LAST_SEEN    0x0002
//||#define MD_DNS_AREC     0x0004
#define MD_DNS_OREC     0x0008
//||#define MD_DEDUP_SSL    0x0002
//||
//||/* YAF TID's */
//||/*#define YAF_SILK_FLOW_TID            0xB000*/
//||#define YAF_STAT_OPTN_FLOW_TID       0xD000 /* old yaf stats tid */
//||#define YAF_OLD_TOMBSTONE_OPTION_TID 0xD001
//||#define YAF_OLD_TOMBSTONE_ACCESS_TID 0xD002
//||#define YAF_PROCESS_STATS_TID        0xD003
//||#define YAF_ENTROPY_TID              0xC002
//||#define YAF_TCP_TID                  0xC003
//||#define YAF_MAC_TID                  0xC004
//||#define YAF_FLOW_STATS_TID           0xC005
//||#define YAF_P0F_TID                  0xC006
//||#define YAF_HTTP_TID                 0xC600
//||#define YAF_FPEXPORT_TID             0xC007
//||#define YAF_PAYLOAD_TID              0xC008
//||#define YAF_MPTCP_TID                0xC009
//||#define YTF_BIF                      0xFF0F
//||#define YAF_IRC_TID                  0xC200
//||#define YAF_POP3_TID                 0xC300
//||#define YAF_TFTP_TID                 0xC400
//||#define YAF_SLP_TID                  0xC500
//||#define YAF_FTP_TID                  0xC700
//||#define YAF_IMAP_TID                 0xC800
//||#define YAF_RTSP_TID                 0xC900
//||#define YAF_SIP_TID                  0xCA00
//||#define YAF_SMTP_211_TID             0xCB00
//||#define YAF_SMTP_TID                 0xCB01
//||#define YAF_SMTP_MESSAGE_TID         0xCB02
//||#define YAF_SMTP_HEADER_TID          0xCB03
//||#define YAF_SSH_TID                  0xCC00
//||#define YAF_NNTP_TID                 0xCD00
//||#define YAF_DNS_TID                  0xCE00
#define YAF_DNSQR_TID                0xCF00
//||#define YAF_DNSA_TID                 0xCE01
//||#define YAF_DNSAAAA_TID              0xCE02
//||#define YAF_DNSCNAME_TID             0xCE03
//||#define YAF_DNSMX_TID                0xCE04
//||#define YAF_DNSNS_TID                0xCE05
//||#define YAF_DNSPTR_TID               0xCE06
//||#define YAF_DNSTXT_TID               0xCE07
//||#define YAF_DNSSRV_TID               0xCE08
//||#define YAF_DNSSOA_TID               0xCE09
//||#define YAF_SSL_TID                  0xCE0A
//||#define YAF_SSL_CERT_TID             0xCE0B
#define YAF_NEWSSL_TID               0xCA0A
//||#define YAF_NEWSSL_CERT_TID          0xCA0B
//||#define SM_INTSSL_FLOW_TID           0xDA0A
//||#define SM_INTCERT_FLOW_TID          0xDA0B
#define YAF_SSL_SUBCERT_TID          0xCE14
//||#define YAF_MYSQL_TID                0xCE0C
//||#define YAF_MYSQL_TXT_TID            0xCE0D
//||#define YAF_DNSDS_TID                0xCE0E
//||#define YAF_DNSRRSIG_TID             0xCE0F
//||#define YAF_DNSNSEC_TID              0xCE11
//||#define YAF_DNSKEY_TID               0xCE12
//||#define YAF_DNSNSEC3_TID             0xCE13
//||#define YAF_DHCP_FP_TID              0xC201
//||#define YAF_DNP_TID                  0xC202
//||#define YAF_DNP_REC_TID              0xC203
//||#define YAF_MODBUS_TID               0xC204
//||#define YAF_ENIP_TID                 0xC205
//||#define YAF_RTP_TID                  0xC206
//||#define YAF_FULL_CERT_TID            0xC207
//||#define YAF_DHCP_OPTIONS_TID         0xC208
//||#define MD_DNS_OUT                   0xCEE0
//||#define MD_DNS_FULL                  0xCEEF
#define MD_SSL_TID                   0xDAAF
//||#define MD_DEDUP_TID                 0xDAA8
#define MD_DEDUP_FULL                0xDAAA
#define YAF_TYPE_METADATA_TID        0xD006
#define YAF_TEMPLATE_METADATA_TID    0xD007

#define MD_TOMBSTONE_MAIN_TID       0xD100
#define MD_TOMBSTONE_ACCESS_TID     0xD101

/* The options scope for the tombstone top-level template */
#define MD_TOMBSTONE_MAIN_SCOPE     3
/* The options scope for the tombstone access-list subtemplate.  No other tool
 * or version sets the options scope on the subtemplate, so do not set it here
 * either. */
#define MD_TOMBSTONE_ACCESS_SCOPE   0


/* This is used with the mdDNSDedupTmplSpec to select LAST_SEEN elements and
 * used to modify the TID generated with MD_DNS_DEDUP_{A,O}REC.  */
#define MD_DNS_DD_LAST_SEEN         0x0001
/* This is used with the mdDNSDedupTmplSpec to select observationDomainId and
 * used to modify the TID generated with MD_DNS_DEDUP_{A,O}REC.  */
#define MD_DNS_DD_XPTR_NAME         0x0004
/* This is used with the mdDNSDedupTmplSpec to select the A-RECORD element;
 * pairs with with MD_DNS_DEDUP_AREC TID. */
#define MD_DNS_DD_AREC              0x0002
/* The base TID for DNS DEDUP A RECORD; pairs with MD_DNS_DD_AREC
 *
 * Therefore:
 *
 * DNS_DEDUP_AREC_LAST_SEEN = 0xDDDB (MD_DNS_DEDUP_AREC | MD_DNS_DD_LAST_SEEN)
 *
 * DNS_DEDUP_AREC_ADD_EXPORTER_NAME = 0xDDDE
 *
 * DNS_DEDUP_AREC_LAST_SEEN_ADD_EXPORTER_NAME = 0xDDDF
 */
#define MD_DNS_DEDUP_AREC           0xDDDA
/* This is used with the mdDNSDedupTmplSpec to select the A-RECORD element;*/
#define MD_DNS_DD_AAAAREC              0x0010

#define MD_DNS_DEDUP_AAAAREC          0xDDD8
/* This is used with the mdDNSDedupTmplSpec to select the O-RECORD element;
 * pairs with with MD_DNS_DEDUP_OREC TID. */
#define MD_DNS_DD_OREC              0x0008
/* The base TID for DNS DEDUP O RECORD; pairs with MD_DNS_DD_OREC
 *
 * Therefore:
 *
 * DNS_DEDUP_OREC_LAST_SEEN = 0xDDD1 (MD_DNS_DEDUP_OREC | MD_DNS_DD_LAST_SEEN)
 *
 * DNS_DEDUP_OREC_ADD_EXPORTER_NAME = 0xDDD4
 *
 * DNS_DEDUP_OREC_LAST_SEEN_ADD_EXPORTER_NAME = 0xDDD5
 */
#define MD_DNS_DEDUP_OREC           0xDDD0

/* TID of DNS_RR template, spec is mdDnsRRSpec, record is md_dns_rr_t.  This
 * is used as TID of internal template and non-FULL external template. */
#define MD_DNSRR                    0xC0C0
/* TID of DNS_RR_FULL template for IPv4 records */
#define MD_DNSRR_IPV4_FULL          0xC0C3
/* TID of DNS_RR_FULL template for IPv6 records */
#define MD_DNSRR_IPV6_FULL          0xC0C1
/* Used to select "FULL" elements from mdDnsRRSpec; also requires one
 * MD_DNSRR_IP4 or MD_DNSRR_IP6 */
#define MD_DNSRR_FULL               0x0001
/* Used to select IPv4 addresses from mdDnsRRSpec */
#define MD_DNSRR_IP4                0x0002
/* Used to select IPv6 addresses from mdDnsRRSpec */
#define MD_DNSRR_IP6                0x0004



#define MD_SSL_CERTIFICATE_TID       0xEE0F
#define MD_SSL_FULL_CERT_LEVEL_2     0xE512
#define MD_SSL_FULL_CERT_LEVEL_3     0xE513

//||#define MD_TEXT_BASE_TID            0xEF10
//||#define MD_TEXT_ENTROPY_TID         0xEF11
//||#define MD_TEXT_MPTCP_TID           0xEF12
//||#define MD_TEXT_MAC_TID             0xEF13
//||#define MD_TEXT_P0F_TID             0xEF14
//||#define MD_TEXT_FPEXPORT_TID        0xEF15
//||#define MD_TEXT_PAYLOAD_TID         0xEF16
//||#define MD_TEXT_STATS_TID           0xEF17
//||#define MD_TEXT_TCP_TID             0xEF18
//||#define MD_TEXT_DHCP_TID            0xEF19

#define MD_ERROR_DOMAIN     g_quark_from_string("MediatorError")
/* Template Issue - Not Critical*/
#define MD_ERROR_TMPL   1
/* IO Error - Critical */
#define MD_ERROR_IO     2
/* Setup Error */
#define MD_ERROR_SETUP  3
/* memory problem */
#define MD_ERROR_MEM    4
/* Error to ignore */
#define MD_ERROR_NODROP 5


/* MD specific names */
#define MD_DNS_AREC_NAME        "sm_dns_dedup_arec"
#define MD_DNS_OREC_NAME        "sm_dns_dedup_orec"
#define MD_DNS_AAAAREC_NAME     "sm_dns_dedup_aaaarec"
#define MD_DNS_AREC_LS_NAME     "sm_dns_dedup_arec_last_seen"
#define MD_DNS_OREC_LS_NAME     "sm_dns_dedup_orec_last_seen"
#define MD_DNS_AAAAREC_LS_NAME     "sm_dns_dedup_aaaarec_last_seen"
#define MD_DNSRR_NAME           "sm_dnsrr"
#define MD_DNSRR_IPV4_FULL_NAME    "sm_dnsrr_ipv4_full"
//||#define MD_DNSRR_IPV6_NAME         "sm_dnsrr_ipv6"
#define MD_DNSRR_IPV6_FULL_NAME    "sm_dnsrr_ipv6_full"
#define MD_SSL_DEDUP_NAME       "sm_ssl_dedup"
#define MD_SSL_CERTIFICATE_NAME "sm_rewritten_ssl_certificate"
#define MD_SSL_DEDUP_CERT_NAME  "sm_ssl_cert"
#define MD_SSL_DEDUP_SUBCERT_NAME   "sm_ssl_sub_cert"
//||
//||/* also defined in yafcore.c, should consider pulling from YAF */
//||#define YTF_TOTAL_NAME "total"
//||#define YTF_REV_NAME         "rev"
//||#define YTF_DELTA_NAME       "delta"
//||#define YTF_IP6_NAME "ip6"
//||#define YTF_IP4_NAME "ip4"
//||#define YTF_DAGIF_NAME       "dagif"
//||#define YTF_MPLS_NAME        "mpls"
//||#define YTF_NDPI_NAME        "ndpi"
//||
//||/* not defined in YAF, should consider including in YAF */
//||#define YTF_TCP_NAME "tcp"
//||#define YTF_PAD_NAME "pad"
//||#define YTF_LIST_NAME "list"
//||
/* YAF-defined values for flowEndReason.  See yafcore.h in YAF sources. */
/** Flow ended due to idle timeout. */
#define YAF_END_IDLE            1
/** Flow ended due to active timeout. */
#define YAF_END_ACTIVE          2
/** Flow ended due to FIN or RST close. */
#define YAF_END_CLOSED          3
/** Flow ended due to YAF shutdown. */
#define YAF_END_FORCED          4
/** Flow flushed due to YAF resource exhaustion. */
#define YAF_END_RESOURCE        5
/** Flow flushed due to udp-uniflow on all or selected ports.*/
#define YAF_END_UDPFORCE        0x1F
/** Flow reason mask */
#define YAF_END_MASK            0x7F
/** SiLK mode flow reason flag - flow was created after active termination */
#define YAF_ENDF_ISCONT         0x80

/* The internal full DNS flow (DNSDedup) record; expected to match
 * mdDNSDedupTmplSpec */
typedef struct md_dns_dedup_st {
    uint64_t      flowStartMilliseconds;
    uint64_t      flowEndMilliseconds;
    uint8_t       sourceIPv6Address[16];
    uint32_t      sourceIPv4Address;
    uint32_t      dnsTTL;
    uint16_t      rrtype;
    /* dnsHitCount is here to support SM1 */
    uint16_t      dnsHitCount;
    uint32_t      smDedupHitCount;
    fbVarfield_t  rrname;
    fbVarfield_t  rrdata;
    fbVarfield_t  observationDomainName;
} md_dns_dedup_t;


/* SSL Dedup Record; must match mdSSLDedupSpec; template ID is MD_SSL_TID */
typedef struct md_ssl_st {
    uint64_t      flowStartMilliseconds;
    uint64_t      flowEndMilliseconds;
    uint64_t      smDedupHitCount;
    fbVarfield_t  sslCertSerialNumber;
    fbVarfield_t  sslCertIssuerCommonName;
    fbVarfield_t  observationDomainName;
} md_ssl_t;

/* "used 1" means used in top stats log message
 * "used 2" means used in lower stats log message */
typedef struct yafStatsV1Rec_st {
    uint64_t    systemInitTimeMilliseconds; /* used 1*/
    uint64_t    exportedFlowRecordTotalCount; /* used 2 */
    uint64_t    packetTotalCount; /* used 2 */
    uint64_t    droppedPacketTotalCount; /* used 2 */
    uint64_t    ignoredPacketTotalCount; /* used 2 */
    uint64_t    notSentPacketTotalCount; /* used 2 */
    uint32_t    yafExpiredFragmentCount; /* used 2 */
    uint32_t    yafAssembledFragmentCount; /* used 2 */
    uint32_t    yafFlowTableFlushEventCount; /* used 2 */
    uint32_t    yafFlowTablePeakCount; /* used 2 */
    uint32_t    exporterIPv4Address; /* used 1 */
    uint32_t    exportingProcessId; /* used 1 */
    uint32_t    yafMeanFlowRate; /* used 2 */
    uint32_t    yafMeanPacketRate; /* used 2 */
} yafStatsV1Rec_t;


typedef struct yafStatsV2Rec_st {
    uint32_t    observationDomainId; /* used 1*/
    uint32_t    exportingProcessId; /* used 1*/
    uint32_t    exporterIPv4Address; /* used 1*/
    uint32_t    observationTimeSeconds; /* used 1*/
    uint64_t    systemInitTimeMilliseconds; /* used 1*/
    uint64_t    exportedFlowRecordTotalCount; /* used 2 */
    uint64_t    packetTotalCount; /* used 2 */
    uint64_t    droppedPacketTotalCount; /* used 2 */
    uint64_t    ignoredPacketTotalCount; /* used 2 */
    uint64_t    notSentPacketTotalCount; /* used 2 */
    uint32_t    yafExpiredFragmentCount; /* used 2 */
    uint32_t    yafAssembledFragmentCount; /* used 2 */
    uint32_t    yafFlowTableFlushEventCount; /* used 2 */
    uint32_t    yafFlowTablePeakCount; /* used 2 */
    uint32_t    yafMeanFlowRate; /* used 2 */
    uint32_t    yafMeanPacketRate; /* used 2 */
} yafStatsV2Rec_t;

typedef struct tombstoneMainV1Rec_st {
    uint16_t            certToolExporterUniqueId;
    uint16_t            certToolExporterConfiguredId;
    uint32_t            certToolTombstoneId;
    fbSubTemplateList_t accessList;
} tombstoneMainV1Rec_t;

typedef struct tombstoneAccessV1Rec_st {
    uint32_t    exportingProcessId;
    uint32_t    observationTimeSeconds;
} tombstoneAccessV1Rec_t;

typedef struct tombstoneMainV2Rec_st {
    uint32_t            observationDomainId;
    uint32_t            exportingProcessId;
    uint16_t            certToolExporterConfiguredId;
    /* for compatibilty with TombstoneMainV1, is paddingOctets in V2 */
    uint16_t            certToolExporterUniqueId;
    uint8_t             paddingOctets[4];
    uint32_t            certToolTombstoneId;
    uint32_t            observationTimeSeconds;
    fbSubTemplateList_t accessList;
} tombstoneMainV2Rec_t;

typedef struct tombstoneAccessV2Rec_st {
    uint32_t    certToolId;
    uint32_t    observationTimeSeconds;
} tombstoneAccessV2Rec_t;

//||typedef struct yaf_ssl_st {
//||    fbBasicList_t sslCipherList;
//||    fbSubTemplateList_t  sslCertList; // TODO: Identify and clean up
//||    uint32_t      sslServerCipher;
//||    uint8_t       sslClientVersion;
//||    uint8_t       sslCompressionMethod;
//||    uint8_t       padding[2];
//||} yaf_ssl_t;

typedef struct yaf_newssl_st {
    fbBasicList_t        sslCipherList;
    fbBasicList_t        sslBinaryCertificateList;
    fbVarfield_t         sslServerName;
    fbSubTemplateList_t  sslCertList;
    uint32_t             sslServerCipher;
    uint8_t              sslClientVersion;
    uint8_t              sslCompressionMethod;
    uint16_t             sslRecordVersion;
} yaf_newssl_t;

typedef struct yaf_ssl_subcert_st {
    fbVarfield_t            sslObjectValue;
    uint8_t                 sslObjectType;
    uint8_t                 padding[7];
} yaf_ssl_subcert_t;

//||
//||typedef struct yaf_ssl_cert_st {
//||    fbVarfield_t sslSignature;
//||    fbVarfield_t sslIssuerCountryName;
//||    fbVarfield_t sslIssuerOrgName;
//||    fbVarfield_t sslIssuerOrgUnitName;
//||    fbVarfield_t sslIssuerZipCode;
//||    fbVarfield_t sslIssuerState;
//||    fbVarfield_t sslIssuerCommonName;
//||    fbVarfield_t sslIssuerLocalityName;
//||    fbVarfield_t sslIssuerStreetAddress;
//||    fbVarfield_t sslSubCountryName;
//||    fbVarfield_t sslSubOrgName;
//||    fbVarfield_t sslSubOrgUnitName;
//||    fbVarfield_t sslSubZipCode;
//||    fbVarfield_t sslSubState;
//||    fbVarfield_t sslSubCommonName;
//||    fbVarfield_t sslSubLocalityName;
//||    fbVarfield_t sslSubStreetAddress;
//||    uint8_t     sslVersion;
//||} yaf_ssl_cert_t;
//||
/* The flattened record representing a single SSL Certificate */
typedef struct md_ssl_certificate_st {
    /** Issuer **/
    /* id-at-commonName {id-at 3} */
    fbBasicList_t       sslCertIssuerCommonNameList;
    /* id-at-countryName {id-at 6} */
    fbVarfield_t        sslCertIssuerCountryName;
    /* id-at-localityName {id-at 7} */
    fbVarfield_t        sslCertIssuerLocalityName;
    /* id-at-stateOrProvidenceName {id-at 8} */
    fbVarfield_t        sslCertIssuerState;
    /* id-at-streetAddress {id-at 9} */
    fbBasicList_t       sslCertIssuerStreetAddressList;
    /* id-at-organizationName {id-at 10} */
    fbBasicList_t       sslCertIssuerOrgNameList;
    /* id-at-organizationUnitName {id-at 11} */
    fbBasicList_t       sslCertIssuerOrgUnitNameList;
    /* id-at-postalCode {id-at 17} */
    fbVarfield_t        sslCertIssuerZipCode;
    /* id-at-title {id-at 12} */
    fbVarfield_t        sslCertIssuerTitle;
    /* id-at-name {id-at 41} */
    fbVarfield_t        sslCertIssuerName;
    /* pkcs-9-emailAddress {pkcs-9 1} */
    fbVarfield_t        sslCertIssuerEmailAddress;
    /* 0.9.2342.19200300.100.1.25 {dc 25} */
    fbBasicList_t       sslCertIssuerDomainComponentList;

    /** Subject **/
    /* id-at-commonName {id-at 3} */
    fbBasicList_t       sslCertSubjectCommonNameList;
    /* id-at-countryName {id-at 6} */
    fbVarfield_t        sslCertSubjectCountryName;
    /* id-at-localityName {id-at 7} */
    fbVarfield_t        sslCertSubjectLocalityName;
    /* id-at-stateOrProvidenceName {id-at 8} */
    fbVarfield_t        sslCertSubjectState;
    /* id-at-streetAddress {id-at 9} */
    fbBasicList_t       sslCertSubjectStreetAddressList;
    /* id-at-organizationName {id-at 10} */
    fbBasicList_t       sslCertSubjectOrgNameList;
    /* id-at-organizationUnitName {id-at 11} */
    fbBasicList_t       sslCertSubjectOrgUnitNameList;
    /* id-at-postalCode {id-at 17} */
    fbVarfield_t        sslCertSubjectZipCode;
    /* id-at-title {id-at 12} */
    fbVarfield_t        sslCertSubjectTitle;
    /* id-at-name {id-at 41} */
    fbVarfield_t        sslCertSubjectName;
    /* pkcs-9-emailAddress {pkcs-9 1} */
    fbVarfield_t        sslCertSubjectEmailAddress;
    /* 0.9.2342.19200300.100.1.25 {dc 25} */
    fbBasicList_t       sslCertSubjectDomainComponentList;

    /** Extensions **/
    /* id-ce-subjectKeyIdentifier {id-ce 14} */
    fbVarfield_t        sslCertExtSubjectKeyIdent;
    /* id-ce-keyUsage {id-ce 15} */
    fbVarfield_t        sslCertExtKeyUsage;
    /* id-ce-privateKeyUsagePeriod {id-ce 16} */
    fbVarfield_t        sslCertExtPrivKeyUsagePeriod;
    /* id-ce-subjectAltName {id-ce 17} */
    fbVarfield_t        sslCertExtSubjectAltName;
    /* id-ce-issuerAltName {id-ce 18} */
    fbVarfield_t        sslCertExtIssuerAltName;
    /* id-ce-certificateIssuer {id-ce 29} */
    fbVarfield_t        sslCertExtCertIssuer;
    /* id-ce-cRLDistributionPoints {id-ce 37} */
    fbVarfield_t        sslCertExtCrlDistribution;
    /* id-ce-certificatePolicies {id-ce 32} */
    fbVarfield_t        sslCertExtCertPolicies;
    /* id-ce-authorityKeyIdentifier {id-ce 35} */
    fbVarfield_t        sslCertExtAuthorityKeyIdent;
    /* id-ce-extKeyUsage {id-ce 37} */
    fbVarfield_t        sslCertExtExtendedKeyUsage;

#if 0
    /* the remaining fields must be kept in sync with yaf_newssl_cert_t */
    fbVarfield_t        sslCertSignature;
    fbVarfield_t        sslCertSerialNumber;
    fbVarfield_t        sslCertValidityNotBefore;
    fbVarfield_t        sslCertValidityNotAfter;
    fbVarfield_t        sslPublicKeyAlgorithm;
    uint16_t            sslPublicKeyLength;
    uint8_t             sslCertVersion;
    uint8_t             paddingOctets[5];
    fbVarfield_t        sslCertificateHash;
#endif  /* 0 */
} md_ssl_certificate_t;

//||typedef struct yaf_http_st {
//||    fbBasicList_t server;
//||    fbBasicList_t userAgent;
//||    fbBasicList_t get;
//||    fbBasicList_t connection;
//||    fbBasicList_t referer;
//||    fbBasicList_t location;
//||    fbBasicList_t host;
//||    fbBasicList_t contentLength;
//||    fbBasicList_t age;
//||    fbBasicList_t response;
//||    fbBasicList_t acceptLang;
//||    fbBasicList_t accept;
//||    fbBasicList_t contentType;
//||    fbBasicList_t version;
//||    fbBasicList_t cookie;
//||    fbBasicList_t setcookie;
//||    fbBasicList_t httpAuthorization;
//||    fbBasicList_t httpVia;
//||    fbBasicList_t xforward;
//||    fbBasicList_t httpRefresh;
//||    uint8_t       httpBasicListBuf[0];
//||} yaf_http_t;
//||
//||typedef struct yaf_irc_st {
//||    fbBasicList_t ircMsg;
//||} yaf_irc_t;
//||
//||typedef struct yaf_pop3_st {
//||    fbBasicList_t pop3msg;
//||} yaf_pop3_t;
//||
//||typedef struct yaf_tftp_st {
//||    fbVarfield_t tftpFilename;
//||    fbVarfield_t tftpMode;
//||} yaf_tftp_t;
//||
//||typedef struct yaf_slp_st {
//||    fbBasicList_t slpString;
//||    uint8_t     slpVersion;
//||    uint8_t     slpMessageType;
//||    uint8_t     padding[6];
//||} yaf_slp_t;
//||
//||typedef struct yaf_ftp_st {
//||    fbBasicList_t ftpReturn;
//||    fbBasicList_t ftpUser;
//||    fbBasicList_t ftpPass;
//||    fbBasicList_t ftpType;
//||    fbBasicList_t ftpRespCode;
//||    uint8_t       ftpBasicListBuf[0];
//||} yaf_ftp_t;
//||
//||typedef struct yaf_imap_st {
//||    fbBasicList_t imapCapability;
//||    fbBasicList_t imapLogin;
//||    fbBasicList_t imapStartTLS;
//||    fbBasicList_t imapAuthenticate;
//||    fbBasicList_t imapCommand;
//||    fbBasicList_t imapExists;
//||    fbBasicList_t imapRecent;
//||    uint8_t       imapBasicListBuf[0];
//||} yaf_imap_t;
//||
//||typedef struct yaf_rtsp_st {
//||    fbBasicList_t rtspURL;
//||    fbBasicList_t rtspVersion;
//||    fbBasicList_t rtspReturnCode;
//||    fbBasicList_t rtspContentLength;
//||    fbBasicList_t rtspCommand;
//||    fbBasicList_t rtspContentType;
//||    fbBasicList_t rtspTransport;
//||    fbBasicList_t rtspCSeq;
//||    fbBasicList_t rtspLocation;
//||    fbBasicList_t rtspPacketsReceived;
//||    fbBasicList_t rtspUserAgent;
//||    fbBasicList_t rtspJitter;
//||    uint8_t       rtspBasicListBuf[0];
//||} yaf_rtsp_t;
//||
//||typedef struct yaf_sip_st {
//||    fbBasicList_t sipInvite;
//||    fbBasicList_t sipCommand;
//||    fbBasicList_t sipVia;
//||    fbBasicList_t sipMaxForwards;
//||    fbBasicList_t sipAddress;
//||    fbBasicList_t sipContentLength;
//||    fbBasicList_t sipUserAgent;
//||    uint8_t       sipBasicListBuf[0];
//||} yaf_sip_t;
//||
//||/* SMTP record up to yaf 2.11.0 inclusive */
//||typedef struct yaf_smtp_211_st {
//||    fbBasicList_t smtpHello;
//||    fbBasicList_t smtpFrom;
//||    fbBasicList_t smtpTo;
//||    fbBasicList_t smtpContentType;
//||    fbBasicList_t smtpSubject;
//||    fbBasicList_t smtpFilename;
//||    fbBasicList_t smtpContentDisposition;
//||    fbBasicList_t smtpResponse;
//||    fbBasicList_t smtpEnhanced;
//||    fbBasicList_t smtpSize;
//||    fbBasicList_t smtpDate;
//||    uint8_t       smtpBasicListBuf[0];
//||} yaf_smtp_211_t;
//||
//||/* SMTP record after yaf 2.11.0 */
//||typedef struct yaf_smtp_st {
//||    fbBasicList_t         smtpFailedCodes;
//||    uint32_t              smtpMessageSize;
//||    uint8_t               padding[4];
//||    fbVarfield_t          smtpHello;
//||    fbSubTemplateList_t   smtpMessageList;
//||    fbVarfield_t          smtpEnhanced;
//||    uint8_t               smtpStartTLS;
//||} yaf_smtp_t;
//||
//||typedef struct yaf_smtp_message_st {
//||    fbBasicList_t         smtpToList;
//||    fbBasicList_t         smtpFromList;
//||    fbBasicList_t         smtpFilenameList;
//||    fbBasicList_t         smtpURLList;
//||    fbSubTemplateList_t   smtpHeaderList;
//||    fbVarfield_t          smtpSubject;
//||} yaf_smtp_message_t;
//||
//||typedef struct yaf_smtp_header_st {
//||    fbVarfield_t   smtpKey;
//||    fbVarfield_t   smtpValue;
//||} yaf_smtp_header_t;
//||
//||typedef struct yaf_ssh_st {
//||    fbBasicList_t sshVersion;
//||    uint8_t       sshBasicListBuf[0];
//||} yaf_ssh_t;
//||
//||typedef struct yaf_nntp_st {
//||    fbBasicList_t nntpResponse;
//||    fbBasicList_t nntpCommand;
//||} yaf_nntp_t;
//||

typedef struct yaf_dns_st {
    fbSubTemplateList_t   dnsQRList;
} yaf_dns_t;


typedef struct yafDnsQR_st {
    fbSubTemplateList_t dnsRRList;
    fbVarfield_t        dnsName;
    uint32_t            dnsTTL;
    uint16_t            dnsRRType;
    uint8_t             dnsQueryResponse;
    uint8_t             dnsAuthoritative;
    uint8_t             dnsResponseCode;
    uint8_t             dnsSection;
    uint16_t            dnsId;
} yafDnsQR_t;

typedef struct yaf_dnsA_st {
    uint32_t dnsA;
} yaf_dnsA_t;

typedef struct yaf_dnsAAAA_st {
    uint8_t  dnsAAAA[16];
} yaf_dnsAAAA_t;

typedef struct yaf_dnsCNAME_st {
    fbVarfield_t dnsCNAME;
} yaf_dnsCNAME_t;

typedef struct yaf_dnsMX_st {
    fbVarfield_t dnsMXExchange;
    uint16_t     dnsMXPreference;
    uint8_t      padding[6];
} yaf_dnsMX_t;

typedef struct yaf_dnsNS_st {
    fbVarfield_t dnsNSDName;
} yaf_dnsNS_t;

typedef struct yaf_dnsPTR_st {
    fbVarfield_t dnsPTRDName;
} yaf_dnsPTR_t;

typedef struct yaf_dnsTXT_st {
    fbVarfield_t dnsTXTData;
} yaf_dnsTXT_t;

typedef struct yaf_dnsSOA_st {
    fbVarfield_t dnsSOAMName;
    fbVarfield_t dnsSOARName;
    uint32_t     dnsSOASerial;
    uint32_t     dnsSOARefresh;
    uint32_t     dnsSOARetry;
    uint32_t     dnsSOAExpire;
    uint32_t     dnsSOAMinimum;
    uint8_t      padding[4];
} yaf_dnsSOA_t;

typedef struct yaf_dnsSRV_st {
    fbVarfield_t dnsSRVTarget;
    uint16_t     dnsSRVPriority;
    uint16_t     dnsSRVWeight;
    uint16_t     dnsSRVPort;
    uint8_t      padding[2];
} yaf_dnsSRV_t;

typedef struct yaf_dnsRRSig_st {
    fbVarfield_t dnsRRSIGSigner;
    fbVarfield_t dnsRRSIGSignature;
    uint32_t     dnsRRSIGSignatureInception;
    uint32_t     dnsRRSIGSignatureExpiration;
    uint32_t     dnsRRSIGOriginalTTL;
    uint16_t     dnsRRSIGKeyTag;
    uint16_t     dnsRRSIGTypeCovered;
    uint8_t      dnsRRSIGAlgorithm;
    uint8_t      dnsRRSIGLabels;
    uint8_t      padding[6];
} yaf_dnsRRSig_t;

//||typedef struct yaf_dnsDS_st {
//||    fbVarfield_t dnsDSDigest;
//||    uint16_t     dnsDSKeyTag;
//||    uint8_t      dnsDSAlgorithm;
//||    uint8_t      dnsDSDigestType;
//||    uint8_t      padding[4];
//||} yaf_dnsDS_t;
//||
//||typedef struct yaf_dnsKey_st {
//||    fbVarfield_t dnsDNSKEYPublicKey;
//||    uint16_t     dnsDNSKEYFlags;
//||    uint8_t      dnsDNSKEYProtocol;
//||    uint8_t      dnsDNSKEYAlgorithm;
//||    uint8_t      padding[4];
//||} yaf_dnsKey_t;
//||
typedef struct yaf_dnsNSEC_st {
    fbVarfield_t dnsNSECNextDomainName;
    /* The following IE was added in YAF3.  It is currently commented out
     * since it is unused in super_mediator. */
    /* fbVarfield_t dnsNSECTypeBitMaps; */
} yaf_dnsNSEC_t;

//||typedef struct yaf_dnsNSEC3_st {
//||    fbVarfield_t dnsNSEC3Salt;
//||    fbVarfield_t dnsNSEC3NextHashedOwnerName;
//||    /* The following IE was added in YAF3. */
//||    fbVarfield_t dnsNSEC3TypeBitMaps;
//||    uint16_t     dnsNSEC3Iterations;
//||    uint8_t      dnsNSEC3Algorithm;
//||    /* The following IE was added in YAF3. */
//||    uint8_t      dnsNSEC3Flags;
//||    uint8_t      padding[4];
//||} yaf_dnsNSEC3_t;
//||
//||typedef struct yaf_mysql_st {
//||    fbSubTemplateList_t mysqlList;
//||    fbVarfield_t        mysqlUsername;
//||} yaf_mysql_t;
//||
//||typedef struct yaf_mysql_txt_st {
//||    fbVarfield_t  mysqlCommandText;
//||    uint8_t       mysqlCommandCode;
//||    uint8_t       padding[7];
//||} yaf_mysql_txt_t;
//||
//||typedef struct yaf_dhcp_fp_st {
//||    fbVarfield_t dhcpFingerprint;
//||    fbVarfield_t dhcpVendorCode;
//||    fbVarfield_t reverseDhcpFingerprint;
//||    fbVarfield_t reverseDhcpVendorCode;
//||} yaf_dhcp_fp_t;
//||
//||typedef struct yaf_dhcp_options_st {
//||    fbBasicList_t options;
//||    fbVarfield_t dhcpVendorCode;
//||    fbBasicList_t revOptions;
//||    fbVarfield_t reverseDhcpVendorCode;
//||} yaf_dhcp_options_t;
//||
//||typedef struct yaf_rtp_st {
//||    uint8_t rtpPayloadType;
//||    uint8_t reverseRtpPayloadType;
//||} yaf_rtp_t;
//||
//||typedef struct yaf_dnp_st {
//||    fbSubTemplateList_t dnp_list;
//||} yaf_dnp_t;
//||
//||typedef struct yaf_dnp_rec_st {
//||    fbVarfield_t dnp3ObjectData;
//||    uint16_t dnp3SourceAddress;
//||    uint16_t dnp3DestinationAddress;
//||    uint8_t  dnp3Function;
//||} yaf_dnp_rec_t;
//||
//||typedef struct yaf_modbus_st {
//||    fbBasicList_t mbmsg;
//||} yaf_modbus_t;
//||
//||typedef struct yaf_enip_st {
//||    fbBasicList_t enipmsg;
//||} yaf_enip_t;
//||

/* DNS RR struct; must match mdDnsRRSpec internal template; TID is MD_DNSRR */
typedef struct md_dns_rr_st {
    uint64_t      flowStartMilliseconds;
    uint8_t       sourceIPv6Address[16];
    uint8_t       destinationIPv6Address[16];
    uint32_t      sourceIPv4Address;
    uint32_t      destinationIPv4Address;
    uint32_t      dnsTTL;
    uint32_t      observationDomainId;
    uint32_t      yafFlowKeyHash;
    uint16_t      dnsRRType;
    uint16_t      sourceTransportPort;
    uint16_t      destinationTransportPort;
    uint16_t      vlanId;
    uint16_t      dnsId;
    uint8_t       protocolIdentifier;
    uint8_t       dnsQueryResponse;
    uint8_t       dnsAuthoritative;
    uint8_t       dnsResponseCode;
    uint8_t       dnsSection;
    uint8_t       padding[5];
    fbVarfield_t  rrname;
    fbVarfield_t  rrdata;
} md_dns_rr_t;

/* The general dedup template as of SM 1.5.0. */
typedef struct md_dedup_st {
    uint64_t      monitoringIntervalStartMilliSeconds;
    uint64_t      monitoringIntervalEndMilliSeconds;
    /* with hash this (stime) makes unique key */
    uint64_t      flowStartMilliseconds;
    uint64_t      smDedupHitCount;
    uint8_t       sourceIPv6Address[16];
    uint32_t      sourceIPv4Address;
    uint32_t      yafFlowKeyHash;
    fbVarfield_t  observationDomainName;
    fbVarfield_t  smDedupData;
    /* ssl only fields */
    fbVarfield_t  sslCertSerialNumber1;
    fbVarfield_t  sslCertIssuerCommonName1;
    fbVarfield_t  sslCertSerialNumber2;
    fbVarfield_t  sslCertIssuerCommonName2;
} md_dedup_t;

/* FIXME: mthomas.2021.10.28 Merge this type with the previous and use a union
 * as the smDedupData member.  This type exists to support dedup on
 * non-Varfield elements (which is currently disabled in the parser until
 * printing of non-Varfield elements is fixed to not SEGV). */
typedef struct md_dedup_general_st {
    uint64_t      monitoringIntervalStartMilliSeconds;
    uint64_t      monitoringIntervalEndMilliSeconds;
    /* with hash this (stime) makes unique key */
    uint64_t      flowStartMilliseconds;
    uint64_t      smDedupHitCount;
    uint8_t       sourceIPv6Address[16];
    uint32_t      sourceIPv4Address;
    uint32_t      yafFlowKeyHash;
    fbVarfield_t  observationDomainName;
    uint8_t       smDedupData[16];
    /* ssl only fields */
    fbVarfield_t  sslCertSerialNumber1;
    fbVarfield_t  sslCertIssuerCommonName1;
    fbVarfield_t  sslCertSerialNumber2;
    fbVarfield_t  sslCertIssuerCommonName2;
} md_dedup_general_t;


/* The general dedup template in SM 1.4.0 and earlier; flowStartMilliseconds
 * was added in SM 1.5.0 */
typedef struct md_dedup_sm140_st {
    uint64_t      fseen;
    uint64_t      lseen;
    uint64_t      count;
    uint8_t       sip6[16];
    uint32_t      sip;
    uint32_t      hash;
    fbVarfield_t  data;
    /* ssl only fields */
    fbVarfield_t  serial1;
    fbVarfield_t  issuer1;
    fbVarfield_t  serial2;
    fbVarfield_t  issuer2;
} md_dedup_sm140_t;

//||typedef struct yaf_entropy_st {
//||    uint8_t     payloadEntropy;
//||    uint8_t     reversePayloadEntropy;
//||} yaf_entropy_t;
//||
//||typedef struct yaf_tcp_st {
//||    uint32_t    tcpSequenceNumber;
//||    uint8_t     initialTCPFlags;
//||    uint8_t     unionTCPFlags;
//||    uint8_t     reverseInitialTCPFlags;
//||    uint8_t     reverseUnionTCPFlags;
//||    uint32_t    reverseTcpSequenceNumber;
//||} yaf_tcp_t;
//||
//||typedef struct yaf_mac_st {
//||    uint8_t     sourceMacAddress[6];
//||    uint8_t     destinationMacAddress[6];
//||} yaf_mac_t;
//||
//||typedef struct yaf_p0f_st {
//||    fbVarfield_t    osName;
//||    fbVarfield_t    osVersion;
//||    fbVarfield_t    osFingerprint;
//||    fbVarfield_t    reverseOsName;
//||    fbVarfield_t    reverseOsVersion;
//||    fbVarfield_t    reverseOsFingerprint;
//||} yaf_p0f_t;
//||
//||typedef struct yaf_fpexport_st {
//||    fbVarfield_t    firstPacketBanner;
//||    fbVarfield_t    secondPacketBanner;
//||    fbVarfield_t    reverseFirstPacketBanner;
//||} yaf_fpexport_t;
//||
//||typedef struct yaf_payload_st {
//||    fbVarfield_t payload;
//||    fbVarfield_t reversePayload;
//||} yaf_payload_t;
//||
//||typedef struct yaf_mptcp_st {
//||    /** initial data seq no. */
//||    uint64_t          mptcpInitialDataSequenceNumber;
//||    /** receiver token */
//||    uint32_t          mptcpReceiverToken;
//||    /** max segment size */
//||    uint16_t          mptcpMaximumSegmentSize;
//||    /* addr id */
//||    uint8_t           mptcpAddressId;
//||    /* hash_flags */
//||    uint8_t           mptcpFlags;
//||} yaf_mptcp_t;
//||
//||typedef struct yaf_flow_stats_st {
//||    uint64_t dataByteCount;
//||    uint64_t averageInterarrivalTime;
//||    uint64_t standardDeviationInterarrivalTime;
//||    uint32_t tcpUrgTotalCount;
//||    uint32_t smallPacketCount;
//||    uint32_t nonEmptyPacketCount;
//||    uint32_t largePacketCount;
//||    uint16_t firstNonEmptyPacketSize;
//||    uint16_t maxPacketSize;
//||    uint16_t standardDeviationPayloadLength;
//||    uint8_t  firstEightNonEmptyPacketDirections;
//||    uint8_t  padding[1];
//||    /* reverse Fields */
//||    uint64_t reverseDataByteCount;
//||    uint64_t reverseAverageInterarrivalTime;
//||    uint64_t reverseStandardDeviationInterarrivalTime;
//||    uint32_t reverseTcpUrgTotalCount;
//||    uint32_t reverseSmallPacketCount;
//||    uint32_t reverseNonEmptyPacketCount;
//||    uint32_t reverseLargePacketCount;
//||    uint16_t reverseFirstNonEmptyPacketSize;
//||    uint16_t reverseMaxPacketSize;
//||    uint16_t reverseStandardDeviationPayloadLength;
//||    uint8_t  padding2[2];
//||} yaf_flow_stats_t;
//||
typedef struct yfSSLFullCert_st {
    fbBasicList_t          cert;
} yfSSLFullCert_t;

typedef struct yafSSLDPICert_st {
    fbSubTemplateList_t     issuer;
    fbSubTemplateList_t     subject;
    fbSubTemplateList_t     extension;
    /* remaining fields must match end of md_ssl_certificate_t */
    fbVarfield_t            sslCertSignature;
    fbVarfield_t            sslCertSerialNumber;
    fbVarfield_t            sslCertValidityNotBefore;
    fbVarfield_t            sslCertValidityNotAfter;
    fbVarfield_t            sslPublicKeyAlgorithm;
    uint16_t                sslPublicKeyLength;
    uint8_t                 sslCertVersion;
    uint8_t                 padding[5];
    fbVarfield_t            sslCertificateHash;
#if 0
    /* these are never referenced by name; are they still needed? */
    fbVarfield_t            sha1;
    fbVarfield_t            md5;
#endif  /* 0 */
} yafSSLDPICert_t;
//||
//||typedef struct md_text_base_rec_st {
//||    uint64_t    flowStartMilliseconds;
//||    uint64_t    flowEndMilliseconds;
//||
//||    uint64_t    octetTotalCount;
//||    uint64_t    reverseOctetTotalCount;
//||    uint64_t    packetTotalCount;
//||    uint64_t    reversePacketTotalCount;
//||
//||    uint64_t    octetDeltaCount;
//||    uint64_t    reverseOctetDeltaCount;
//||    uint64_t    packetDeltaCount;
//||    uint64_t    reversePacketDeltaCount;
//||
//||    uint8_t     sourceIPv6Address[16];
//||    uint8_t     destinationIPv6Address[16];
//||
//||    uint32_t    sourceIPv4Address;
//||    uint32_t    destinationIPv4Address;
//||
//||    uint16_t    sourceTransportPort;
//||    uint16_t    destinationTransportPort;
//||    uint16_t    flowAttributes;
//||    uint16_t    reverseFlowAttributes;
//||
//||    uint8_t     protocolIdentifier;
//||    uint8_t     flowEndReason;
//||    uint16_t    silkAppLabel;
//||    int32_t     reverseFlowDeltaMilliseconds;
//||
//||    uint16_t    vlanId;
//||    uint16_t    reverseVlanId;
//||    uint32_t    ingressInterface;
//||    uint32_t    egressInterface;
//||    uint8_t     ipClassOfService;
//||    uint8_t     reverseIpClassOfService;
//||
//||    uint8_t     paddingOctets;
//||    uint8_t     mplsTopLabelStackSection[3];
//||    uint8_t     mplsLabelStackSection2[3];
//||    uint8_t     mplsLabelStackSection3[3];
//||
//||    uint16_t    ndpiL7Protocol;
//||    uint16_t    ndpiL7SubProtocol;
//||
//||    fbSubTemplateMultiList_t subTemplateMultiList;
//||
//||} md_text_base_rec_t;
//||
//||typedef struct md_text_entropy_st {
//||    uint8_t     payloadEntropy;
//||    uint8_t     reversePayloadEntropy;
//||} md_text_entropy_t;
//||
//||typedef struct md_text_mptcp_st {
//||    uint64_t          mptcpInitialDataSequenceNumber;
//||    uint32_t          mptcpReceiverToken;
//||    uint16_t          mptcpMaximumSegmentSize;
//||    uint8_t           mptcpAddressId;
//||    uint8_t           mptcpFlags;
//||} md_text_mptcp_t;
//||
//||typedef struct md_text_mac_st {
//||    uint8_t     sourceMacAddress[6];
//||    uint8_t     destinationMacAddress[6];
//||} md_text_mac_t;
//||
//||typedef struct md_text_p0f_st {
//||    fbVarfield_t    osName;
//||    fbVarfield_t    osVersion;
//||    fbVarfield_t    osFingerprint;
//||    fbVarfield_t    reverseOsName;
//||    fbVarfield_t    reverseOsVersion;
//||    fbVarfield_t    reverseOsFingerprint;
//||} md_text_p0f_t;
//||
//||typedef struct md_text_fpexport_st {
//||    fbVarfield_t    firstPacketBanner;
//||    fbVarfield_t    secondPacketBanner;
//||    fbVarfield_t    reverseFirstPacketBanner;
//||} md_text_fpexport_t;
//||
//||typedef struct md_text_payload_st {
//||    fbVarfield_t payload;
//||    fbVarfield_t reversePayload;
//||} md_text_payload_t;
//||
typedef struct md_text_stats_st {
    uint64_t dataByteCount;
    uint64_t averageInterarrivalTime;
    uint64_t standardDeviationInterarrivalTime;
    uint32_t tcpUrgTotalCount;
    uint32_t smallPacketCount;
    uint32_t nonEmptyPacketCount;
    uint32_t largePacketCount;
    uint16_t firstNonEmptyPacketSize;
    uint16_t maxPacketSize;
    uint16_t standardDeviationPayloadLength;
    uint8_t  firstEightNonEmptyPacketDirections;
    uint8_t  padding[1];
    /* reverse Fields */
    uint64_t reverseDataByteCount;
    uint64_t reverseAverageInterarrivalTime;
    uint64_t reverseStandardDeviationInterarrivalTime;
    uint32_t reverseTcpUrgTotalCount;
    uint32_t reverseSmallPacketCount;
    uint32_t reverseNonEmptyPacketCount;
    uint32_t reverseLargePacketCount;
    uint16_t reverseFirstNonEmptyPacketSize;
    uint16_t reverseMaxPacketSize;
    uint16_t reverseStandardDeviationPayloadLength;
    uint8_t  padding2[2];
} md_text_stats_t;
//||
//||typedef struct md_text_tcp_st {
//||    uint32_t    tcpSequenceNumber;
//||    uint8_t     initialTCPFlags;
//||    uint8_t     unionTCPFlags;
//||    uint8_t     reverseInitialTCPFlags;
//||    uint8_t     reverseUnionTCPFlags;
//||    uint32_t    reverseTcpSequenceNumber;
//||} md_text_tcp_t;

#endif  /* _MEDIATOR_TEMPLATES_H */

