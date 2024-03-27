/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file specs.h
 *
 *  Declares fbInfoElementSpec_t array variables used for recognizing incoming
 *  records and for transcoding.
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

#ifndef _MEDIATOR_SPECS_H
#define _MEDIATOR_SPECS_H

/*
 *  This file contains both the declarations and the definitions of the spec
 *  arrays, but the definitions are only read when this value is TRUE.
 */
#ifndef MEDIATOR_SPECS_SOURCE
#define MEDIATOR_SPECS_SOURCE 0
#endif

#include <fixbuf/public.h>
#include "templates.h"

#define NUM_SPEC_IES(_spec_)                                                \
    ((sizeof(_spec_) / sizeof(_spec_[0])) - 1)

#define YAF_2_IE                    0x00000001
#define YAF_3_IE                    0x00000002
#define YAF_SSL_CERT_EXPORT_FLAG    0x00000004
#define YAF_PADDING                 0x00000008

/* specs used by template labelers to certify classes of templates */

/* ------------------------------CHECKERS-------------------------------------*/
/* these are groups of elements that identify classes of templates
 * they do not provide exact matches for templates and structs */
/* spec that identifies FLOW */
/* all elements of this means: TT_FLOW, TT_NO_TMD_FLOW
 * and TC_FLOW */
extern const fbInfoElementSpec_t mdCheckerFlow[9];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdCheckerFlow[] = {
    { "flowStartMilliseconds",              8, 0 },
    { "flowEndMilliseconds",                8, 0 },
    { "sourceTransportPort",                2, 0 },
    { "destinationTransportPort",           2, 0 },
    { "flowAttributes",                     2, 0 },
    { "protocolIdentifier",                 1, 0 },
    { "flowEndReason",                      1, 0 },
    { "vlanId",                             2, 0 },
    FB_IESPEC_NULL
}; /* 9 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/* whether the template is the SubTemplate used by YAF-2 for TCP flags */
extern const fbInfoElementSpec_t mdCheckerTcpSubrec[];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdCheckerTcpSubrec[] = {
    {"tcpSequenceNumber",        4, 0},
    {"initialTCPFlags",          1, 0},
    {"unionTCPFlags",            1, 0},
    {"reverseInitialTCPFlags",   1, 1},
    {"reverseUnionTCPFlags",     1, 1},
    {"reverseTcpSequenceNumber", 4, 1},
    FB_IESPEC_NULL
};
#endif  /* MEDIATOR_SPECS_SOURCE */

#if 0
/* all elements of this means: TC_FLOW_REV. This is checked after TC_FLOW */
extern const fbInfoElementSpec_t mdCheckerFlowRev[5];
/* diagnoses a record as having an ipv4 address pair */
extern const fbInfoElementSpec_t mdCheckerIPv4Addresses[3];
/* diagnoses a record as having an ipv6 address pair */
extern const fbInfoElementSpec_t mdCheckerIPv6Addresses[3];
#endif  /* 0 */

#define mdCheckerYafStats mdEmSpecYafStatsV2
/* if there are 10 elements of yafStatsV2Spec, call the rec yaf stats */
#define CHECKER_YAF_STATS_THRESHOLD 10

/* spec that identifies TOMBSTONE */
extern const fbInfoElementSpec_t mdCheckerTombstone[2];
#if MEDIATOR_SPECS_SOURCE
/* pick an SEI element where it can only be us */
const fbInfoElementSpec_t mdCheckerTombstone[] = {
    { "certToolTombstoneId",                4, 0 },
    FB_IESPEC_NULL /* 2 */
};
#endif  /* MEDIATOR_SPECS_SOURCE */

/* ssl dedup records */
extern const fbInfoElementSpec_t mdCheckerSSLDedup[5];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdCheckerSSLDedup[] = {
    { "flowEndMilliseconds",                8, 0 },
    { "smDedupHitCount",                    8, 0 },
    { "sslCertSerialNumber",                FB_IE_VARLEN, 0 },
    { "sslCertIssuerCommonName",            FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL /* 5 */
};
#endif  /* MEDIATOR_SPECS_SOURCE */

/* rewritten SSL checker -- used to set TC_APP_DPI_SSL_RW_L2*/
extern const fbInfoElementSpec_t mdCheckerSSLRWCert[4];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdCheckerSSLRWCert[] = {
    {"sslCertIssuerCountryName",        FB_IE_VARLEN, 4},
    {"sslCertExtSubjectAltName",        FB_IE_VARLEN, 4},
    {"sslCertSubjectCountryName",       FB_IE_VARLEN, 4},
    FB_IESPEC_NULL
}; /* 4 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/* general (non dns or ssl) dedup records (TC_GENERAL_DEDUP) */
extern const fbInfoElementSpec_t generalDedupCheckerSpec[3];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t generalDedupCheckerSpec[] = {
    { "observationDomainName",              FB_IE_VARLEN, 0 },
    { "yafFlowKeyHash",                     4, 0 },
    FB_IESPEC_NULL /* 3 */
};
#endif  /* MEDIATOR_SPECS_SOURCE */

/* says this template has detailed resource record info
 *
 * could be DPI (has an STL), DNS RR (mdCheckerDNSRRGivenDNSResRecInfo), or
 * DNS Dedup (mdCheckerDNSDedupGivenDNSResRecInfo) */
extern const fbInfoElementSpec_t mdCheckerDNSResRecInfo[3];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdCheckerDNSResRecInfo[] = {
    {"dnsName",             FB_IE_VARLEN, 0 },
    {"dnsRRType",           2, 0 },
    FB_IESPEC_NULL
}; /* 3 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/* given that mdCheckerDNSResRecInfo is all there, identify DNS RR
 * with this */
extern const fbInfoElementSpec_t mdCheckerDNSRRGivenDNSResRecInfo[3];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdCheckerDNSRRGivenDNSResRecInfo[] = {
    { "yafFlowKeyHash",                     4, 0 },
    { "flowStartMilliseconds",              8, 0 },
    FB_IESPEC_NULL
}; /* 3 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/* DNS RR FULL given it's dns RR, also use to determine ipv4/6 */
extern const fbInfoElementSpec_t mdCheckerDNSRRFullGivenDNSRR[9];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdCheckerDNSRRFullGivenDNSRR[] = {
    { "sourceIPv4Address",                  4, TC_DNS_RR_FULL_4 },
    { "destinationIPv4Address",             4, TC_DNS_RR_FULL_4 },
    { "sourceIPv6Address",                  16,TC_DNS_RR_FULL_6 },
    { "destinationIPv6Address",             16,TC_DNS_RR_FULL_6 },
    { "sourceTransportPort",                2, 0 },
    { "destinationTransportPort",           2, 0 },
    { "vlanId",                             2, 0 },
    { "protocolIdentifier",                 1, 0 },
    FB_IESPEC_NULL
}; /* 9 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/* DNS DEDUP given DNS resource rec
 *
 * If so, need to further categorize as AREC or OREC and as not-LastSeen,
 * LastSeen-V1, or LastSeen-V2 */
extern const fbInfoElementSpec_t mdCheckerDNSDedupGivenDNSResRecInfo[];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdCheckerDNSDedupGivenDNSResRecInfo[] = {
    { "flowStartMilliseconds",              8, 0 },
    FB_IESPEC_NULL
}; /* 2 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/* DNS AREC given DNS DEDUP */
extern const fbInfoElementSpec_t mdCheckerARecGivenDNSDedup[2];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdCheckerARecGivenDNSDedup[] = {
    { "sourceIPv4Address",                  4, 0 },
    FB_IESPEC_NULL
}; /* 2 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/* DNS AAAAREC given DNS DEDUP */
extern const fbInfoElementSpec_t mdCheckerAAAARecGivenDNSDedup[2];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdCheckerAAAARecGivenDNSDedup[] = {
    { "sourceIPv6Address",                  16, 0 },
    FB_IESPEC_NULL
}; /* 2 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/* DNS OREC given DNS DEDUP */
extern const fbInfoElementSpec_t mdCheckerORecGivenDNSDedup[2];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdCheckerORecGivenDNSDedup[] = {
    { "smDNSData",                          FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
}; /* 2 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/* DNS LAST SEEN V1 given DNS Dedup */
extern const fbInfoElementSpec_t mdCheckerLastSeenV1GivenDNSDedup[];
#if MEDIATOR_SPECS_SOURCE
/* dnsHitCount is used in SM-v1.x */
const fbInfoElementSpec_t mdCheckerLastSeenV1GivenDNSDedup[] = {
    { "dnsHitCount",                        2, 0 },
    { "flowEndMilliseconds",                8, 0 },
    FB_IESPEC_NULL
}; /* 3 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/* DNS LAST SEEN V2 given DNS Dedup */
extern const fbInfoElementSpec_t mdCheckerLastSeenV2GivenDNSDedup[];
#if MEDIATOR_SPECS_SOURCE
/* smDedupHitCount is used starting with SM-v2.0.0 */
const fbInfoElementSpec_t mdCheckerLastSeenV2GivenDNSDedup[] = {
    { "smDedupHitCount",                    4, 0 },
    { "flowEndMilliseconds",                8, 0 },
    FB_IESPEC_NULL
}; /* 3 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/* Identify TLS/SSL DPI Level 1.  Labeled as TC_APP_DPI_SSL_L1.  Stored in
 * sslLevel1Tid of mdKnownTemplates_t. */
extern const fbInfoElementSpec_t mdCheckerYafSSLLevel1[3];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdCheckerYafSSLLevel1[] = {
    {"sslServerCipher",           4, 0 },
    {"sslServerName",             FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
}; /* 3 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/* Identify TLS/SSL DPI Level 2.  Labeled as TC_APP_DPI_SSL_L2.  Stored in
 * sslLevel2Tid of mdKnownTemplates_t. */
extern const fbInfoElementSpec_t mdCheckerYafSSLLevel2[4];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdCheckerYafSSLLevel2[] = {
    {"sslCertSignature",          FB_IE_VARLEN, 0 },
    {"sslCertSerialNumber",       FB_IE_VARLEN, 0 },
    {"sslCertVersion",            1, 0 },
    FB_IESPEC_NULL
}; /* 4 */
#endif  /* MEDIATOR_SPECS_SOURCE */

#define mdCheckerYafSSlLevel3 mdEmSpecYafSSLLevel3

/* -----------------------------------END CHECKERS----------------------------*/

/* -------------------------------MATCHES and STRUCTS ------------------------*/

/*These specs are used to build templates to use for structs and to determine
 * relative contents to received templates */

/*
 * old yaf stats - prior to yaf-2.11.0, starting at yaf-2.3.0
 *
 * template yafStatsV1Tmpl; struct yafStatsV1Rec_t
 *
 * prior to yaf-2.3.0, systemInitTimeMilliseconds and notSentPacketTotalCount
 * were not present, but that was 2012.
 */
extern const fbInfoElementSpec_t mdEmSpecYafStatsV1[];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdEmSpecYafStatsV1[] = {
    { "systemInitTimeMilliseconds",         8, 0 },
    { "exportedFlowRecordTotalCount",       8, 0 },
    { "packetTotalCount",                   8, 0 },
    { "droppedPacketTotalCount",            8, 0 },
    { "ignoredPacketTotalCount",            8, 0 },
    { "notSentPacketTotalCount",            8, 0 },
    { "yafExpiredFragmentCount",            4, 0 },
    { "yafAssembledFragmentCount",          4, 0 },
    { "yafFlowTableFlushEventCount",        4, 0 },
    { "yafFlowTablePeakCount",              4, 0 },
    { "exporterIPv4Address",                4, 0 },
    { "exportingProcessId",                 4, 0 },
    { "yafMeanFlowRate",                    4, 0 },
    { "yafMeanPacketRate",                  4, 0 },
    FB_IESPEC_NULL /* 15 */
};
#endif  /* MEDIATOR_SPECS_SOURCE */

/*
 * yaf stats - as of yaf-2.11.0
 *
 * template yafStatsV2Tmpl; struct yafStatsV2Rec_t
 */
extern const fbInfoElementSpec_t mdEmSpecYafStatsV2[];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdEmSpecYafStatsV2[] = {
    { "observationDomainId",                4, 0 },
    { "exportingProcessId",                 4, 0 },
    { "exporterIPv4Address",                4, 0 },
    { "observationTimeSeconds",             4, 0 },
    { "systemInitTimeMilliseconds",         8, 0 },
    { "exportedFlowRecordTotalCount",       8, 0 },
    { "packetTotalCount",                   8, 0 },
    { "droppedPacketTotalCount",            8, 0 },
    { "ignoredPacketTotalCount",            8, 0 },
    { "notSentPacketTotalCount",            8, 0 },
    { "yafExpiredFragmentCount",            4, 0 },
    { "yafAssembledFragmentCount",          4, 0 },
    { "yafFlowTableFlushEventCount",        4, 0 },
    { "yafFlowTablePeakCount",              4, 0 },
    { "yafMeanFlowRate",                    4, 0 },
    { "yafMeanPacketRate",                  4, 0 },
    FB_IESPEC_NULL /* 17 */
};
#endif  /* MEDIATOR_SPECS_SOURCE */

/* tombstone top level records from YAF 2.10.0 only */
extern const fbInfoElementSpec_t mdEmSpecTombstoneMainV1[5];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdEmSpecTombstoneMainV1[] = {
    { "certToolExporterConfiguredId",       2, 0 },
    { "certToolExporterUniqueId",           2, 0 },
    { "certToolTombstoneId",                4, 0 },
    { "subTemplateList",                    FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL /* 5 */
};
#endif  /* MEDIATOR_SPECS_SOURCE */

/* Use this internal-only template to read a top-level tombstone V1 record.
 * Its elements align things with the tombstone V2 record.
 *
 * Template is tombstoneMainV1ReaderTmpl; TID will be that used to read the
 * MainV1 tombstone template.
 *
 * Must keep this in sync with tombstoneMainV2Rec_t.
 */
extern const fbInfoElementSpec_t mdEmSpecTombstoneMainV1Reader[];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdEmSpecTombstoneMainV1Reader[] = {
    /* first paddingOctets == observationDomainId, exportingProcessId */
    { "paddingOctets",                      8, 0 },
    { "certToolExporterConfiguredId",       2, 0 },
    /* UniqueId and paddingOctets[4] == paddingOctets[6] in V2 */
    { "certToolExporterUniqueId",           2, 0 },
    { "paddingOctets",                      4, 0 },
    { "certToolTombstoneId",                4, 0 },
    /* these paddingOctets == observationTimeSeconds in V2 */
    { "paddingOctets",                      4, 0 },
    /* is certToolTombstoneAccessList in V2 */
    { "subTemplateList",                    FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL /* 5 */
};
#endif  /* MEDIATOR_SPECS_SOURCE */

/* tombstone access list subrecords from YAF 2.10.0 only.
 *
 * The first element holds the equivalent of the certToolId but the template
 * did not use that IE; these may be directly mapped to V2 of the access list.
 */
extern const fbInfoElementSpec_t mdEmSpecTombstoneAccessV1[3];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdEmSpecTombstoneAccessV1[] = {
    { "exportingProcessId",                 4, 0 },
    { "observationTimeSeconds",             4, 0 },
    FB_IESPEC_NULL /* 3 */
};
#endif  /* MEDIATOR_SPECS_SOURCE */

/* tombstone top level records as of YAF 2.11.0 */
extern const fbInfoElementSpec_t mdEmSpecTombstoneMainV2[8];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdEmSpecTombstoneMainV2[] = {
    { "observationDomainId",                4, 0 },
    { "exportingProcessId",                 4, 0 },
    { "certToolExporterConfiguredId",       2, 0 },
    { "paddingOctets",                      6, 0 },
    { "certToolTombstoneId",                4, 0 },
    { "observationTimeSeconds",             4, 0 },
    { "certToolTombstoneAccessList",        FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL /* 8 */
};
#endif  /* MEDIATOR_SPECS_SOURCE */

/* tombstone access list records as of YAF 2.11.0 */
extern const fbInfoElementSpec_t mdEmSpecTombstoneAccessV2[3];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdEmSpecTombstoneAccessV2[] = {
    { "certToolId",                         4, 0 },
    { "observationTimeSeconds",             4, 0 },
    FB_IESPEC_NULL /* 3 */
};
#endif  /* MEDIATOR_SPECS_SOURCE */

/* DNS DPI: YAF v2 and v3 using flags for named lists. yaf_dns_qr */
extern const fbInfoElementSpec_t mdEmSpecYafDnsQR[11];
#if MEDIATOR_SPECS_SOURCE
/* this spec is a match of the current YAF, which matches the struct
 * and is what we mean by TC_EXACT
 */
const fbInfoElementSpec_t mdEmSpecYafDnsQR[] = {
    {"subTemplateList",       FB_IE_VARLEN, YAF_2_IE }, /*based on type of RR */
    {"dnsDetailRecordList",   FB_IE_VARLEN, YAF_3_IE }, /*based on type of RR */
    {"dnsName",               FB_IE_VARLEN, 0 }, /*name - varfield*/
    {"dnsTTL",                4, 0 },
    {"dnsRRType",             2, 0 },  /* Type - uint8*/
    {"dnsQueryResponse",      1, 0 },  /* Q or R - uint8*/
    {"dnsAuthoritative",      1, 0 },  /* authoritative response (1)*/
    {"dnsResponseCode",       1, 0 },  /* nxdomain (1) */
    {"dnsSection",            1, 0 },  /* 0, 1, 2 (ans, auth, add'l) */
    {"dnsId",                 2, 0 },
    FB_IESPEC_NULL
}; /* 11 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/* SSL DPI Level 1. YAF v2 - yaf_ssl */
extern const fbInfoElementSpec_t mdEmSpecYafV2SSLLevel1[8];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdEmSpecYafV2SSLLevel1[] = {
    {"basicList",                 FB_IE_VARLEN, 0 }, /*list of ciphers 32bit */
    {"sslServerCipher",           4, 0 }, /*cipher suite in server hello */
    {"sslClientVersion",          1, 0 },
    {"sslCompressionMethod",      1, 0 }, /*compression method in serv hello*/
    {"sslRecordVersion",          2, 0 },
    {"subTemplateList",           FB_IE_VARLEN, 0 }, /* list of certs */
    {"sslServerName",             FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
}; /* 8 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/* SSL DPI Level 1. YAF v3 - yaf_ssl */
extern const fbInfoElementSpec_t mdEmSpecYafV3SSLLevel1[9];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdEmSpecYafV3SSLLevel1[] = {
    {"sslCipherList",             FB_IE_VARLEN, 0 }, /*list of ciphers 32bit */
    {"sslBinaryCertificateList",  FB_IE_VARLEN, YAF_SSL_CERT_EXPORT_FLAG },
    {"sslServerName",             FB_IE_VARLEN, 0 },
    {"sslCertList",               FB_IE_VARLEN, 0 }, /* list of certs */
    {"sslServerCipher",           4, 0 }, /*cipher suite in server hello */
    {"sslClientVersion",          1, 0 }, /* protocol version, 2 ssl, 3 tls */
    {"sslCompressionMethod",      1, 0 }, /*compression method in serv hello*/
    {"sslRecordVersion",          2, 0 }, /* message version */
    FB_IESPEC_NULL
}; /* 9 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/* SSL DPI Level 2. YAF v2 and v3 using flags for named lists. yaf_ssl_cert */
extern const fbInfoElementSpec_t mdEmSpecYafSSLLevel2[16]; /* certs */
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdEmSpecYafSSLLevel2[] = {
    {"subTemplateList",             FB_IE_VARLEN, YAF_2_IE },
    {"subTemplateList",             FB_IE_VARLEN, YAF_2_IE },
    {"subTemplateList",             FB_IE_VARLEN, YAF_2_IE },
    {"sslIssuerFieldList",          FB_IE_VARLEN, YAF_3_IE },
    {"sslSubjectFieldList",         FB_IE_VARLEN, YAF_3_IE },
    {"sslExtensionFieldList",       FB_IE_VARLEN, YAF_3_IE },
    {"sslCertSignature",            FB_IE_VARLEN, 0 },
    {"sslCertSerialNumber",         FB_IE_VARLEN, 0 },
    {"sslCertValidityNotBefore",    FB_IE_VARLEN, 0 },
    {"sslCertValidityNotAfter",     FB_IE_VARLEN, 0 },
    {"sslPublicKeyAlgorithm",       FB_IE_VARLEN, 0 },
    {"sslPublicKeyLength",          2, 0 },
    {"sslCertVersion",              1, 0 },
    {"paddingOctets",               5, 0 },
    {"sslCertificateHash",          FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL /* 16 */
};
#endif  /* MEDIATOR_SPECS_SOURCE */

/* SSL DPI Level 3. Applies to YAF v2 and v3 as they are the same */
extern const fbInfoElementSpec_t mdEmSpecYafSSLLevel3[3]; /* key values */
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdEmSpecYafSSLLevel3[] = {
    {"sslObjectValue",              FB_IE_VARLEN, 0 },
    {"sslObjectType",               1, 0 },
    FB_IESPEC_NULL
}; /* 3 */
#endif  /* MEDIATOR_SPECS_SOURCE */

#if 0
/* SMTP DPI Level 1. Used by the text exporter */
extern const fbInfoElementSpec_t mdTextSMTPSpec[8]; /* key values */

/* SSL DPI Level 1. Used by the text exporter */
extern const fbInfoElementSpec_t mdTextSSLSpec[9]; /* key values */
#endif  /* 0 */

/* ---------------------------END MATCHES and STRUCTS ------------------------*/

/* ---------------------- SPECS FOR SM GENERATED RECORDS ---------------------*/

/* DNS Dedup internal template - only used as int when exporting DNS
 * DEDUP records that this super mediator generated
 * for now, all DNS dedup records have all of these fields coming out
 * of the hash tables,
 * or at least have the ones that will be exported */
extern const fbInfoElementSpec_t mdDNSDedupTmplSpec[12];
#if MEDIATOR_SPECS_SOURCE
/*
 *  The template spec used to generate the internal DNSDedup template (all
 *  elements) and the export DNSDedup record for A-Records (MD_DNS_DD_AREC)
 *  and Other-Records (MD_DNS_DD_OREC) in both regular and last-seen
 *  (MD_DNS_DD_LAST_SEEN) flavors with an optional exporter name
 *  (MD_DNS_DD_XPTR_NAME).
 *
 * This should match md_dns_dedup_t.
 */
const fbInfoElementSpec_t mdDNSDedupTmplSpec[] = {
    /* Millisecond first seen and last seen (epoch) (native time) */
    { "flowStartMilliseconds",              8, 0 },
    { "flowEndMilliseconds",                8, MD_DNS_DD_LAST_SEEN },
    /* AAAA-record IP */
     { "sourceIPv6Address",                 16, MD_DNS_DD_AAAAREC },
    /* A-record IP */
    { "sourceIPv4Address",                  4, MD_DNS_DD_AREC},
    /* Max TTL */
    { "dnsTTL",                             4, MD_DNS_DD_LAST_SEEN },
    /* rrType */
    { "dnsRRType",                          2, 0 },
    /* dnsHitCount is in internal template for reading SM1 data */
    { "dnsHitCount",                        2, 0x80000000 },
    /* how many times we saw it */
    { "smDedupHitCount",                    4, MD_DNS_DD_LAST_SEEN },
    { "dnsName",                            FB_IE_VARLEN, 0 },
    { "smDNSData",                          FB_IE_VARLEN, MD_DNS_DD_OREC },
    { "observationDomainName",              FB_IE_VARLEN, MD_DNS_DD_XPTR_NAME },
    FB_IESPEC_NULL
}; /* 12 */
#endif  /* MEDIATOR_SPECS_SOURCE */

#if 0
/* DNS Dedup AREC template - for exporting and matching in callback*/
extern const fbInfoElementSpec_t mdDNSDedupARecSpec[10];

/* DNS Dedup OREC template - for exporting and matching in callback */
extern const fbInfoElementSpec_t mdDNSDedupORecSpec[10];
#endif  /* 0 */

/* SSL Dedup Spec; must match md_ssl_t; template ID is MD_SSL_TID */
extern const fbInfoElementSpec_t mdSSLDedupSpec[7];
#if MEDIATOR_SPECS_SOURCE
const fbInfoElementSpec_t mdSSLDedupSpec[] = {
    { "flowStartMilliseconds",              8, 0 },
    { "flowEndMilliseconds",                8, 0 },
    { "smDedupHitCount",                    8, 0 },
    { "sslCertSerialNumber",                FB_IE_VARLEN, 0 },
    { "sslCertIssuerCommonName",            FB_IE_VARLEN, 0 },
    { "observationDomainName",              FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
}; /* 7 */
#endif  /* MEDIATOR_SPECS_SOURCE */

/*
 * The "flattened" or rewritten TLS/SSL certificate.
 *
 * struct is md_ssl_certificate_t.  Tid is MD_SSL_CERTIFICATE_TID.
 */
extern const fbInfoElementSpec_t mdSSLRWCertLevel2Spec[];
#if MEDIATOR_SPECS_SOURCE
/* FIXME: The flattened version from SM1 uses the basciList element for the
 * elements of type basicList.  */
const fbInfoElementSpec_t mdSSLRWCertLevel2Spec[] = {
    /** Issuer **/
    /* id-at-commonName {id-at 3} ("sslCertIssuerCommonName") */
    {"sslCertIssuerCommonNameList",     FB_IE_VARLEN, 4},
    /* id-at-countryName {id-at 6} */
    {"sslCertIssuerCountryName",        FB_IE_VARLEN, 4},
    /* id-at-localityName {id-at 7} */
    {"sslCertIssuerLocalityName",       FB_IE_VARLEN, 4},
    /* id-at-stateOrProvidenceName {id-at 8} */
    {"sslCertIssuerState",              FB_IE_VARLEN, 4},
    /* id-at-streetAddress {id-at 9} ("sslCertIssuerStreetAddress") */
    {"sslCertIssuerStreetAddressList",  FB_IE_VARLEN, 4},
    /* id-at-organizationName {id-at 10} ("sslCertIssuerOrgName") */
    {"sslCertIssuerOrgNameList",        FB_IE_VARLEN, 4},
    /* id-at-organizationUnitName {id-at 11} ("sslCertIssuerOrgUnitName") */
    {"sslCertIssuerOrgUnitNameList",    FB_IE_VARLEN, 4},
    /* id-at-postalCode {id-at 17} */
    {"sslCertIssuerZipCode",            FB_IE_VARLEN, 4},
    /* id-at-title {id-at 12} */
    {"sslCertIssuerTitle",              FB_IE_VARLEN, 4},
    /* id-at-name {id-at 41} */
    {"sslCertIssuerName",               FB_IE_VARLEN, 4},
    /* pkcs-9-emailAddress {pkcs-9 1} */
    {"sslCertIssuerEmailAddress",       FB_IE_VARLEN, 4},
    /* 0.9.2342.19200300.100.1.25 {dc 25} ("sslCertIssuerDomainComponent") */
    {"sslCertIssuerDomainComponentList",FB_IE_VARLEN, 4},

    /** Subject **/
    /* id-at-commonName {id-at 3} ("sslCertSubjectCommonName") */
    {"sslCertSubjectCommonNameList",    FB_IE_VARLEN, 4},
    /* id-at-countryName {id-at 6} */
    {"sslCertSubjectCountryName",       FB_IE_VARLEN, 4},
    /* id-at-localityName {id-at 7} */
    {"sslCertSubjectLocalityName",      FB_IE_VARLEN, 4},
    /* id-at-stateOrProvidenceName {id-at 8} */
    {"sslCertSubjectState",             FB_IE_VARLEN, 4},
    /* id-at-streetAddress {id-at 9} ("sslCertSubjectStreetAddress") */
    {"sslCertSubjectStreetAddressList", FB_IE_VARLEN, 4},
    /* id-at-organizationName {id-at 10} ("sslCertSubjectOrgName") */
    {"sslCertSubjectOrgNameList",       FB_IE_VARLEN, 4},
    /* id-at-organizationUnitName {id-at 11} ("sslCertSubjectOrgUnitName") */
    {"sslCertSubjectOrgUnitNameList",   FB_IE_VARLEN, 4},
    /* id-at-postalCode {id-at 17} */
    {"sslCertSubjectZipCode",           FB_IE_VARLEN, 4},
    /* id-at-title {id-at 12} */
    {"sslCertSubjectTitle",             FB_IE_VARLEN, 4},
    /* id-at-name {id-at 41} */
    {"sslCertSubjectName",              FB_IE_VARLEN, 4},
    /* pkcs-9-emailAddress {pkcs-9 1} */
    {"sslCertSubjectEmailAddress",      FB_IE_VARLEN, 4},
    /* 0.9.2342.19200300.100.1.25 {dc 25} ("sslCertSubjectDomainComponent") */
    {"sslCertSubjectDomainComponentList",FB_IE_VARLEN, 4},

    /** Extensions **/
    /* id-ce-subjectKeyIdentifier {id-ce 14} */
    {"sslCertExtSubjectKeyIdent",       FB_IE_VARLEN, 4},
    /* id-ce-keyUsage {id-ce 15} */
    {"sslCertExtKeyUsage",              FB_IE_VARLEN, 4},
    /* id-ce-privateKeyUsagePeriod {id-ce 16} */
    {"sslCertExtPrivKeyUsagePeriod",    FB_IE_VARLEN, 4},
     /* id-ce-subjectAltName {id-ce 17} */
    {"sslCertExtSubjectAltName",        FB_IE_VARLEN, 4},
    /* id-ce-issuerAltName {id-ce 18} */
    {"sslCertExtIssuerAltName",         FB_IE_VARLEN, 4},
    /* id-ce-certificateIssuer {id-ce 29} */
    {"sslCertExtCertIssuer",            FB_IE_VARLEN, 4},
    /* id-ce-cRLDistributionPoints {id-ce 31} */
    {"sslCertExtCrlDistribution",       FB_IE_VARLEN, 4},
    /* id-ce-certificatePolicies {id-ce 32} */
    {"sslCertExtCertPolicies",          FB_IE_VARLEN, 4},
    /* id-ce-authorityKeyIdentifier {id-ce 35} */
    {"sslCertExtAuthorityKeyIdent",     FB_IE_VARLEN, 4},
    /* id-ce-extKeyUsage {id-ce 37} */
    {"sslCertExtExtendedKeyUsage",      FB_IE_VARLEN, 4},

#if 0
    /* Values from the YAF SSL record */
    {"sslCertSignature",                FB_IE_VARLEN, 4},
    {"sslCertSerialNumber",             FB_IE_VARLEN, 4},
    {"sslCertValidityNotBefore",        FB_IE_VARLEN, 4},
    {"sslCertValidityNotAfter",         FB_IE_VARLEN, 4},
    {"sslPublicKeyAlgorithm",           FB_IE_VARLEN, 4},
    {"sslPublicKeyLength",              2,            4},
    {"sslCertVersion",                  1,            4},
    {"paddingOctets",                   5,            2},
    {"sslCertificateHash",              FB_IE_VARLEN, 4},
#endif  /* 0 */

    FB_IESPEC_NULL
}; /* 44 */
#endif  /* MEDIATOR_SPECS_SOURCE */


/*
 * DNS RR template - only used as int when exporting DNS
 * DEDUP records that this super mediator generated
 * for now, all DNS dedup records have all of these fields coming out
 * of the hash tables,
 * or at least have the ones that will be exported
 */
extern const fbInfoElementSpec_t mdDnsRRSpec[22];
#if MEDIATOR_SPECS_SOURCE
/*
 *  DNS RR spec.  All elements used for the internal template, and it must
 *  match md_dns_rr_r.  IEs with MD_DNSRR_FULL are included for FULL output,
 *  with IP address as either IPv4 or IPv6.
 */
const fbInfoElementSpec_t mdDnsRRSpec[] = {
    { "flowStartMilliseconds",              8, 0 },
    { "sourceIPv6Address",                  16, MD_DNSRR_FULL | MD_DNSRR_IP6},
    { "destinationIPv6Address",             16, MD_DNSRR_FULL | MD_DNSRR_IP6},
    { "sourceIPv4Address",                  4,  MD_DNSRR_FULL | MD_DNSRR_IP4},
    { "destinationIPv4Address",             4,  MD_DNSRR_FULL | MD_DNSRR_IP4},
    { "dnsTTL",                             4, 0 },
    { "observationDomainId",                4, 0 },
    { "yafFlowKeyHash",                     4, 0 },
    { "dnsRRType",                          2, 0 },
    { "sourceTransportPort",                2, MD_DNSRR_FULL },
    { "destinationTransportPort",           2, MD_DNSRR_FULL },
    { "vlanId",                             2, MD_DNSRR_FULL },
    { "dnsId",                              2, 0 },
    { "protocolIdentifier",                 1, MD_DNSRR_FULL },
    { "dnsQueryResponse",                   1, 0 }, /* Q or R - uint8*/
    { "dnsAuthoritative",                   1, 0 }, /* auth response (1)*/
    { "dnsResponseCode",                    1, 0 }, /* nxdomain (1) */
    { "dnsSection",                         1, 0 }, /* (qry,ans,auth,add'l) */
    { "paddingOctets",                      5, 0x80000000 },
    { "dnsName",                            FB_IE_VARLEN, 0 },
    { "smDNSData",                          FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
}; /* 22 */
#endif  /* MEDIATOR_SPECS_SOURCE */

//extern const fbInfoElementSpec_t mdDnsRRIpv6Spec[20];
//
//extern const fbInfoElementSpec_t mdDnsRRIpv4Spec[20];

/* ---------------------- END SPECS FOR SM GENERATED RECORDS -----------------*/

/************ Standard Templates For Checking Equality ******************/
/* allocated in mdCoreInit() */
/* NOT USED FOR ADDING TO SESSIONS (not sure why) */

extern fbTemplate_t   *yafStatsV1Tmpl;
extern fbTemplate_t   *yafStatsV2Tmpl;
extern fbTemplate_t   *tombstoneMainV1Tmpl;
extern fbTemplate_t   *tombstoneMainV2Tmpl;
extern fbTemplate_t   *tombstoneAccessV1Tmpl;
extern fbTemplate_t   *tombstoneAccessV2Tmpl;
//||extern fbTemplate_t   *dnsDedupArecTmpl;
//||extern fbTemplate_t   *dnsDedupOrecTmpl;
//||extern fbTemplate_t   *dnsDedupLastSeenArecTmpl;
//||extern fbTemplate_t   *dnsDedupLastSeenOrecTmpl;
extern fbTemplate_t   *sslDedupTmpl;
extern fbTemplate_t   *yafDnsQRTmplV2;
extern fbTemplate_t   *yafDnsQRTmplV3;

/* First level of a TLS/SSL DPI exported from YAF. Labeled as
 * TC_APP_DPI_SSL_L1; stored in sslLevel1Tid of mdKnownTemplates_t */
extern fbTemplate_t   *yafV2SSLLevel1Tmpl;

extern fbTemplate_t   *yafV2SSLLevel2Tmpl;

extern fbTemplate_t   *yafV3SSLLevel1Tmpl;
extern fbTemplate_t   *yafV3SSLLevel1TmplCertList;
extern fbTemplate_t   *yafV3SSLLevel2Tmpl;

extern fbTemplate_t   *yafSSLLevel3Tmpl;
extern fbTemplate_t   *mdSSLRWCertLevel2Tmpl;

/********************* End Template for Equality *********************/

#endif  /* MD_SPEC */
