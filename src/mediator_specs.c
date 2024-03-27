/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_specs.c
 *
 *  Defines the specs used by template labelers to certify classes of
 *  templates.
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

#define  MEDIATOR_SPECS_SOURCE 1
#include "mediator_structs.h"
#include "specs.h"


#if 0
/* diagnoses a record as ipv4 after the general contents type is set */
fbInfoElementSpec_t mdSpecIPv4Addresses[] = {
    { "sourceIPv4Address",                  4, 0 },
    { "destinationIPv4Address",             4, 0 },
    FB_IESPEC_NULL
}; /* 3 */
#endif /* 0 */

#if 0
/* diagnoses a record as ipv6 after the general contents type is set */
fbInfoElementSpec_t mdSpecIPv6Addresses[] = {
    { "sourceIPv6Address",                  16, 0 },
    { "destinationIPv6Address",             16, 0 },
    FB_IESPEC_NULL
}; /* 3 */
#endif /* 0 */

#if 0
/* TC_FLOW_REV */
fbInfoElementSpec_t mdCheckerFlowRev[] = {
    { "reverseFlowAttributes",              2, 0 },
    { "reverseFlowDeltaMilliseconds",       4, 0 },
    { "reverseVlanId",                      2, 0 },
    { "reverseIpClassOfService",            1, 0 },
    FB_IESPEC_NULL
}; /* 5 */
#endif  /* 0 */

#if 0
fbInfoElementSpec_t tmdOrigCheckerSpec[] = {
    { "templateId",                         2, 0 },
    { "templateName",                       FB_IE_VARLEN, 0 },
    { "templateDescription",                FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
};
#endif /* 0 */

#if 0
fbInfoElementSpec_t mdDNSDedupARecSpec[] = {
    /* Millisecond first seen and last seen (epoch) (native time) */
    { "flowStartMilliseconds",              8, 0 },
    { "flowEndMilliseconds",                8, MD_DNS_DD_LAST_SEEN },
    /* A-record IP */
    { "sourceIPv4Address",                  4, 0 },
    /** Max TTL */
    { "dnsTTL",                             4, MD_DNS_DD_LAST_SEEN },
    /* rrType */
    { "dnsRRType",                          2, 0 },
    /* how many times we saw it */
    /* dnsHitCount only used to read SM-v1 data */
    { "dnsHitCount",                        2, MD_DNS_DD_LAST_SEEN },
    { "smDedupHitCount",                    4, MD_DNS_DD_LAST_SEEN },
    /* rrData */
    { "dnsName",                            FB_IE_VARLEN, 0 },
    { "observationDomainName",              FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
}; /* 10 */
#endif  /* 0 */

#if 0
fbInfoElementSpec_t mdDNSDedupORecSpec[] = {
    /* Millisecond first seen and last seen (epoch) (native time) */
    { "flowStartMilliseconds",              8, 0 },
    { "flowEndMilliseconds",                8, MD_DNS_DD_LAST_SEEN },
    /** Max TTL */
    { "dnsTTL",                             4, MD_DNS_DD_LAST_SEEN },
    /* rrType */
    { "dnsRRType",                          2, 0 },
    /* how many times we saw it */
    /* dnsHitCount only used to read SM-v1 data */
    { "dnsHitCount",                        2, MD_DNS_DD_LAST_SEEN },
    { "smDedupHitCount",                    4, MD_DNS_DD_LAST_SEEN },
    /* rrData */
    { "dnsName",                            FB_IE_VARLEN, 0 },
    { "smDNSData",                          FB_IE_VARLEN, 0 },
    { "observationDomainName",              FB_IE_VARLEN, 0 },
    FB_IESPEC_NULL
}; /* 10 */
#endif  /* 0 */

#if 0
/* this plus an STL is minimum usage for dns dedup and to say it's DNS */
fbInfoElementSpec_t mdSpecDNSDedupMinUseSpec[] = {
    {"subTemplateList",       FB_IE_VARLEN, YAF_2_IE },
    {"dnsDetailRecordList",   FB_IE_VARLEN, YAF_3_IE },
    {"dnsName",               FB_IE_VARLEN, 0 }, /*name - varfield*/
    {"dnsTTL",                4, 0 },
    {"dnsRRType",             2, 0 },  /* Type - uint8*/
    {"dnsQueryResponse",      1, 0 },  /* Q or R - uint8*/
    {"dnsResponseCode",       1, 0 },  /* nxdomain (1) */
    {"dnsSection",            1, 0 },  /* 0, 1, 2 (ans, auth, add'l) */
    FB_IESPEC_NULL
}; /* 9 */
#endif /* 0 */

#if 0
fbInfoElementSpec_t mdTextSMTPSpec[] = {
    {"smtpResponseList",  FB_IE_VARLEN, 0 },
    {"smtpMessageSize",   4, 0 },
    {"paddingOctets",     4, 0 },
    {"smtpHello",         FB_IE_VARLEN, 0 },
    {"smtpMessageList",   FB_IE_VARLEN, 0 },
    {"smtpEnhanced",      FB_IE_VARLEN, 0 },
    {"smtpStartTLS",      1, 0 },
    FB_IESPEC_NULL
};
#endif  /* 0 */

#if 0
fbInfoElementSpec_t mdTextSSLSpec[] = {
    {"sslCipherList",             FB_IE_VARLEN, 0 }, /*list of ciphers 32bit */
    {"sslBinaryCertificateList",  FB_IE_VARLEN, 0 },
    {"sslServerName",             FB_IE_VARLEN, 0 },
    {"sslCertList",               FB_IE_VARLEN, 0 }, /* list of certs */
    {"sslServerCipher",           4, 0 }, /*cipher suite in server hello */
    {"sslClientVersion",          1, 0 }, /* protocol version, 2 ssl, 3 tls */
    {"sslCompressionMethod",      1, 0 }, /*compression method in serv hello*/
    {"sslRecordVersion",          2, 0 }, /* message version */
    FB_IESPEC_NULL
};
#endif  /* 0 */

///* used for not full also */
//fbInfoElementSpec_t mdDnsRRIpv4Spec[] = {
//    { "flowStartMilliseconds",              8, 0 },
//    { "sourceIPv4Address",                  4, MD_DNSRR_FULL },
//    { "destinationIPv4Address",             4, MD_DNSRR_FULL },
//    { "dnsTTL",                             4, 0 },
//    { "observationDomainId",                4, 0 },
//    { "yafFlowKeyHash",                     4, 0 },
//    { "dnsRRType",                          2, 0 },
//    { "sourceTransportPort",                2, MD_DNSRR_FULL },
//    { "destinationTransportPort",           2, MD_DNSRR_FULL },
//    { "vlanId",                             2, MD_DNSRR_FULL },
//    { "dnsId",                              2, 0 },
//    { "protocolIdentifier",                 1, MD_DNSRR_FULL },
//    { "dnsQueryResponse",                   1, 0 }, /* Q or R - uint8*/
//    { "dnsAuthoritative",                   1, 0 }, /* auth response (1)*/
//    { "dnsResponseCode",                    1, 0 }, /* nxdomain (1) */
//    { "dnsSection",                         1, 0 }, /* (qry,ans,auth,add'l) */
//    { "paddingOctets",                      5, 0 },
//    { "dnsName",                            FB_IE_VARLEN, 0 },
//    { "smDNSData",                          FB_IE_VARLEN, 0 },
//    FB_IESPEC_NULL
//}; /* 20 */
//
//fbInfoElementSpec_t mdDnsRRIpv6Spec[] = { /* has to be full */
//    { "flowStartMilliseconds",              8, 0 },
//    { "sourceIPv6Address",                  16,0 },
//    { "destinationIPv6Address",             16,0 },
//    { "dnsTTL",                             4, 0 },
//    { "observationDomainId",                4, 0 },
//    { "yafFlowKeyHash",                     4, 0 },
//    { "dnsRRType",                          2, 0 },
//    { "sourceTransportPort",                2, 0 },
//    { "destinationTransportPort",           2, 0 },
//    { "vlanId",                             2, 0 },
//    { "dnsId",                              2, 0 },
//    { "protocolIdentifier",                 1, 0 },
//    { "dnsQueryResponse",                   1, 0 }, /* Q or R - uint8*/
//    { "dnsAuthoritative",                   1, 0 }, /* auth response (1)*/
//    { "dnsResponseCode",                    1, 0 }, /* nxdomain (1) */
//    { "dnsSection",                         1, 0 }, /* (qry,ans,auth,add'l) */
//    { "paddingOctets",                      5, 0 },
//    { "dnsName",                            FB_IE_VARLEN, 0 },
//    { "smDNSData",                          FB_IE_VARLEN, 0 },
//    FB_IESPEC_NULL
//}; /* 20 */


/***************** END CHECKERS **********************/
