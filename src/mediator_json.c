/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_json.c
 *
 *  Contains most of the JSON-y functions.
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

#include "mediator_structs.h"
#include "mediator_util.h"
#include "mediator_inf.h"
#include "mediator_print.h"
#include "mediator_json.h"
#include "specs.h"

/* RFC 4627 -
Any character may be escaped.  If the character is in the Basic
   Multilingual Plane (U+0000 through U+FFFF), then it may be
   represented as a six-character sequence: a reverse solidus, followed
   by the lowercase letter u, followed by four hexadecimal digits that
   encode the character's code point.  The hexadecimal letters A though
   F can be upper or lowercase.  So, for example, a string containing
   only a single reverse solidus character may be represented as
   "\u005C".
*/

#if 0
//gboolean
//mdJsonifyEscapeChars(
//    mdBuf_t  *mdbuf,
//    size_t   *rem,
//    uint8_t  *buf,
//    size_t   buflen)
//{
//    size_t i;
//    ssize_t ret;
//    uint8_t ch;
//
//    for (i = 0; i < buflen; i++) {
//        ch = buf[i];
//        if (ch < 32 || ch >= 127) {
//            ret = snprintf(mdbuf->cp, *rem, "\\u%04x", ch);
//        } else if (ch == '\\') {
//            ret = snprintf(mdbuf->cp, *rem, "\\\\");
//        } else if (ch == '"') {
//            ret = snprintf(mdbuf->cp, *rem, "\\\"");
//        } else {
//            ret = snprintf(mdbuf->cp, *rem, "%c", ch);
//        }
//        if (ret < 0) return FALSE;
//        if ((size_t)ret >= *rem) return FALSE;
//        *rem -= ret;
//        mdbuf->cp += ret;
//    }
//
//    return TRUE;
//
//}
#endif  /* 0 */

/*
 *    If this is true, invalid UTF-8 is treated as ASCII and anything outside
 *    of 32-126 (space to tilde) is escaped.  If this is false, invalid UTF-8
 *    is made valid by substituting the Unicode replacement character.
 */
#ifndef MD_INVALID_UTF8_ASCII
#define MD_INVALID_UTF8_ASCII 1
#endif



/**
 *    Appends `len` octets from `cp` to `str` treating each octet as ASCII,
 *    escaping '\"' and '\\', and using \\xhh (double-slash, x, two lowercase
 *    hexadecimal characters) for anything outside [ -~].
 *
 *    This function does not stop at '\0'.
 */
gboolean
mdJsonifyAsAscii(
    GString        *str,
    const uint8_t  *cp,
    size_t          len)
{
#if 0
    static const char ascii_chars[] =
        " !#$%&'()*+,-./0123456789:;<=>?"   /* 0x20-0x21,0x23-0x3f (no \") */
        "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"   /* 0x40-0x5b,0x5d-0x5f (no \\) */
        "`abcdefghijklmnopqrstuvwxyz{|}~";  /* 0x60-0x7e (no del) */
#endif

    for ( ; len > 0; ++cp, --len) {
        if (*cp < (uint8_t)' ' || *cp > (uint8_t)'~') {
            g_string_append_printf(str, "\\\\x%02x", *cp);
        } else if (*cp == (uint8_t)'\"') {
            g_string_append(str, "\\\"");
        } else if (*cp == (uint8_t)'\\') {
            g_string_append(str, "\\\\");
        } else {
            g_string_append_c(str, (gchar)*cp);
        }
    }

    return TRUE;
}


/**
 *    Appends a Unicode string to a GString.
 *
 *    Attempts to treat the first `len` octets of `cp` as UTF-8 encoded
 *    Unicode and appends it to `str`, escaping quotation mark ('\"'), reverse
 *    solidus ('\\'), newline ('\n'), carriage-return ('\r'), and tab ('\t'),
 *    and using \uHHHH (reverse solidus, u, four uppercase hexadecimal
 *    characters) for any non-printable character.
 *
 *    If `cp` is not valid UTF-8, calls mdJsonifyAsAscii() to process the
 *    data.
 */
gboolean
mdJsonifyEscapeCharsGStringAppend(
    GString        *str,
    const uint8_t  *cp,
    size_t          len)
{
    const gchar *c = (const gchar *)cp;
    gunichar     p;

#if MD_INVALID_UTF8_ASCII

    if (!g_utf8_validate(c, len, NULL)) {
        /* Use ASCII escaping */
        return mdJsonifyAsAscii(str, cp, len);
    }

#else  /* #if !MD_INVALID_UTF8_ASCII */

    /* Make invalid UTF-8 valid by using Unicode replacement char */
    gchar *validated = NULL;

    if (!g_utf8_validate(c, len, NULL)) {
        validated = g_utf8_make_valid(c, len);
        len = strlen(validated);
        c = validated;
    }

#endif  /* #else of #if MD_INVALID_UTF8_ASCII */

    for (; (p = g_utf8_get_char(c)) != '\0'; c = g_utf8_next_char(c)) {
        switch (p) {
          case '\n':
            g_string_append(str, "\\n");
            break;
          case '\r':
            g_string_append(str, "\\r");
            break;
          case '\t':
            g_string_append(str, "\\t");
            break;
          case '"':
            g_string_append(str, "\\\"");
            break;
          case '\\':
            g_string_append(str, "\\\\");
            break;
          default:
            if (g_unichar_isprint(p)) {
                g_string_append_unichar(str, p);
            } else if (p <= 0xFFFF) {
                g_string_append_printf(str, "\\u%04" PRIX32, p);
            } else if (p <= 0x10FFFF) {
                /* Encode as a UTF-16 surrogate pair */
                g_string_append_printf(str, "\\u%04" PRIX32 "\\u%04" PRIX32,
                                       (0xD800 | ((p - 0x10000) >> 10)),
                                       (0xDC00 | ((p - 0x10000) & 0x03FF)));
            }
            break;
        }
    }

#if !MD_INVALID_UTF8_ASCII
    g_free(validated);
#endif

    return TRUE;
}


gboolean
mdJsonifyDNSRRRecord(
    const mdGenericRec_t   *mdRec,
    GString                *buf)
{
    char                     sabuf[40];
    const fbTemplateField_t *field;
    fbTemplateIter_t         iter = FB_TEMPLATE_ITER_NULL;
    fbRecordValue_t          value = FB_RECORD_VALUE_INIT;
    gboolean                 noComma = TRUE;
    uint8_t                  dnsRRType = 0;

    /* Following code assumes dnsRRType is seen before smDNSData. */

    g_string_append(buf, "{\"dns\":{");

    fbTemplateIterInit(&iter, mdRec->fbRec->tmpl);
    while ((field = fbTemplateIterNext(&iter))) {
        if (fbTemplateFieldCheckIdent(field, 0, 210)) {
            /* paddingOctets */
            continue;
        }

        fbRecordValueClear(&value);
        if (noComma) {
            noComma = FALSE;
        } else {
            g_string_append_c(buf, ',');
        }

        fbRecordGetValueForField(mdRec->fbRec, field, &value);

        /* handle certain fields specially */
        if (CERT_PEN == fbTemplateFieldGetPEN(field)) {
            switch (fbTemplateFieldGetId(field)) {
              case 174:
                /* dnsQueryResponse -- do not print */
                noComma = TRUE;
                continue;
              case 175:
                /* dnsRRType -- remember this value; print */
                dnsRRType = value.v.u64;
                g_string_append_printf(buf, "\"dnsRRType\":%" PRIu64,
                                       value.v.u64);
                continue;
              case 176:
                /* dnsAuthoritative -- print as boolean */
                g_string_append_printf(buf, "\"dnsAuthoritative\":\"%s\"",
                                       (value.v.u64 == 1) ? "True" : "False");
                continue;
              case 927:
                /* smDNSData -- print by value in dnsRRType */
                if (0 == value.v.varfield.len) {
                    noComma = TRUE;
                    continue;
                }
                switch (dnsRRType) {
                  case 0:
                    noComma = TRUE;
                    continue;
                  case 1:
                    if (sizeof(uint32_t) == value.v.varfield.len) {
                        uint32_t sip;
                        memcpy(&sip, value.v.varfield.buf, sizeof(uint32_t));
                        md_util_print_ip4_addr(sabuf, sip);
                        g_string_append_printf(buf, "\"A\":\"%s\"", sabuf);
                        continue;
                    }
                    /* else unexpected size; print using default */
                    break;
                  case 2:
                    g_string_append(buf, "\"dnsNSDName\":\"");
                    mdJsonifyEscapeCharsGStringAppend(
                        buf, value.v.varfield.buf, value.v.varfield.len);
                    g_string_append_c(buf, '\"');
                    continue;
                  case 5:
                    g_string_append(buf, "\"dnsCNAME\":\"");
                    mdJsonifyEscapeCharsGStringAppend(
                        buf, value.v.varfield.buf, value.v.varfield.len);
                    g_string_append_c(buf, '\"');
                    continue;
                  case 12:
                    g_string_append(buf, "\"dnsPTRDName\":\"");
                    mdJsonifyEscapeCharsGStringAppend(
                        buf, value.v.varfield.buf, value.v.varfield.len);
                    g_string_append_c(buf, '\"');
                    continue;
                  case 15:
                    g_string_append(buf, "\"dnsMXExchange\":\"");
                    mdJsonifyEscapeCharsGStringAppend(
                        buf, value.v.varfield.buf, value.v.varfield.len);
                    g_string_append_c(buf, '\"');
                    continue;
                  case 28:
                    if (16 == value.v.varfield.len) {
                        uint8_t sip[16];
                        memcpy(sip, value.v.varfield.buf, sizeof(sip));
                        md_util_print_ip6_addr(sabuf, sip);
                        g_string_append_printf(buf, "\"AAAA\":\"%s\"", sabuf);
                        continue;
                    }
                    /* else unexpected size; print using default */
                    break;
                  case 16:
                    g_string_append(buf, "\"dnsTXTData\":\"");
                    mdJsonifyEscapeCharsGStringAppend(
                        buf, value.v.varfield.buf, value.v.varfield.len);
                    g_string_append_c(buf, '\"');
                    continue;
                  case 33:
                    g_string_append(buf, "\"dnsSRVTarget\":\"");
                    mdJsonifyEscapeCharsGStringAppend(
                        buf, value.v.varfield.buf, value.v.varfield.len);
                    g_string_append_c(buf, '\"');
                    continue;
                  case 6:
                    g_string_append(buf, "\"dnsSOAMName\":\"");
                    mdJsonifyEscapeCharsGStringAppend(
                        buf, value.v.varfield.buf, value.v.varfield.len);
                    g_string_append_c(buf, '\"');
                    continue;
                  case 46:
                    g_string_append(buf, "\"dnsRRSIGSigner\":\"");
                    mdJsonifyEscapeCharsGStringAppend(
                        buf, value.v.varfield.buf, value.v.varfield.len);
                    g_string_append_c(buf, '\"');
                    continue;
                  case 47:
                    g_string_append(buf, "\"dnsNSECNextDomainName\":\"");
                    mdJsonifyEscapeCharsGStringAppend(
                        buf, value.v.varfield.buf, value.v.varfield.len);
                    g_string_append_c(buf, '\"');
                    continue;
                }
                /* unrecognized dnsRRType; print using default */
            }
        }
        /* if no special handler, format based on type */
        switch (fbTemplateFieldGetType(field)) {
          case FB_BOOL:
          case FB_UINT_8:
          case FB_UINT_16:
          case FB_UINT_32:
          case FB_UINT_64:
            g_string_append_printf(buf, "\"%s\":%" PRIu64,
                                   fbTemplateFieldGetName(field),
                                   value.v.u64);
            break;
          case FB_INT_8:
          case FB_INT_16:
          case FB_INT_32:
          case FB_INT_64:
            g_string_append_printf(buf, "\"%s\":%" PRId64,
                                   fbTemplateFieldGetName(field),
                                   value.v.s64);
            break;
          case FB_DT_SEC:
          case FB_DT_MILSEC:
          case FB_DT_MICROSEC:
          case FB_DT_NANOSEC:
            g_string_append_printf(buf, "\"%s\":\"",
                                   fbTemplateFieldGetName(field));
            md_util_timespec_append(buf, &value.v.dt);
            break;
          case FB_FLOAT_32:
          case FB_FLOAT_64:
            g_string_append_printf(buf, "\"%s\":%f",
                                   fbTemplateFieldGetName(field),
                                   value.v.dbl);
            break;
          case FB_MAC_ADDR:
            g_string_append_printf(
                buf, "\"%s\":\"%02x:%02x:%02x:%02x:%02x:%02x\"",
                fbTemplateFieldGetName(field),
                value.v.mac[0], value.v.mac[1], value.v.mac[2],
                value.v.mac[3], value.v.mac[4], value.v.mac[5]);
            break;
          case FB_STRING:
            g_string_append_printf(buf, "\"%s\":\"",
                                   fbTemplateFieldGetName(field));
            mdJsonifyEscapeCharsGStringAppend(
                buf, value.v.varfield.buf, value.v.varfield.len);
            g_string_append_c(buf, '"');
            break;
          case FB_OCTET_ARRAY:
            {
                gchar *base1;
                base1 = g_base64_encode((const guchar *)value.v.varfield.buf,
                                        value.v.varfield.len);
                g_string_append_printf(buf, "\"%s\":\"%s\"",
                                       fbTemplateFieldGetName(field), base1);
                g_free(base1);
            }
            break;
          case FB_IP4_ADDR:
            md_util_print_ip4_addr(sabuf, value.v.ip4);
            g_string_append_printf(buf, "\"%s\":\"%s\"",
                                   fbTemplateFieldGetName(field), sabuf);
            break;
          case FB_IP6_ADDR:
            md_util_print_ip6_addr(sabuf, value.v.ip6);
            g_string_append_printf(buf, "\"%s\":\"%s\"",
                                   fbTemplateFieldGetName(field), sabuf);
            break;
          case FB_BASIC_LIST:
          case FB_SUB_TMPL_LIST:
          case FB_SUB_TMPL_MULTI_LIST:
            break;
          default:
            return FALSE;
        }
    }

    fbRecordValueClear(&value);

    /* remove trailing comma if present */
    if (',' == buf->str[buf->len - 1]) {
        g_string_truncate(buf, buf->len - 1);
    }
    g_string_append(buf, "}}\n");
    return TRUE;
}


gboolean
mdJsonifyDNSRecord(
    const yafDnsQR_t   *dns,
    GString            *buf)
{
    /* prepend the comma separator for all key/value pairs after the first */

    g_string_append_printf(buf,
                           ("\"dnsSection\":%d,\"dnsResponseCode\":%d"
                            ",\"dnsAuthoritative\":\"%s\""
                            ",\"dnsRRType\":%d,\"dnsTTL\":%u,\"dnsId\":%d"),
                           dns->dnsSection, dns->dnsResponseCode,
                           ((dns->dnsAuthoritative) ? "True" : "False"),
                           dns->dnsRRType, dns->dnsTTL, dns->dnsId);

    if (dns->dnsName.buf) {
        g_string_append(buf, ",\"dnsName\":\"");
        mdJsonifyEscapeCharsGStringAppend(buf,
                                          dns->dnsName.buf, dns->dnsName.len);
        g_string_append_c(buf, '"');
    } /* else - query may be for the root server which is NULL*/

    if (dns->dnsRRType == 1) {
        yaf_dnsA_t *aflow = NULL;
        char ipaddr[20];
        while ((aflow = fbSTLNext(yaf_dnsA_t, &(dns->dnsRRList), aflow))) {
            if (aflow->dnsA) {
                md_util_print_ip4_addr(ipaddr, aflow->dnsA);
                g_string_append_printf(buf, ",\"dnsA\":\"%s\"", ipaddr);
            }
        }
    } else if (dns->dnsRRType == 2) {
        yaf_dnsNS_t *ns = NULL;
        while ((ns = fbSTLNext(yaf_dnsNS_t, &(dns->dnsRRList), ns))) {
            g_string_append(buf, ",\"dnsNSDName\":\"");
            mdJsonifyEscapeCharsGStringAppend(buf, ns->dnsNSDName.buf,
                                      ns->dnsNSDName.len);
            g_string_append_c(buf, '\"');
        }

    } else if (dns->dnsRRType == 5) {
        yaf_dnsCNAME_t *c = NULL;
        while ((c = fbSTLNext(yaf_dnsCNAME_t, &(dns->dnsRRList), c))) {
            g_string_append(buf, ",\"dnsCNAME\":\"");
            mdJsonifyEscapeCharsGStringAppend(buf, c->dnsCNAME.buf,
                                  c->dnsCNAME.len);
            g_string_append_c(buf, '\"');
        }
    } else if (dns->dnsRRType == 12) {
        yaf_dnsPTR_t *ptr = NULL;
        while ((ptr = fbSTLNext(yaf_dnsPTR_t, &(dns->dnsRRList), ptr))) {
            g_string_append(buf, ",\"dnsPTRDName\":\"");
            mdJsonifyEscapeCharsGStringAppend(buf, ptr->dnsPTRDName.buf,
                                      ptr->dnsPTRDName.len);
            g_string_append_c(buf, '\"');
        }
    } else if (dns->dnsRRType == 15) {
        yaf_dnsMX_t *mx = NULL;
        while (( mx = fbSTLNext(yaf_dnsMX_t, &(dns->dnsRRList), mx))) {
            g_string_append(buf, ",\"dnsMXExchange\":\"");
            mdJsonifyEscapeCharsGStringAppend(buf, mx->dnsMXExchange.buf,
                                  mx->dnsMXExchange.len);
            g_string_append_c(buf, '\"');
        }
    } else if (dns->dnsRRType == 28) {
        yaf_dnsAAAA_t *aa = NULL;
        char ipaddr[40];
        while ((aa = fbSTLNext(yaf_dnsAAAA_t, &(dns->dnsRRList), aa))) {
            md_util_print_ip6_addr(ipaddr, (uint8_t *)&(aa->dnsAAAA));
            g_string_append_printf(buf, ",\"dnsAAAA\":\"%s\"", ipaddr);
        }
    } else if (dns->dnsRRType == 16) {
        yaf_dnsTXT_t *txt = NULL;
        while ((txt = fbSTLNext(yaf_dnsTXT_t, &(dns->dnsRRList), txt))) {
            g_string_append(buf, ",\"dnsTXTData\":\"");
            mdJsonifyEscapeCharsGStringAppend(buf, txt->dnsTXTData.buf,
                                  txt->dnsTXTData.len);
            g_string_append_c(buf, '\"');
        }
    } else if (dns->dnsRRType == 33) {
        yaf_dnsSRV_t *srv = NULL;
        while ((srv = fbSTLNext(yaf_dnsSRV_t, &(dns->dnsRRList), srv))) {
            g_string_append(buf, ",\"dnsSRVTarget\":\"");
            mdJsonifyEscapeCharsGStringAppend(buf,srv->dnsSRVTarget.buf,
                                      srv->dnsSRVTarget.len);
            g_string_append_c(buf, '\"');
        }
    } else if (dns->dnsRRType == 6) {
        yaf_dnsSOA_t *soa = NULL;
        while ((soa = fbSTLNext(yaf_dnsSOA_t, &(dns->dnsRRList), soa))) {
            g_string_append(buf, ",\"dnsSOAMName\":\"");
            mdJsonifyEscapeCharsGStringAppend(buf,soa->dnsSOAMName.buf,
                                      soa->dnsSOAMName.len);
            g_string_append_c(buf, '\"');
        }
    } else if (dns->dnsRRType == 46) {
        yaf_dnsRRSig_t *rr = NULL;
        while ((rr = fbSTLNext(yaf_dnsRRSig_t, &(dns->dnsRRList), rr))) {
            g_string_append(buf, ",\"dnsRRSIGSigner\":\"");
            mdJsonifyEscapeCharsGStringAppend(buf, rr->dnsRRSIGSigner.buf,
                                      rr->dnsRRSIGSigner.len);
            g_string_append_c(buf, '\"');
        }
    } else if (dns->dnsRRType == 47) {
        yaf_dnsNSEC_t *nsec = NULL;
        while ((nsec = fbSTLNext(yaf_dnsNSEC_t, &(dns->dnsRRList), nsec)))
        {
            g_string_append(buf, ",\"dnsNSECNextDomainName\":\"");
            mdJsonifyEscapeCharsGStringAppend(
                buf, nsec->dnsNSECNextDomainName.buf,
                nsec->dnsNSECNextDomainName.len);
            g_string_append_c(buf, '\"');
        }
    }

    return TRUE;
}

size_t
mdPrintJsonStats(
    const mdGenericRec_t  *mdRec,
    const char            *collectorName,
    FILE                  *lfp,
    GError               **err)
{
    const yafStatsV2Rec_t *stats;
    fbRecord_t             copiedRec = FB_RECORD_INIT;
    yafStatsV2Rec_t        convertedStats;
    GString               *str = g_string_sized_new(512);
    char                   ipaddr[20];
    size_t                 rc;
    mdUtilTCSpecYafStats_t version;

    g_assert(TC_YAF_STATS == mdRec->intTmplCtx->templateContents.general);
    version = mdRec->intTmplCtx->templateContents.specCase.yafStats;
    if (TC_YAF_STATS_V2_SCOPE2 == version) {
        version = TC_YAF_STATS_V2;
    }

    switch (version) {
      case TC_YAF_STATS_V2:
        stats = (yafStatsV2Rec_t *)(mdRec->fbRec->rec);
        break;

      case TC_YAF_STATS_V1:
        stats = &convertedStats;
        copiedRec.rec = (uint8_t *)stats;
        copiedRec.reccapacity = sizeof(*stats);
        if (!fbRecordCopyToTemplate(mdRec->fbRec, &copiedRec, yafStatsV2Tmpl,
                                    256, err))
        {
            return -1;
        }
        break;

      default:
        g_error("Unrecognized templateContents.specCase.yafStats value %d",
                (int)version);
    }

    md_util_print_ip4_addr(ipaddr, stats->exporterIPv4Address);

    g_string_append(str, "{\"stats\":{");

    if (TC_YAF_STATS_V2 == version) {
        g_string_append_printf(str, "\"observationDomainId\":%d,",
                               stats->observationDomainId);
    }
    g_string_append_printf(str, "\"exportingProcessId\":%d,",
                           stats->exportingProcessId);
    g_string_append_printf(str, "\"exporterIPv4Address\":\"%s\",", ipaddr);
    if (TC_YAF_STATS_V2 == version) {
        g_string_append(str, "\"observationTimeSeconds\":\"");
        md_util_time_append(str, stats->observationTimeSeconds,
                            MD_TIME_FMT_ISO);
        g_string_append(str, "\",");
    }
    g_string_append(str, "\"systemInitTimeMilliseconds\":\"");
    md_util_millitime_append(str, stats->systemInitTimeMilliseconds);
    g_string_append_printf(str,
                           "\",\"exportedFlowRecordTotalCount\":%" PRIu64 ",",
                           stats->exportedFlowRecordTotalCount);
    g_string_append_printf(str, "\"packetTotalCount\":%" PRIu64 ",",
                           stats->packetTotalCount);
    g_string_append_printf(str, "\"droppedPacketTotalCount\":%" PRIu64 ",",
                           stats->droppedPacketTotalCount);
    g_string_append_printf(str, "\"ignoredPacketTotalCount\":%" PRIu64 ",",
                           stats->ignoredPacketTotalCount);
    g_string_append_printf(str, "\"notSentPacketTotalCount\":%" PRIu64 ",",
                           stats->notSentPacketTotalCount);
    g_string_append_printf(str, "\"yafExpiredFragmentCount\":%u,",
                           stats->yafExpiredFragmentCount);
    g_string_append_printf(str, "\"yafAssembledFragmentCount\":%u,",
                           stats->yafAssembledFragmentCount);
    g_string_append_printf(str, "\"yafFlowTableFlushEventCount\":%u,",
                           stats->yafFlowTableFlushEventCount);
    g_string_append_printf(str, "\"yafFlowTablePeakCount\":%u,",
                           stats->yafFlowTablePeakCount);
    g_string_append_printf(str, "\"yafMeanFlowRate\":%u,",
                           stats->yafMeanFlowRate);
    g_string_append_printf(str, "\"yafMeanPacketRate\":%u,",
                           stats->yafMeanPacketRate);
    g_string_append_printf(str, "\"collectorName\":\"%s\"", collectorName);

    g_string_append(str, "}}\n");

    rc = fwrite(str->str, 1, str->len, lfp);

    if (rc != str->len) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "Error writing %d b ytes to file: %s\n",
                    (unsigned int)str->len, strerror(errno));
        return 0;
    }

    g_string_free(str, TRUE);

    return rc;
}

size_t
mdPrintJsonTombstone(
    const tombstoneMainV2Rec_t  *tombstone,
    const char                  *collectorName,
    FILE                        *lfp,
    GError                     **err)
{
    GString *str = g_string_sized_new(256);
    size_t rc;
    gboolean firstIter = TRUE;
    const tombstoneAccessV2Rec_t *entry = NULL;

    MD_UNUSED_PARAM(collectorName);

    g_string_append(str, "{\"tombstone\":{");

    g_string_append_printf(str, "\"observationDomainId\":%" PRIu32 ",",
                           tombstone->observationDomainId);
    g_string_append_printf(str, "\"exportingProcessId\":%" PRIu32 ",",
                           tombstone->exportingProcessId);
    g_string_append_printf(str, "\"certToolExporterConfiguredId\":%" PRIu16 ",",
                           tombstone->certToolExporterConfiguredId);
    g_string_append_printf(str, "\"certToolTombstoneId\":%" PRIu32 ",",
                           tombstone->certToolTombstoneId);
    g_string_append(str, "\"observationTimeSeconds\":\"");
    md_util_time_append(str, tombstone->observationTimeSeconds,
                        MD_TIME_FMT_ISO);
    g_string_append(str, "\",");

    g_string_append(str, "\"certToolTombstoneAccessList\":[");

    while ((entry = fbSTLNext(tombstoneAccessV2Rec_t, &tombstone->accessList,
                              entry)))
    {
        if (firstIter) {
            firstIter = FALSE;
        } else {
            g_string_append_c(str, ',');
        }
        g_string_append_printf(str, ("{\"tombstoneAccessEntry\":{"
                                     "\"certToolId\":%" PRIu32
                                     ",\"observationTimeSeconds\":\""),
                               entry->certToolId);
        md_util_time_append(str, entry->observationTimeSeconds,
                            MD_TIME_FMT_ISO);
        g_string_append(str, "\"}}");
    }

    g_string_append(str, "]}}\n");

    rc = fwrite(str->str, 1, str->len, lfp);

    if (rc != str->len) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "Error writing %d bytes to file: %s\n",
                    (unsigned int)str->len, strerror(errno));
        return 0;
    }

    g_string_free(str, TRUE);

    return rc;
}

int
mdJsonifyDNSDedupRecord(
    FILE           *fp,
    GString        *buf,
    mdGenericRec_t *mdRec,
    gboolean        print_last,
    gboolean        base64,
    GError        **err)
{
    size_t rc = 0;
    char sabuf[40];
    md_dns_dedup_t *record = (md_dns_dedup_t *)mdRec->fbRec->rec;
    gchar *base1 = NULL;
    gboolean encode = FALSE;

    /* prepend the comma separator for all key/value pairs after the first */

    g_string_append_printf(buf, "{\"dns\":{\"flowStartMilliseconds\":\"");

    md_util_millitime_append(buf, record->flowStartMilliseconds);
    /* closing quote part of next g_string_append */

    if (print_last) {
        g_string_append(buf, "\",\"flowEndMilliseconds\":\"");
        md_util_millitime_append(buf, record->flowEndMilliseconds);
    }

    g_string_append_printf(buf, "\",\"dnsRRType\":%d", record->rrtype);

    if (print_last) {
        g_string_append_printf(buf, ",\"smDedupHitCount\":%d,\"dnsTTL\":%d",
                               record->smDedupHitCount, record->dnsTTL);
    }

    if (record->rrname.len) {
        if (base64) {
            base1 = g_base64_encode((const guchar *)record->rrname.buf,
                                    record->rrname.len-1);
            g_string_append_printf(buf, ",\"dnsName\":\"%s\"", base1);
            g_free(base1);
        } else {
            g_string_append(buf, ",\"dnsName\":\"");
            mdJsonifyEscapeCharsGStringAppend(buf, record->rrname.buf,
                                              record->rrname.len-1);
            g_string_append_c(buf, '\"');
        }
    }

    switch (record->rrtype) {
      case 1:
        if (record->sourceIPv4Address) {
            md_util_print_ip4_addr(sabuf, record->sourceIPv4Address);
            g_string_append_printf(buf, ",\"A\":\"%s\"", sabuf);
        }
        break;
      case 2:
        g_string_append(buf, ",\"dnsNSDName\":\"");
        encode = TRUE;
        break;
      case 5:
        g_string_append(buf, ",\"dnsCNAME\":\"");
        encode = TRUE;
        break;
      case 12:
        g_string_append(buf, ",\"dnsPTRDName\":\"");
        encode = TRUE;
        break;
      case 15:
        g_string_append(buf, ",\"dnsMXExchange\":\"");
        encode = TRUE;
        break;
      case 28:
        if (16 == record->rrdata.len) {
            md_util_print_ip6_addr(sabuf, record->rrdata.buf);
            g_string_append_printf(buf, ",\"AAAA\":\"%s\"", sabuf);
        } else {
            md_util_print_ip6_addr(sabuf, record->sourceIPv6Address);
            g_string_append_printf(buf, ",\"AAAA\":\"%s\"", sabuf);
        }
        break;
      case 16:
        g_string_append(buf, ",\"dnsTXTData\":\"");
        encode = TRUE;
        break;
      case 33:
        g_string_append(buf, ",\"dnsSRVTarget\":\"");
        encode = TRUE;
        break;
      case 6:
        g_string_append(buf, ",\"dnsSOAMName\":\"");
        encode = TRUE;
        break;
      case 46:
        g_string_append(buf, ",\"dnsRRSIGSigner\":\"");
        encode = TRUE;
        break;
      case 47:
        g_string_append(buf, ",\"dnsNSECNextDomainName\":\"");
        mdJsonifyEscapeCharsGStringAppend(buf, record->rrdata.buf,
                                          record->rrdata.len);
        if (base64) {
            encode = TRUE;
        }  else {
            g_string_append_c(buf, '\"');
        }
    }

    if (encode) {
        if (base64) {
            base1 = g_base64_encode((const guchar *)record->rrdata.buf,
                                    record->rrdata.len-1);
            g_string_append_printf(buf, "%s", base1);
            g_free(base1);
        } else {
            mdJsonifyEscapeCharsGStringAppend(buf, record->rrdata.buf,
                                              record->rrdata.len);
        }
        g_string_append_c(buf, '\"');
    }

    if (record->observationDomainName.len) {
        g_string_append(buf, ",\"observationDomainName\":\"");
        mdJsonifyEscapeCharsGStringAppend(buf,
                                          record->observationDomainName.buf,
                                          record->observationDomainName.len);
        g_string_append_c(buf, '\"');
    }

    g_string_append(buf, "}}\n");

    rc = md_util_write_buffer(fp, buf, "", err);

    if (!rc) {
        return -1;
    }

    return rc;
}

int
mdJsonifySSLDedupRecord(
    FILE        *fp,
    GString     *buf,
    mdGenericRec_t *mdRec,
    GError      **err)
{
    size_t rc = 0;
    md_ssl_t *ssl = (md_ssl_t *)mdRec->fbRec->rec;

    /* prepend the comma separator for all key/value pairs after the first */

    g_string_append(buf, "{\"ssl\":{\"firstSeen\":\"");
    md_util_millitime_append(buf, ssl->flowStartMilliseconds);
    g_string_append(buf, "\",\"lastSeen\":\"");

    md_util_millitime_append(buf, ssl->flowEndMilliseconds);
    g_string_append(buf, "\",\"sslCertSerialNumber\":\"");

    md_util_hexdump_append_nospace(buf,
                                   ssl->sslCertSerialNumber.buf,
                                   ssl->sslCertSerialNumber.len);
    if (ssl->observationDomainName.len) {
        g_string_append(buf, "\",\"observationDomainName\":\"");
        mdJsonifyEscapeCharsGStringAppend(buf, ssl->observationDomainName.buf,
                                          ssl->observationDomainName.len);
    }

    g_string_append_printf(buf, "\",\"smDedupHitCount\":%" PRIu64
                           ",\"sslCertIssuerCommonName\":\"",
                           ssl->smDedupHitCount);

    mdJsonifyEscapeCharsGStringAppend(buf, ssl->sslCertIssuerCommonName.buf,
                                      ssl->sslCertIssuerCommonName.len);
    g_string_append(buf, "\"}}\n");

    rc = md_util_write_buffer(fp, buf, "", err);

    if (!rc) {
        return -1;
    }

    return rc;
}

int
mdJsonifyDedupRecord(
    FILE                *fp,
    GString             *buf,
    const char          *prefix,
    md_dedup_t          *rec,
    GError              **err)
{
    size_t rc = 0;
    char   sabuf[40];

    /* prepend the comma separator for all key/value pairs after the first */

    g_string_append(buf, "{\"dedup\":{\"firstSeen\":\"");

    md_util_millitime_append(
        buf, rec->monitoringIntervalStartMilliSeconds);
    g_string_append(buf, "\",\"lastSeen\":\"");

    md_util_millitime_append(
        buf, rec->monitoringIntervalEndMilliSeconds);

    if (rec->sourceIPv4Address != rec->yafFlowKeyHash) {
        if (rec->sourceIPv4Address == 0) {
            g_string_append(buf, "\",\"sourceIPv6Address\":\"");
            md_util_print_ip6_addr(sabuf, rec->sourceIPv6Address);
        } else {
            g_string_append(buf, "\",\"sourceIPv4Address\":\"");
            md_util_print_ip4_addr(sabuf, rec->sourceIPv4Address);
        }
        g_string_append_printf(
            buf, "%s\",\"yafFlowKeyHash\":%u,\"smDedupHitCount\":%" PRIu64,
            sabuf, rec->yafFlowKeyHash, rec->smDedupHitCount);
    } else {
        /* deduped on hash, not IP so don't print IP */
        g_string_append_printf(
            buf, "\",\"yafFlowKeyHash\":%u,\"smDedupHitCount\":%" PRIu64,
            rec->yafFlowKeyHash, rec->smDedupHitCount);
    }

    /* flow's start time */
    g_string_append(buf, ",\"flowStartMilliseconds\":\"");

    md_util_millitime_append(buf, rec->flowStartMilliseconds);
    g_string_append_c(buf, '\"');

    if (rec->observationDomainName.len) {
        g_string_append(buf, ",\"observationDomainName\":\"");
        mdJsonifyEscapeCharsGStringAppend(buf, rec->observationDomainName.buf,
                                          rec->observationDomainName.len);
    }

    if (rec->smDedupData.len) {
        g_string_append_printf(buf, ",\"%s\":\"", prefix);
        mdJsonifyEscapeCharsGStringAppend(buf, rec->smDedupData.buf,
                                          rec->smDedupData.len);
        g_string_append_c(buf, '\"');
    } else if (rec->sslCertSerialNumber1.len) {
        g_string_append(buf, ",\"sslCertificateChain\":[{\""
                       "sslCertSerialNumber\":\"");
        md_util_hexdump_append_nospace(buf,
                                       rec->sslCertSerialNumber1.buf,
                                       rec->sslCertSerialNumber1.len);
        g_string_append(buf, "\",\"sslCertIssuerCommonName\":\"");
        mdJsonifyEscapeCharsGStringAppend(buf,
                                          rec->sslCertIssuerCommonName1.buf,
                                          rec->sslCertIssuerCommonName1.len);
        g_string_append(buf, "\"}");
        if (rec->sslCertSerialNumber2.len) {
            g_string_append(buf, ",{\"sslCertSerialNumber\":\"");
            md_util_hexdump_append_nospace(buf,
                                           rec->sslCertSerialNumber2.buf,
                                           rec->sslCertSerialNumber2.len);
            g_string_append(buf, "\",\"sslCertIssuerCommonName\":\"");
            mdJsonifyEscapeCharsGStringAppend(
                buf, rec->sslCertIssuerCommonName2.buf,
                rec->sslCertIssuerCommonName2.len);
            g_string_append(buf, "\"}]");
        } else {
            g_string_append_c(buf, ']');
        }
    }

    g_string_append(buf, "}}\n");

    rc = md_util_write_buffer(fp, buf, "", err);

    if (!rc) {
        return -1;
    }

    return rc;
}

#if 0
gboolean
mdJsonifySSLCertBase64(
    GString             *buf,
    fbVarfield_t        *cert)
{
    gchar *base1 = NULL;

    /* remove '},' */
    g_string_truncate(buf, buf->len - 2);

    base1 = g_base64_encode((const guchar *)cert->buf,
                            cert->len);

    g_string_append_printf(buf, ",\"sslCertificate\":\"%s\"},", base1);

    if (base1) {
        g_free(base1);
    }

    return TRUE;
}
#endif  /* 0 */
