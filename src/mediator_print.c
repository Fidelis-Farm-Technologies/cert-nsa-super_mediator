/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_print.c
 *
 *  Contains all printing functions for custom field printers
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


typedef struct mdCollectFieldCtx_st {
    GArray     *valueList;
    gboolean    onlyOne;
} mdCollectFieldCtx_t;

static int
mdCollectFieldCallback(
    const fbRecord_t       *parent_record,
    const fbBasicList_t    *parent_bl,
    const fbInfoElement_t  *field,
    const fbRecordValue_t  *value,
    void                   *ctx)
{
    mdCollectFieldCtx_t *cfctx = (mdCollectFieldCtx_t *)ctx;
    fbRecordValue_t dstValue = FB_RECORD_VALUE_INIT;

    MD_UNUSED_PARAM(parent_record);
    MD_UNUSED_PARAM(parent_bl);
    MD_UNUSED_PARAM(field);

    fbRecordValueCopy(&dstValue, value);
    g_array_append_val(cfctx->valueList, dstValue);

    return (cfctx->onlyOne ? 1 : 0);
}

static gboolean
mdJsonPrintSTMLEntry(
    mdExporter_t                   *exporter,
    fbSubTemplateMultiListEntry_t  *entry,
    GString                        *buf,
    char                            delimiter,
    gboolean                        escape);

static gboolean
mdJsonPrintSTL(
    mdExporter_t               *exporter,
    const fbSubTemplateList_t  *stl,
    GString                    *buf,
    char                        delimiter,
    gboolean                    escape);

static gboolean
mdJsonPrintSTML(
    mdExporter_t                    *exporter,
    const fbSubTemplateMultiList_t  *stml,
    GString                         *buf,
    char                             delimiter,
    gboolean                         escape);

static gboolean
mdJsonPrintBL(
    mdExporter_t         *exporter,
    const fbBasicList_t  *bl,
    GString              *buf,
    char                  delimiter,
    gboolean              escape);


/*
 *  Prints a non-existent value.
 *
 *  Keep the output formats here consistent with those in mdPrintRecordValue()
 *  for elements where we convert numbers to strings (e.g., TCP Flags).
 */
static gboolean
printEmptyValue(
    const fbInfoElement_t  *ie,
    GString                *buf,
    gboolean                json)
{
    if (NULL == ie) {
        return TRUE;
    }

    /* handle certain fields specially */

    switch (fbInfoElementGetType(ie)) {
      case FB_BOOL:
      case FB_UINT_8:
      case FB_UINT_16:
      case FB_UINT_32:
      case FB_UINT_64:
      case FB_INT_8:
      case FB_INT_16:
      case FB_INT_32:
      case FB_INT_64:
        switch (fbInfoElementGetPEN(ie)) {
          case 0:
          case FB_IE_PEN_REVERSE:
            switch (fbInfoElementGetId(ie)) {
              case 6:
                /* tcpControlBits, reverseTcpControlBits */
                md_util_print_tcp_flags(buf, 0, json);
                return TRUE;
              case 136:
                /* flowEndReason (word output) */
                if (json) { g_string_append(buf, "\"\""); }
                return TRUE;
            }
            break;

          case CERT_PEN:
            switch (fbInfoElementGetId(ie)) {
              case 14:
              case 15:
              case FB_IE_VENDOR_BIT_REVERSE | 14:
              case FB_IE_VENDOR_BIT_REVERSE | 15:
                /* initialTCPFlags, unionTCPFlags, and their reverse */
                md_util_print_tcp_flags(buf, 0, json);
                return TRUE;

              case 288:
                /* sslRecordVersion -- print as a string */
                if (json) {
                    g_string_append(buf, "\"\"");
                }
                return TRUE;
            }
            break;
        }
        g_string_append_c(buf, '0');
        break;

      case FB_FLOAT_32:
      case FB_FLOAT_64:
        g_string_append(buf, "0.0");
        break;

      case FB_MAC_ADDR:
        if (json) {
            g_string_append(buf, "\"00:00:00:00:00:00\"");
        } else {
            g_string_append(buf, "00:00:00:00:00:00");
        }
        break;

      case FB_DT_SEC:
      case FB_DT_MILSEC:
      case FB_DT_MICROSEC:
      case FB_DT_NANOSEC:
      case FB_STRING:
      case FB_OCTET_ARRAY:
      case FB_IP4_ADDR:
      case FB_IP6_ADDR:
        if (json) {
            g_string_append(buf, "\"\"");
        }
        break;

      case FB_BASIC_LIST:
      case FB_SUB_TMPL_LIST:
      case FB_SUB_TMPL_MULTI_LIST:
      default:
        return FALSE;
    }
    return TRUE;
}


/*
 *  Keep the formats here consistent with printEmptyValue().
 */
static gboolean
mdPrintRecordValue(
    mdExporter_t           *exporter,
    const fbRecordValue_t  *value,
    GString                *buf,
    char                    delimiter,
    gboolean                escape,
    gboolean                json)
{
    char     tmpchars[40];
    gchar   *base1 = NULL;

    /* handle certain fields specially */
    switch (fbInfoElementGetPEN(value->ie)) {
      case 0:
      case FB_IE_PEN_REVERSE:
        switch (fbInfoElementGetId(value->ie)) {
          case 6:
            /* tcpControlBits, reverseTcpControlBits */
            md_util_print_tcp_flags(buf, value->v.u64, json);
            return TRUE;

          case 136:
            /* flowEndReason (word output) */
            if (json) { g_string_append_c(buf, '"'); }
            switch (value->v.u64 & YAF_END_MASK) {
              case YAF_END_IDLE:
                g_string_append(buf, "idle");
                break;
              case YAF_END_ACTIVE:
                g_string_append(buf, "active");
                break;
              case YAF_END_FORCED:
                g_string_append(buf, "eof");
                break;
              case YAF_END_RESOURCE:
                g_string_append(buf, "rsrc");
                break;
              case YAF_END_UDPFORCE:
                g_string_append(buf, "force");
                break;
            }
            if (json) { g_string_append_c(buf, '"'); }
            return TRUE;

          case 161:
            /* flowDurationMilliseconds */
            if (!json) {
                ldiv_t ms = ldiv((long)value->v.u64, 1000);
                g_string_append_printf(buf, "%ld.%03ld", ms.quot, ms.rem);
                return TRUE;
            }
            break;

          case 351:
            /* layer2SegmentId -- show as hex since high byte is a flag,
             * middle 4 bytes empty, lower 3 bytes are an ID */
            if (json) { g_string_append_c(buf, '"'); }
            g_string_append_printf(buf, "%#018" PRIx64, value->v.u64);
            if (json) { g_string_append_c(buf, '"'); }
            break;
        }
        break;

      case CERT_PEN:
        switch (fbInfoElementGetId(value->ie)) {
          case 14:
            /* initialTCPFlags */
          case 15:
            /* unionTCPFlags */
          case FB_IE_VENDOR_BIT_REVERSE | 14:
            /* reverseInitialTCPFlags */
          case FB_IE_VENDOR_BIT_REVERSE | 15:
            /* reverseUnionTCPFlags */
            md_util_print_tcp_flags(buf, value->v.u64, json);
            return TRUE;

          case 21:
            /* reverseFlowDeltaMilliseconds */
            if (!json) {
                ldiv_t ms = ldiv((long)value->v.u64, 1000);
                g_string_append_printf(buf, "%ld.%03ld", ms.quot, ms.rem);
                return TRUE;
            }
            break;

          case 190:
            /* sslCertSignature -- decode OID */
          case 249:
            /* sslPublicKeyAlgorithm -- decode OID */
            if (json) {
                g_string_append_c(buf, '\"');
                mdUtilAppendDecodedOID(buf, &value->v.varfield);
                g_string_append_c(buf, '\"');
                return TRUE;
            }
            break;

          case 244:
            /* sslCertSerialNumber -- colon separated hexdump */
          case 295:
            /* sslCertificateHash -- colon separated hexdump */
          case 296:
            /* sslBinaryCertificate -- colon separated hexdump */
          case 298:
            /* sslCertificateSHA1 -- colon separated hexdump */
          case 299:
            /* sslCertificateMD5 -- colon separated hexdump */
          case 316:
            /* sslCertExtSubjectKeyIdent -- colon separated hexdump */
          case 324:
            /* sslCertExtAuthorityKeyIdent -- colon separated hexdump */
          case 462:
            /* sslCertificateSHA256 -- colon separated hexdump */
          case 478:
            /* sshServerHostKey -- colon separated hexdump (MD5) */
            if (json) { g_string_append_c(buf, '\"'); }
            mdUtilAppendColonSeparatedHash(buf, &value->v.varfield);
            if (json) { g_string_append_c(buf, '\"'); }
            return TRUE;

          case 247:
            /* sslCertValidityNotBefore -- format date */
          case 248:
            /* sslCertValidityNotAfter -- format date */
            if (json) {
                time_t t;
                g_string_append_c(buf, '"');
                if (mdUtilParseValidityDate(&value->v.varfield, &t)) {
                    md_util_time_append(buf, t, MD_TIME_FMT_ISO);
                } else {
                    md_util_append_varfield(buf, &value->v.varfield);
                }
                g_string_append_c(buf, '"');
                return TRUE;
            }
            break;

          case 288:
            /* sslRecordVersion -- print as hex */
            if (json) {
                g_string_append_printf(buf, "\"%#06" PRIx64 "\"", value->v.u64);
            } else {
                g_string_append_printf(buf, "%#06" PRIx64, value->v.u64);
            }
            return TRUE;

          case 317:
            /* sslCertExtKeyUsage -- expect this to be a set of flags encoded
             * as a bitfield (ASN.1 type 0x03) */
            if (json && value->v.varfield.len >= 2 &&
                0x03 == value->v.varfield.buf[0])
            {
                /* byte after type is the number of remaining bytes; the byte
                 * after that is the number of bit to ignore in final byte */
                const char *usage[] = {
                    "digitalSignature",
                    "nonRepudiation",
                    "keyEncipherment",
                    "dataEncipherment",
                    "keyAgreement",
                    "keyCertSign",
                    "cRLSign",
                    "encipherOnly",
                    "decipherOnly",
                };
                uint8_t len = value->v.varfield.buf[1];
                uint16_t bitlen;
                uint16_t bitpos;
                const uint8_t *byte;
                uint8_t  flag = 0;
                gboolean first = TRUE;
                if (len > 0x7f || len < 2 ||
                    (size_t)(len + 2) != value->v.varfield.len)
                {
                    /* unexpected length; give up */
                    break;
                }
                bitlen = 8 * (len - 1) - value->v.varfield.buf[2];
                if (bitlen > (sizeof(usage)/sizeof(usage[0]))) {
                    bitlen = sizeof(usage)/sizeof(usage[0]);
                }

                byte = &value->v.varfield.buf[2];

                g_string_append_c(buf, '[');
                for (bitpos = 0; bitpos < bitlen; ++bitpos, flag >>= 1) {
                    if (0 == flag) {
                        flag = 0x80;
                        ++byte;
                    }
                    if (*byte & flag) {
                        if (first) {
                            first = FALSE;
                        } else {
                            g_string_append_c(buf, ',');
                        }
                        g_string_append_printf(buf, "\"%s\"", usage[bitpos]);
                    }
                }
                g_string_append_c(buf, ']');
                return TRUE;
            }
            break;

          case 319:
            /* sslCertExtSubjectAltName -- decode type(s) and value(s) */
          case 320:
            /* sslCertExtIssuerAltName -- decode type(s) and value(s) */
          case 321:
            /* sslCertExtCertIssuer -- decode type(s) and value(s) */
            if (json && value->v.varfield.len) {
                /* Enable printing as a list of values, but if count is 1 once
                 * all values are printed the leading '[' will be erased. */
                uint8_t *cc = (uint8_t *)value->v.varfield.buf;
                size_t len = value->v.varfield.len;
                size_t startlen = buf->len;
                uint16_t count = 0;
                uint16_t newlen;

                while ((newlen = md_util_decode_asn1_sequence(&cc, &len))) {
                    if (*cc == 0x30) {
                        /* this is a sequence - ignore */
                        break;
                    }
                    if (0 == count) {
                        count = 1;
                        g_string_append(buf, "[\"");
                    } else {
                        ++count;
                        g_string_append(buf, "\",\"");
                    }
                    mdJsonifyEscapeCharsGStringAppend(buf, cc, newlen);
                    cc += newlen;
                    len -= newlen;
                }
                if (count) {
                    if (1 == count) {
                        /* remove '[' at position startlen */
                        g_string_erase(buf, startlen, 1);
                        g_string_append_c(buf, '"');
                    } else {
                        g_string_append(buf, "\"]");
                    }
                    return TRUE;
                }
                /* else we did not append anything to the output, so drop into
                 * the code below to print the value generically */
            }
            break;

          case 463:
            /* sslClientJA3 -- (MD5) hexdump no colons */
          case 465:
            /* sslServerJA3S -- (MD5) hexdump no colons */
          case 468:
            /* sshHassh -- (MD5) hexdump no colons */
          case 470:
            /* sshServerHassh -- (MD5) hexdump no colons */
            if (json) { g_string_append_c(buf, '\"'); }
            mdUtilAppendHash(buf, &value->v.varfield);
            if (json) { g_string_append_c(buf, '\"'); }
            return TRUE;

          case 507:
            /* firstEightNonEmptyPacketDirections -- print in base 2; forward
             * is 0 and reverse is 1 */
            if (json) { g_string_append_c(buf, '\"'); }
            g_string_append_printf(buf, "%c%c%c%c%c%c%c%c",
                                   ((value->v.u64 & (1 << 7)) ? '1' : '0'),
                                   ((value->v.u64 & (1 << 6)) ? '1' : '0'),
                                   ((value->v.u64 & (1 << 5)) ? '1' : '0'),
                                   ((value->v.u64 & (1 << 4)) ? '1' : '0'),
                                   ((value->v.u64 & (1 << 3)) ? '1' : '0'),
                                   ((value->v.u64 & (1 << 2)) ? '1' : '0'),
                                   ((value->v.u64 & (1 << 1)) ? '1' : '0'),
                                   ((value->v.u64 & (1 << 0)) ? '1' : '0'));
            if (json) { g_string_append_c(buf, '\"'); }
            return TRUE;

          case 943:
            /* yafLayer2SegmentId -- show as hex since high byte is a flag,
             * remainder is an ID */
            if (json) { g_string_append_c(buf, '"'); }
            g_string_append_printf(buf, "%#010" PRIx64, value->v.u64);
            if (json) { g_string_append_c(buf, '"'); }
            break;
        }
        break;
    }

    switch (fbInfoElementGetType(value->ie)) {
      case FB_BOOL:
      case FB_UINT_8:
      case FB_UINT_16:
      case FB_UINT_32:
      case FB_UINT_64:
        g_string_append_printf(buf, "%" PRIu64, value->v.u64);
        break;
      case FB_INT_8:
      case FB_INT_16:
      case FB_INT_32:
      case FB_INT_64:
        g_string_append_printf(buf, "%" PRId64, value->v.s64);
        break;
      case FB_DT_SEC:
      case FB_DT_MILSEC:
      case FB_DT_MICROSEC:
      case FB_DT_NANOSEC:
        if (json) { g_string_append_c(buf, '"'); }
        md_util_timespec_append(buf, &value->v.dt);
        if (json) { g_string_append_c(buf, '"'); }
        break;
      case FB_FLOAT_32:
      case FB_FLOAT_64:
        g_string_append_printf(buf, "%f", value->v.dbl);
        break;
      case FB_MAC_ADDR:
        if (json) { g_string_append_c(buf, '"'); }
        g_string_append_printf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                               value->v.mac[0], value->v.mac[1],
                               value->v.mac[2], value->v.mac[3],
                               value->v.mac[4], value->v.mac[5]);
        if (json) { g_string_append_c(buf, '"'); }
        break;
      case FB_STRING:
        if (json) {
            g_string_append_c(buf, '"');
            mdJsonifyEscapeCharsGStringAppend(buf, value->v.varfield.buf,
                                              value->v.varfield.len);
            g_string_append_c(buf, '"');
        } else if (!escape) {
            g_string_append_len(buf, (char *)value->v.varfield.buf,
                                value->v.varfield.len);
        } else {
            mdPrintEscapeChars(buf, value->v.varfield.buf,
                               value->v.varfield.len, delimiter, FALSE);
        }
        break;
      case FB_OCTET_ARRAY:
        if (json) {
            base1 = g_base64_encode((const guchar *)value->v.varfield.buf,
                                    value->v.varfield.len);
            g_string_append_printf(buf, "\"%s\"", base1);
            g_free(base1);
        } else {
            g_string_append_c(buf, '\n');
            md_util_hexdump_append_block(buf, "  -> ",
                                         value->v.varfield.buf,
                                         value->v.varfield.len);
        }
        break;
      case FB_IP4_ADDR:
        if (json) { g_string_append_c(buf, '"'); }
        md_util_print_ip4_addr(tmpchars, value->v.ip4);
        g_string_append_printf(buf, "%s", tmpchars);
        if (json) { g_string_append_c(buf, '"'); }
        break;
      case FB_IP6_ADDR:
        if (json) { g_string_append_c(buf, '"'); }
        md_util_print_ip6_addr(tmpchars, value->v.ip6);
        g_string_append_printf(buf, "%s", tmpchars);
        if (json) { g_string_append_c(buf, '"'); }
        break;
      case FB_BASIC_LIST:
        if (json) {
            mdJsonPrintBL(exporter, value->v.bl, buf, delimiter, escape);
        }
        break;
      case FB_SUB_TMPL_LIST:
        if (json) {
            mdJsonPrintSTL(exporter, value->v.stl, buf, delimiter, escape);
        }
        break;
      case FB_SUB_TMPL_MULTI_LIST:
        if (json) {
            mdJsonPrintSTML(exporter, value->v.stml, buf, delimiter, escape);
        }
        break;
      default:
        return FALSE;
    }

#if 0
    if (json && quote) {
        g_string_append_c(buf, '"');
    }

    if (escape) {
        if (!mdPrintEscapeChars(buf, (uint8_t *)tmpbuf.buf,
                                tmpbuf.cp - tmpbuf.buf, delimiter, json))
        {
            return FALSE;
        }
    } else {
        g_string_append_len(buf, tmpbuf.buf, tmpbuf.cp - tmpbuf.buf);
    }

    if (json && quote) {
        g_string_append_c(buf, '"');
    }
#endif  /* 0 */

    return TRUE;
}


gboolean
mdPrintFieldEntry(
    mdFullFlow_t    *flow,
    mdExporter_t    *exporter,
    GString         *buf,
    mdFieldEntry_t  *field,
    gboolean         json)
{
    mdCollectFieldCtx_t    ctx;
    fbRecordValue_t     *value;
    unsigned int i;

    /* FIXME: Change this function so the callback appends the value to the
     * GString instead of needing to copy all the values into an GArray,
     * copying them into the GString, then clearing the GArray. */

    ctx.valueList = g_array_new(0, 0, sizeof(fbRecordValue_t));
    ctx.onlyOne = field->onlyFetchOne;

    mdFieldEntryFindAllElementValues(flow, field, 0, mdCollectFieldCallback,
                                     (void *)(&ctx));

    if (json) {
        g_string_append_printf(buf, "\"%s\":", field->elem->name);
    }

    if (ctx.valueList->len == 0) {
        printEmptyValue(field->elem, buf, json);
        g_string_append_printf(buf, "%c", exporter->delimiter);
        g_array_free(ctx.valueList, TRUE);
        return TRUE;
    }

    if (ctx.valueList->len > 1) {
        g_string_append_c(buf, '[');
    }

    for (i = 0; i < ctx.valueList->len; ++i) {
        value = &g_array_index(ctx.valueList, fbRecordValue_t, i);
        if (i > 0) {
            g_string_append(buf, ", ");
        }
        if (!mdPrintRecordValue(exporter, value, buf, exporter->delimiter,
                                exporter->escape_chars, json))
        {
            fbRecordValueClear(value);
            for (++i; i < ctx.valueList->len; ++i) {
                value = &g_array_index(ctx.valueList, fbRecordValue_t, i);
                fbRecordValueClear(value);
            }
            g_array_free(ctx.valueList, TRUE);
            return FALSE;
        }
        fbRecordValueClear(value);
    }
    if (ctx.valueList->len > 1) {
        g_string_append_c(buf, ']');
    }
    g_string_append_c(buf, exporter->delimiter);

    g_array_free(ctx.valueList, TRUE);
    return TRUE;
}


/**
 *    Print a textual representation of 'entry' to 'fp'.
 */
static gboolean
mdJsonPrintSTMLEntry(
    mdExporter_t                   *exporter,
    fbSubTemplateMultiListEntry_t  *entry,
    GString                        *buf,
    char                            delimiter,
    gboolean                        escape)
{
    gboolean   first = TRUE;
    fbRecord_t subrec = FB_RECORD_INIT;

    subrec.tid = fbSubTemplateMultiListEntryGetTemplateID(entry);
    subrec.tmpl = fbSubTemplateMultiListEntryGetTemplate(entry);

    g_string_append(buf, "[{");

    while ((subrec.rec = fbSTMLEntryNext(uint8_t, entry, subrec.rec))) {
        if (!first) {
            g_string_append(buf, "},{");
        } else {
            first = FALSE;
        }
        mdPrintDPIRecord(exporter, &subrec, NULL, buf, delimiter,
                         escape, TRUE);
    }

    g_string_append(buf, "}]");

    return TRUE;
}

/**
 *    Print a textual representation of 'stl' to 'fp'.
 */
static gboolean
mdJsonPrintSTL(
    mdExporter_t               *exporter,
    const fbSubTemplateList_t  *stl,
    GString                    *buf,
    char                        delimiter,
    gboolean                    escape)
{
    gboolean   first = TRUE;
    fbRecord_t subrec = FB_RECORD_INIT;

    subrec.tid = fbSubTemplateListGetTemplateID(stl);
    subrec.tmpl = fbSubTemplateListGetTemplate(stl);

    g_string_append(buf, "[{");
    while ((subrec.rec = fbSTLNext(uint8_t, stl, subrec.rec))) {
        if (!first) {
            g_string_append(buf, "},{");
        } else {
            first = FALSE;
        }
        mdPrintDPIRecord(exporter, &subrec, NULL, buf, delimiter, escape, TRUE);
    }

    g_string_append(buf, "}]");

    return TRUE;
}

/**
 *    Print a textual representation of 'stml' to 'fp'.
 */
static gboolean
mdJsonPrintSTML(
    mdExporter_t                    *exporter,
    const fbSubTemplateMultiList_t  *stml,
    GString                         *buf,
    char                             delimiter,
    gboolean                         escape)
{
    fbSubTemplateMultiListEntry_t *entry = NULL;
    gboolean first = TRUE;

    /* protect against a double or trailing comma in the parent
     * when this STML is empty */
    if (0 == fbSubTemplateMultiListCountElements(stml)) {
        g_string_append(buf, "{}");
        return TRUE;
    }

    while ((entry = fbSubTemplateMultiListGetNextEntry(stml, entry))) {
        if (!first) {
            g_string_append_c(buf, ',');
        } else {
            first = FALSE;
        }
        mdJsonPrintSTMLEntry(exporter, entry, buf, delimiter, escape);
    }

    return TRUE;
}

/**
 *    Print a textual representation of 'bl' to 'fp'.
 */
static gboolean
mdJsonPrintBL(
    mdExporter_t         *exporter,
    const fbBasicList_t  *bl,
    GString              *buf,
    char                  delimiter,
    gboolean              escape)
{
    const fbInfoElement_t *ie = fbBasicListGetInfoElement(bl);
    fbTemplateField_t      field = FB_TEMPLATEFIELD_INIT;
    fbRecord_t             rec = FB_RECORD_INIT;
    gboolean first = TRUE;
    fbRecordValue_t        value = FB_RECORD_VALUE_INIT;

    if (!ie) {
        return FALSE;
    }
    /* create a fake field */
    field.canon = ie;
    field.len = fbBasicListGetElementLength(bl);

    /* create a fake record */
    rec.recsize = field.len;
    rec.reccapacity = field.len;

    g_string_append_c(buf, '[');

    while ((rec.rec = fbBLNext(uint8_t, bl, rec.rec))) {
        if (!first) {
            g_string_append_c(buf, ',');
        } else {
            first = FALSE;
        }
        fbRecordValueClear(&value);
        fbRecordGetValueForField(&rec, &field, &value);
        mdPrintRecordValue(exporter, &value, buf, delimiter, escape,
                           TRUE);
    }

    g_string_append_c(buf, ']');

    return TRUE;
}



static gboolean
mdPrintDPIRecordValue(
    mdExporter_t           *exporter,
    const fbRecordValue_t  *value,
    GString                *buf,
    const GString          *prefixString,
    char                    delimiter,
    gboolean                escape)
{
    int     ret;
    char   *label;
    FILE   *fp = NULL;
    GError *err = NULL;

    label = mdGetTableItem(value->ie->name);
    if (label == NULL) {
        return TRUE;
    }
    g_string_append_printf(buf, "%s|", label);

    if (prefixString->len) {
        g_string_append_printf(buf, "%s", prefixString->str);
    }

    g_string_append_printf(buf, "%d%c", value->ie->num, delimiter);

    mdPrintRecordValue(exporter, value, buf, delimiter, escape, FALSE);

    g_string_append_c(buf, '\n');

    if (exporter->multi_files) {
        if (mdTableHashEnabled()) {
            label = mdGetTableItem(value->ie->name);
            if (label == NULL) {
                return TRUE;
            }
        }

        fp = mdGetTableFile(exporter, value->ie->name);
        if (fp == NULL) {
            g_warning("Error: File does not exist for DPI element");
            return TRUE;
        }

        ret = md_util_write_buffer(fp, buf, exporter->name, &err);
        if (!ret) {
            return -1;
        }
    }

    return TRUE;
}


/*
 *  Appends the name of `field` to `buf`, ensuring the name is unique.
 *
 *  Specifically, it appends "-COUNT" to the name if the name has been seen
 *  before: The first instance is "foo", the next is "foo-2", the third
 *  "foo-3", et cetera.
 *
 *  If `field` is of type basicList, the name of the InfoElement in the
 *  basicList is printed, which is why `value` must also be provided.
 *
 *  `table` is used to maintain the unique counts for each name.  It should be
 *  created as
 *
 *  g_hash_table_new_full(g_str_hash, g_str_equal, NULL, &g_free);
 */
static void
mdJsonPrintFieldName(
    const fbTemplateField_t *field,
    const fbRecordValue_t   *value,
    GString                 *buf,
    GHashTable              *table)
{
    unsigned int *current;
    const char *name;

    /* It is tempting to use the repeat count (midx) value here, but using a
     * separate hash table works in the bizarre case where a template contains
     * IE "foo" and a basicList of IE "foo". */

    /* Get the field's name; for a basicList, use the IE it contains */
    if (fbTemplateFieldGetType(field) != FB_BASIC_LIST) {
        name = fbTemplateFieldGetName(field);
    } else {
        name = fbInfoElementGetName(fbBasicListGetInfoElement(value->v.bl));
    }

    current = (unsigned int *)g_hash_table_lookup(table, name);
    if (current) {
        /* we've seen it before */
        ++*current;
        g_string_append_printf(buf, "\"%s-%u\": ", name, *current);
    } else {
        /* first time we've seen it; add it to the table */
        g_string_append_printf(buf, "\"%s\": ", name);
        current = g_new(unsigned int, 1);
        *current = 1;
        g_hash_table_insert(table, (gpointer)name, current);
    }
}


gboolean
mdPrintDPIRecord(
    mdExporter_t       *exporter,
    const fbRecord_t   *rec,
    const GString      *prefixString,
    GString            *buf,
    char                delimiter,
    gboolean            escape,
    gboolean            json)
{
    fbTemplateIter_t   iter;
    const fbTemplateField_t *field;
    fbRecord_t         subrec = FB_RECORD_INIT;
    fbSubTemplateMultiListEntry_t *entry = NULL;
    fbRecordValue_t    value = FB_RECORD_VALUE_INIT;
    gboolean           first = TRUE;
    GHashTable        *uniqNames = NULL;

    if (json) {
        uniqNames = g_hash_table_new_full(g_str_hash, g_str_equal,
                                          NULL, &g_free);
    }

    fbTemplateIterInit(&iter, rec->tmpl);
    while ((field = fbTemplateIterNext(&iter))) {
        if (fbTemplateFieldCheckIdent(field, 0, 210)) {
            /* paddingOctets */
            continue;
        }

        fbRecordValueClear(&value);
        if (json) {
            if (!first) {
                g_string_append_c(buf, ',');
            } else {
                first = FALSE;
            }
            fbRecordGetValueForField(rec, field, &value);
            mdJsonPrintFieldName(field, &value, buf, uniqNames);
            mdPrintRecordValue(exporter, &value, buf, delimiter,
                               escape, json);
        } else {
            fbRecordGetValueForField(rec, field, &value);
            switch (fbTemplateFieldGetType(field)) {
              case FB_BASIC_LIST:
                mdPrintDPIBasicList(exporter, buf, prefixString, value.v.bl,
                                    delimiter, escape);
                break;
              case FB_SUB_TMPL_LIST:
                subrec.tid = fbSubTemplateListGetTemplateID(value.v.stl);
                subrec.tmpl = fbSubTemplateListGetTemplate(value.v.stl);

                while ((subrec.rec = fbSTLNext(uint8_t, value.v.stl,
                                               subrec.rec)))
                {
                    mdPrintDPIRecord(exporter, &subrec, prefixString, buf,
                                     delimiter, escape, json);
                }
                break;
              case FB_SUB_TMPL_MULTI_LIST:
                while ((entry = fbSTMLNext(value.v.stml, entry))) {
                    subrec.tid = fbSubTemplateMultiListEntryGetTemplateID(
                        entry);
                    subrec.tmpl = fbSubTemplateMultiListEntryGetTemplate(entry);
                    while ((subrec.rec = fbSTMLEntryNext(uint8_t, entry,
                                                         subrec.rec)))
                    {
                        mdPrintDPIRecord(exporter, &subrec, prefixString, buf,
                                         delimiter, escape, json);
                    }
                }
                break;
              default:
                mdPrintDPIRecordValue(exporter, &value, buf, prefixString,
                                      delimiter, escape);
                break;
            }
        }
    }
    fbRecordValueClear(&value);
    if (uniqNames) {
        g_hash_table_destroy(uniqNames);
    }
    return TRUE;
}


gboolean
mdPrintDecimal(
    GString  *buf,
    char      delimiter,
    int       decimal)
{
    g_string_append_printf(buf, "%d%c", decimal, delimiter);
    return TRUE;
}

/**
 * mdPrintStats
 *
 * print a YAF stats message to the given exporter
 *
 */
size_t
mdPrintStats(
    yafStatsV2Rec_t  *stats,
    const char       *name,
    FILE             *lfp,
    char              delim,
    gboolean          allYafStatsAllowed,
    gboolean          statsOnlySpecified,
    GError          **err)
{
    GString *str = NULL;
    char     ipaddr[20];
    size_t   rc;

    md_util_print_ip4_addr(ipaddr, stats->exporterIPv4Address);
    str = g_string_new(NULL);

    if (allYafStatsAllowed) {
        g_string_printf(str,
                        "stats%c%" PRIu64 "%c%" PRIu64 "%c%" PRIu64 "%c%"
                        PRIu64 "%c",
                        delim, stats->exportedFlowRecordTotalCount,
                        delim,
                        stats->packetTotalCount, delim,
                        stats->droppedPacketTotalCount, delim,
                        stats->ignoredPacketTotalCount, delim);
    } else if (statsOnlySpecified) {
        /* stats only */
        g_string_printf(str,
                        "\\N%c%" PRIu64 "%c%" PRIu64 "%c%" PRIu64 "%c%"
                        PRIu64 "%c", delim,
                        stats->exportedFlowRecordTotalCount, delim,
                        stats->packetTotalCount, delim,
                        stats->droppedPacketTotalCount, delim,
                        stats->ignoredPacketTotalCount, delim);
    }

    g_string_append_printf(str, "%u%c%u%c%u%c%u%c%s%c",
                           stats->yafExpiredFragmentCount, delim,
                           stats->yafAssembledFragmentCount, delim,
                           stats->yafFlowTableFlushEventCount, delim,
                           stats->yafFlowTablePeakCount, delim,
                           ipaddr, delim);
    g_string_append_printf(str, "%d%c%u%c%u%c%s\n",
                           stats->exportingProcessId, delim,
                           stats->yafMeanFlowRate, delim,
                           stats->yafMeanPacketRate, delim,
                           name);

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


/**
 * mdPrintBasicHeader
 *
 * appends a format header to the given GString
 *
 */
void
mdPrintBasicHeader(
    mdExporter_t   *exporter,
    GString        *rstr)
{
    mdFieldEntry_t *fLNode;

    if (NULL == exporter->customFieldList) {
        return;
    }

    fLNode = exporter->customFieldList;
    for (;;) {
        if (fLNode->next != NULL) {
            g_string_append_printf(
                rstr, "%s%c", fLNode->elem->name, exporter->delimiter);
            fLNode = fLNode->next;
        } else {
            g_string_append_printf(rstr, "%s\n", fLNode->elem->name);
            break;
        }
    }
}

int
mdPrintDNSDedupRecord(
    FILE            *fp,
    GString         *buf,
    char             delimiter,
    mdGenericRec_t  *mdRec,
    gboolean         base64,
    gboolean         print_last,
    gboolean         escape_chars,
    GError         **err)
{
    char      sabuf[40];
    md_dns_dedup_t *record = (md_dns_dedup_t *)mdRec->fbRec->rec;
    size_t    rc;
    gchar    *base1 = NULL;

    md_util_millitime_append(buf, record->flowStartMilliseconds);
    g_string_append_c(buf, delimiter);

    if (print_last) {
        md_util_millitime_append(buf, record->flowEndMilliseconds);
        g_string_append_c(buf, delimiter);
    }

    g_string_append_printf(buf, "%d%c", record->rrtype, delimiter);

    if (record->rrname.len) {
        if (base64) {
            base1 = g_base64_encode((const guchar *)record->rrname.buf,
                                    record->rrname.len - 1);
            g_string_append_printf(buf, "%s%c", base1, delimiter);
            g_free(base1);
        } else {
            /* this is a dns dedup record so we have to subtract one
             * from the name since we added one for the hash table
             * (string hash requires null char at end of string) */
            if (escape_chars) {
                mdPrintEscapeChars(buf, (uint8_t *)(record->rrname.buf),
                                   record->rrname.len - 1, delimiter, FALSE);
            } else {
                g_string_append_len(buf, (gchar *)record->rrname.buf,
                                    record->rrname.len - 1);
            }
            g_string_append_c(buf, delimiter);
        }
    }

    if (print_last) {
        g_string_append_printf(buf, "%d%c",
                       record->smDedupHitCount, delimiter);
    }

    if (record->rrtype == 1) {
        md_util_print_ip4_addr(sabuf, record->sourceIPv4Address);
        g_string_append_printf(buf, "%s", sabuf);
    } else if (record->rrtype == 28) {
        if (record->rrdata.len == 16) {
            md_util_print_ip6_addr(sabuf, record->rrdata.buf);
        } else {
            md_util_print_ip6_addr(sabuf, record->sourceIPv6Address);
        }
        g_string_append_printf(buf, "%s", sabuf);
    } else if (record->rrdata.len) {
        if (base64) {
            base1 = g_base64_encode((const guchar *)record->rrdata.buf,
                                    record->rrdata.len);
            g_string_append_printf(buf, "%s", base1);
            g_free(base1);
        } else {
            if (escape_chars) {
                mdPrintEscapeChars(buf, (uint8_t *)(record->rrdata.buf),
                                   record->rrdata.len, delimiter, FALSE);
            } else {
                g_string_append_len(buf, (gchar *)record->rrdata.buf,
                                    record->rrdata.len);
            }
        }
    }
    if (record->observationDomainName.len) {
        g_string_append_c(buf, delimiter);
        g_string_append_len(buf, (gchar *)record->observationDomainName.buf,
                            record->observationDomainName.len);
    }

    g_string_append_c(buf, '\n');

    rc = md_util_write_buffer(fp, buf, "", err);

    if (!rc) {
        return -1;
    }

    return rc;
}

int
mdPrintDNSRRRecord(
    GString         *buf,
    FILE            *fp,
    char             delimiter,
    mdGenericRec_t  *mdRec,
    gboolean         base64,
    gboolean         escape_chars,
    GError         **err)
{
    char         sabuf[40];
    md_dns_rr_t *record = (md_dns_rr_t *)mdRec->fbRec->rec;
    size_t       rc;
    gchar       *base1 = NULL;

    md_util_millitime_append(buf, record->flowStartMilliseconds);
    g_string_append_printf(buf, "%c%u%c%u%c", delimiter,
                           record->yafFlowKeyHash, delimiter,
                           record->observationDomainId, delimiter);

    if (record->sourceIPv4Address) {
        md_util_print_ip4_addr(sabuf, record->sourceIPv4Address);
    } else {
        md_util_print_ip6_addr(sabuf, record->sourceIPv6Address);
    }

    g_string_append_printf(buf, "%s%c", sabuf, delimiter);

    if (record->destinationIPv4Address) {
        md_util_print_ip4_addr(sabuf, record->destinationIPv4Address);
    } else {
        md_util_print_ip6_addr(sabuf, record->sourceIPv6Address);
    }
    g_string_append_printf(buf, "%s", sabuf);

    g_string_append_printf(buf, "%c%d%c%d%c%d%c%d",
                   delimiter, record->protocolIdentifier,
                   delimiter, record->sourceTransportPort, delimiter,
                   record->destinationTransportPort, delimiter, record->vlanId);

    if (record->dnsQueryResponse) {
        /* this is a response */
        g_string_append_printf(buf, "%cR%c%d%c", delimiter, delimiter,
                       record->dnsId, delimiter);
    } else {
        g_string_append_printf(buf, "%cQ%c%d%c", delimiter, delimiter,
                       record->dnsId, delimiter);
    }

    /* section, nxdomain, auth, type, ttl */

    g_string_append_printf(buf, "%d%c%d%c%d%c%d%c%u%c", record->dnsSection,
                   delimiter, record->dnsResponseCode, delimiter,
                   record->dnsAuthoritative,
                   delimiter, record->dnsRRType, delimiter, record->dnsTTL,
                   delimiter);

    if (record->rrname.len) {
        if (base64) {
            base1 = g_base64_encode((const guchar *)record->rrname.buf,
                                    record->rrname.len);
            g_string_append_printf(buf, "%s%c", base1, delimiter);
            g_free(base1);
        } else {
            if (escape_chars) {
                mdPrintEscapeChars(buf, (uint8_t *)(record->rrname.buf),
                                   record->rrname.len, delimiter, FALSE);
            } else {
                g_string_append_len(buf, (gchar *)record->rrname.buf,
                                    record->rrname.len);
            }
            g_string_append_c(buf, delimiter);
        }
    }

    if (record->rrdata.len) {
        if (record->dnsRRType == 1) {
            uint32_t sip;
            memcpy(&sip, record->rrdata.buf, sizeof(uint32_t));
            md_util_print_ip4_addr(sabuf, sip);
            g_string_append_printf(buf, "%s", sabuf);
        } else if (record->dnsRRType == 28) {
            uint8_t sip[16];
            memcpy(sip, record->rrdata.buf, sizeof(sip));
            md_util_print_ip6_addr(sabuf, sip);
            g_string_append_printf(buf, "%s", sabuf);
        } else {
            if (base64) {
                base1 = g_base64_encode((const guchar *)record->rrdata.buf,
                                        record->rrdata.len);
                g_string_append_printf(buf, "%s", base1);
                g_free(base1);
            } else {
                if (escape_chars) {
                    mdPrintEscapeChars(buf, (uint8_t *)(record->rrdata.buf),
                                       record->rrdata.len, delimiter,
                                       FALSE);
                } else {
                    g_string_append_len(buf, (gchar *)record->rrdata.buf,
                                        record->rrdata.len);
                }
            }
        }
    }

    g_string_append_c(buf, '\n');

    rc = md_util_write_buffer(fp, buf, "", err);
    if (!rc) {
        return -1;
    }

    return rc;
}


gboolean
mdPrintEscapeChars(
    GString        *mdbuf,
    const uint8_t  *data,
    size_t          datalen,
    char            delimiter,
    gboolean        json)
{
    size_t  i;
    uint8_t ch;
    /* TODO: Check all uses for proper json argument */

    if (json) {
        return mdJsonifyEscapeCharsGStringAppend(mdbuf, data, datalen);
    }

    for (i = 0; i < datalen; i++) {
        ch = data[i];
        if (ch < 32 || ch > 126) {
            if (json) {
                g_string_append_printf(mdbuf, "\\u%04X", ch);
            } else {
                g_string_append_printf(mdbuf, "\\u%04x", ch);
            }
        } else if (ch == '\\') {
            g_string_append(mdbuf, "\\\\");
        } else if (!json && ch == delimiter) {
            g_string_append_printf(mdbuf, "\\%c", ch);
        } else if (json && ch == '"') {
            g_string_append(mdbuf, "\\\"");
        } else {
            g_string_append_c(mdbuf, ch);
        }
    }

    return TRUE;
}

gboolean
mdPrintDPIBasicList(
    mdExporter_t         *exporter,
    GString              *buf,
    const GString        *prefixString,
    const fbBasicList_t  *bl,
    char                  delimiter,
    gboolean              escape)
{
    uint16_t w = 0;
    fbRecordValue_t value = FB_RECORD_VALUE_INIT;

    for (w = 0; fbBasicListGetIndexedRecordValue(bl, w, &value); w++) {
        mdPrintDPIRecordValue(exporter, &value, buf, prefixString,
                              delimiter, escape);
    }
    fbRecordValueClear(&value);

    return TRUE;
}

gboolean
mdPrintVariableLength(
    GString        *mdbuf,
    const uint8_t  *data,
    size_t          datalen,
    char            delimiter,
    gboolean        hex,
    gboolean        escape,
    gboolean        json)
{
    if (json) {
        g_error("Programmer error: Never use this function for JSON output");
    }
    if (!datalen || !data) {
        return TRUE;
    }

    if (hex) {
        md_util_hexdump_append(mdbuf, data, datalen);
    } else if (escape) {
        return mdPrintEscapeChars(mdbuf, data, datalen, delimiter, json);
    } else {
        g_string_append_len(mdbuf, (gchar *)data, datalen);
    }

    return TRUE;
}

int
mdPrintDedupRecord(
    FILE        *fp,
    GString     *buf,
    md_dedup_t  *rec,
    char         delimiter,
    GError     **err)
{
    char     sabuf[40];
    size_t   rc;

    md_util_millitime_append(
        buf, rec->monitoringIntervalStartMilliSeconds);
    g_string_append_c(buf, delimiter);

    md_util_millitime_append(
        buf, rec->monitoringIntervalEndMilliSeconds);
    g_string_append_c(buf, delimiter);

    if (rec->sourceIPv4Address != rec->yafFlowKeyHash) {
        if (rec->sourceIPv4Address == 0) {
            md_util_print_ip6_addr(sabuf, rec->sourceIPv6Address);
        } else {
            md_util_print_ip4_addr(sabuf, rec->sourceIPv4Address);
        }
        g_string_append_printf(buf, "%s%c", sabuf, delimiter);
    } else {
        /* configured to dedup on hash (not IP) */
        g_string_append_printf(buf, "%u%c", rec->sourceIPv4Address,
                       delimiter);
    }

    /*stime for flow - with hash makes unique key */
    md_util_millitime_append(buf, rec->flowStartMilliseconds);
    g_string_append_c(buf, delimiter);

    /* hash, count */
    g_string_append_printf(buf, "%u%c%" PRIu64 "%c",
                   rec->yafFlowKeyHash, delimiter, rec->smDedupHitCount,
                   delimiter);

    if (rec->smDedupData.len) {
        /* md_util_append_varfield(buf, &(rec->smDedupData)); */
        mdPrintEscapeChars(buf, rec->smDedupData.buf, rec->smDedupData.len,
                           delimiter, FALSE);
    } else if (rec->sslCertSerialNumber1.len) {
        md_util_hexdump_append_nospace(buf,
                                       rec->sslCertSerialNumber1.buf,
                                       rec->sslCertSerialNumber1.len);
        g_string_append_c(buf, delimiter);

        md_util_append_varfield(buf, &(rec->sslCertIssuerCommonName1));
        g_string_append_c(buf, delimiter);

        if (rec->sslCertSerialNumber2.len) {
            md_util_hexdump_append_nospace(buf,
                                           rec->sslCertSerialNumber2.buf,
                                           rec->sslCertSerialNumber2.len);
            g_string_append_c(buf, delimiter);

            md_util_append_varfield(buf, &(rec->sslCertIssuerCommonName2));

        } else {
            g_string_append_c(buf, delimiter);
        }
    }

    /* Print MAPNAME/exporter-name if available */
    if (rec->observationDomainName.len) {
        g_string_append_c(buf, delimiter);
        md_util_append_varfield(buf, &(rec->observationDomainName));
    }

    g_string_append_c(buf, '\n');

    rc = md_util_write_buffer(fp, buf, "", err);
    if (!rc) {
        return -1;
    }

    return rc;
}

int
mdPrintSSLDedupRecord(
    FILE            *fp,
    GString         *buf,
    mdGenericRec_t  *mdRec,
    char             delimiter,
    GError         **err)
{
    md_ssl_t *ssl = (md_ssl_t *)mdRec->fbRec->rec;
    size_t    rc;

    md_util_millitime_append(buf, ssl->flowStartMilliseconds);
    g_string_append_c(buf, delimiter);

    md_util_millitime_append(buf, ssl->flowEndMilliseconds);
    g_string_append_c(buf, delimiter);

    md_util_hexdump_append_nospace(buf, ssl->sslCertSerialNumber.buf,
                                   ssl->sslCertSerialNumber.len);

    g_string_append_printf(buf, "%c%" PRIu64 "%c", delimiter,
                   ssl->smDedupHitCount,
                   delimiter);

    md_util_append_varfield(buf, &(ssl->sslCertIssuerCommonName));

    if (ssl->observationDomainName.len) {
        g_string_append_c(buf, delimiter);
        md_util_append_varfield(buf, &(ssl->observationDomainName));
    }

    g_string_append_c(buf, '\n');

    rc = md_util_write_buffer(fp, buf, "", err);
    if (!rc) {
        return -1;
    }

    return rc;
}


void
mdPrintEscapeStrChars(
    GString        *str,
    const uint8_t  *data,
    size_t          datalen,
    char            delimiter)
{
    size_t  i;
    uint8_t ch;

    for (i = 0; i < datalen; i++) {
        ch = data[i];
        if (ch < 32 || ch > 126) {
            g_string_append_printf(str, "\\u00%02X", ch);
        } else if (ch == '\\') {
            g_string_append(str, "\\\\");
        } else if (ch == delimiter) {
            g_string_append_printf(str, "\\%c", ch);
        } else {
            g_string_append_c(str, ch);
        }
    }
}

/**
 * mdAppendDPIStr
 *
 * append the given string and label to the given GString
 *
 */
static gboolean
mdAppendDPIStr(
    mdExporter_t  *exporter,
    const GString *data,
    const char    *label,
    const GString *index_str,
    uint16_t       id,
    gboolean       hex)
{
    char     delim = exporter->dpi_delimiter;
    GString *mdbuf = exporter->buf;
    FILE    *fp;
    int      rc;
    GError  *err = NULL;

    if (data->len == 0) {
        return TRUE;
    }

    if (exporter->multi_files) {
        if (mdTableHashEnabled()) {
            label = mdGetTableItem("flow"); /*TODO: needs to be more dynamic */
            if (label == NULL) {
                return TRUE;
            }
        }
    } else {
        /* conditionally abort export of this element based on config
         * eg. DPI_FIELD_LIST */
        if (exporter->dpi_field_table) {
            if (!mdGetDPIItem(exporter->dpi_field_table, id)) {
                /* The exporter config dictates that this element shouldn't
                 * be exported (not present in exporter->dpi_field_table)*/
                return TRUE;
            }
        }
    }

    if (!exporter->no_index) {
        g_string_append_printf(mdbuf, "%s%c", label, delim);
    }

    g_string_append_len(mdbuf, index_str->str, index_str->len);
    g_string_append_printf(mdbuf, "%d%c", id, delim);

    if (!mdPrintVariableLength(mdbuf, (uint8_t *)data->str, data->len, delim,
                               hex, exporter->escape_chars, FALSE))
    {
        return FALSE;
    }

    g_string_append_c(mdbuf, '\n');

    if (exporter->multi_files) {
        fp = mdGetTableFile(exporter, "flow"); /*TODO: needs to be more dynamic */

        if (fp == NULL) {
            g_warning("Error: File does not exist for id %d", id);
            return FALSE;
        }

        rc = md_util_write_buffer(fp, mdbuf, exporter->name, &err);

        if (!rc) {
            g_warning("Error writing file for id %d: %s",
                      id, err->message);
            g_clear_error(&err);
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean
mdExporterTextNewSSLCertObjectPrint(
    mdExporter_t             *exporter,
    const yaf_ssl_subcert_t  *obj,
    const GString            *index_str,
    uint8_t                   section,
    uint8_t                   cert_no,
    char                      ise,
    char                      delim)
{
    const char  *label = SSL_DEFAULT;
    GString *buf = exporter->buf;

    if (!mdExporterCheckSSLConfig(exporter, obj->sslObjectType, section)) {
        return FALSE;
    }

    if (obj->sslObjectValue.len == 0) {
        return FALSE;
    }

    if (!exporter->no_index && !exporter->multi_files) {
        /* print label */
        g_string_append_printf(buf, "%s%c", label, delim);
    }

    g_string_append_len(buf, index_str->str, index_str->len);
    g_string_append_printf(buf, "%d%c%c%c%d%c",
                           obj->sslObjectType, delim,
                           ise, delim,
                           cert_no, delim);
    if (section == 4) {
        return TRUE;
    }

    if (exporter->escape_chars) {
        mdPrintEscapeChars(buf, obj->sslObjectValue.buf,
                           obj->sslObjectValue.len, delim, FALSE);
    } else {
        md_util_append_varfield(buf, &(obj->sslObjectValue));
    }

    g_string_append_c(buf, '\n');

    return TRUE;
}


gboolean
mdExporterTextNewSSLCertPrint(
    mdExporter_t           *exporter,
    const yafSSLDPICert_t  *cert,
    const GString          *index_str,
    uint8_t                 cert_no)
{
    const yaf_ssl_subcert_t *obj = NULL;
    char        delim = exporter->dpi_delimiter;
    GString    *ssl_buffer = g_string_sized_new(2500);
    GString    *new_index = g_string_sized_new(500);
    size_t      bufstart;
    GString    *buf = exporter->buf;
    int         ret;
    time_t      t;

    while ((obj = fbSTLNext(yaf_ssl_subcert_t, &(cert->issuer), obj))) {
        mdExporterTextNewSSLCertObjectPrint(exporter, obj, index_str,
                                            1, cert_no, 'I', delim);
    }

    obj = NULL;
    while ((obj = fbSTLNext(yaf_ssl_subcert_t, &(cert->subject), obj))) {
        mdExporterTextNewSSLCertObjectPrint(exporter, obj, index_str,
                                            2, cert_no, 'S', delim);
    }

    obj = NULL;

    /* Extensions have to be manually set in the SSL_CONFIG -
     * they will not print in any default configuration */
    while ((obj = fbSTLNext(yaf_ssl_subcert_t, &cert->extension, obj))) {
        /* append text to the exporter's GString, then copy it into new_index
         * and reset length of that GString */
        bufstart = buf->len;
        if (!mdExporterTextNewSSLCertObjectPrint(exporter, obj, index_str,
                                                 4, cert_no, 'E', delim))
        {
            continue;
        }
        g_string_overwrite_len(new_index, 0, (buf->str + bufstart),
                               (buf->len - bufstart));
        g_string_truncate(buf, bufstart);
        if (obj->sslObjectValue.len) {
            switch (obj->sslObjectType) {
              case 14:
              case 15:
              case 16:
                g_string_append_len(buf, new_index->str, new_index->len);
                /* subject key identifier - just an octet string*/
                md_util_hexdump_append(buf,
                                       obj->sslObjectValue.buf,
                                       obj->sslObjectValue.len);
                g_string_append_c(buf, '\n');
                continue;
              case 17:
              case 18:
              case 29:
                /* subject/issuer alt name can be a list */
                {
                    uint8_t *buffer = obj->sslObjectValue.buf;
                    size_t   len = obj->sslObjectValue.len;
                    uint16_t newlen;

                    while ((newlen = md_util_decode_asn1_sequence(&buffer,
                                                                  &len)))
                    {
                        if (*buffer == 0x30) {
                            /* this is a sequence - ignore */
                            break;
                        }
                        g_string_append_len(buf, new_index->str,
                                            new_index->len);
                        if (exporter->escape_chars) {
                            mdPrintEscapeChars(buf, buffer,
                                               newlen, delim, FALSE);
                        } else {
                            g_string_append_len(buf, (gchar *)buffer, newlen);
                        }
                        buffer += newlen;
                        len -= newlen;
                        g_string_append_c(buf, '\n');
                    }
                }
                continue;
              case 31:
                {
                    uint8_t *buffer = obj->sslObjectValue.buf;
                    size_t   len = obj->sslObjectValue.len;
                    uint16_t newlen;
                    gboolean a;
                    while ((newlen = md_util_decode_asn1_sequence(&buffer,
                                                                  &len)))
                    {
                        a = FALSE;
                        while (*buffer == 0xa0) {
                            buffer++;
                            len -= 1;
                            md_util_decode_asn1_length(&buffer, &len);
                            a = TRUE;
                        }
                        if (a) {
                            continue;     /* start over */
                        }
                        g_string_append_len(buf, new_index->str,
                                            new_index->len);
                        if (exporter->escape_chars) {
                            if (!mdPrintEscapeChars(buf, buffer,
                                                    newlen, delim, FALSE))
                            {
                                return FALSE;
                            }
                        } else {
                            g_string_append_len(buf, (gchar *)buffer, newlen);
                        }
                        buffer += newlen;
                        len -= newlen;
                        g_string_append_c(buf, '\n');
                    }
                }
                continue;
              case 32:
                {
                    uint8_t *buffer = obj->sslObjectValue.buf;
                    size_t   len = obj->sslObjectValue.len;
                    uint16_t newlen;

                    newlen = md_util_decode_asn1_sequence(&buffer, &len);
                    if (*buffer == 0x06) {
                        /* OID */
                        buffer++;
                        newlen = (uint16_t)*buffer;
                        buffer++;
                        g_string_append_len(buf, new_index->str,
                                            new_index->len);

                        /* subject key identifier - just an octet string*/
                        md_util_hexdump_append(buf, buffer, newlen);
                        g_string_append_c(buf, '\n');
                        buffer += newlen;
                    }
                    /* now to a sequqnece {policyQualifierID, qualifier} */
                    if (*buffer == 0x30) {
                        /* string */
                        len = len - newlen - 2;
                        newlen = md_util_decode_asn1_sequence(&buffer, &len);
                        if (*buffer == 0x06) {
                            /* OID */
                            buffer++;
                            newlen = (uint16_t)*buffer;
                            buffer += newlen + 1;
                            if (*buffer == 0x16) {
                                buffer++;
                                newlen = (uint16_t)*buffer;
                                buffer++;
                                g_string_append_len(buf, new_index->str,
                                                    new_index->len);
                                g_string_append_len(buf, (gchar *)buffer,
                                                    newlen);
                                g_string_append_c(buf, '\n');
                            }
                        }
                    }
                }
                continue;
              default:
                continue;
            }
        }
    }

    if (exporter->multi_files) {
        FILE   *fp = mdGetTableFile(exporter, "ssl");
        GError *err = NULL;

        if (fp == NULL) {
            g_warning("Error: File does not exist for 443");
            return FALSE;
        }

        ret = md_util_write_buffer(fp, buf, exporter->name, &err);

        if (!ret) {
            g_warning("Error writing file for id 443: %s",
                      err->message);
            g_clear_error(&err);
        }

/*        exporter->exp_bytes += ret;*/
    }

    /* print cert version */
    if (mdExporterCheckSSLConfig(exporter, 189, MD_SSLCONFIG_OTHER)) {
        g_string_printf(ssl_buffer, "I%c%d%c%d", delim,
                        cert_no, delim, cert->sslCertVersion);
        mdAppendDPIStr(exporter, ssl_buffer,
                       SSL_DEFAULT, index_str, 189, FALSE);
    }
    if (cert->sslCertSerialNumber.len &&
        mdExporterCheckSSLConfig(exporter, 244, MD_SSLCONFIG_OTHER))
    {
        g_string_printf(ssl_buffer, "I%c%d%c", delim, cert_no, delim);
        md_util_hexdump_append(ssl_buffer, cert->sslCertSerialNumber.buf,
                               cert->sslCertSerialNumber.len);
        mdAppendDPIStr(exporter, ssl_buffer,
                       SSL_DEFAULT, index_str, 244, FALSE);
    }
    if (cert->sslCertValidityNotBefore.len &&
        mdExporterCheckSSLConfig(exporter, 247, MD_SSLCONFIG_OTHER))
    {
        g_string_printf(ssl_buffer, "I%c%d%c", delim, cert_no, delim);
        if (mdUtilParseValidityDate(&cert->sslCertValidityNotBefore, &t)) {
            md_util_time_append(ssl_buffer, t, MD_TIME_FMT_ISO);
        } else {
            md_util_append_varfield(ssl_buffer,
                                    &cert->sslCertValidityNotBefore);
        }
        mdAppendDPIStr(exporter, ssl_buffer,
                       SSL_DEFAULT, index_str, 247, FALSE);
    }

    if (cert->sslCertValidityNotAfter.len &&
        mdExporterCheckSSLConfig(exporter, 248, MD_SSLCONFIG_OTHER))
    {
        g_string_printf(ssl_buffer, "I%c%d%c", delim, cert_no, delim);
        if (mdUtilParseValidityDate(&cert->sslCertValidityNotBefore, &t)) {
            md_util_time_append(ssl_buffer, t, MD_TIME_FMT_ISO);
        } else {
            md_util_append_varfield(ssl_buffer, &cert->sslCertValidityNotAfter);
        }
        mdAppendDPIStr(exporter, ssl_buffer,
                       SSL_DEFAULT, index_str, 248, FALSE);
    }

    if (cert->sslPublicKeyLength &&
        mdExporterCheckSSLConfig(exporter, 250, MD_SSLCONFIG_OTHER))
    {
        g_string_printf(ssl_buffer, "I%c%d%c%d", delim,
                        cert_no, delim, cert->sslPublicKeyLength);
        mdAppendDPIStr(exporter, ssl_buffer,
                       SSL_DEFAULT, index_str, 250, FALSE);
    }

    if (cert->sslCertificateHash.len &&
        mdExporterCheckSSLConfig(exporter, 295, MD_SSLCONFIG_OTHER))
    {
        g_string_printf(ssl_buffer, "I%c%d%c", delim, cert_no, delim);
        md_util_hexdump_append(ssl_buffer, cert->sslCertificateHash.buf,
                               cert->sslCertificateHash.len);
        mdAppendDPIStr(exporter, ssl_buffer,
                       SSL_DEFAULT, index_str, 295, FALSE);
    }

    if (cert->sslCertSignature.len &&
        mdExporterCheckSSLConfig(exporter, 190, MD_SSLCONFIG_OTHER))
    {
        g_string_printf(ssl_buffer, "I%c%d%c", delim, cert_no, delim);
        md_util_hexdump_append(ssl_buffer, cert->sslCertSignature.buf,
                               cert->sslCertSignature.len);
        mdAppendDPIStr(exporter, ssl_buffer,
                       SSL_DEFAULT, index_str, 190, FALSE);
    }

    g_string_free(ssl_buffer, TRUE);
    g_string_free(new_index, TRUE);

    return TRUE;
}

gboolean
mdExporterTextRewrittenSSLCertPrint(
    mdExporter_t          *exporter,
    md_ssl_certificate_t  *cert,
    const GString         *index_str,
    uint8_t                cert_no)
{
    char          delim = exporter->dpi_delimiter;
    GString      *ssl_buffer = g_string_sized_new(2500);
    GString      *buf = exporter->buf;
    const char   *label = SSL_DEFAULT;
    int           ret;
    fbVarfield_t *item;
    /* time_t        t; */

#define PRINT_VARFIELD(cert_name, varfieldName, elem_id, section)       \
    if (cert->varfieldName.len != 0 &&                                  \
        mdExporterCheckSSLConfig(exporter, elem_id, section))           \
    {                                                                   \
        if (!exporter->no_index && !exporter->multi_files) {            \
            g_string_append_printf(buf, "%s%c", label, delim);          \
        }                                                               \
        g_string_append_len(buf, index_str->str, index_str->len);       \
        g_string_append_printf(buf, "%d%c%c%c%d%c", elem_id, delim,     \
                               cert_name, delim, cert_no, delim);       \
        if (exporter->escape_chars) {                                   \
            mdPrintEscapeChars(buf, cert->varfieldName.buf,             \
                               cert->varfieldName.len, delim, FALSE);   \
        } else {                                                        \
            md_util_append_varfield(buf, &(cert->varfieldName));        \
        }                                                               \
        g_string_append_c(buf, '\n');                                   \
    }

#define PRINT_BASICLIST(cert_name, basicListName, elem_id, section)     \
    if (cert->basicListName.numElements != 0 &&                         \
        mdExporterCheckSSLConfig(exporter, elem_id, section))           \
    {                                                                   \
        item = fbBLNext(fbVarfield_t, &(cert->basicListName), NULL);    \
        while (NULL != item) {                                          \
            if (!exporter->no_index && !exporter->multi_files) {        \
                g_string_append_printf(buf, "%s%c", label, delim);      \
            }                                                           \
            g_string_append_len(buf, index_str->str, index_str->len);   \
            g_string_append_printf(buf, "%d%c%c%c%d%c", elem_id, delim, \
                                   cert_name, delim, cert_no, delim);   \
            if (exporter->escape_chars) {                               \
                mdPrintEscapeChars(buf, item->buf,                      \
                                   item->len, delim, FALSE);            \
            } else {                                                    \
                md_util_append_varfield(buf, item);                     \
            }                                                           \
            g_string_append_c(buf, '\n');                               \
            item = fbBLNext(fbVarfield_t, &cert->basicListName, item);  \
        }                                                               \
    }

#define PRINT_ISSUER_VARFIELD(varfieldName, elem_id) \
    PRINT_VARFIELD('I', varfieldName, elem_id, MD_SSLCONFIG_ISSUER)

#define PRINT_SUBJECT_VARFIELD(varfieldName, elem_id) \
    PRINT_VARFIELD('S', varfieldName, elem_id, MD_SSLCONFIG_SUBJECT)

#define PRINT_ISSUER_BASICLIST(basicListName, elem_id) \
    PRINT_BASICLIST('I', basicListName, elem_id, MD_SSLCONFIG_ISSUER)

#define PRINT_SUBJECT_BASICLIST(basicListName, elem_id) \
    PRINT_BASICLIST('S', basicListName, elem_id, MD_SSLCONFIG_SUBJECT)

    PRINT_ISSUER_VARFIELD(sslCertIssuerCountryName, 6);
    PRINT_ISSUER_VARFIELD(sslCertIssuerState, 8);
    PRINT_ISSUER_VARFIELD(sslCertIssuerLocalityName, 7);
    PRINT_ISSUER_VARFIELD(sslCertIssuerZipCode, 17);
    PRINT_ISSUER_BASICLIST(sslCertIssuerStreetAddressList, 9);
    PRINT_ISSUER_BASICLIST(sslCertIssuerOrgNameList, 10);
    PRINT_ISSUER_BASICLIST(sslCertIssuerOrgUnitNameList, 11);
    PRINT_ISSUER_BASICLIST(sslCertIssuerCommonNameList, 3);
    PRINT_ISSUER_VARFIELD(sslCertIssuerTitle, 12);
    PRINT_ISSUER_VARFIELD(sslCertIssuerName, 41);
    PRINT_ISSUER_VARFIELD(sslCertIssuerEmailAddress, 1);
    PRINT_ISSUER_BASICLIST(sslCertIssuerDomainComponentList, 25);

    PRINT_SUBJECT_VARFIELD(sslCertSubjectCountryName, 6);
    PRINT_SUBJECT_VARFIELD(sslCertSubjectState, 8);
    PRINT_SUBJECT_VARFIELD(sslCertSubjectLocalityName, 7);
    PRINT_SUBJECT_VARFIELD(sslCertSubjectZipCode, 17);
    PRINT_SUBJECT_BASICLIST(sslCertSubjectStreetAddressList, 9);
    PRINT_SUBJECT_BASICLIST(sslCertSubjectOrgNameList, 10);
    PRINT_SUBJECT_BASICLIST(sslCertSubjectOrgUnitNameList, 11);
    PRINT_SUBJECT_BASICLIST(sslCertSubjectCommonNameList, 3);
    PRINT_SUBJECT_VARFIELD(sslCertSubjectTitle, 12);
    PRINT_SUBJECT_VARFIELD(sslCertSubjectName, 41);
    PRINT_SUBJECT_VARFIELD(sslCertSubjectEmailAddress, 1);
    PRINT_SUBJECT_BASICLIST(sslCertSubjectDomainComponentList, 25);

#undef PRINT_BASICLIST
#undef PRINT_ISSUER_VARFIELD
#undef PRINT_SUBJECT_VARFIELD
#undef PRINT_ISSUER_BASICLIST
#undef PRINT_SUBJECT_BASICLIST

    /* TODO: Insert extension logic here */

    if (exporter->multi_files) {
        FILE   *fp = mdGetTableFile(exporter, "ssl");
        GError *err = NULL;

        if (fp == NULL) {
            g_warning("Error: File does not exist for 443");
            return FALSE;
        }

        ret = md_util_write_buffer(fp, buf, exporter->name, &err);

        if (!ret) {
            g_warning("Error writing file for id 443: %s",
                      err->message);
            g_clear_error(&err);
        }

/*        exporter->exp_bytes += ret;*/
    }

#if 0
    /* print cert version */
    if (mdExporterCheckSSLConfig(exporter, 189, MD_SSLCONFIG_OTHER)) {
        g_string_printf(ssl_buffer, "I%c%d%c%d", delim,
                        cert_no, delim, cert->sslCertVersion);
        mdAppendDPIStr(exporter, ssl_buffer,
                       SSL_DEFAULT, index_str, 189, FALSE);
    }
    if (cert->sslCertSerialNumber.len &&
        mdExporterCheckSSLConfig(exporter, 244, MD_SSLCONFIG_OTHER))
    {
        g_string_printf(ssl_buffer, "I%c%d%c", delim, cert_no, delim);
        md_util_hexdump_append(ssl_buffer, cert->sslCertSerialNumber.buf,
                               cert->sslCertSerialNumber.len);
        mdAppendDPIStr(exporter, ssl_buffer,
                       SSL_DEFAULT, index_str, 244, FALSE);
    }
    if (cert->sslCertValidityNotBefore.len &&
        mdExporterCheckSSLConfig(exporter, 247, MD_SSLCONFIG_OTHER))
    {
        g_string_printf(ssl_buffer, "I%c%d%c", delim, cert_no, delim);
        if (mdUtilParseValidityDate(&cert->sslCertValidityNotBefore, &t)) {
            md_util_time_append(ssl_buffer, t, MD_TIME_FMT_ISO);
        } else {
            md_util_append_varfield(ssl_buffer,
                                    &cert->sslCertValidityNotBefore);
        }
        mdAppendDPIStr(exporter, ssl_buffer,
                       SSL_DEFAULT, index_str, 247, FALSE);
    }
    if (cert->sslCertValidityNotAfter.len &&
        mdExporterCheckSSLConfig(exporter, 248, MD_SSLCONFIG_OTHER))
    {
        g_string_printf(ssl_buffer, "I%c%d%c", delim, cert_no, delim);
        if (mdUtilParseValidityDate(&cert->sslCertValidityNotAfter, &t)) {
            md_util_time_append(ssl_buffer, t, MD_TIME_FMT_ISO);
        } else {
            md_util_append_varfield(ssl_buffer, &cert->sslCertValidityNotAfter);
        }
        mdAppendDPIStr(exporter, ssl_buffer,
                       SSL_DEFAULT, index_str, 248, FALSE);
    }

    if (cert->sslPublicKeyLength &&
        mdExporterCheckSSLConfig(exporter, 250, MD_SSLCONFIG_OTHER))
    {
        g_string_printf(ssl_buffer, "I%c%d%c%d", delim,
                        cert_no, delim, cert->sslPublicKeyLength);
        mdAppendDPIStr(exporter, ssl_buffer,
                       SSL_DEFAULT, index_str, 250, FALSE);
    }

    if (cert->sslCertificateHash.len &&
        mdExporterCheckSSLConfig(exporter, 295, MD_SSLCONFIG_OTHER))
    {
        g_string_printf(ssl_buffer, "I%c%d%c", delim, cert_no, delim);
        md_util_hexdump_append(ssl_buffer, cert->sslCertificateHash.buf,
                               cert->sslCertificateHash.len);
        mdAppendDPIStr(exporter, ssl_buffer,
                       SSL_DEFAULT, index_str, 295, FALSE);
    }

    if (cert->sslCertSignature.len &&
        mdExporterCheckSSLConfig(exporter, 190, MD_SSLCONFIG_OTHER))
    {
        g_string_printf(ssl_buffer, "I%c%d%c", delim, cert_no, delim);
        md_util_hexdump_append(ssl_buffer, cert->sslCertSignature.buf,
                               cert->sslCertSignature.len);
        mdAppendDPIStr(exporter, ssl_buffer,
                       SSL_DEFAULT, index_str, 190, FALSE);
    }
#endif  /* 0 */

    g_string_free(ssl_buffer, TRUE);

    return TRUE;
}

gboolean
mdExporterTextNewSSLPrint(
    mdExporter_t  *exporter,
    fbRecord_t    *subrec,
    const GString *prefixStr)
{
    char   delim = exporter->dpi_delimiter;
    const fbSubTemplateList_t *stl;
    int    cert_no = 0;
    GString *ssl_buffer = g_string_sized_new(500);
    fbTemplateIter_t   iter;
    const fbTemplateField_t *field;
    fbRecordValue_t    value = FB_RECORD_VALUE_INIT;

    fbTemplateIterInit(&iter, subrec->tmpl);
    while ((field = fbTemplateIterNext(&iter))) {
        if (fbTemplateFieldCheckIdent(field, 0, 210)) {
            /* paddingOctets */
            continue;
        }

        fbRecordValueClear(&value);
        fbRecordGetValueForField(subrec, field, &value);
        switch (field->canon->num) {
          case 425:
            /* sslCertList */
            stl = value.v.stl;
            if (fbSubTemplateListGetTemplateID(stl) == MD_SSL_CERTIFICATE_TID) {
                md_ssl_certificate_t *cert = NULL;
                while ((cert = fbSTLNext(md_ssl_certificate_t, stl, cert))) {
                    if (!mdExporterTextRewrittenSSLCertPrint(exporter, cert,
                                                             prefixStr,
                                                             cert_no))
                    {
                        return FALSE;
                    }
                    ++cert_no;
                } /* cert list loop */
            } else {
                yafSSLDPICert_t *cert = NULL;
                while ((cert = fbSTLNext(yafSSLDPICert_t, stl, cert))) {
                    if (!mdExporterTextNewSSLCertPrint(exporter, cert,
                                                       prefixStr, cert_no))
                    {
                        return FALSE;
                    }
                    cert_no++;
                } /* cert list loop */
            }
            fbSubTemplateListClear((fbSubTemplateList_t *)stl);
            break;
          case 187:
            /* sslServerCipher */
            if (value.v.u64 &&
                mdExporterCheckSSLConfig(exporter, 187, MD_SSLCONFIG_OTHER))
            {
                g_string_printf(ssl_buffer, "I%c%d%c%#06x",
                                delim, 0, delim, (uint32_t)value.v.u64);
                mdAppendDPIStr(exporter, ssl_buffer,
                               SSL_DEFAULT, prefixStr, 187, FALSE);
            }
            break;
          case 188:
            /* sslCompressionMethod */
            if (value.v.u64 &&
                mdExporterCheckSSLConfig(exporter, 188, MD_SSLCONFIG_OTHER))
            {
                g_string_printf(ssl_buffer, "I%c%d%c%d", delim, 0,
                                delim, (uint8_t)value.v.u64);
                mdAppendDPIStr(exporter, ssl_buffer,
                               SSL_DEFAULT, prefixStr, 188, FALSE);
            }
            break;
          case 186:
            /* sslClientVersion */
            if (value.v.u64 &&
                mdExporterCheckSSLConfig(exporter, 186, MD_SSLCONFIG_OTHER))
            {
                g_string_printf(ssl_buffer, "I%c%d%c%d", delim, 0,
                                delim, (uint8_t)value.v.u64);
                mdAppendDPIStr(exporter, ssl_buffer,
                               SSL_DEFAULT, prefixStr, 186, FALSE);
            }
            break;
          case 288:
            /* sslRecordVersion */
            if (value.v.u64 &&
                mdExporterCheckSSLConfig(exporter, 288, MD_SSLCONFIG_OTHER))
            {
                g_string_printf(ssl_buffer, "I%c%d%c%#06x", delim,
                                0, delim, (uint16_t)value.v.u64);
                mdAppendDPIStr(exporter, ssl_buffer,
                               SSL_DEFAULT, prefixStr, 288, FALSE);
            }
            break;
          case 389:
            /* sslCipherList */
            if (value.v.varfield.buf &&
                mdExporterCheckSSLConfig(exporter, 294, MD_SSLCONFIG_OTHER))
            {
                g_string_printf(ssl_buffer, "I%c%d%c", delim, 0, delim);
                g_string_append_len(ssl_buffer, (gchar *)value.v.varfield.buf,
                                    value.v.varfield.len);
                mdAppendDPIStr(exporter, ssl_buffer,
                               SSL_DEFAULT, prefixStr, 294, FALSE);
            }
            break;
        }
    }

    return TRUE;
}
