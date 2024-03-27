/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_util.c
 *
 *  Contains the basic utility functions for super_mediator
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

#define _XOPEN_SOURCE          /* for strptime() on Linux */
#include <sys/wait.h>
#include "mediator_util.h"
#include "mediator_core.h"
#include "specs.h"

#if defined(ENABLE_SKIPSET) && defined(HAVE_SILK_UTILS_H)
#include <silk/utils.h>
#endif

#define MD_COMPRESSOR "gzip"

uint32_t
hashword(
    const uint32_t  *k,
    size_t           length,
    uint32_t         initval);
void
hashword2(
    const uint32_t  *k,
    size_t           length,
    uint32_t        *pc,
    uint32_t        *pb);
uint32_t
hashlittle(
    const void  *key,
    size_t       length,
    uint32_t     initval);
void
hashlittle2(
    const void  *key,
    size_t       length,
    uint32_t    *pc,
    uint32_t    *pb);
uint32_t
hashbig(
    const void  *key,
    size_t       length,
    uint32_t     initval);

#if !defined(__GNUC__)
#include "lookup3.c"
#else

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#include "lookup3.c"
#pragma GCC diagnostic pop

#endif  /* __GNUC__ */


/**
 * md_util_hexdump_append
 *
 */
int
md_util_hexdump_append(
    GString        *str,
    const uint8_t  *src,
    size_t          len)
{
    size_t i = 0;

    if (len) {
        /* first one shouldn't have a space */
        g_string_append_printf(str, "%02hhx", src[i]);
    }
    for (i = 1; i < len; i++) {
        g_string_append_printf(str, " %02hhx", src[i]);
    }

    return 0;
}

/**
 * md_util_hexdump_append_nospace
 *
 */
int
md_util_hexdump_append_nospace(
    GString        *str,
    const uint8_t  *src,
    size_t          len)
{
    size_t i = 0;

    if (len) {
        g_string_append_printf(str, "0x%02hhx", src[i]);
    }
    for (i = 1; i < len; i++) {
        g_string_append_printf(str, "%02hhx", src[i]);
    }

    return 1;
}


/**
 * md_util_hexdump_append_block_line
 *
 * stolen from airframe to print yaf payloads
 *
 */
static uint32_t
md_util_hexdump_append_block_line(
    GString        *str,
    const char     *lpfx,
    const uint8_t  *cp,
    uint32_t        lineoff,
    uint32_t        buflen)
{
    uint32_t cwr = 0, twr = 0;

    /* stubbornly refuse to print nothing */
    if (!buflen) {return 0;}

    /* print line header */
    g_string_append_printf(str, "%s %04x:", lpfx, lineoff);

    /* print hex characters */
    for (twr = 0; twr < 16; twr++) {
        if (buflen) {
            g_string_append_printf(str, " %02hhx", cp[twr]);
            cwr++; buflen--;
        } else {
            g_string_append(str, "   ");
        }
    }

    /* print characters */
    g_string_append_c(str, ' ');
    for (twr = 0; twr < cwr; twr++) {
        if ((cp[twr] > 32 && cp[twr] < 128) || cp[twr] == 32) {
            g_string_append_c(str, cp[twr]);
        } else {
            g_string_append_c(str, '.');
        }
    }
    g_string_append_c(str, '\n');

    return cwr;
}

/**
 * md_util_hexdump_append_block
 *
 * stolen from airframe to print hex
 *
 */
void
md_util_hexdump_append_block(
    GString        *str,
    const char     *lpfx,
    const uint8_t  *buf,
    uint32_t        len)
{
    uint32_t cwr = 0, lineoff = 0;

    do {
        cwr = md_util_hexdump_append_block_line(str, lpfx, buf, lineoff, len);
        buf += cwr; len -= cwr; lineoff += cwr;
    } while (cwr == 16);
}

/**
 *  Appends TCP flags to a GString.  Surrounds the flags with double-quotes
 *  when `quoted` is true.
 *
 */
void
md_util_print_tcp_flags(
    GString  *str,
    uint64_t  flags,
    gboolean  quoted)
{
    if (quoted) { g_string_append_c(str, '"'); }
    if (flags & 0x100) { g_string_append_c(str, 'N'); }
    if (flags &  0x80) { g_string_append_c(str, 'C'); }
    if (flags &  0x40) { g_string_append_c(str, 'E'); }
    if (flags &  0x20) { g_string_append_c(str, 'U'); }
    if (flags &  0x10) { g_string_append_c(str, 'A'); }
    if (flags &  0x08) { g_string_append_c(str, 'P'); }
    if (flags &  0x04) { g_string_append_c(str, 'R'); }
    if (flags &  0x02) { g_string_append_c(str, 'S'); }
    if (flags &  0x01) { g_string_append_c(str, 'F'); }
    if (quoted) { g_string_append_c(str, '"'); }
}

/**
 * md_util_print_ip6_addr
 *
 *
 */
void
md_util_print_ip6_addr(
    char           *ipaddr_buf,
    const uint8_t  *ipaddr)
{
    char     *cp = ipaddr_buf;
    uint16_t *aqp = (uint16_t *)ipaddr;
    uint16_t  aq;
    gboolean  colon_start = FALSE;
    gboolean  colon_end = FALSE;

    for (; (uint8_t *)aqp < ipaddr + 16; aqp++) {
        aq = g_ntohs(*aqp);
        if (aq || colon_end) {
            if ((uint8_t *)aqp < ipaddr + 14) {
                snprintf(cp, 6, "%04hx:", aq);
                cp += 5;
            } else {
                snprintf(cp, 5, "%04hx", aq);
                cp += 4;
            }
            if (colon_start) {
                colon_end = TRUE;
            }
        } else if (!colon_start) {
            if ((uint8_t *)aqp == ipaddr) {
                snprintf(cp, 3, "::");
                cp += 2;
            } else {
                snprintf(cp, 2, ":");
                cp += 1;
            }
            colon_start = TRUE;
        }
    }
}


/**
 * md_util_print_ip4_addr
 *
 *
 */
void
md_util_print_ip4_addr(
    char      *ipaddr_buf,
    uint32_t   ip)
{
    snprintf(ipaddr_buf, 16, "%hhu.%hhu.%hhu.%hhu",
             (ip >> 24) & 0xff, (ip >> 16) & 0xff,
             (ip >> 8) & 0xff, ip & 0xff);
}


/**
 * md_util_flow_key_hash
 *
 *
 */
uint32_t
md_util_flow_key_hash(
    const mdFullFlow_t *flow)
{
    uint32_t  hash = 0;
    const uint32_t *v6p;

    if (flow->ipv4) {
        hash = (flow->sourceTransportPort << 16) ^
            (flow->destinationTransportPort) ^
            (flow->protocolIdentifier << 12) ^ (4 << 4) ^
            (flow->vlanId << 20) ^ (flow->sourceIPv4Address) ^
            (flow->destinationIPv4Address);
        return hash;
    } else {
        v6p = (const uint32_t *)flow->sourceIPv6Address;
        hash = (flow->sourceTransportPort << 16) ^
            (flow->destinationTransportPort) ^
            (flow->protocolIdentifier << 12) ^ (6 << 4) ^
            (flow->vlanId << 20) ^ *v6p;
        v6p++;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        v6p = (const uint32_t *)flow->destinationIPv6Address;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        return hash;
    }
}

uint32_t
md_util_rev_flow_key_hash(
    const mdFullFlow_t *flow)
{
    uint32_t  hash = 0;
    const uint32_t *v6p;

    if (flow->sourceIPv4Address || flow->destinationIPv4Address) {
        hash = (flow->destinationTransportPort << 16) ^
            (flow->sourceTransportPort) ^
            (flow->protocolIdentifier << 12) ^ (4 << 4) ^
            (flow->vlanId << 20) ^ (flow->destinationIPv4Address) ^
            (flow->sourceIPv4Address);
        return hash;
    } else {
        v6p = (const uint32_t *)flow->destinationIPv6Address;
        hash = (flow->destinationTransportPort << 16) ^
            (flow->sourceTransportPort) ^
            (flow->protocolIdentifier << 12) ^ (6 << 4) ^
            (flow->vlanId << 20) ^ *v6p;
        v6p++;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        v6p = (const uint32_t *)flow->sourceIPv6Address;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        v6p++;
        hash ^= *v6p;
        return hash;
    }
}


/*  Helper to format secs & millis as "%Y-%m-%d %H:%M:%S.%03d" */
inline static void
md_util_timesecmilli_append(
    GString    *str,
    time_t      secs,
    long        millis)
{
    struct tm time_tm;

    gmtime_r(&secs, &time_tm);
    g_string_append_printf(str, MD_TIME_FORMAT_ISO ".%03ld",
                           time_tm.tm_year + 1900,
                           time_tm.tm_mon + 1,
                           time_tm.tm_mday,
                           time_tm.tm_hour,
                           time_tm.tm_min,
                           time_tm.tm_sec,
                           millis);
}

/**
 * add a formatted millisecond-timestamp to the str
 */
void
md_util_millitime_append(
    GString    *str,
    uint64_t    millitime)
{
#if   SIZEOF_TIME_T == SIZEOF_LONG
    ldiv_t div_time = ldiv((long)millitime, 1000);
#elif SIZEOF_TIME_T == SIZEOF_LONG_LONG
    lldiv_t div_time = lldiv((long long)millitime, 1000);
#else
#   error "Do not know size of time_t"
#endif

    md_util_timesecmilli_append(
        str, (time_t)div_time.quot, (long)div_time.rem);
}

/**
 * add a formatted millisecond-timestamp based on a timespec to the str
 */
void
md_util_timespec_append(
    GString                *str,
    const struct timespec  *tspec)
{
    md_util_timesecmilli_append(
        str, tspec->tv_sec, tspec->tv_nsec / 1000000);
}

/**
 *
 * add a formated time string to the str.
 *
 */
void
md_util_time_append(
    GString        *str,
    time_t          c_time,
    md_time_fmt_t   format)
{
    struct tm time_tm;

    gmtime_r(&c_time, &time_tm);

    switch (format) {
      case MD_TIME_FMT_ISO:
        g_string_append_printf(str, MD_TIME_FORMAT_ISO,
                               time_tm.tm_year + 1900,
                               time_tm.tm_mon + 1,
                               time_tm.tm_mday,
                               time_tm.tm_hour,
                               time_tm.tm_min,
                               time_tm.tm_sec);
        break;
      case MD_TIME_FMT_YMDHMS:
        g_string_append_printf(str, MD_TIME_FORMAT_YMDHMS,
                               time_tm.tm_year + 1900,
                               time_tm.tm_mon + 1,
                               time_tm.tm_mday,
                               time_tm.tm_hour,
                               time_tm.tm_min,
                               time_tm.tm_sec);
        break;
    }
}


gboolean
mdUtilAppendDecodedOID(
    GString            *str,
    const fbVarfield_t *oid)
{
    const uint8_t *c = oid->buf;
    size_t avail     = oid->len;
    size_t strlen    = str->len;

    if (0 == avail) {
        return TRUE;
    }
    /* first two digits (a.b) are encoded as (40 * a + b) */
    g_string_append_printf(str, "%u.%u", *c / 40, *c % 40);
    ++c; --avail;
    while (avail) {
        if (*c < 0x80) {
            /* single byte */
            g_string_append_printf(str, ".%u", *c);
            ++c; --avail;
        } else {
            uint32_t val = 0;
            while (*c & 0x80) {
                val = (val | (*c & 0x7f)) << 7;
                ++c; --avail;
                if (0 == avail) {
                    g_string_truncate(str, strlen);
                    return FALSE;
                }
            }
            val |= *c;
            g_string_append_printf(str, ".%u", val);
            ++c; --avail;
        }
    }
    return TRUE;
}

void
mdUtilAppendColonSeparatedHash(
    GString            *str,
    const fbVarfield_t *hash)
{
    size_t n;

    for (n = 0; n < hash->len; ++n) {
        g_string_append_printf(str, "%02x:", hash->buf[n]);
    }
    if (n) {
        g_string_truncate(str, str->len - 1);
    }
}

void
mdUtilAppendHash(
    GString            *str,
    const fbVarfield_t *hash)
{
    size_t n;

    for (n = 0; n < hash->len; ++n) {
        g_string_append_printf(str, "%02x", hash->buf[n]);
    }
}


gboolean
mdUtilParseValidityDate(
    const fbVarfield_t *validity,
    time_t             *t)
{
    char        timebuf[20] = "20";
    struct tm   tm;
    const char *c;

    g_assert(validity);

    switch (validity->len) {
      case 15:
        /* four digit year: YYYYMMDDHHMMSSZ */
        memcpy(timebuf, validity->buf, validity->len);
        break;
      case 13:
        /* two digit year: YYMMDDHHMMSSZ.  RFC5280: year >=50 is 19xx, year
         * <50 is 20xx */
        switch (validity->buf[0]) {
          case '0': case '1': case '2': case '3': case '4':
            break;
          case '5': case '6': case '7': case '8': case '9':
            timebuf[0] = '1'; timebuf[1] = '9';
            break;
          default:
            /* unexpected starting character */
            g_debug("unexpected leading char '%c'", validity->buf[0]);
            return FALSE;
        }
        memcpy(timebuf + 2, validity->buf, validity->len);
        break;
      default:
        /* unexpected length */
        g_debug("unexpected length %zu", validity->len);
        return FALSE;
    }

    if ('Z' != timebuf[14]) {
        /* unexpected trailing char */
        g_debug("unexpected trailing char '%c'", validity->buf[14]);
        return FALSE;
    }
    timebuf[14] = '\0';

    c = strptime(timebuf, "%4Y%2m%2d%2H%2M%2S", &tm);
    if (NULL == c) {
        /* conversion failed */
        g_debug("failed to parse '%s'", timebuf);
        return FALSE;
    }
    g_assert(c == (timebuf + 14));

    *t = timegm(&tm);

    return TRUE;
}



uint16_t
md_util_decode_length(
    uint8_t   *buffer,
    uint16_t  *offset)
{
    uint16_t obj_len;

    obj_len = *(buffer + *offset);
    if (obj_len == 0x81) {
        (*offset)++;
        obj_len = *(buffer + *offset);
    } else if (obj_len == 0x82) {
        (*offset)++;
        obj_len = ntohs(*(uint16_t *)(buffer + *offset));
        (*offset)++;
    }

    return obj_len;
}



uint16_t
md_util_decode_tlv(
    md_asn_tlv_t  *tlv,
    uint8_t       *buffer,
    uint16_t      *offset)
{
    uint8_t  val = *(buffer + *offset);
    uint16_t len = 0;

    tlv->class = (val & 0xD0) >> 6;
    tlv->p_c = (val & 0x20) >> 5;
    tlv->tag = (val & 0x1F);

    (*offset)++;

    len = md_util_decode_length(buffer, offset);
    (*offset)++;

    if (tlv->tag == 0x05) { /*CERT_NULL 0x05 */
        *offset += len;
        return md_util_decode_tlv(tlv, buffer, offset);
    }

    return len;
}



uint16_t
md_util_decode_asn1_length(
    uint8_t **buffer,
    size_t   *len)
{
    uint16_t obj_len;

    obj_len = **buffer;

    if (obj_len == 0x81) {
        (*buffer)++;
        obj_len = (uint16_t)**buffer;
        (*buffer)++;
        *len -= 2;
    } else if (obj_len == 0x82) {
        (*buffer)++;
        obj_len = ntohs(*(uint16_t *)(*buffer));
        (*buffer) += 2;
        *len -= 3;
    } else if ((obj_len & 0x80) == 0) {
        /* first byte describes length */
        obj_len = (uint16_t)**buffer;
        (*buffer)++;
        *len -= 1;
    }

    return obj_len;
}

uint8_t
md_util_asn1_sequence_count(
    uint8_t   *buffer,
    uint16_t   seq_len)
{
    uint16_t     offsetptr = 0;
    uint16_t     len = 0;
    uint16_t     obj_len;
    uint8_t      count = 0;
    md_asn_tlv_t tlv;

    obj_len = md_util_decode_tlv(&tlv, buffer, &offsetptr);
    while (tlv.tag == 0x11 && len < seq_len) {
        len += obj_len + 2;
        count++;
        offsetptr += obj_len;
        obj_len = md_util_decode_tlv(&tlv, buffer, &offsetptr);
    }

    return count;
}



/* moves buffer to next item and returns length
 */
uint16_t
md_util_decode_asn1_sequence(
    uint8_t **buffer,
    size_t   *len)
{
    uint8_t  val = **buffer;
    uint16_t newlen = 0;

    if (*len == 0) {
        return 0;
    }

    if (val == 0x30) {
        (*buffer)++;
        *len -= 1;
        newlen = md_util_decode_asn1_length(buffer, len);
    }

    if (newlen > *len) {
        return 0;
    }

    val = **buffer;
    if ((val & 0x80) == 0x80) {
        (*buffer)++;
        *len -= 1;
        newlen = md_util_decode_asn1_length(buffer, len);
    } else if (val == 0x30) {
        /* sequence of sequence */
        (*buffer)++;
        *len -= 1;
        newlen = md_util_decode_asn1_length(buffer, len);
    }

    return newlen;
}

/**
 *  Function: attachHeadToDLL
 *  Description: attach a new entry to the head of a doubly
 *      linked list
 *  Params: **head - double pointer to the head of the DLL.  The
 *                head will point to the new head at the end.
 *          **tail - double pointer to the tail of the DLL.
 *                NULL if tail not used
 *          *newEntry - a pointer to the entry to add as the new head
 *  Return:
 */
void
attachHeadToDLL(
    mdDLL_t **head,
    mdDLL_t **tail,
    mdDLL_t  *newEntry)
{
    assert(newEntry);
    assert(head);

    /*  if this is NOT the first entry in the list */
    if (*head) {
        /*  typical linked list attachements */
        newEntry->next = *head;
        newEntry->prev = NULL;
        (*head)->prev = newEntry;
        *head = newEntry;
    } else {
        /*  the new entry is the only entry now, set head to it */
        *head = newEntry;
        newEntry->prev = NULL;
        newEntry->next = NULL;
        /*  if we're keeping track of tail, assign that too */
        if (tail) {
            *tail = newEntry;
        }
    }
}

/**
 * detachFromEndOfDLL
 *
 * detach a node from the end of a doubly linked list
 *
 */
void *
detachFromEndOfDLL(
    mdDLL_t **head,
    mdDLL_t **tail)
{
    mdDLL_t *node = NULL;

    assert(head);
    assert(tail);

    node = *tail;

    if (*tail) {
        *tail = (*tail)->prev;
        if (*tail) {
            (*tail)->next = NULL;
        } else {
            *head = NULL;
        }
    }

    return node;
}

/**
 * detachThisEntryOfDLL
 *
 * detach this specific node of the DLL
 *
 */
void
detachThisEntryOfDLL(
    mdDLL_t **head,
    mdDLL_t **tail,
    mdDLL_t  *entry)
{
    assert(entry);
    assert(head);

    /*  entry already points to the entry to remove, so we're good
     *  there */
    /*  if it's NOT the head of the list, patch up entry->prev */
    if (entry->prev != NULL) {
        entry->prev->next = entry->next;
    } else {
        /*  if it's the head, reassign the head */
        *head = entry->next;
    }
    /*  if it's NOT the tail of the list, patch up entry->next */
    if (entry->next != NULL) {
        entry->next->prev = entry->prev;
    } else {
        /*  it is the last entry in the list, if we're tracking the
         *  tail, reassign */
        if (tail) {
            *tail = entry->prev;
        }
    }

    /*  finish detaching by setting the next and prev pointers to
     *  null */
    entry->prev = NULL;
    entry->next = NULL;
}

/**
 * Hash Functions
 *
 *
 */
guint
sm_octet_array_hash(
    gconstpointer   v)
{
    const smVarHashKey_t *key = (smVarHashKey_t *)v;
    guint                 h;
    size_t                i;

    if (key->len == 0) {
        return 0;
    }

    h = key->val[0];
    for (i = 1; i < key->len; i++) {
        h = (h << 5) - h + key->val[i];
    }

    return h;
}

gboolean
sm_octet_array_equal(
    gconstpointer   v1,
    gconstpointer   v2)
{
    const smVarHashKey_t *var1 = (smVarHashKey_t *)v1;
    const smVarHashKey_t *var2 = (smVarHashKey_t *)v2;

    if (var1->len != var2->len) {
        return FALSE;
    }
    return (memcmp(var1->val, var2->val, var1->len) == 0);
}

void
sm_octet_array_key_destroy(
    gpointer   data)
{
    smVarHashKey_t *key = data;

    if (data) {
        g_slice_free1(key->len, key->val);
        g_slice_free(smVarHashKey_t, key);
    }
}

smVarHashKey_t *
sm_new_hash_key(
    uint8_t  *val,
    size_t    len)
{
    smVarHashKey_t *key = g_slice_new0(smVarHashKey_t);

    key->val = g_slice_alloc0(len);
    memcpy(key->val, val, len);
    key->len = len;

    return key;
}

size_t
md_util_write_buffer(
    FILE         *fp,
    GString      *buf,
    const char   *exp_name,
    GError      **err)
{
    size_t rc;

    rc = fwrite(buf->str, 1, buf->len, fp);
    if (rc != buf->len) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "%s: Error writing to file: %s\n",
                    exp_name, strerror(errno));
        return 0;
    }

    /* reset buffer */
    //buf->cp = buf->buf;
    g_string_truncate(buf, 0);

    return rc;
}

gboolean
md_util_append_buffer(
    GString        *buf,
    const uint8_t  *var,
    size_t          len)
{
    g_string_append_len(buf, (const gchar *)var, len);
    return TRUE;
}

gboolean
md_util_append_varfield(
    GString            *str,
    const fbVarfield_t *var)
{
    g_string_append_len(str, (const gchar *)var->buf, var->len);
    return TRUE;
}

/*
 * compress and optionally relocate the compressed file
 * parameters:
 *   file - the input file name for the compressor
 *   dest - the path to the destination directory of the
 *          compressed file
 */
void
md_util_compress_file(
    const char  *file,
    const char  *dest)
{
    pid_t    pid;
    int      status = 0;
    GString *new_name = NULL;
    GString *mv_name = NULL;  /* allocated by sm_util_move_file */

#ifndef MD_COMPRESSOR
    g_warning("gzip is not defined - will not compress file");
    return;
#endif

    /* fork a child to spawn a completely detached gzip process.
     * Monitor the child until it has successfully forked the detached child.
     */
    pid = fork();
    if (pid == -1) {
        g_warning("Could not fork for %s command: %s", MD_COMPRESSOR,
                  strerror(errno));
        return;
    }

    /* In parent, top-level SM process, wait until child has forked then return
     * */
    if (pid != 0) {
        waitpid(pid, NULL, 0);
        return;
    }

    setpgid(0, 0);

    /* Create the grandchild which will be completely detached from the parent
     * SM process.
     */
    pid = fork();
    if (pid == -1) {
        g_warning("Child could not fork for %s command: %s\n",
                  MD_COMPRESSOR, strerror(errno));
        _exit(EXIT_FAILURE);
    }
    /* in the child, exit immediately so top-level SM may resume operation */
    if (pid != 0) {
        _exit(EXIT_SUCCESS);
    }
    /* If we are moving the file, we have to wait for compression to be
     * completed.
     * Since we don't want to hold up the primary SM process, we can't wait for
     *it
     * in the child process, and since execlp will replace the forked process
     * we must create ANOTHER forked process where we can compress, monitor,
     *and move
     */
    if (dest != NULL) {
        /* fork compress and move */
        pid = fork();
        if (pid == -1) {
            g_warning("Could not fork for %s and move: %s", MD_COMPRESSOR,
                      strerror(errno));
            return;
        }

        /* In the grandchild process, wait for grandgrandchild (gzip) to exit,
         * and check status */
        if (pid != 0) {
            waitpid(pid, &status, 0);
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                /* compression child exited with success, move the compressed
                 * output */
                new_name = g_string_new(NULL);
                g_string_printf(new_name, "%s.gz", file);
                mv_name = sm_util_move_file(new_name->str, dest);
                if (!mv_name) {
                    g_warning("Unable to move file %s to %s", new_name->str,
                              dest);
                }
                g_string_free(new_name, TRUE);
                g_string_free(mv_name, TRUE);
                _exit(EXIT_SUCCESS);
            } else {
                g_warning("Abnormal termination of gzip process,"
                          " not moving output file %s",
                          file);
                _exit(EXIT_FAILURE);
            }
        }
    }

    /* Replace this (grand)grandchild with gzip. */
    if (execlp(MD_COMPRESSOR, MD_COMPRESSOR, "-f", file, (char *)NULL) == -1) {
        g_warning("Error invoking '%s': %s", MD_COMPRESSOR, strerror(errno));
        _exit(EXIT_FAILURE);
    }
}

static guint
sm_fixed_hash4(
    gconstpointer   v)
{
    return hashlittle(v, 4, 4216);
}

static gboolean
sm_fixed_equal4(
    gconstpointer   v1,
    gconstpointer   v2)
{
    return (memcmp(v1, v2, 4) == 0);
}

void
md_free_hash_key(
    gpointer   v1)
{
    g_slice_free(smFieldMapKV_t, v1);
}

static guint
sm_fixed_hash6(
    gconstpointer   v)
{
    return hashlittle(v, 6, 4216);
}

static gboolean
sm_fixed_equal6(
    gconstpointer   v1,
    gconstpointer   v2)
{
    return (memcmp(v1, v2, 6) == 0);
}

static guint
sm_fixed_hash8(
    gconstpointer   v)
{
    return hashlittle(v, 8, 4216);
}

static gboolean
sm_fixed_equal8(
    gconstpointer   v1,
    gconstpointer   v2)
{
    return (memcmp(v1, v2, 8) == 0);
}

guint
sm_fixed_hash12(
    gconstpointer   v)
{
    return hashlittle(v, 12, 4216);
}

gboolean
sm_fixed_equal12(
    gconstpointer   v1,
    gconstpointer   v2)
{
    return (memcmp(v1, v2, 12) == 0);
}

static guint
sm_fixed_hash16(
    gconstpointer   v)
{
    return hashlittle(v, 16, 4216);
}

static gboolean
sm_fixed_equal16(
    gconstpointer   v1,
    gconstpointer   v2)
{
    return (memcmp(v1, v2, 16) == 0);
}

static guint
sm_fixed_hash18(
    gconstpointer   v)
{
    return hashlittle(v, 18, 4216);
}

static gboolean
sm_fixed_equal18(
    gconstpointer   v1,
    gconstpointer   v2)
{
    return (memcmp(v1, v2, 18) == 0);
}

static guint
sm_fixed_hash20(
    gconstpointer   v)
{
    return hashlittle(v, 20, 4216);
}

static gboolean
sm_fixed_equal20(
    gconstpointer   v1,
    gconstpointer   v2)
{
    return (memcmp(v1, v2, 20) == 0);
}

smHashTable_t *
smCreateHashTable(
    size_t           length,
    GDestroyNotify   freeKeyfn,
    GDestroyNotify   freeValfn)
{
    smHashTable_t *hTable = g_slice_new0(smHashTable_t);

    hTable->len = length;
    switch (length) {
      case 4:
        hTable->table = g_hash_table_new_full((GHashFunc)sm_fixed_hash4,
                                              (GEqualFunc)sm_fixed_equal4,
                                              freeKeyfn, freeValfn);
      break;
      case 6:
        hTable->table = g_hash_table_new_full((GHashFunc)sm_fixed_hash6,
                                              (GEqualFunc)sm_fixed_equal6,
                                              freeKeyfn, freeValfn);
      break;
      case 8:
        hTable->table = g_hash_table_new_full((GHashFunc)sm_fixed_hash8,
                                              (GEqualFunc)sm_fixed_equal8,
                                              freeKeyfn, freeValfn);
      break;
      case 12:
        hTable->table = g_hash_table_new_full((GHashFunc)sm_fixed_hash12,
                                              (GEqualFunc)sm_fixed_equal12,
                                              freeKeyfn, freeValfn);
      break;
      case 16:
        hTable->table = g_hash_table_new_full((GHashFunc)sm_fixed_hash16,
                                              (GEqualFunc)sm_fixed_equal16,
                                              freeKeyfn, freeValfn);
      break;
      case 18:
        hTable->table = g_hash_table_new_full((GHashFunc)sm_fixed_hash18,
                                              (GEqualFunc)sm_fixed_equal18,
                                              freeKeyfn, freeValfn);
      break;
      case 20:
        hTable->table = g_hash_table_new_full((GHashFunc)sm_fixed_hash20,
                                              (GEqualFunc)sm_fixed_equal20,
                                              freeKeyfn, freeValfn);
      break;
      default:
        hTable->table = g_hash_table_new_full((GHashFunc)sm_octet_array_hash,
                                              (GEqualFunc)sm_octet_array_equal,
                                              freeKeyfn, freeValfn);
        break;
    }

    return hTable;
}

gpointer
smHashLookup(
    smHashTable_t  *table,
    uint8_t        *key)
{
    return g_hash_table_lookup(table->table, key);
}

void
smHashTableInsert(
    smHashTable_t  *table,
    uint8_t        *key,
    uint8_t        *value)
{
    g_hash_table_insert(table->table, (gpointer)key, (gpointer)value);
}

void
smHashTableFree(
    smHashTable_t  *table)
{
    g_hash_table_destroy(table->table);
    g_slice_free(smHashTable_t, table);
}

void
smHashTableRemove(
    smHashTable_t  *table,
    uint8_t        *key)
{
    g_hash_table_remove(table->table, (gpointer)key);
}

uint32_t
smFieldMapTranslate(
    smFieldMap_t  *map,
    mdFullFlow_t  *flow)
{
    smFieldMapKV_t *value;
    smFieldMapKV_t  key;

    switch (map->field) {
      case OBDOMAIN:
        key.val = *(flow->observationDomain);
        break;
      case VLAN:
        key.val = flow->vlanId;
        break;
      default:
        break;
    }

    value = smHashLookup(map->table, (uint8_t *)&key);

    if (value) {
        return value->val;
    } else {
        return 0;
    }
}

/* move file from *file to *new_dir */
GString *
sm_util_move_file(
    const char  *file,
    const char  *new_dir)
{
    GString    *new_file = NULL;
    const char *filename;

    filename = g_strrstr(file, "/");
    if (filename == NULL) {
        /* if no slash, use entire filename */
        filename = file;
    }

    new_file = g_string_new(NULL);

    g_string_append_printf(new_file, "%s", new_dir);
    g_string_append_printf(new_file, "%s", filename);
    if (g_rename(file, new_file->str) != 0) {
        g_string_free(new_file, TRUE);
        return NULL;
    }

    return new_file;
}

static mdUtilTemplateType_t
mdUtilDetermineTemplateType(
    const fbTemplate_t      *tmpl,
    uint16_t                 tid,
    const fbTemplateInfo_t  *mdInfo)
{
    uint16_t parentTid = 0;
    gboolean matchesFlowChecker = FALSE;

    MD_UNUSED_PARAM(tid);

    if (fbTemplateGetOptionsScope(tmpl)) {
        /* options record */
        /* if TMD or IE, no need for metadata */
        if (fbTemplateIsMetadata(tmpl, FB_TMPL_IS_META_TMPL_ANY)) {
            return TT_TMD;
        }

        if (fbTemplateIsMetadata(tmpl, FB_TMPL_IS_META_ELEMENT)) {
            return TT_IE_SPEC;
        }

        if (mdInfo) {
            parentTid = fbTemplateInfoGetParentTid(mdInfo);
            if (parentTid == FB_TMPL_MD_LEVEL_NA) {
                return TT_NO_TMD_OPTIONS;
            } else if (parentTid) {
                return TT_NESTED_OPTIONS;
            } else {
                return TT_TOP_OPTIONS;
            }
        } else {
            return TT_NO_TMD_OPTIONS;
        }
    } else {
        matchesFlowChecker = fbTemplateContainsAllElementsByName(
            tmpl, mdCheckerFlow);
        /* data record */
        if (mdInfo) {
            parentTid = fbTemplateInfoGetParentTid(mdInfo);
            if (parentTid == FB_TMPL_MD_LEVEL_NA) {
                if (matchesFlowChecker) {
                    return TT_NO_TMD_FLOW;
                } else {
                    return TT_NO_TMD_DATA;
                }
            } else if (parentTid) {
                return TT_NESTED_DATA;
            } else {
                if (matchesFlowChecker) {
                    return TT_TOP_FLOW;
                } else {
                    return TT_TOP_OTHER;
                }
            }
        } else {
            if (matchesFlowChecker) {
                return TT_NO_TMD_FLOW;
            }

            return TT_NO_TMD_DATA;
        }
    }

    return TT_UNKNOWN;
}


static mdUtilTemplateContents_t
mdUtilDataRecDetector(
    const fbTemplate_t *tmpl,
    uint16_t            tid)
{
    mdUtilTemplateContents_t tc     = MD_TC_INIT;
    const fbTemplateField_t *field  = NULL;

    /* TCP subrecord used by YAF-2 for TCP flags */
    if (fbTemplateContainsAllFlaggedElementsByName(
            tmpl, mdCheckerTcpSubrec, 0) &&
        fbTemplateCountElements(tmpl) <= 6)
    {
        if (fbTemplateContainsAllFlaggedElementsByName(
            tmpl, mdCheckerTcpSubrec, 1) &&
            fbTemplateCountElements(tmpl) == 6)
        {
            tc.specCase.dpi = TC_APP_DPI_TCP_REV;
            tc.yafVersion = TC_YAF_VERSION_2;
            return tc;
        }
        if (fbTemplateCountElements(tmpl) == 3) {
            tc.specCase.dpi = TC_APP_DPI_TCP_FWD;
            tc.yafVersion = TC_YAF_VERSION_2;
            return tc;
        }
    }

    /* DNS
     * Try DNS YAF 2, then YAF 3
     */
    /* see if it's template with resource record info:
     * if so, could be DNS DPI (2 or 3), DNS RR, DNS Dedup */
    if (fbTemplateContainsAllElementsByName(
            tmpl, mdCheckerDNSResRecInfo))
    {
        /* determine DPI vs RR vs Dedup */
        field = fbTemplateFindFieldByDataType(tmpl, FB_SUB_TMPL_LIST, NULL, 0);
        if (field) { /* DNS DPI */
            tc.specCase.dpi = TC_APP_DPI_DNS;
            if (fbTemplateFieldCheckIdent(field, 0, 292)) {
                /* subTemplateList, V2 DNS DPI */
                tc.yafVersion = TC_YAF_VERSION_2;
                tc.relative = mdUtilDetermineRelative(tmpl, yafDnsQRTmplV2);
                return tc;
            } else if (fbTemplateFieldCheckIdent(field, CERT_PEN, 431)) {
                /* dnsDetailRecordList, V3 DNS DPI */
                tc.yafVersion = TC_YAF_VERSION_3;
                tc.relative = mdUtilDetermineRelative(tmpl, yafDnsQRTmplV3);
                return tc;
            } else {
                g_warning("Unrecognized STL in potential DNS DPI. Can't use");
                return tc;
            }
        }

        /* NOT DNS DPI - check RR and DEDUP */
        if (fbTemplateContainsAllElementsByName(
                tmpl, mdCheckerDNSRRGivenDNSResRecInfo))
        {
            tc.general = TC_DNS_RR;
            /* this is a DNS RR Rec. Look for full, and ipv4 vs ipv6 */
            if (fbTemplateContainsAllFlaggedElementsByName(
                    tmpl,
                    mdCheckerDNSRRFullGivenDNSRR,
                    TC_DNS_RR_FULL_4))
            {
                /* no need for relative as it's not "used", just forwarded */
                tc.specCase.dnsRR = TC_DNS_RR_FULL_4;
            } else if (fbTemplateContainsAllFlaggedElementsByName(
                           tmpl,
                           mdCheckerDNSRRFullGivenDNSRR,
                           TC_DNS_RR_FULL_6))
            {
                /* no need for relative as it's not "used", just forwarded */
                tc.specCase.dnsRR = TC_DNS_RR_FULL_6;
            } else {
                /* regular dns rr...nothin to set */
            }
            return tc;
        }

        /* NOT DNS DPI or RR, check DEDUP -- the DEDUP-checker-spec contains
         * only flowStartMilliseconds, so not a strenuous test */
        /* TODO add relatives for DEDUPs, checking arec/orec single field */
        if (fbTemplateContainsAllElementsByName(
                tmpl, mdCheckerDNSDedupGivenDNSResRecInfo))
        {
            tc.general = TC_DNS_DEDUP;
            if (fbTemplateContainsAllElementsByName(
                    tmpl, mdCheckerARecGivenDNSDedup))
            {
                /* if it ALSO contains the fields from OREC, it is an internal
                 * template and should be ignored */
                if (fbTemplateContainsAllElementsByName(
                       tmpl, mdCheckerORecGivenDNSDedup))
                {
                    g_debug("Ignoring probable DNS DEDUP internal template %#x",
                            tid);
                    tc.general = TC_UNKNOWN;
                    return tc;
                }
                /* else it is an AREC */
                tc.specCase.dnsDedup = TC_DNS_DEDUP_AREC;
            } else if (fbTemplateContainsAllElementsByName(
                           tmpl, mdCheckerORecGivenDNSDedup))
            {
                tc.specCase.dnsDedup = TC_DNS_DEDUP_OREC;
            } else if(fbTemplateContainsAllElementsByName(
                           tmpl, mdCheckerAAAARecGivenDNSDedup))
            {
                tc.specCase.dnsDedup = TC_DNS_DEDUP_AAAAREC;
            }
            else {
                g_warning("Unrecognized DNS DEDUP template");
            }

            if (fbTemplateContainsAllElementsByName(
                    tmpl, mdCheckerLastSeenV2GivenDNSDedup))
            {
                /* record type set...increment by LS to reset */
                tc.specCase.dnsDedup |= TC_DNS_DEDUP_LS_V2;
            } else if (fbTemplateContainsAllElementsByName(
                           tmpl, mdCheckerLastSeenV1GivenDNSDedup))
            {
                /* record type set...increment by LS to reset */
                tc.specCase.dnsDedup |= TC_DNS_DEDUP_LS_V1;
            }
            return tc;
        }

        /* NOT DNS DPI, RR, or DEDUP. No clue */
        g_warning("Unrecognized DNS-related template");
        return tc;
    }

    /* NOT DNS resource record (DPI, RR, or DEDUP) */

    /* SSL Detection - Not a lot overlap, just check for each */
    /* rewritten SSL is the biggest and easiest*/
    /* rewritten SSL would also meed the L2 checker requirements, as orig L2
     * is a subset of rewritten. rewritten has to go first */
    /* ssl dedup shares sslCertSerialNumber only */
    /* ssl cert records are another story TODO */

    /* FIXME: Need to do a better job of distinguishing SSL DPI templates and
     * top-level SSL records written by SSL_DEDUP */

    if (fbTemplateContainsAllElementsByName(tmpl, mdCheckerSSLRWCert)) {
        /* this is a rewritten record. Look for exact. */
        tc.specCase.dpi = TC_APP_DPI_SSL_RW_L2;
        tc.relative = mdUtilDetermineRelative(tmpl, mdSSLRWCertLevel2Tmpl);
        return tc;
    }

    if (fbTemplateContainsAllElementsByName(tmpl, mdCheckerYafSSLLevel1)) {
        field = fbTemplateFindFieldByDataType(tmpl, FB_SUB_TMPL_LIST, NULL, 0);
        if (field) { /* SSL DPI L1 */
            tc.specCase.dpi = TC_APP_DPI_SSL_L1;

            if (fbTemplateFieldCheckIdent(field, 0, 292)) {
                /* V2 SSL DPI L1 */
                tc.yafVersion = TC_YAF_VERSION_2;
                tc.relative = mdUtilDetermineRelative(tmpl, yafV2SSLLevel1Tmpl);
                return tc;
            }

            /* sslCertList */
            if (fbTemplateFieldCheckIdent(field, CERT_PEN, 425)) {
                /* V3 SSL DPI L1  */
                tc.yafVersion = TC_YAF_VERSION_3;
                /* sslBinaryCertificateList */
                if (fbTemplateFindFieldByIdent(tmpl, CERT_PEN, 429, NULL, 0)) {
                    /* YAF 3 ssl L1 with cert list */
                    tc.specCase.dpi = TC_APP_DPI_SSL_L1_CERT_LIST;
                    tc.relative = mdUtilDetermineRelative(
                        tmpl, yafV3SSLLevel1TmplCertList);
                } else {
                    /* YAF 3 ssl L1 without cert list */
                    tc.relative = mdUtilDetermineRelative(
                        tmpl, yafV3SSLLevel1Tmpl);
                }
                return tc;
            }
        } else { /* if no STL, it could be something else */
            g_warning("Matched SSL Level 1 checker, but no STL %#x", tid);
        }
    }

    if (fbTemplateContainsAllElementsByName(tmpl, mdCheckerYafSSLLevel2)) {
        uint8_t  v2Count     = 0;
        uint8_t  v3Count     = 0;
        uint16_t skipCount   = 0;

        while ((field = fbTemplateFindFieldByDataType(tmpl,
                                                      FB_SUB_TMPL_LIST, NULL,
                                                      skipCount)))
        {
            skipCount++;
            if (field->canon->ent == 0 && field->canon->num == 292) {
                v2Count++;
            } else {
                v3Count++;
            }
        }

        if (skipCount == 3) {
            tc.specCase.dpi = TC_APP_DPI_SSL_L2;
            if (v2Count == 3) {
                tc.yafVersion = TC_YAF_VERSION_2;
                tc.relative = mdUtilDetermineRelative(tmpl, yafV2SSLLevel2Tmpl);
                return tc;
            } else if (v3Count) {
                tc.yafVersion = TC_YAF_VERSION_3;
                tc.relative = mdUtilDetermineRelative(tmpl, yafV3SSLLevel2Tmpl);
                return tc;
            } else {
                g_error("invalid number of STLS for SSL L2");
            }
        }
    }

    /* template exactly the same for both yaf versions */
    if (fbTemplateContainsAllElementsByName(tmpl, mdCheckerYafSSlLevel3)) {
        tc.specCase.dpi = TC_APP_DPI_SSL_L3;
        tc.relative = mdUtilDetermineRelative(tmpl, yafSSLLevel3Tmpl);
        return tc;
    }

    /* NOT SSL DPI or rewritten SSL Level 2 */
    if (fbTemplateContainsAllElementsByName(tmpl, mdCheckerSSLDedup)) {
        tc.general = TC_SSL_DEDUP;
        return tc;
    }

    return tc;
}

static gboolean
looksLikeYafStats(
    const fbTemplate_t  *inTmpl)
{
    fbTemplate_t *specTmpl = fbTemplateAlloc(mdInfoModel());
    uint16_t      numMatch = 0;

    /* if the template has 10 of the 16 yaf stats v2 elements, it's yaf stats
     * */
    /* 10 was chosen somewhat arbitrarily */
    mdTemplateAppendSpecArray(specTmpl, mdCheckerYafStats, 0);
    fbTemplatesSetCompare(inTmpl, specTmpl, &numMatch,
                          FB_TMPL_CMP_IGNORE_LENGTHS);
    fbTemplateFreeUnused(specTmpl);

    if (numMatch >= CHECKER_YAF_STATS_THRESHOLD) {
        return TRUE;
    }
    return FALSE;
}

static gboolean
looksLikeTombstone(
    const fbTemplate_t  *tmpl)
{
    /* only templates with "certToolTombstoneId" are tombstone mains */
    return fbTemplateContainsAllFlaggedElementsByName(tmpl,
                                                      mdCheckerTombstone,
                                                      0);
}

#define SET_KNOWN_TID(_param_, _tid_, _string_)                         \
    do {                                                                \
        if (knownTids->_param_ && (knownTids->_param_ != _tid_)) {      \
            g_warning("%s Already have TID %#x for %s,"                 \
                      " ignoring replacement %#x",                      \
                      name->str, knownTids->_param_, _string_, _tid_);  \
        } else {                                                        \
            knownTids->_param_ = _tid_;                                 \
        }                                                               \
    } while(0)


void
mdUtilUpdateKnownTemplates(
    const GString                  *name,
    const mdUtilTemplateContents_t  tc,
    uint16_t                        tid,
    mdKnownTemplates_t             *knownTids)
{
    switch (tc.general) {
      case TC_TOMBSTONE:
        /* SM v1 emits both templates even though it only uses V2 */
        switch (tc.specCase.tombstone) {
          case TC_TOMBSTONE_V2:
            SET_KNOWN_TID(tombstoneV2MainTid, tid, "tombstone main V2");
            break;
          case TC_TOMBSTONE_ACCESS_V2:
            SET_KNOWN_TID(tombstoneV2AccessTid, tid, "tombstone access V2");
            break;
          case TC_TOMBSTONE_V1:
            SET_KNOWN_TID(tombstoneV1MainTid, tid, "tombstone main V1");
            break;
          case TC_TOMBSTONE_ACCESS_V1:
            SET_KNOWN_TID(tombstoneV1AccessTid, tid, "tombstone access V1");
            break;
          case TC_TOMBSTONE_NOT_SET:
            break;
        }
        break;
      case TC_YAF_STATS:
        SET_KNOWN_TID(yafStatsTid, tid, "yaf stats");
        break;
      case TC_DNS_DEDUP:
        switch (tc.specCase.dnsDedup) {
          case TC_DNS_DEDUP_AREC:
            SET_KNOWN_TID(dnsDedupArecExtTid, tid, "dns dedup arec");
            break;
          case TC_DNS_DEDUP_LS_AREC_V1:
            SET_KNOWN_TID(dnsDedupArecLSExtTid, tid, "dns dedup arec ls v1");
            break;
          case TC_DNS_DEDUP_LS_AREC_V2:
            SET_KNOWN_TID(dnsDedupArecLSExtTid, tid, "dns dedup arec ls v2");
            break;
          case TC_DNS_DEDUP_AAAAREC:
            SET_KNOWN_TID(dnsDedupArecExtTid, tid, "dns dedup aaaaarec");
            break;
          case TC_DNS_DEDUP_LS_AAAAREC_V1:
            SET_KNOWN_TID(dnsDedupArecLSExtTid, tid, "dns dedup aaaaarec ls v1");
            break;
          case TC_DNS_DEDUP_LS_AAAAREC_V2:
            SET_KNOWN_TID(dnsDedupArecLSExtTid, tid, "dns dedup aaaarec ls v2");
            break;
          case TC_DNS_DEDUP_OREC:
            SET_KNOWN_TID(dnsDedupOrecExtTid, tid, "dns dedup orec");
            break;
          case TC_DNS_DEDUP_LS_OREC_V1:
            SET_KNOWN_TID(dnsDedupOrecLSExtTid, tid, "dns dedup orec ls v1");
            break;
          case TC_DNS_DEDUP_LS_OREC_V2:
            SET_KNOWN_TID(dnsDedupOrecLSExtTid, tid, "dns dedup orec ls v2");
            break;
          case TC_DNS_DEDUP_NOT_SET:
          case TC_DNS_DEDUP_LS_V1:
          case TC_DNS_DEDUP_LS_V2:
            break;
        }
        break;
      case TC_DPI:
      case TC_UNKNOWN_DATA:
        switch (tc.specCase.dpi) {
          case TC_APP_DPI_DNS:
            SET_KNOWN_TID(dnsDPITid, tid, "dns dpi qr");
            break;
          case TC_APP_DPI_SSL_L1:
          case TC_APP_DPI_SSL_L1_CERT_LIST:
            SET_KNOWN_TID(sslLevel1Tid, tid, "ssl dpi level 1");
            break;
          case TC_APP_DPI_SSL_L2:
            SET_KNOWN_TID(sslLevel2Tid, tid, "ssl dpi level 2");
            break;
          case TC_APP_DPI_SSL_L3:
            /*SET_KNOWN_TID(sslLevel3Tid, tid, "ssl dpi level 3");*/
            break;
          case TC_APP_DPI_SSL_RW_L2:
            SET_KNOWN_TID(flattenedSSLTid, tid, "flattened ssl level 2");
            break;
          case TC_APP_DPI_TCP_REV:
            SET_KNOWN_TID(tcpRevSubrecTid, tid, "TCP flags biflow subrecord");
            break;
          case TC_APP_DPI_TCP_FWD:
            SET_KNOWN_TID(tcpFwdSubrecTid, tid, "TCP flags uniflow subrecord");
            break;
          case TC_APP_UNKNOWN:
            /* UKNOWN isn't a known template */
            break;
        }
        break;
      case TC_SSL_DEDUP:
        SET_KNOWN_TID(sslDedupTid, tid, "ssl dedup tid");
        break;
      case TC_UNKNOWN:
      case TC_FLOW:
      case TC_GENERAL_DEDUP:
      case TC_DNS_RR:
      case TC_TMD_OR_IE:
      case TC_UNKNOWN_OPTIONS:
        /* no known templates for these types */
        break;
      case TC_NUM_TYPES:
        g_error("%s TC_NUM_TYPES into UpdateKnownTemplate", name->str);
        break;
    }
}


static mdUtilTemplateContents_t
mdUtilDetermineTemplateContents(
    const fbTemplate_t    *tmpl,
    uint16_t               tid,
    mdUtilTemplateType_t   templateType)
{
    mdUtilTemplateContents_t tc          = MD_TC_INIT;
    mdUtilTemplateContents_t dataTc      = MD_TC_INIT;
    const fbTemplateField_t *BLField     = NULL;
    const fbTemplateField_t *STLField    = NULL;
    const fbTemplateField_t *STMLField   = NULL;
    gboolean hasLists    = FALSE;
    gboolean hasSTL      = FALSE;
    gboolean seiListIE   = FALSE;
    uint16_t position;

    switch (templateType) {
      case TT_UNKNOWN:
        /* error condition */
        return tc;

      case TT_TMD:
      case TT_IE_SPEC:
        tc.general = TC_TMD_OR_IE;
        return tc;

      case TT_TOP_FLOW:
      case TT_NO_TMD_FLOW:
        tc.general = TC_FLOW;
        /* either version of flow works here */
        position = 0;
        while (FALSE == seiListIE &&
               (STLField = fbTemplateFindFieldByDataType(
                   tmpl, FB_SUB_TMPL_LIST, &position, 0)))
        {
            hasLists = TRUE;
            hasSTL = TRUE;
            if (IS_CERT_IE(STLField->canon->ent)) {
                seiListIE = TRUE;
            }
            position++;
        }

        position = 0;
        while (FALSE == seiListIE &&
               (BLField = fbTemplateFindFieldByDataType(
                   tmpl, FB_BASIC_LIST, &position, 0)))
        {
            hasLists = TRUE;
            if (IS_CERT_IE(BLField->canon->ent)) {
                seiListIE = TRUE;
            }
            position++;
        }

        position = 0;
        while (FALSE == seiListIE &&
               (STMLField = fbTemplateFindFieldByDataType(
                   tmpl, FB_SUB_TMPL_MULTI_LIST, &position, 0)))
        {
            hasLists = TRUE;
            if (IS_CERT_IE(STMLField->canon->ent)) {
                seiListIE = TRUE;
            }
            position++;
        }

        if (hasLists) {
            tc.specCase.flow = TC_FLOW_HAS_LISTS;
        }

        /* for now...call it orig if it's not STL...TODO...do better */
        if (hasSTL) {
            tc.yafVersion = TC_YAF_VERSION_3;
        } else {
            tc.yafVersion = TC_YAF_VERSION_2;
        }

        /* TODO...removed warning, placeholder for potential future check */
        if (seiListIE) {
            /* tc += TC_FLOW_YAF_V3;*/ /* not sure if this is right */
        } else {
            /* tc += TC_FLOW_YAF_ORIG;*/ /* not sure if this is right */
        }

        return tc;

      case TT_NO_TMD_DATA:
      case TT_TOP_OTHER: /* have metadata, definitely top */
      case TT_NESTED_DATA:
        if (templateType == TT_NESTED_DATA) {
            tc.general = TC_DPI;
        } else {
            tc.general = TC_UNKNOWN_DATA;
        }

        if (fbTemplatesAreEqual(tmpl, tombstoneAccessV2Tmpl)) {
            tc.general  = TC_TOMBSTONE;
            tc.relative = TC_EXACT;
            tc.specCase.tombstone = TC_TOMBSTONE_ACCESS_V2;
            return tc;
        }
        if (fbTemplatesAreEqual(tmpl, tombstoneAccessV1Tmpl)) {
            tc.general  = TC_TOMBSTONE;
            tc.relative = TC_EXACT;
            tc.specCase.tombstone = TC_TOMBSTONE_ACCESS_V1;
            return tc;
        }

        dataTc = mdUtilDataRecDetector(tmpl, tid);
        if (dataTc.general == TC_UNKNOWN) {
            /* use gen case of tc, as it wasn't an SM rec type, copy rest */
            tc.specCase.notSet  = dataTc.specCase.notSet;
            tc.relative         = dataTc.relative;
            tc.yafVersion       = dataTc.yafVersion;
        } else {
            /* was labeled dedup, rr, or an SM rec type, just take it */
            tc = dataTc;
        }

        /* TODO, move into DAtaRecDetector() */
        if (fbTemplateContainsAllFlaggedElementsByName(tmpl,
                                                       generalDedupCheckerSpec,
                                                       0))
        {
            /* TODO do more to verify general dedup */
            tc.specCase.notSet  = TC_SPEC_NOT_SET;
            tc.relative         = TC_EXACT_DEF;
            tc.yafVersion       = TC_YAF_ALL_VERSIONS;
            tc.general = TC_GENERAL_DEDUP;
            return tc;
        }

        return tc;

      case TT_TOP_OPTIONS:
      case TT_NO_TMD_OPTIONS:
        /* could be top tombstone, top stats, access tombstone, or other */
        /* LOOKS LIKE TOMBSTONE */
        if (looksLikeTombstone(tmpl)) {
            /* it's one of the tombstones, now find the version */
            tc.general   = TC_TOMBSTONE;
            tc.relative  = TC_EXACT;
            if (fbTemplatesAreEqual(tmpl, tombstoneMainV1Tmpl)) {
                tc.specCase.tombstone = TC_TOMBSTONE_V1;
            } else if (fbTemplatesAreEqual(tmpl, tombstoneMainV2Tmpl)) {
                tc.specCase.tombstone = TC_TOMBSTONE_V2;
            } else {
                g_warning("tombstone mix %#x", tid);
                tc.general = TC_UNKNOWN;
                return tc;
            }
            return tc;
        }

        /* LOOKS LIKE YAF STATS */
        if (looksLikeYafStats(tmpl)) {
            /* it's one of the YAF STATS.
             * Contains: exporterFlowRecordTotalCount, droppedPacketTotalCount,
             * and yafMeanFlowRate.
             * now find the version */
            tc.general   = TC_YAF_STATS;
            tc.relative  = TC_EXACT;
            if (fbTemplatesAreEqual(tmpl, yafStatsV1Tmpl)) {
                tc.specCase.yafStats = TC_YAF_STATS_V1;
            } else if (fbTemplatesAreEqual(tmpl, yafStatsV2Tmpl)) {
                tc.specCase.yafStats = TC_YAF_STATS_V2;
            } else if (0 == fbTemplatesCompare(tmpl, yafStatsV2Tmpl,
                                               FB_TMPL_CMP_IGNORE_SCOPE))
            {
                /* this clause is for output from super_mediator 1.x which
                 * uses incorrect scope count when exporting this template */
                tc.specCase.yafStats = TC_YAF_STATS_V2_SCOPE2;
            } else {
                g_warning("stats mix %#x", tid);
                tc.general = TC_UNKNOWN;
            }
            return tc;
        }

        tc.general = TC_UNKNOWN_OPTIONS;
        return tc;

      case TT_NESTED_OPTIONS:
        /* do we care about labeling tombstone access ?
         * no, for now, UNKNOWN OPTIONS will get default template context,
         * and will be added into a session pair */
        tc.general = TC_UNKNOWN_OPTIONS;
        return tc;
    }

    tc.general = TC_UNKNOWN;
    return tc;
}


mdUtilTemplateType_t
mdUtilExamineTemplate(
    const fbTemplate_t         *tmpl,
    uint16_t                    tid,
    const fbTemplateInfo_t     *mdInfo,
    mdUtilTemplateContents_t   *templateContents)
{
    mdUtilTemplateType_t tt;

    tt = mdUtilDetermineTemplateType(tmpl, tid, mdInfo);
    *templateContents = mdUtilDetermineTemplateContents(tmpl, tid, tt);
    return tt;
}


void
templateCtxFree(
    void  *tmpl_ctx,
    void  *app_ctx)
{
    mdDefaultTmplCtx_t *ctx = (mdDefaultTmplCtx_t *)tmpl_ctx;

    MD_UNUSED_PARAM(app_ctx);

    g_free(ctx->blOffsets);
    g_free(ctx->stlOffsets);
    g_free(ctx->stmlOffsets);

    switch (ctx->contextType) {
      case TCTX_TYPE_TOMBSTONE:
        g_slice_free(mdTombstoneTmplCtx_t, (mdTombstoneTmplCtx_t *)ctx);
        break;
      case TCTX_TYPE_GENERAL_DEDUP:
        g_slice_free(mdGeneralDedupTmplCtx_t, (mdGeneralDedupTmplCtx_t *)ctx);
        break;
      case TCTX_TYPE_COL_FLOW:
        g_slice_free(mdCollIntFlowTmplCtx_t, (mdCollIntFlowTmplCtx_t *)ctx);
        break;
      case TCTX_TYPE_EXPORTER:
        g_slice_free(mdExpFlowTmplCtx_t, (mdExpFlowTmplCtx_t *)ctx);
        break;
      case TCTX_TYPE_YAF_STATS:
        g_slice_free(mdYafStatsTmplCtx_t, (mdYafStatsTmplCtx_t *)ctx);
        break;
      case TCTX_TYPE_DEFAULT:
        g_slice_free(mdDefaultTmplCtx_t, ctx);
        break;
      case TCTX_TYPE_UNKNOWN:
        g_warning("unknown template context being freed");
        break;
    }
}

static void
mdUtilUpdateTemplateField(
    const fbTemplateField_t **dstTF,
    const fbTemplateField_t  *srcTF,
    fbTemplate_t             *newTmpl)
{
    /* srcTF allowed to be NULL, rest not */
    if (srcTF) {
        *dstTF = fbTemplateFindFieldByIdent(newTmpl,
                                            srcTF->canon->ent,
                                            srcTF->canon->num,
                                            NULL, 0);
    }
}


/* add original template as well...finish rest of types */
mdDefaultTmplCtx_t *
templateCtxCopy(
    mdDefaultTmplCtx_t  *origCtx,
    fbTemplate_t        *newTmpl)
{
    mdDefaultTmplCtx_t *newDefTmplCtx = NULL;
    switch (origCtx->contextType) {
      case TCTX_TYPE_TOMBSTONE:
        {
            mdTombstoneTmplCtx_t *tsTmplCtx = g_slice_new0(
                mdTombstoneTmplCtx_t);
            mdTombstoneTmplCtx_t *origTsTmplCtx =
                (mdTombstoneTmplCtx_t *)origCtx;

            if (!tsTmplCtx) {
                g_error("Couldn't allocate new tombstone tmpl ctx in copy");
            }

            memcpy(tsTmplCtx, origTsTmplCtx, sizeof(mdTombstoneTmplCtx_t));

            newDefTmplCtx = (mdDefaultTmplCtx_t *)tsTmplCtx;
            break;
        }
      case TCTX_TYPE_GENERAL_DEDUP:
        {
            mdGeneralDedupTmplCtx_t *dedupTmplCtx =
                g_slice_new0(mdGeneralDedupTmplCtx_t);
            mdGeneralDedupTmplCtx_t *origDedupTmplCtx =
                (mdGeneralDedupTmplCtx_t *)origCtx;

            if (!dedupTmplCtx) {
                g_error("Couldn't allocate new dedup tmpl ctx in copy");
            }

            memcpy(dedupTmplCtx, origDedupTmplCtx, sizeof(*dedupTmplCtx));

            newDefTmplCtx = (mdDefaultTmplCtx_t *)dedupTmplCtx;
            break;
        }
      case TCTX_TYPE_COL_FLOW:
        {
            mdCollIntFlowTmplCtx_t *colIntTmplCtx = g_slice_new0(
                mdCollIntFlowTmplCtx_t);
            mdCollIntFlowTmplCtx_t *origColIntTmplCtx =
                (mdCollIntFlowTmplCtx_t *)
                origCtx;
            if (!colIntTmplCtx) {
                g_error("Couldn't allocate new collector int tmpl ctx in copy");
            }

            memcpy(colIntTmplCtx, origColIntTmplCtx,
                   sizeof(mdCollIntFlowTmplCtx_t));

            colIntTmplCtx->flowStartMS      = NULL;
            mdUtilUpdateTemplateField(&colIntTmplCtx->flowStartMS,
                                      origColIntTmplCtx->flowStartMS,
                                      newTmpl);

            colIntTmplCtx->sip4             = NULL;
            mdUtilUpdateTemplateField(&colIntTmplCtx->sip4,
                                      origColIntTmplCtx->sip4,
                                      newTmpl);

            colIntTmplCtx->dip4             = NULL;
            mdUtilUpdateTemplateField(&colIntTmplCtx->dip4,
                                      origColIntTmplCtx->dip4,
                                      newTmpl);

            colIntTmplCtx->sport            = NULL;
            mdUtilUpdateTemplateField(&colIntTmplCtx->sport,
                                      origColIntTmplCtx->sport,
                                      newTmpl);

            colIntTmplCtx->dport            = NULL;
            mdUtilUpdateTemplateField(&colIntTmplCtx->dport,
                                      origColIntTmplCtx->dport,
                                      newTmpl);

            colIntTmplCtx->vlanId           = NULL;
            mdUtilUpdateTemplateField(&colIntTmplCtx->vlanId,
                                      origColIntTmplCtx->vlanId,
                                      newTmpl);

            colIntTmplCtx->protocol         = NULL;
            mdUtilUpdateTemplateField(&colIntTmplCtx->protocol,
                                      origColIntTmplCtx->protocol,
                                      newTmpl);

            colIntTmplCtx->flowEndReason    = NULL;
            mdUtilUpdateTemplateField(&colIntTmplCtx->flowEndReason,
                                      origColIntTmplCtx->flowEndReason,
                                      newTmpl);

            newDefTmplCtx = (mdDefaultTmplCtx_t *)colIntTmplCtx;
            break;
        }
      case TCTX_TYPE_EXPORTER:
        {
            mdExpFlowTmplCtx_t *expTmplCtx = g_slice_new0(mdExpFlowTmplCtx_t);
            mdExpFlowTmplCtx_t *origExpTmplCtx = (mdExpFlowTmplCtx_t *)origCtx;

            memcpy(expTmplCtx, origExpTmplCtx, sizeof(mdExpFlowTmplCtx_t));

            newDefTmplCtx = (mdDefaultTmplCtx_t *)expTmplCtx;
            break;
        }
      case TCTX_TYPE_YAF_STATS:
      /* YAF stats is just default at this point */
      case TCTX_TYPE_DEFAULT:
        newDefTmplCtx = g_slice_new0(mdDefaultTmplCtx_t);
        /* nothing to do...let the bottom section do the work */
        break;
      case TCTX_TYPE_UNKNOWN:
        g_warning("unknown template context being copied");
        return NULL;
    }

    if (NULL == newDefTmplCtx) {
        g_error("No new def tmpl Ctx to copy");
    }

    /* newDefTmplCtx's lists are pointing at origCtx's; rebuild them */
    newDefTmplCtx->blOffsets            = NULL;
    newDefTmplCtx->stlOffsets           = NULL;
    newDefTmplCtx->stmlOffsets          = NULL;
    mdTemplateContextSetListOffsets(newDefTmplCtx, newTmpl);

    newDefTmplCtx->dataCTimeIE          = NULL;
    mdUtilUpdateTemplateField(&newDefTmplCtx->dataCTimeIE,
                              origCtx->dataCTimeIE,
                              newTmpl);

    newDefTmplCtx->sourceRuntimeCTimeIE = NULL;
    mdUtilUpdateTemplateField(&newDefTmplCtx->sourceRuntimeCTimeIE,
                              origCtx->sourceRuntimeCTimeIE,
                              newTmpl);

    return newDefTmplCtx;
}


uint16_t
mdSessionAddTemplateHelper(
    fbSession_t        *session,
    gboolean            isInternal,
    uint16_t            tid,
    fbTemplate_t       *tmpl,
    fbTemplateInfo_t   *mdInfo,
    const char         *filename,
    int                 linenum)
{
    GError *err = NULL;
    uint16_t newtid;

    newtid = fbSessionAddTemplate(session, isInternal, tid, tmpl,
                                  mdInfo, &err);
    if (newtid) {
        return newtid;
    }

    const uint16_t ASAT_MAX_PRINT = 3;
    GString *str = g_string_sized_new(256);
    uint16_t count = fbTemplateCountElements(tmpl);

    if (0 == count) {
        g_string_printf(str, "empty");
    } else {
        const fbTemplateField_t *f;
        uint16_t toprint =
            (count <= ASAT_MAX_PRINT) ? count : (ASAT_MAX_PRINT - 1);
        uint16_t i;
        for (i = 0; i < toprint; ++i) {
            f = fbTemplateGetFieldByPosition(tmpl, i);
            g_string_append_printf(str, "%s%s",
                                   ((i > 0) ? "," : ""),
                                   fbTemplateFieldGetName(f));
        }
        if (i < count) {
            g_string_append_printf(str, ",& %d more", count - i);
        }
    }

    g_error(("Unable to add %sternal template [%s] with ID %#06x to session: %s"
             "\n\tAborting at %s:%d"),
            (isInternal ? "in" : "ex"), str->str, tid, err->message,
           filename, linenum);
}

void
mdAbortTemplateAppendSpecArray(
    fbTemplate_t               *tmpl,
    const fbInfoElementSpec_t  *specArray,
    uint32_t                    flags,
    GError                     *err,
    const char                 *filename,
    int                         linenum)
{
    uint32_t count = 0;
    uint32_t first = UINT32_MAX;
    uint32_t i;

#define MD_ATASA_ABORT_MSG  "\n\tProgrammer error. Aborting at %s:%d"

    MD_UNUSED_PARAM(tmpl);

    for (i = 0; NULL != specArray[i].name; ++i) {
        if ((specArray[i].flags & flags) == specArray[i].flags) {
            ++count;
            if (UINT32_MAX == first) {
                first = i;
            }
        }
    }
    if (count > 1) {
        --count;
        g_error(("Unable to add '%s' and %u other element%s to a template: %s"
                 MD_ATASA_ABORT_MSG),
                specArray[first].name, count, ((1 == count) ? "" : "s"),
                err->message, filename, linenum);
    }
    if (1 == count) {
        g_error("Unable to add '%s' to a template: %s" MD_ATASA_ABORT_MSG,
                specArray[first].name, err->message, filename, linenum);
    }
    g_error(("Unable to add an empty SpecArray to a template: %s"
             MD_ATASA_ABORT_MSG),
            err->message, filename, linenum);
}

void
mdAbortTemplateAppendArraySpecId(
    fbTemplate_t                   *tmpl,
    const fbInfoElementSpecId_t    *idSpecArray,
    uint32_t                        flags,
    GError                         *err,
    const char                     *filename,
    int                             linenum)
{
    uint32_t count = 0;
    uint32_t first = UINT32_MAX;
    uint32_t i;

#define MD_ATASA_ABORT_MSG  "\n\tProgrammer error. Aborting at %s:%d"

    MD_UNUSED_PARAM(tmpl);

    for (i = 0; 0 != idSpecArray[i].ident.element_id; ++i) {
        if ((idSpecArray[i].flags & flags) == idSpecArray[i].flags) {
            ++count;
            if (UINT32_MAX == first) {
                first = i;
            }
        }
    }
    if (count > 1) {
        --count;
        g_error(("Unable to add Element (%u/%u) and %u other element%s"
                 " to a template: %s" MD_ATASA_ABORT_MSG),
                idSpecArray[first].ident.enterprise_id,
                idSpecArray[first].ident.element_id,
                count, ((1 == count) ? "" : "s"),
                err->message, filename, linenum);
    }
    if (1 == count) {
        g_error(("Unable to add Element (%u/%u)"
                 " to a template: %s" MD_ATASA_ABORT_MSG),
                idSpecArray[first].ident.enterprise_id,
                idSpecArray[first].ident.element_id,
                err->message, filename, linenum);
    }
    g_error(("Unable to add an empty IdSpecArray to a template: %s"
             MD_ATASA_ABORT_MSG),
            err->message, filename, linenum);
}



uint16_t
mdUtilGetIEOffset(
    const fbTemplate_t *tmpl,
    uint32_t            ent,
    uint16_t            num)
{
    const fbTemplateField_t *ie = NULL;
    if (!tmpl || !num) {
        return UINT16_MAX;
    }

    ie = fbTemplateFindFieldByIdent(tmpl, ent, num, NULL, 0);
    if (!ie) {
        return UINT16_MAX;
    }

    return ie->offset;
}

mdUtilTCRelative_t
mdUtilDetermineRelative(
    const fbTemplate_t *inTmpl,
    const fbTemplate_t *globalTmpl)
{
    fbTemplatesSetCompareStatus_t setCompare  = FB_TMPL_SETCMP_DISJOINT;
    uint16_t ieCount     = 0;
    const fbTemplateField_t      *lastIE      = NULL;
    unsigned int cmpFlags    = 0;

    ieCount = fbTemplateCountElements(inTmpl);
    if (!ieCount) {
        g_error("template with 0 elements into determine relative");
    }

    lastIE = fbTemplateGetFieldByPosition(inTmpl, ieCount - 1);
    if (!lastIE) {
        g_error("no last IE in determine relative");
    }

    setCompare = fbTemplatesSetCompare(inTmpl, globalTmpl, NULL,
                                       FB_TMPL_CMP_IGNORE_PADDING);
    switch (setCompare) {
      case FB_TMPL_SETCMP_SUBSET:
        return TC_SUB;
      case FB_TMPL_SETCMP_EQUAL:
        /* if the last IE is padding, use ignore padding, else do all */
        /* this will cause problems if the incoming template has padding at
         * the end which we want to ignore, but that padding doesn't align
         * inside the core of the template, and this difference is not caught
         * by fbTemplatesSetCompare() */
        if (lastIE->canon->ent == 0 && lastIE->canon->num == 210) {
            cmpFlags = FB_TMPL_CMP_IGNORE_PADDING;
        } else {
            cmpFlags = 0;
        }

        if (fbTemplatesCompare(inTmpl, globalTmpl, cmpFlags)) {
            return TC_SUPER;
        } else {
            return TC_EXACT;
        }
      case FB_TMPL_SETCMP_SUPERSET:
        return TC_SUPER;
      case FB_TMPL_SETCMP_COMMON:
        return TC_MIX;
      case FB_TMPL_SETCMP_DISJOINT:
        g_error("disjoint somehow!");
        exit(1);
    }

    return TC_MIX;
}

const char *
mdUtilDebugTemplateType(
    mdUtilTemplateType_t   tt)
{
    switch (tt) {
      case TT_UNKNOWN:
        return "UNKNOWN";
      case TT_TOP_FLOW:
        return "TOP FLOW";
      case TT_TOP_OTHER:
        return "TOP OTHER";
      case TT_TOP_OPTIONS:
        return "TOP OPTIONS";
      case TT_NESTED_DATA:
        return "NESTED DATA";
      case TT_NESTED_OPTIONS:
        return "NESTED OPTIONS";
      case TT_TMD:
        return "TMD";
      case TT_IE_SPEC:
        return "IE_SPEC";
      case TT_NO_TMD_FLOW:
        return "NO TMD FLOW";
      case TT_NO_TMD_DATA:
        return "NO TMD DATA";
      case TT_NO_TMD_OPTIONS:
        return "NO TMD OPTIONS";
    }
    return NULL;
}

GString *
mdUtilDebugTemplateContents(
    const mdUtilTemplateContents_t  tc)
{
    GString    *tcStr       = g_string_new(NULL);
    const char *genStr      = NULL;
    const char *specStr     = NULL;
    const char *relStr      = NULL;
    const char *yafStr      = NULL;

    genStr  = mdUtilDebugTemplateContentsGeneral(tc.general);
    specStr = mdUtilDebugTemplateContentsSpecCase(tc.general, tc.specCase);
    relStr  = mdUtilDebugTemplateContentsRelative(tc.relative);
    yafStr  = mdUtilDebugTemplateContentsYafVersion(tc.yafVersion);

    /* tcStr = genStr <- yafStr> <- specStr> <-relStr> */

    g_string_append(tcStr, genStr);
    if (yafStr) {
        g_string_append_printf(tcStr, " - %s", yafStr);
    }

    if (specStr) {
        g_string_append_printf(tcStr, " - %s", specStr);
    }

    if (relStr) {
        g_string_append_printf(tcStr, " - %s", relStr);
    }

    return tcStr;
}

const char *
mdUtilDebugTemplateContentsGeneral(
    mdUtilTCGeneral_t   gen)
{
    switch (gen) {
      case TC_UNKNOWN:
        return "UNKNOWN";
      case TC_FLOW: /* no relative specification needed, get what we get */
        return "FLOW";
      case TC_DPI:
        return "DPI";
      case TC_DNS_DEDUP:
        return "DNS DEDUP";
      case TC_SSL_DEDUP:
        return "SSL DEDUP";
      case TC_GENERAL_DEDUP:
        return "GENERAL DEDUP";
      case TC_DNS_RR:
        return "DNS RR";
      case TC_YAF_STATS:
        return "YAF STATS";
      case TC_TOMBSTONE:
        return "TOMBSTONE";
      case TC_TMD_OR_IE:
        return "TMD OR IE";
      case TC_UNKNOWN_DATA:
        return "UNKNOWN DATA";
      case TC_UNKNOWN_OPTIONS:
        return "UNKNOWN OPTIONS";
      case TC_NUM_TYPES:
        g_error("Num types passed to debug TC gen");
    }

    return NULL;
}

const char *
mdUtilDebugTemplateContentsSpecCase(
    mdUtilTCGeneral_t    gen,
    mdUtilTCSpecCase_t   specCase)
{
    switch (gen) {
      case TC_UNKNOWN:
      case TC_SSL_DEDUP:
      case TC_GENERAL_DEDUP:
      case TC_TMD_OR_IE:
      case TC_UNKNOWN_OPTIONS:
      case TC_NUM_TYPES:
        return NULL;
      case TC_FLOW:
        return mdUtilDebugSpecCaseFlow(specCase);
      case TC_YAF_STATS:
        return mdUtilDebugSpecCaseYafStats(specCase);
      case TC_TOMBSTONE:
        return mdUtilDebugSpecCaseTombstone(specCase);
      case TC_DNS_DEDUP:
        return mdUtilDebugSpecCaseDnsDedup(specCase);
      case TC_DNS_RR:
        return mdUtilDebugSpecCaseDnsRR(specCase);
      case TC_UNKNOWN_DATA:
      case TC_DPI:
        return mdUtilDebugSpecCaseDPI(specCase);
    }

    return NULL;
}

const char *
mdUtilDebugSpecCaseFlow(
    mdUtilTCSpecCase_t   specCase)
{
    mdUtilTCSpecFlow_t flow = specCase.flow;

    switch (flow) {
      case TC_FLOW_DEFAULT:
        return "NO LISTS";
      case TC_FLOW_REV:
        return "REVERSE - NO LISTS";
      case TC_FLOW_HAS_LISTS:
        return "HAS LISTS";
      case TC_FLOW_REV_AND_HAS_LISTS:
        return "REVERSE - HAS LISTS";
    }

    return NULL;
}

const char *
mdUtilDebugSpecCaseDnsDedup(
    mdUtilTCSpecCase_t   specCase)
{
    mdUtilTCSpecDNSDedup_t dnsDedup = specCase.dnsDedup;

    switch (dnsDedup) {
      case TC_DNS_DEDUP_NOT_SET:
        return "NOT SET";
      case TC_DNS_DEDUP_AREC:
        return "AREC";
      case TC_DNS_DEDUP_AAAAREC:
        return "AAAAREC";
      case TC_DNS_DEDUP_OREC:
        return "OREC";
      case TC_DNS_DEDUP_LS_V1:
      case TC_DNS_DEDUP_LS_V2:
        g_error("DNS DEDUP LS in debug dns dedup TC");
        break;
      case TC_DNS_DEDUP_LS_AREC_V1:
        return "AREC - LS V1";
      case TC_DNS_DEDUP_LS_AAAAREC_V1:
        return "AAAAREC - LS V1";
      case TC_DNS_DEDUP_LS_OREC_V1:
        return "OREC - LS V1";
      case TC_DNS_DEDUP_LS_AREC_V2:
        return "AREC - LS V2";
      case TC_DNS_DEDUP_LS_AAAAREC_V2:
        return "AAAAREC - LS V2";
      case TC_DNS_DEDUP_LS_OREC_V2:
        return "OREC - LS V2";
    }

    return NULL;
}

const char *
mdUtilDebugSpecCaseDnsRR(
    mdUtilTCSpecCase_t   specCase)
{
    mdUtilTCSpecDNSRR_t dnsRR = specCase.dnsRR;

    switch (dnsRR) {
      case TC_DNS_RR_NOT_SET:
        return "NOT SET";
      case TC_DNS_RR_FULL_4:
        return "FULL IPv4";
      case TC_DNS_RR_FULL_6:
        return "FULL IPv4";
    }

    return NULL;
}

const char *
mdUtilDebugSpecCaseYafStats(
    mdUtilTCSpecCase_t   specCase)
{
    mdUtilTCSpecYafStats_t yafStats = specCase.yafStats;

    switch (yafStats) {
      case TC_YAF_STATS_NOT_SET:
        return "NOT SET";
      case TC_YAF_STATS_V1:
        return "V1";
      case TC_YAF_STATS_V2:
      case TC_YAF_STATS_V2_SCOPE2:
        return "V2";
    }

    return NULL;
}

const char *
mdUtilDebugSpecCaseTombstone(
    mdUtilTCSpecCase_t   specCase)
{
    mdUtilTCSpecTombstone_t tombstone = specCase.tombstone;

    switch (tombstone) {
      case TC_TOMBSTONE_NOT_SET:
        return "NOT SET";
      case TC_TOMBSTONE_V1:
        return "V1";
      case TC_TOMBSTONE_V2:
        return "V2";
      case TC_TOMBSTONE_ACCESS_V1:
        return "V1 ACCESS";
      case TC_TOMBSTONE_ACCESS_V2:
        return "V2 ACCESS";
    }

    return NULL;
}

const char *
mdUtilDebugSpecCaseDPI(
    mdUtilTCSpecCase_t   specCase)
{
    mdUtilTCSpecDPI_t dpi = specCase.dpi;

    switch (dpi) {
      case TC_APP_UNKNOWN:
        return "DPI UNKNOWN";
      case TC_APP_DPI_DNS:
        return "DNS";
      case TC_APP_DPI_SSL_L1:
        return "SSL - Level 1";
      case TC_APP_DPI_SSL_L1_CERT_LIST:
        return "SSL - Level 1 - Cert List";
      case TC_APP_DPI_SSL_L2:
        return "SSL - Level 2";
      case TC_APP_DPI_SSL_L3:
        return "SSL - Level 3";
      case TC_APP_DPI_SSL_RW_L2:
        return "SSL - Rewritten";
      case TC_APP_DPI_TCP_REV:
        return "TCP Biflow Subrecord";
      case TC_APP_DPI_TCP_FWD:
        return "TCP Uniflow Subrecord";
    }

    return NULL;
}

const char *
mdUtilDebugTemplateContentsRelative(
    mdUtilTCRelative_t   rel)
{
    switch (rel) {
      case TC_EXACT_DEF:
        return "EXACT_DEF";
      case TC_SUB:
        return "SUB";
      case TC_EXACT:
        return "EXACT";
      case TC_SUPER:
        return "SUPER";
      case TC_MIX:
        return "MIX";
    }

    g_error("Unknown rel tc value: %#x\n", rel);
    return NULL;
}

#if 0
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
#endif  /* 0 */

#if 0
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

    /* Copy over the common parts */
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
#endif  /* 0 */

/*
 *    Parse the IPv4 address at 'ip_string' and put the result--in
 *    native byte order--into the referent of 'ip'.
 *    Return TRUE on success and FALSE error.
 */
/* This code based on sku-string in SiLK */
static gboolean
mdUtilParseIPv4(
    uint32_t    *ip,
    const char  *ip_string,
    GError     **err)
{
    unsigned long final = 0;
    unsigned long val;
    const char   *sp = ip_string;
    char         *ep;
    int           i;

    *ip = 0;

    for (i = 3; i >= 0; --i) {
        /* parse the number */
        errno = 0;
        val = strtoul(sp, &ep, 10);
        if (sp == ep) {
            /* parse error */
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Unexpected character '%c' parsing IP octet #%d.",
                        *ep, 4 - i);
            return FALSE;
        }
        if (val == ULONG_MAX && errno == ERANGE) {
            /* overflow */
            if (i == 3) {
                /* entire value is too large */
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "Value overflows the parser during IP parsing.");
                return FALSE;
            }
            /* octet value is too large */
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "IP octet #%d too large while parsing IP.", 4 - i);
            return FALSE;
        }
        if (val > UINT8_MAX) {
            if (i == 3 && *ep != '.') {
                /* treat as a single integer */
#if (SIZEOF_LONG > 4)
                if (val > UINT32_MAX) {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                                "Integer too large for IPv4 while parsing IP.");
                    return FALSE;
                }
#endif /* if (SIZEOF_LONG > 4) */
                sp = ep;
                final = val;
                break;
            }
            /* value too big for octet */
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "IP octet #%d too large while parsing IP.", 4 - i);
            return FALSE;
        }

        sp = ep;
        if (*sp != '.') {
            if (i == 3) {
                /* treat as a single integer */
                assert(val <= UINT8_MAX);
                final = val;
                break;
            }
            if (i != 0) {
                if (*sp == '\0') {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                                "Unexpected end-of-input while parsing IP.");
                    return FALSE;
                }
                /* need a '.' between octets */
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "Unexpected character '%c' while parsing IP.",
                            *sp);
                return FALSE;
            }
            /* else i == 0 and we've finished parsing */
        } else if (i == 0) {
            /* found a trailing '.' */
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Found fourth '.' while parsing IP.");
            return FALSE;
        } else {
            /* move to start of next octet */
            ++sp;
            if (!isdigit((int)*sp)) {
                /* error: only '.' and digits are allowed */
                if (*sp == '\0') {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                                "Unexpected end-of-input while parsing IP.");
                    return FALSE;
                }
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "Unexpected character '%c' while parsing IP.",
                            *sp);
                return FALSE;
            }
        }

        final |= val << (8 * i);
    }

    /* ignore trailing whitespace, but only if we reach the end of the
     * string.  cache the current position. */
    while (isspace((int)*sp)) {
        ++sp;
    }
    if ('\0' != *sp) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Unexpected character '%c' follows IP.", *sp);
        return FALSE;
    }

    *ip = (uint32_t)final;
    return TRUE;
}

/*
 *    Parse the IPv6 address at 'ip_string' and put the result--in
 *    native byte order--into the memory pointed at by 'out_val'.
 *    Return a negative (silk_utils_errcode_t) value on error;
 *    otherwise return a positive value specifying the number of
 *    characters that were parsed.
 */
/* This code is based on sku-string in SiLK */
static gboolean
mdUtilParseIPv6(
    fbRecordValue_t  *out_val,
    const char       *ip_string,
    GError          **err)
{
    uint8_t       ipv6[16];
    unsigned int  double_colon = UINT_MAX;
    unsigned long val;
    unsigned int  i;
    const char   *sp = ip_string;
    char         *ep;

    /* handle a "::" at the start of the address */
    if (':' == *sp) {
        if (':' != *(sp + 1)) {
            /* address cannot begin with single ':' */
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "IP address cannot begin with single ':'");
            return FALSE;
        }
        if (':' == *(sp + 2)) {
            /* triple colon */
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Unexpected ':::' while parsing IP.");
            return FALSE;
        }
        double_colon = 0;
        sp += 2;
    }

    for (i = 0; i < 8; ++i) {
        /* expecting a base-16 number */
        if (!isxdigit((int)*sp)) {
            if (double_colon != UINT_MAX) {
                /* treat as end of string */
                break;
            }
            if (*sp == '\0') {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "Unexpected end-of-input while parsing IP.");
                return FALSE;
            }
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Unexpected character '%c' while parsing IP.", *sp);
            return FALSE;
        }

        /* parse the number */
        errno = 0;
        val = strtoul(sp, &ep, 16);
        if (sp == ep) {
            if (double_colon != UINT_MAX) {
                /* treat as end of string */
                break;
            }
            /* parse error */
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Unexpected character '%c' while parsing IP.", *sp);
            return FALSE;
        }
        if (val == ULONG_MAX && errno == ERANGE) {
            /* overflow */
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Value overflows the parser while parsing IP");
            return FALSE;
        }
        if (val > UINT16_MAX) {
            /* value too big for octet */
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Value is above maximum while parsing IP");
            return FALSE;
        }

        /* if a dot follows the number we just parsed, treat that
         * number as the start of an embedded IPv4 address. */
        if (*ep == '.') {
            unsigned int j;
            uint32_t     ipv4;

            if (i > 6) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "Unexpected character while parsing IP.");
                return FALSE;
            }
            /* IPv4 address */
            if (!mdUtilParseIPv4(&ipv4, sp, err)) {
                return FALSE;
            }

            for (j = 0; j < 4; ++j) {
                ipv6[2 * i + j] = ((ipv4 >> (8 * (3 - j))) & 0xFF);
            }
            i += 2;
            /* move sp to end of text */
            sp += strlen(sp);
            break;
        }

        ipv6[2 * i] = ((val >> 8) & 0xFF);
        ipv6[2 * i + 1] = (val & 0xFF);
        sp = ep;

        /* handle section separator */
        if (*sp != ':') {
            if (i != 7) {
                if (double_colon != UINT_MAX) {
                    /* treat as end of string */
                    ++i;
                    break;
                }
                if (*sp == '\0') {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                                "Unexpected end-of-input while parsing IP.");
                    return FALSE;
                }
                /* need a ':' between sections */
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "Unexpected character '%c' while parsing IP.",
                            *sp);
                return FALSE;
            }
            /* else i == 7 and we've finished parsing */
        } else if (i == 7) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Unexpected character while parsing IP.");
            return FALSE;
        } else {
            /* move to start of next section */
            ++sp;
            if (':' == *sp) {
                if (double_colon != UINT_MAX) {
                    /* parse error */
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                                "Unexpected character while parsing IP.");
                    return FALSE;
                }
                if (':' == *(sp + 1)) {
                    /* triple colon */
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                                "Unexpected character while parsing IP.");
                    return FALSE;
                }
                double_colon = i + 1;
                ++sp;
            } else if (*sp == '\0') {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "Unexpected end-of-input while parsing IP.");
                return FALSE;
            } else if (!isxdigit((int)*sp)) {
                /* number must follow lone ':' */
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "Unexpected character while parsing IP.");
                return FALSE;
            }
        }
    }

    if (double_colon != UINT_MAX) {
        if (i == 8) {
            /* error */
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Unexpected character while parsing IP.");
            return FALSE;
        }
        memmove(&ipv6[2 * (8 + double_colon - i)], &ipv6[2 * double_colon],
                2 * (i - double_colon));
        memset(&ipv6[2 * double_colon], 0, 2 * (8 - i));
    } else if (i != 8) {
        /* error */
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Unexpected end-of-input while parsing IP.");
        return FALSE;
    }

    /* ignore trailing whitespace, but only if we reach the end of the
     * string.  cache the current position. */
    while (isspace((int)*sp)) {
        ++sp;
    }
    if ('\0' != *sp) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Unexpected character '%c' follows IP.", *sp);
        return FALSE;
    }

    memcpy(out_val->v.ip6, ipv6, 16);
    return TRUE;
}

/* Parse a string as an IPv4 or IPv6 address.  If the string is a
 * single integer, treat is an an IPv4 address. */
/* This code is based on sku-string in SiLK */
gboolean
mdUtilParseIP(
    fbRecordValue_t  *out_val,
    const char       *ip_string,
    gboolean         *isV6,
    GError          **err)
{
    const char *sp;
    const char *dot;
    const char *colon;

    /* verify input */
    if (!ip_string) {
        g_error("ip_string is NULL");
    }

    sp = ip_string;
    while (isspace((int)*sp)) {
        ++sp;
    }

    /* determine if IPv4 or IPv6 */
    dot = strchr(sp, '.');
    colon = strchr(sp, ':');
    if (colon == NULL) {
        /* no ':', so must be IPv4 or an integer */
    } else if (dot == NULL) {
        /* no '.', so must be IPv6 */
    } else if ((dot - sp) < (colon - sp)) {
        /* dot appears first, assume IPv4 */
        colon = NULL;
    } else {
        /* colon appears first, assume IPv6 */
        dot = NULL;
    }

    /* parse the address */
    if (NULL == colon) {
        /* an IPv4 address */
        uint32_t ipv4;

        if (!mdUtilParseIPv4(&ipv4, sp, err)) {
            g_prefix_error(err, "Error parsing IPv4 address \"%s\": ",
                           ip_string);
            return FALSE;
        }
        if (isV6) { *isV6 = FALSE; }
        out_val->v.ip4 = ipv4;
    } else {
        /* an IPv6 address */
        if (!mdUtilParseIPv6(out_val, sp, err)) {
            g_prefix_error(err, "Error parsing IPv6 address \"%s\": ",
                           ip_string);
            return FALSE;
        }
        if (isV6) { *isV6 = TRUE; }
    }

    return TRUE;
}


/**
 *   * This code taken from fixbuf (fbuf.c) *
 *
 *  Treats `ntptime` as pointer to a uint64_t representing a timestamp
 *  in the NTP format and converts it to a timespec.
 */
void
mdNtptimeToTimespec(
    const void               *ntptime,
    struct timespec          *ts,
    fbInfoElementDataType_t   datatype)
{
    /* FIXME: Handle NTP wraparaound for Feb 8 2036 */

    /* The number of seconds between Jan 1, 1900 (the NTP epoch) and
     * Jan 1, 1970 (the UNIX epoch) */
    const uint64_t NTP_EPOCH_TO_UNIX_EPOCH = UINT64_C(0x83AA7E80);

    /* 1^32 */
    const uint64_t NTPFRAC = UINT64_C(0x100000000);
    uint64_t       u64;

    memcpy(&u64, ntptime, sizeof(u64));
    ts->tv_sec = (int64_t)(u64 >> 32) - NTP_EPOCH_TO_UNIX_EPOCH;
    if (datatype == FB_DT_MICROSEC) {
        ts->tv_nsec = (u64 & UINT64_C(0xfffff800)) / NTPFRAC;
    } else {
        ts->tv_nsec = (u64 & UINT32_MAX) / NTPFRAC;
    }
}

int
mdFieldEntryFindAllElementValues(
    mdFullFlow_t              *flow,
    mdFieldEntry_t            *field,
    unsigned int               flags,
    fbRecordValueCallback_fn   callback,
    void                      *ctx)
{
    if (field == NULL) {
        return 0;
    }

    if (field->isDerived) {
        if (field->findDerived == NULL) {
            return 0;
        }
        return field->findDerived(flow, field, flags, callback, ctx);
    } else {
        return fbRecordFindAllElementValues(flow->fbRec, field->elem, flags,
                                            callback, ctx);
    }
}

int
mdFindFlowKeyHash(
    mdFullFlow_t              *flow,
    mdFieldEntry_t            *field,
    unsigned int               flags,
    fbRecordValueCallback_fn   callback,
    void                      *ctx)
{
    fbRecordValue_t value = FB_RECORD_VALUE_INIT;

    MD_UNUSED_PARAM(flags);

    value.ie = field->elem;
    value.v.u64 = *(flow->flowKeyHash);

    return callback(flow->fbRec, NULL, field->elem, &value, ctx);
}

int
mdFindCollector(
    mdFullFlow_t              *flow,
    mdFieldEntry_t            *field,
    unsigned int               flags,
    fbRecordValueCallback_fn   callback,
    void                      *ctx)
{
    fbRecordValue_t value = FB_RECORD_VALUE_INIT;
    int ret;

    MD_UNUSED_PARAM(flags);

    /* FIXME: Replace fbRecordValue_t with some other type defined within
     * super_mediator. SM should not need to know so much about the internals
     * of fbRecordValue_t. */

    value.ie = field->elem;
    value.stringbuf = g_string_new(flow->collector->name);
    value.v.varfield.buf = (uint8_t *)value.stringbuf->str;
    value.v.varfield.len = value.stringbuf->len;

    ret = callback(flow->fbRec, NULL, field->elem, &value, ctx);
    g_string_free(value.stringbuf, TRUE);

    return ret;
}

int
mdFindAnySIP(
    mdFullFlow_t              *flow,
    mdFieldEntry_t            *field,
    unsigned int               flags,
    fbRecordValueCallback_fn   callback,
    void                      *ctx)
{
    fbInfoModel_t         *md_info_model = mdInfoModel();
    const fbInfoElement_t *fieldIE = NULL;

    MD_UNUSED_PARAM(field);

    if (flow->ipv4) {
        /* sourceIPv4Address */
        fieldIE = fbInfoModelGetElementByID(md_info_model, 8, 0);
        if (NULL == fieldIE) {
            return 0;
        }
        return fbRecordFindAllElementValues(flow->fbRec, fieldIE, flags,
                                            callback, ctx);
    } else {
        /* sourceIPv6Address */
        fieldIE = fbInfoModelGetElementByID(md_info_model, 27, 0);
        if (NULL == fieldIE) {
            return 0;
        }
        return fbRecordFindAllElementValues(flow->fbRec, fieldIE, flags,
                                            callback, ctx);
    }
}

int
mdFindAnyDIP(
    mdFullFlow_t              *flow,
    mdFieldEntry_t            *field,
    unsigned int               flags,
    fbRecordValueCallback_fn   callback,
    void                      *ctx)
{
    fbInfoModel_t         *md_info_model = mdInfoModel();
    const fbInfoElement_t *fieldIE = NULL;

    MD_UNUSED_PARAM(field);

    if (flow->ipv4) {
        /* destinationIPv4Address */
        fieldIE = fbInfoModelGetElementByID(md_info_model, 12, 0);
        if (NULL == fieldIE) {
            return 0;
        }
        return fbRecordFindAllElementValues(flow->fbRec, fieldIE, flags,
                                            callback, ctx);
    } else {
        /* destinationIPv6Address */
        fieldIE = fbInfoModelGetElementByID(md_info_model, 28, 0);
        if (NULL == fieldIE) {
            return 0;
        }
        return fbRecordFindAllElementValues(flow->fbRec, fieldIE, flags,
                                            callback, ctx);
    }
}

int
mdFindDuration(
    mdFullFlow_t              *flow,
    mdFieldEntry_t            *field,
    unsigned int               flags,
    fbRecordValueCallback_fn   callback,
    void                      *ctx)
{
    const fbTemplateField_t *startMillisecondsField;
    const fbTemplateField_t *endMillisecondsField;
    const uint64_t          *startMilliseconds;
    const uint64_t          *endMilliseconds;
    fbRecordValue_t    value = FB_RECORD_VALUE_INIT;

    MD_UNUSED_PARAM(flags);

    if (flow->flowStartMilliseconds) {
        startMilliseconds = &flow->flowStartMilliseconds;
    } else {
        if (flow->intTmplCtx && flow->intTmplCtx->flowStartMS) {
            startMillisecondsField = flow->intTmplCtx->flowStartMS;
        } else {
            startMillisecondsField = (fbTemplateFindFieldByIdent(
                                          flow->intTmpl, 0, 152, NULL, 0));
            if (NULL == startMillisecondsField) {
                return 0;
            }
        }
        startMilliseconds = ((uint64_t *)(flow->fbRec->rec +
                                          fbTemplateFieldGetOffset(
                                              startMillisecondsField)));
    }

    if (flow->intTmplCtx && flow->intTmplCtx->defCtx.dataCTimeIE) {
        endMillisecondsField = flow->intTmplCtx->defCtx.dataCTimeIE;
    } else {
        endMillisecondsField = (fbTemplateFindFieldByIdent(
                                    flow->intTmpl, 0, 153, NULL, 0));
        if (NULL == endMillisecondsField) {
            return 0;
        }
    }
    endMilliseconds = ((uint64_t *)(flow->fbRec->rec +
                                    fbTemplateFieldGetOffset(
                                        endMillisecondsField)));
    value.ie = field->elem;
    value.v.u64 = (*endMilliseconds - *startMilliseconds);

    return callback(flow->fbRec, NULL, field->elem, &value, ctx);
}

const char *
mdUtilDebugTemplateContentsYafVersion(
    mdUtilTCYafVersion_t   yaf)
{
    switch (yaf) {
      case TC_YAF_ALL_VERSIONS:
        return NULL;
      case TC_YAF_VERSION_2:
        return "YAF_V2";
      case TC_YAF_VERSION_3:
        return "YAF_V3";
    }

    return NULL;
}

const char *
mdUtilDebugExportFormat(
    mdExportFormat_t   expFormat)
{
    switch (expFormat) {
      case EF_NONE:
        return "NONE";
      case EF_IPFIX:
        return "IPFIX";
      case EF_JSON:
        return "JSON";
      case EF_TEXT:
        return "TEXT";
    }

    return NULL;
}

const char *
mdUtilDebugExportMethod(
    mdExportMethod_t   expMethod)
{
    switch (expMethod) {
      case EM_NONE:
        return "NONE";
      case EM_SINGLE_FILE:
        return "SINGLE FILE";
      case EM_ROTATING_FILES:
        return "ROTATING FILES";
      case EM_TCP:
        return "TCP";
      case EM_UDP:
        return "UDP";
    }

    return NULL;
}

const char *
mdUtilDebugCollectionMethod(
    mdCollectionMethod_t   colMethod)
{
    switch (colMethod) {
      case CM_NONE:
        return "NONE";
      case CM_SINGLE_FILE:
        return "SINGLE FILE";
      case CM_DIR_POLL:
        return "DIRECTORY POLL";
      case CM_TCP:
        return "TCP";
      case CM_UDP:
        return "UDP";
    }

    return NULL;
}


gboolean
mdExporterCheckSSLConfig(
    mdExporter_t  *exporter,
    unsigned int   obj_id,
    uint8_t        type)
{
    /* if no config at all, return TRUE.  otherwise, only true when the
     * 'obj_id' is set for 'type' */

    if (NULL == exporter->ssl_config) {
        return TRUE;
    }
    return ((type <= MD_SSLCONFIG_TYPE_MAX) &&
            (obj_id < mdSSLConfigArraySize[type]) &&
            (exporter->ssl_config->enabled[type] != NULL) &&
            (exporter->ssl_config->enabled[type][obj_id] != 0));
}


#ifdef ENABLE_SKIPSET
/*
 *  Maps IPSet pathname to an mdIPSet_t, where the pathname is contained on
 *  the mdIPSet_t object.
 */
static GHashTable *md_ipset_table;
static pthread_mutex_t md_ipset_table_mutex = PTHREAD_MUTEX_INITIALIZER;

mdIPSet_t *
mdUtilIPSetOpen(
    const char     *path,
    GError        **err)
{
    mdIPSet_t *ipset;
    ssize_t rv;

    pthread_mutex_lock(&md_ipset_table_mutex);

    if (!app_registered) {
        skAppRegister(g_get_prgname());
        ++app_registered;
    }

    if (!md_ipset_table) {
        md_ipset_table = g_hash_table_new(g_str_hash, g_str_equal);
    } else if ((ipset = (mdIPSet_t *)g_hash_table_lookup(md_ipset_table, path))
               != NULL)
    {
        /* pthread_mutex_lock(&ipset->mutex); */
        ++ipset->ref;
        /* pthread_mutex_unlock(&ipset->mutex); */
        pthread_mutex_unlock(&md_ipset_table_mutex);
        return ipset;
    }

    ipset = g_slice_new0(mdIPSet_t);
    rv = skIPSetLoad(&ipset->ipset, path);
    if (SKIPSET_OK != rv) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Unable to load IPSet '%s': %s",
                    path, skIPSetStrerror(rv));
        g_slice_free(mdIPSet_t, ipset);
        pthread_mutex_unlock(&md_ipset_table_mutex);
        return NULL;
    }

    ++ipset->ref;
    ipset->path = g_strdup(path);
    /* pthread_mutex_init(&ipset->mutex, NULL); */
    g_hash_table_insert(md_ipset_table, (gpointer)ipset->path, (gpointer)ipset);
    pthread_mutex_unlock(&md_ipset_table_mutex);
    return ipset;
}

void
mdUtilIPSetClose(
    mdIPSet_t      *ipset)
{
    if (NULL == ipset) {
        return;
    }
    pthread_mutex_lock(&md_ipset_table_mutex);
    /* pthread_mutex_lock(&ipset->mutex); */
    if (ipset->ref > 1) {
        --ipset->ref;
        /* pthread_mutex_unlock(&ipset->mutex); */
        pthread_mutex_unlock(&md_ipset_table_mutex);
        return;
    }
    if (ipset->ref == 0) {
        /* pthread_mutex_unlock(&ipset->mutex); */
        pthread_mutex_unlock(&md_ipset_table_mutex);
        return;
    }
    ipset->ref = 0;

    g_hash_table_remove(md_ipset_table, (gpointer)ipset->path);

    skIPSetDestroy(&ipset->ipset);
    g_free(ipset->path);
    /* pthread_mutex_unlock(&ipset->mutex); */
    /* pthread_mutex_destroy(&ipset->mutex); */
    g_slice_free(mdIPSet_t, ipset);

    pthread_mutex_unlock(&md_ipset_table_mutex);
}
#endif  /* ENABLE_SKIPSET */
