/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_util.h
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

#ifndef _MEDIATOR_UTIL_H
#define _MEDIATOR_UTIL_H

#include <stdlib.h>
#include <stdint.h>
#include <glib.h>
#include <time.h>
#include <fixbuf/public.h>
#include "mediator_structs.h"


/*
 *  Appends the fbInfoElementSpec_t array `specArray_` to `tmpl_` using
 *  `flags_`.  Aborts the program on error.
 */
#define mdTemplateAppendSpecArray(tmpl_, specArray_, flags_)            \
    do {                                                                \
        GError *err_ = NULL;                                            \
        if (!fbTemplateAppendSpecArray(                                 \
                tmpl_, specArray_, flags_, &err_))                      \
        {                                                               \
            mdAbortTemplateAppendSpecArray(                             \
                tmpl_, specArray_, flags_, err_, __FILE__, __LINE__);   \
        }                                                               \
    } while (0)

/*
 *  Appends a single fbInfoElementSpec_t `infoSpec_` to `tmpl_` using
 *  `flags_`.  Aborts the program on error.
 */
#define mdTemplateAppendOneSpec(tmpl_, infoSpec_, flags_)               \
    do {                                                                \
        GError *err_ = NULL;                                            \
        if (!fbTemplateAppendSpec(                                      \
                tmpl_, infoSpec_, flags_, &err_))                       \
        {                                                               \
            fbInfoElementSpec_t array[2];                               \
            array[0] = *infoSpec_;                                      \
            memset(&array[1], 0, sizeof(array[1]));                     \
            mdAbortTemplateAppendSpecArray(                             \
                tmpl_, array, flags_, err_, __FILE__, __LINE__);        \
        }                                                               \
    } while (0)

/*
 *  Appends the fbInfoElementSpecId_t array `idSpecArray_` to `tmpl_` using
 *  `flags_`.  Aborts the program on error.
 */
#define mdTemplateAppendArraySpecId(tmpl_, idSpecArray_, flags_)        \
    do {                                                                \
        GError *err_ = NULL;                                            \
        if (!fbTemplateAppendArraySpecId(                               \
                tmpl_, idSpecArray_, flags_, &err_))                    \
        {                                                               \
            mdAbortTemplateAppendArraySpecId(                           \
                tmpl_, idSpecArray_, flags_, err_, __FILE__, __LINE__); \
        }                                                               \
    } while (0)

/*
 *  Appends a single fbInfoElementSpecId_t `infoSpecId_` to `tmpl_` using
 *  `flags_`.  Aborts the program on error.
 */
#define mdTemplateAppendOneSpecId(tmpl_, infoSpecId_, flags_)           \
    do {                                                                \
        GError *err_ = NULL;                                            \
        if (!fbTemplateAppendSpecId(                                    \
                tmpl_, infoSpecId_, flags_, &err_))                     \
        {                                                               \
            fbInfoElementSpecId_t array[2];                             \
            array[0] = *infoSpecId_;                                    \
            memset(&array[1], 0, sizeof(array[1]));                     \
            mdAbortTemplateAppendArraySpecId(                           \
                tmpl_, array, flags_, err_, __FILE__, __LINE__);        \
        }                                                               \
    } while (0)


/*
 *  Adds fbTemplate_t `tmpl_` to fbSession_t `sess_` with ID `tid_` as either
 *  internal or export according to `isInt_` with associated fbTemplateInfo_t
 *  `tinfo_` and returns the template id.  Aborts the program on error.
 */
#define mdSessionAddTemplate(sess_, isInt_, tid_, tmpl_, tinfo_) \
    mdSessionAddTemplateHelper(sess_, isInt_, tid_, tmpl_,       \
                               tinfo_, __FILE__, __LINE__)

/*
 *  Helper for mdSessionAppendTemplate() that adds `tmpl` to `session` with ID
 *  `tid` as either internal or external (export) according to `isInternal`,
 *  and assigns it TemplateInfo `mdInfo`. On error, creates an error message
 *  and calls g_error() to abort the program.
 */
uint16_t
mdSessionAddTemplateHelper(
    fbSession_t        *session,
    gboolean            isInternal,
    uint16_t            tid,
    fbTemplate_t       *tmpl,
    fbTemplateInfo_t   *mdInfo,
    const char         *filename,
    int                 linenum);

/*
 *  Helper for mdTemplateAppendSpecArray() and mdTemplateAppendOneSpec() that
 *  creates an error message and calls g_error() to abort the program.
 */
void
mdAbortTemplateAppendSpecArray(
    fbTemplate_t               *tmpl,
    const fbInfoElementSpec_t  *specArray,
    uint32_t                    flags,
    GError                     *err,
    const char                 *filename,
    int                         linenum);

/*
 *  Helper for mdTemplateAppendArraySpecId() and mdTemplateAppendOneSpecId()
 *  that creates an error message and calls g_error() to abort the program.
 */
void
mdAbortTemplateAppendArraySpecId(
    fbTemplate_t                   *tmpl,
    const fbInfoElementSpecId_t    *idSpecArray,
    uint32_t                        flags,
    GError                         *err,
    const char                     *filename,
    int                             linenum);


void
templateCtxFree(
    void  *tmpl_ctx,
    void  *app_ctx);

mdDefaultTmplCtx_t *
templateCtxCopy(
    mdDefaultTmplCtx_t  *origCtx,
    fbTemplate_t        *newTmpl);

typedef struct smVarHashKey_st {
    size_t    len;
    uint8_t  *val;
} smVarHashKey_t;

typedef struct md_asn_tlv_st {
    uint8_t   class : 2;
    uint8_t   p_c   : 1;
    uint8_t   tag   : 5;
} md_asn_tlv_t;

#ifdef ENABLE_SKIPSET
/* A wrapper over the SiLK IPSet structure to avoid opening the same file
 * multiple times. */
typedef struct mdIPSet_st {
    skipset_t          *ipset;
    gchar              *path;
    /* pthread_mutex_t     mutex; */
    unsigned int        ref;
} mdIPSet_t;
#endif  /* ENABLE_SKIPSET */


/*
 *  Format `src` as a space-separated sequence of 2-hexadecimal-digit numbers
 *  and append to `str`; for example ""01 02 03 04"
 */
int
md_util_hexdump_append(
    GString        *str,
    const uint8_t  *src,
    size_t          len);

/*
 *  Format `src` as a hexadecimal number with a leading 0x prefix and append
 *  to `str`; for example "0x01020304".
 */
int
md_util_hexdump_append_nospace(
    GString        *str,
    const uint8_t  *src,
    size_t          len);

/**
 *  Format `hash`->buf as a colon-separated sequence of 2-hexadecimal-digit
 *  numbers and append to `str`; for example "01:02:03:04".
 */
void
mdUtilAppendColonSeparatedHash(
    GString            *str,
    const fbVarfield_t *hash);

/**
 *  Format `hash`->buf as a sequence of 2-hexadecimal-digit numbers and append
 *  to `str` with nothing between the numbers; for example "01020304".
 */
void
mdUtilAppendHash(
    GString            *str,
    const fbVarfield_t *hash);

/*
 *  Format `buf` in the style of the `hexdump -C` utility, prefixing each line
 *  with `lpfx`.
 */
void
md_util_hexdump_append_block(
    GString        *str,
    const char     *lpfx,
    const uint8_t  *buf,
    uint32_t        len);

void
md_util_print_tcp_flags(
    GString  *str,
    uint64_t  flags,
    gboolean  quoted);

void
md_util_print_ip6_addr(
    char           *ipaddr_buf,
    const uint8_t  *ipaddr);

void
md_util_print_ip4_addr(
    char      *ipaddr_buf,
    uint32_t   ip);

uint32_t
md_util_flow_key_hash(
    const mdFullFlow_t *flow);

uint32_t
md_util_rev_flow_key_hash(
    const mdFullFlow_t *flow);

/**
 *  Formats a UNIX millisecond timestamp as "%Y-%m-%d %H:%M:%s.%03d" and
 *  appends it to `str`.
 */
void
md_util_millitime_append(
    GString        *str,
    uint64_t        millitime);

/**
 *  Formats the timespec as "%Y-%m-%d %H:%M:%s.%03d" and appends it to `str`.
 */
void
md_util_timespec_append(
    GString                *str,
    const struct timespec  *tspec);

/**
 *    Flag to specify how md_util_time_append() should format the time.
 */
typedef enum md_time_fmt_en {
    /* "%Y-%m-%d %H:%M:%S" */
    MD_TIME_FMT_ISO,
    /* "%Y%m%d%H%M%S" */
    MD_TIME_FMT_YMDHMS
} md_time_fmt_t;

/**   printf() format string for MD_TIME_FMT_ISO */
#define MD_TIME_FORMAT_ISO      "%04u-%02u-%02u %02u:%02u:%02u"
/**   printf() format string for MD_TIME_FMT_YMDHMS */
#define MD_TIME_FORMAT_YMDHMS   "%04u%02u%02u%02u%02u%02u"

/**
 *  Formats a UNIX epoch time according to `fmt` and appends it to `str`.
 */
void
md_util_time_append(
    GString        *str,
    time_t          c_time,
    md_time_fmt_t   fmt);

/**
 *  Parses an fbVarfield_t holding an X.509 validity date and stores the
 *  result in a time_t.  Returns TRUE on success or FALSE on failure.  A
 *  zero-length string is considered a failure.
 *
 *  The varfield is expected to contain either 13 or 15 characters, in the
 *  form "YYMMDDHHMMSSZ" or "YYYYMMDDHHMMSSZ".
 *
 *  Note that "99991231235959Z", the value designated as "no meaningful end
 *  date" (such as for a certificate bound to a piece of hardware; see RFC5280
 *  Sec 4.1.2.5), is not handled in any special way by this function, and sets
 *  `t` to 253_402_300_799.
 */
gboolean
mdUtilParseValidityDate(
    const fbVarfield_t *validity,
    time_t             *t);

uint16_t
md_util_decode_asn1_length(
    uint8_t **buffer,
    size_t   *len);

uint16_t
md_util_decode_asn1_sequence(
    uint8_t **buffer,
    size_t   *len);

gboolean
mdUtilAppendDecodedOID(
    GString            *str,
    const fbVarfield_t *oid);

void *
detachFromEndOfDLL(
    mdDLL_t **head,
    mdDLL_t **tail);

void
detachThisEntryOfDLL(
    mdDLL_t **head,
    mdDLL_t **tail,
    mdDLL_t  *entry);

void
attachHeadToDLL(
    mdDLL_t **head,
    mdDLL_t **tail,
    mdDLL_t  *newEntry);

guint
sm_octet_array_hash(
    gconstpointer   v);

gboolean
sm_octet_array_equal(
    gconstpointer   v1,
    gconstpointer   v2);

void
sm_octet_array_key_destroy(
    gpointer   data);

smVarHashKey_t *
sm_new_hash_key(
    uint8_t  *val,
    size_t    len);

/**
 *  Writes the contents of `buf` to `fp` and, if successful, truncates `buf`
 *  to zero length and returns the number of bytes written.
 *
 *  On error sets `err`, leaves `buf` unchanged, and returns 0.  The parameter
 *  `exp_name` is only used when reporting an error.
 *
 *  If `buf` has length 0 when this function is called, the function returns 0
 *  but does not set `err`.
 */
size_t
md_util_write_buffer(
    FILE         *fp,
    GString      *buf,
    const char   *exp_name,
    GError      **err);

gboolean
md_util_append_buffer(
    GString        *str,
    const uint8_t  *var,
    size_t          len);

gboolean
md_util_append_varfield(
    GString             *str,
    const fbVarfield_t  *var);


uint16_t
md_util_decode_length(
    uint8_t   *buffer,
    uint16_t  *offset);

uint16_t
md_util_decode_tlv(
    md_asn_tlv_t  *tlv,
    uint8_t       *buffer,
    uint16_t      *offset);

uint8_t
md_util_asn1_sequence_count(
    uint8_t   *buffer,
    uint16_t   seq_len);

void
md_util_compress_file(
    const char  *file,
    const char  *dest);

smHashTable_t *
smCreateHashTable(
    size_t           length,
    GDestroyNotify   freeKeyfn,
    GDestroyNotify   freeValfn);

gpointer
smHashLookup(
    smHashTable_t  *table,
    uint8_t        *key);

void
smHashTableInsert(
    smHashTable_t  *table,
    uint8_t        *key,
    uint8_t        *value);

void
smHashTableFree(
    smHashTable_t  *table);

void
smHashTableRemove(
    smHashTable_t  *table,
    uint8_t        *key);

uint32_t
smFieldMapTranslate(
    smFieldMap_t  *map,
    mdFullFlow_t  *flow);

void
md_free_hash_key(
    gpointer   v1);

GString *
sm_util_move_file(
    const char  *file,
    const char  *new_dir);

/**
 *  Determines the type of `tmpl` and fills `templateContents` with additional
 *  information about the template. Returns the template type.
 *
 *  @param tmpl              The template to examine
 *  @param tid               The ID of `tmpl` in the current session
 *  @param mdInfo            The metadata for `tmpl` from the current session
 *  @param templateContents  The contents to be filled
 *  @return                  The type of `tmpl`
 */
mdUtilTemplateType_t
mdUtilExamineTemplate(
    const fbTemplate_t         *tmpl,
    uint16_t                    tid,
    const fbTemplateInfo_t     *mdInfo,
    mdUtilTemplateContents_t   *templateContents);

void
mdUtilUpdateKnownTemplates(
    const GString                  *name,
    const mdUtilTemplateContents_t  tc,
    uint16_t                        tid,
    mdKnownTemplates_t             *knownTids);

uint16_t
mdUtilGetIEOffset(
    const fbTemplate_t *tmpl,
    uint32_t            ent,
    uint16_t            num);

uint16_t
mdUtilNumPaddingIEsInTmpl(
    fbTemplate_t  *tmpl);

mdUtilTCRelative_t
mdUtilDetermineRelative(
    const fbTemplate_t *inTmpl,
    const fbTemplate_t *globalTmpl);

/* DEBUG TEMPLATE INFORMATION */
const char *
mdUtilDebugTemplateType(
    mdUtilTemplateType_t   tt);

/* delivers a complete string */
/* uses a gstring as it needs to be built in pieces */
GString *
mdUtilDebugTemplateContents(
    const mdUtilTemplateContents_t  tc);

const char *
mdUtilDebugTemplateContentsGeneral(
    mdUtilTCGeneral_t   gen);

const char *
mdUtilDebugTemplateContentsSpecCase(
    mdUtilTCGeneral_t    gen,
    mdUtilTCSpecCase_t   specCase);

const char *
mdUtilDebugSpecCaseFlow(
    mdUtilTCSpecCase_t   specCase);

const char *
mdUtilDebugSpecCaseDnsDedup(
    mdUtilTCSpecCase_t   specCase);

const char *
mdUtilDebugSpecCaseDnsRR(
    mdUtilTCSpecCase_t   specCase);

const char *
mdUtilDebugSpecCaseYafStats(
    mdUtilTCSpecCase_t   specCase);

const char *
mdUtilDebugSpecCaseTombstone(
    mdUtilTCSpecCase_t   specCase);

const char *
mdUtilDebugSpecCaseDPI(
    mdUtilTCSpecCase_t   specCase);

const char *
mdUtilDebugTemplateContentsRelative(
    mdUtilTCRelative_t   rel);

const char *
mdUtilDebugTemplateContentsYafVersion(
    mdUtilTCYafVersion_t   yaf);

/* DEBUG COL/EXP INFO */

const char *
mdUtilDebugExportFormat(
    mdExportFormat_t   expFormat);

const char *
mdUtilDebugExportMethod(
    mdExportMethod_t   expMethod);

const char *
mdUtilDebugCollectionMethod(
    mdCollectionMethod_t   colMethod);

gboolean
mdExporterCheckSSLConfig(
    mdExporter_t  *exporter,
    unsigned int   obj_id,
    uint8_t        type);

guint
sm_fixed_hash12(
    gconstpointer   v);

gboolean
sm_fixed_equal12(
    gconstpointer   v1,
    gconstpointer   v2);

fbTemplate_t *
mdUtilMakeSslFlatCertTmpl(
    const fbTemplate_t         *srcTmpl,
    const fbInfoElementSpec_t  *addlSpecs,
    uint32_t                    addlSpecFlags,
    GError                    **err);

int
mdUtilFlattenOneSslCertificate(
    const fbRecord_t           *origRecord,
    fbRecord_t                 *flatRecord,
    const mdDefaultTmplCtx_t   *origRecTmplCtx,
    GError                    **err);


gboolean
mdUtilParseIP(
    fbRecordValue_t  *out_val,
    const char       *ip_string,
    gboolean         *isV6,
    GError          **err);

void
mdNtptimeToTimespec(
    const void               *ntptime,
    struct timespec          *ts,
    fbInfoElementDataType_t   datatype);

int
mdFieldEntryFindAllElementValues(
    mdFullFlow_t              *flow,
    mdFieldEntry_t            *field,
    unsigned int               flags,
    fbRecordValueCallback_fn   callback,
    void                      *ctx);

int
mdFindFlowKeyHash(
    mdFullFlow_t              *flow,
    mdFieldEntry_t            *field,
    unsigned int               flags,
    fbRecordValueCallback_fn   callback,
    void                      *ctx);

int
mdFindAnySIP(
    mdFullFlow_t              *flow,
    mdFieldEntry_t            *field,
    unsigned int               flags,
    fbRecordValueCallback_fn   callback,
    void                      *ctx);

int
mdFindAnyDIP(
    mdFullFlow_t              *flow,
    mdFieldEntry_t            *field,
    unsigned int               flags,
    fbRecordValueCallback_fn   callback,
    void                      *ctx);

int
mdFindDuration(
    mdFullFlow_t              *flow,
    mdFieldEntry_t            *field,
    unsigned int               flags,
    fbRecordValueCallback_fn   callback,
    void                      *ctx);

int
mdFindCollector(
    mdFullFlow_t              *flow,
    mdFieldEntry_t            *field,
    unsigned int               flags,
    fbRecordValueCallback_fn   callback,
    void                      *ctx);

#ifdef ENABLE_SKIPSET
/**
 *  Returns an object holding the SiLK IPSet file read from `path`.
 *
 *  If the IPSet at `path` was already opened, that object's reference count
 *  is incremented and it is returned.  Otherwise the IPSet file is loaded, a
 *  new mdIPSet_t object is created and returned.
 *
 *  Uses a simple string match when comparing values of `path`.
 *
 *  @param path   The path of the IPSet file to open.
 *  @param err    An err reference set if the file cannot be opened as a set.
 */
mdIPSet_t *
mdUtilIPSetOpen(
    const char     *path,
    GError        **err);

/**
 *  Decreases the reference count of `ipset`.  Deletes the in-memory IPset and
 *  the mdIPSet_t object if the reference count gets to zero.
 */
void
mdUtilIPSetClose(
    mdIPSet_t      *ipset);
#endif  /* ENABLE_SKIPSET */

#endif /* _MEDIATOR_UTIL_H */
