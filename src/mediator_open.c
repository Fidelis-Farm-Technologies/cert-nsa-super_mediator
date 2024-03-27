/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_open.c
 *
 *  All IPFIX collector functionality
 *
 *  this file is responsible for collecting incoming records and distributing
 *  them to the right processing function(s)
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


/*RFC 1950 */
#define ZLIB_HEADER 0x9C78
/* RFC 1952 */
#define GZIP_HEADER 0x8B1F
#define SM_CHUNK 16384

#include "mediator_autohdr.h"
#include "mediator_inf.h"
#include "mediator_core.h"
#include "mediator_filter.h"
#include "templates.h"
#include "specs.h"
#include "infomodel.h"
#include <sys/time.h>
#include <errno.h>
#include "mediator_stat.h"

#ifdef SM_ENABLE_ZLIB
#include <zlib.h>
#endif

/* convert a timespec (epoch seconds and nanosec) to epoch millisec */
#define TIMESPEC_TO_MILLI(tspec)                        \
    ((tspec.tv_sec * 1000) + (tspec.tv_nsec / 1000000))

static pthread_mutex_t global_listener_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_cond_t global_listener_cond = PTHREAD_COND_INITIALIZER;

static unsigned int num_collectors = 0;

static void
mdfBufFree(
    mdCollector_t     *collector)
{
    fBufFree(collector->fbuf);
    collector->fbuf = NULL;
    collector->session = NULL;
    collector->collector = NULL;
}


void
mdInterruptListeners(
    mdConfig_t        *cfg)
{
    mdCollector_t      *collector = NULL;

    /* send interrupt signal to all active listeners */
    for (collector = cfg->firstCol; collector; collector = collector->next) {
        if (collector->active) {
            if (collector->listener) {
                fbListenerInterrupt(collector->listener);
                pthread_cond_signal(&collector->cond);
            }
        }
    }
    pthread_cond_signal(&global_listener_cond);
}

mdCollector_t *
mdNewCollector(
    mdCollectionMethod_t    collectionMethod,
    const char             *name)
{
    mdCollector_t      *collector = NULL;

    if (UINT8_MAX == num_collectors) {
        g_warning("Maximum number of collectors reached");
        return NULL;
    }

    collector = g_slice_new0(mdCollector_t);

    /* collection method is tcp, udp, single file, or poll directory */
    collector->collectionMethod = collectionMethod;

    if (collectionMethod == CM_DIR_POLL) {
        collector->pollingInterval = DEFAULT_POLLING_INTERVAL;
    }

    /* if it's TCP or UDP, build up the connspec */
    if (collectionMethod == CM_TCP) {
        collector->connspec.transport = FB_TCP;
    } else if (collectionMethod == CM_UDP) {
        collector->connspec.transport = FB_UDP;
    }

    num_collectors++;
    collector->id = num_collectors;
    if (name) {
        collector->name = g_strdup(name);
    } else {
        collector->name = g_strdup_printf("C%d", collector->id);
    }

    return collector;
}

#if 0
/* set that there is a timestamp field of some kind */
static void
mdCollectorHasTimestampField(
    mdCollector_t      *collector)
{
    collector->hasTimestampField = TRUE;
}
#endif  /* 0 */

/* set that the collector has a timestamp field that's in the data itself */
void
mdCollectorHasDataTimestampField(
    mdCollector_t      *collector)
{
    collector->hasTimestampField = TRUE;
    collector->hasDataTimestampField = TRUE;
}

/* set that the collector has a timestamp field of clock time from an earlier
 * tool in the processing chain */
void
mdCollectorHasSourceRuntimeTimestampField(
    mdCollector_t      *collector)
{
    collector->hasTimestampField = TRUE;
    collector->hasSourceRuntimeTimestampField = TRUE;
}

/* update max record size for this collecor due to the new template
 * if max is bigger than before, set it, and reallocate the buffer used to store
 * records so they'll all fit */
void
mdCollectorUpdateMaxRecord(
    mdCollector_t      *collector)
{
    uint16_t    newMaxSize =
        fbSessionGetLargestInternalTemplateSize(collector->session) + 100;

    if (newMaxSize > collector->largestRecTemplateSize) {
        collector->largestRecTemplateSize = newMaxSize;
        collector->recBuf = g_realloc(collector->recBuf,
                                      collector->largestRecTemplateSize);
    }
}

#ifdef SM_ENABLE_ZLIB
/*
 *  Uncompress the open file 'src', named 'input_file', to a temporary file
 *  and return a FILE pointer to the uncompressed data.  Use 'tmp_dir_path' as
 *  the temporary directory, else TMPDIR, else /tmp.
 */
static FILE *
mdFileDecompress(
    FILE *src,
    const char *input_file,
    const char *tmp_dir_path)
{
    int ret;
    z_stream strm;
    unsigned int leftover;
    unsigned char in[SM_CHUNK];
    unsigned char out[SM_CHUNK];
    FILE *dst = NULL;
    int fd;
    char tmpname[SM_CHUNK];
    char temp_suffix[] = ".XXXXXX";

    /*allocate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    if (tmp_dir_path) {
        snprintf(tmpname, SM_CHUNK, "%s/sm_def_tmp%s", tmp_dir_path,
                 temp_suffix);
    } else if (getenv("TMPDIR")) {
        const char *env = getenv("TMPDIR");
        snprintf(tmpname, SM_CHUNK, "%s/sm_def_tmp%s", env, temp_suffix);
    } else {
        snprintf(tmpname, SM_CHUNK, "/tmp/sm_def_tmp%s", temp_suffix);
    }

    g_debug("Input file \"%s\" is compressed, attempting decompression",
            input_file);

    fd = mkstemp(tmpname);
    if (fd == -1) {
        g_warning("Unable to open decompression tmp file '%s': %s",
                  tmpname, strerror(errno));
        return NULL;
    } else {
        dst = fdopen(fd, "wb+");
        if (!dst) {
            g_warning("Unable to open decompression tmp file '%s': %s",
                      tmpname, strerror(errno));
            return NULL;
        }
    }

    ret = inflateInit2(&strm, 16+MAX_WBITS);
    if (ret != Z_OK) {
        return NULL;
    }
    do {
        strm.avail_in = fread(in, 1, SM_CHUNK, src);
        if (ferror(src)) {
            (void)inflateEnd(&strm);
            return NULL;
        }

        if (strm.avail_in == 0) {
            break;
        }
        strm.next_in = in;

        do {
            strm.avail_out = SM_CHUNK;
            strm.next_out = out;

            ret = inflate(&strm, Z_NO_FLUSH);
            if (ret == Z_STREAM_ERROR) { return NULL; }
            leftover = SM_CHUNK - strm.avail_out;
            if (fwrite(out, 1, leftover, dst) != leftover || ferror(dst)) {
                (void)inflateEnd(&strm);
                return NULL;
            }
        } while(strm.avail_out == 0);

    } while (ret != Z_STREAM_END);

    (void)inflateEnd(&strm);

    rewind(dst);
    unlink(tmpname);

    return dst;
}
#endif  /* SM_ENABLE_ZLIB */

gboolean
mdCollectorSetInSpec(
    mdCollector_t          *collector,
    const char             *inspec,
    GError                **err)
{
    if (collector->inspec) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "The Collector has already been assigned the input \"%s\"",
                    collector->inspec);
        return FALSE;
    }
    collector->inspec = g_strdup(inspec);

    if (COLLMETHOD_IS_SOCKET(collector->collectionMethod)) {
        collector->connspec.host = collector->inspec;

    } else if (CM_DIR_POLL == collector->collectionMethod) {
        if (!g_file_test(inspec, G_FILE_TEST_IS_DIR)) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "DIRECTORY_POLL Collector uses"
                        " nonexistent directory \"%s\"",
                        inspec);
            return FALSE;
        }

    } else if (collector->collectionMethod != CM_SINGLE_FILE) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Unexpected value for collection method (%d)",
                    collector->collectionMethod);
        return FALSE;

    } else if (0 == g_strcmp0("-", inspec)) {
        if (isatty(fileno(stdin))) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Refusing to read from terminal on stdin");
            return FALSE;
        }
    }

    return TRUE;
}

gboolean
mdCollectorSetPollingInterval(
    mdCollector_t          *collector,
    int                     pollingInterval,
    GError                **err)
{
    if (collector->collectionMethod != CM_DIR_POLL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "May not set polling interval on a"
                    " non directory poll collector");
        return FALSE;
    }
    if (pollingInterval < 1 || pollingInterval > UINT16_MAX) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Invalid polling interval %d: Valid range is 1-65535",
                    pollingInterval);
        return FALSE;
    }
    collector->pollingInterval = (uint16_t)pollingInterval;
    return TRUE;
}

/*
 * called by both config parser and command line
 * sets the directory to move files to for DIR_POLL collectors
 * Copies `move_dir`.
 */
gboolean
mdCollectorSetMoveDir(
    mdCollector_t          *collector,
    const char             *move_dir,
    GError                **err)
{
    if (collector->collectionMethod != CM_DIR_POLL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "May not set move on a non directory poll collector");
        return FALSE;
    }
    if (!g_file_test(move_dir, G_FILE_TEST_IS_DIR)) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Path for move is not a valid directory: \"%s\"", move_dir);
        return FALSE;
    }

    g_free(collector->move_dir);
    collector->move_dir = g_strdup(move_dir);
    return TRUE;
}

void
mdCollectorSetNoLockedFilesMode(
    mdCollector_t          *collector)
{
    collector->noLockedFiles = TRUE;
}

gboolean
mdCollectorSetPort(
    mdCollector_t      *collector,
    const char         *port,
    GError            **err)
{
    int p = atoi(port);

    if (!COLLMETHOD_IS_SOCKET(collector->collectionMethod)) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Collector port only valid for TCP or UDP collectors");
        return FALSE;
    }
    if (p < 1024 || p > UINT16_MAX) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Invalid Port %s. Valid range of Collector listening port "
                    "is 1024-65535", port);
        return FALSE;
    }
    if (collector->connspec.svc) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "The Collector has already been assigned the port %s",
                    collector->connspec.svc);
        return FALSE;
    }
    collector->connspec.svc = g_strdup(port);
    return TRUE;
}

const char *
mdCollectorGetName(
    const mdCollector_t    *collector)
{
    return collector->name;
}

gboolean
mdCollectorSetDecompressWorkingDir(
    mdCollector_t      *collector,
    const char         *path,
    GError            **err)
{
    if (COLLMETHOD_IS_SOCKET(collector->collectionMethod)) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "A decompression path is only allowed with file"
                    " and directory-based collectors");
        return FALSE;
    }
    if (!g_file_test(path, G_FILE_TEST_IS_DIR)) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Decompression path is not a directory \"%s\"", path);
        return FALSE;
    }

    g_free(collector->decompressWorkingDirectory);
    collector->decompressWorkingDirectory = g_strdup(path);
    return TRUE;
}

uint8_t
mdCollectorGetID(
    const mdCollector_t    *collector)
{
    return collector->id;
}

gboolean
mdCollectorSetDeleteFiles(
    mdCollector_t      *collector,
    gboolean            delete,
    GError            **err)
{
    if (collector->collectionMethod != CM_DIR_POLL) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Delete files only valid for directory polling collectors");
        return FALSE;
    }
    collector->delete_files = delete;
    return TRUE;
}

/* generally ensure things are constructed for processing */
gboolean
mdCollectorVerifySetup(
    mdCollector_t      *collector,
    GError            **err)
{
    switch (collector->collectionMethod) {
      case CM_UDP:
      case CM_TCP:
        /* sockets needs a port to listen on */
        if (!collector->connspec.svc) {
            collector->connspec.svc = g_strdup(MD_DEFAULT_LISTEN_PORT);
        }
        break;
      case CM_SINGLE_FILE:
        /* a single file needs a file path */
        if (collector->inspec == NULL) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "No input specificier given");
            return FALSE;
        }
        break;
      case CM_DIR_POLL:
        /* a directory poller needs a directory, and move or delete */
        if (collector->inspec == NULL) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "No input specificier given");
            return FALSE;
        }
        if (!g_file_test(collector->inspec, G_FILE_TEST_IS_DIR)) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Path for directory poll collector "
                        "is not a directory: \"%s\"", collector->inspec);
            return FALSE;
        }
        if (0 == collector->pollingInterval) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Polling interval is zero");
            return FALSE;
        }
        if (!collector->move_dir && !collector->delete_files) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Error: Either MOVE or DELETE must be present "
                        "in DIRECTORY COLLECTOR block");
            return FALSE;
        }
        break;
      case CM_NONE:
      default:
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "Error: No collection method set");
        return FALSE;
    }

    /* make a default collector name of C1, C2, etc */
    if (!collector->name) {
        collector->name = g_strdup_printf("C%d", collector->id);
    }

    return TRUE;
}


/**
 *  Add the tombstone templates to the internal session.
 *
 *  Perhaps this should use an arbitrary high TID.
 */
static void
mdCollectorAddTombstoneTemplates(
    mdCollector_t      *collector)
{
    fbTemplate_t     *tmpl;
    uint16_t          tid;

    /* Only the access list template is needed so the STL can be transcoded to
     * the template that will be used for export, saving the exporter from
     * having to do this. */

#if 0
    /* main tombstone template */
    tmpl = fbTemplateAlloc(fbSessionGetInfoModel(collector->session));
    mdTemplateAppendSpecArray(tmpl, mdEmSpecTombstoneMainV2, 0);
    fbTemplateSetOptionsScope(tmpl, MD_TOMBSTONE_MAIN_SCOPE);
    tid = mdSessionAddTemplate(collector->session, TRUE, MD_TOMBSTONE_MAIN_TID,
                               tmpl, NULL);
    collector->tombstoneMainTid = tid;
#endif  /* 0 */

    /* tombstone access list template */
    tmpl = fbTemplateAlloc(fbSessionGetInfoModel(collector->session));
    mdTemplateAppendSpecArray(tmpl, mdEmSpecTombstoneAccessV2, 0);
#if MD_TOMBSTONE_ACCESS_SCOPE > 0
    fbTemplateSetOptionsScope(tmpl, MD_TOMBSTONE_ACCESS_SCOPE);
#endif
    tid = mdSessionAddTemplate(collector->session, TRUE,
                               MD_TOMBSTONE_ACCESS_TID, tmpl, NULL);
    collector->tombstoneAccessTid = tid;
}


/** druef-new
 * mdCollectorCreateSession
 * gets info model
 * allocates session
 * sets callback
 * attaches session to collector
 **/
static void
mdCollectorCreateSession(
    mdCollector_t      *collector)
{
    fbInfoModel_t  *model = mdInfoModel();

    if (collector->session) {
        pthread_mutex_lock(&(collector->cfg->log_mutex));
        g_warning("already have session in init collector session");
        pthread_mutex_unlock(&(collector->cfg->log_mutex));
        return;
    }

    collector->session = fbSessionAlloc(model);
    if (collector->cfg->gen_tombstone) {
        mdCollectorAddTombstoneTemplates(collector);
    }

    fbSessionAddNewTemplateCallback(collector->session,
                                    mdCollectorTemplateCallback,
                                    (void*)collector);
}


/**
 * mdFlowSourceClose
 *
 * close the file we were reading
 *
 */
static void
mdFlowSourceClose(
    mdCollector_t      *collector)
{
    if (collector->lfp) {
        fclose(collector->lfp);
        collector->lfp = NULL;
    }
}


/**
 * mdFindListener
 * We got an connection on a listener, figure out which mdCollector it is
 *
 *
 */
static mdCollector_t *
mdCollectorFindListener(
    mdConfig_t         *cfg,
    const fbListener_t *listener)
{
    mdCollector_t *collector = NULL;

    for (collector = cfg->firstCol; collector; collector = collector->next) {
        if (collector->listener == listener) {
            collector->active = TRUE;
            return collector;
        }
    }

    return NULL;
}

/**
 *  Callback function passed to fbListenerAlloc() and invoked when a new
 *  connection arrives.
 */
static gboolean
mdListenerConnect(
    fbListener_t         *listener,
    void                 **ctx,
    int                  fd,
    struct sockaddr      *peer,
    size_t               peerlen,
    GError               **err)
{
    mdCollector_t *collector = NULL;

    MD_UNUSED_PARAM(fd);
    MD_UNUSED_PARAM(peerlen);
    MD_UNUSED_PARAM(err);

    if (!peer) {
        /* this is UDP */
        return TRUE;
    }

    /* set context based on which listener this is */
    collector = mdCollectorFindListener(&md_config, listener);

    if (!collector) {
        return FALSE;
    }

    if (peer->sa_family == AF_INET) {
        char *ip = inet_ntoa((((struct sockaddr_in *)peer)->sin_addr));
        pthread_mutex_lock(&md_config.log_mutex);
        g_message("%s: accepting connection from %s:%d",
                  mdCollectorGetName(collector), ip,
                  ((struct sockaddr_in *)peer)->sin_port);
        pthread_mutex_unlock(&md_config.log_mutex);
    } else if (peer->sa_family == AF_INET6) {
        char straddr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)peer)->sin6_addr),
                  straddr, sizeof(straddr));
        pthread_mutex_lock(&md_config.log_mutex);
        g_message("%s: accepting connection from %s:%d",
                  mdCollectorGetName(collector), straddr,
                  ((struct sockaddr_in6 *)peer)->sin6_port);
        pthread_mutex_unlock(&md_config.log_mutex);
    }

    collector->colStats.restarts++;

    *ctx = (void *)collector;

    return TRUE;
}

/**
 * mdCollectorOpenFileAndInitSession
 *
 * open an IPFIX file for reading and initialize the session
 *
 */
static fBuf_t *
mdCollectorOpenFileAndInitSession(
    mdCollector_t      *collector,
    const char         *path,
    GError            **err)
{
    fBuf_t            *buf;

    /* file is already open - close it & done,
     * means it was a single file and we're done now */
    if (collector->lfp || collector->std_in) {
        mdFlowSourceClose(collector);
        return NULL;
    }

    /* if reading from stdin */
    if ((path[0] == '-') && (strlen(path) == 1)) {
        if (isatty(fileno(stdin))) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "Refusing to read from terminal on stdin");
            return NULL;
        }
        collector->collector = fbCollectorAllocFile(NULL, path, err);
        collector->std_in = TRUE;
    } else { /* if reading from a named file (could be file poller as well) */
#ifdef SM_ENABLE_ZLIB
        /* deal with zipped files, if ZLIB enabled */
        if (g_file_test(path, G_FILE_TEST_IS_REGULAR)) { /* file is zipped */
            FILE *tmp = fopen(path, "rb");
            uint16_t header = 0;
            if (NULL == tmp) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                            "Cannot open file %s for reading", path);
                return NULL;
            }
            fread(&header, 1, 2, tmp);
            if ((header == ZLIB_HEADER) || (header == GZIP_HEADER)) {
                rewind(tmp);
                collector->lfp = mdFileDecompress(tmp, path,
                                      collector->decompressWorkingDirectory);
                fclose(tmp);
            } else {
                fclose(tmp);
                collector->lfp = fopen(path, "rb");
            }
        } else /* not zipped, open normally */
#endif  /* SM_ENABLE_ZLIB */
        {
            collector->lfp = fopen(path, "rb");
        }
        if ( collector->lfp == NULL ) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "Cannot open file %s for reading", path);
            return NULL;
        }

        /* everything above got a file pointer, use that to build collector */
        collector->collector = fbCollectorAllocFP(NULL, collector->lfp);

    }

    if (collector->collector == NULL ) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                    "Error creating the fbCollector");
        return NULL;
    }

    collector->session = NULL;
    /* allocate the new session and configure it where necessary */
    mdCollectorCreateSession(collector);

    if (collector->session == NULL) {
        return NULL;
    }

    buf = fBufAllocForCollection(collector->session, collector->collector);

    return buf;
}

/**
 * mdCollectorMoveFile
 *
 * move a file once we are done with it
 *
 */
static gboolean
mdCollectorMoveFile(
    const char *file,
    const char *new_dir,
    GError    **err)
{
    GString *new_file = g_string_new(NULL);
    const char *filename;
    gboolean ret = TRUE;

    filename = g_strrstr(file, "/");
    if (NULL == filename) {
        filename = file;
    }

    g_string_append_printf(new_file, "%s", new_dir);
    g_string_append_printf(new_file, "%s", filename);

    if (g_rename(file, new_file->str) != 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO, "Unable to move file "
                    "to %s", new_file->str);
        ret = FALSE;
    }

    g_string_free(new_file, TRUE);

    return ret;
}

/**
 * mdCollectorFileNext
 *
 *  Function called by pthread_create() to do polling for new files in the
 *  given collector's directory.
 *
 */
static void *
mdCollectorFileNext(
    void   *v_collector)
{
    mdCollector_t      *collector = (mdCollector_t *)v_collector;
    GDir               *dir;
    GError             *direrror = NULL;
    const gchar        *name;
    gboolean            error = FALSE;
    GString            *fullpath = g_string_new(NULL);

    while (!md_quit) {
        dir = g_dir_open(collector->inspec, 0, &direrror);
        if (!dir) {
            g_set_error_literal(&collector->err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                                direrror->message);
            g_clear_error(&direrror);
            break;
        }

        /* Iterate over paths */
        for (;;) {
            errno = 0;
            name = g_dir_read_name(dir);
            if (!name) {
                if (errno) {
                    g_set_error_literal(&collector->err, MD_ERROR_DOMAIN,
                                        MD_ERROR_IO, strerror(errno));
                    g_dir_close(dir);
                    error = TRUE;
                }
                break;
            }

            g_string_printf(fullpath, "%s/%s", collector->inspec, name);
            if (fullpath->len >= 5 &&
                0 == strcmp(".lock", fullpath->str + fullpath->len - 5))
            {
                /* entry ends with ".lock" */
                continue;
            }

            if (!g_file_test(fullpath->str, G_FILE_TEST_IS_REGULAR)) {
                /* entry is not a file */
                continue;
            }

            if (!collector->fname_lock) {
                collector->fname_lock = g_string_new(NULL);
            }
            g_string_printf(collector->fname_lock, "%s.lock", fullpath->str);

            if (g_file_test(collector->fname_lock->str,
                            G_FILE_TEST_IS_REGULAR))
            {
                /* file is locked */
                continue;
            }

            /* filename stored here */
            collector->fname_in = g_string_new(fullpath->str);

            /* we now have the next file that matches the incoming glob */

            pthread_mutex_lock(&collector->mutex);
            collector->fbuf = mdCollectorOpenFileAndInitSession(
                                             collector,
                                             collector->fname_in->str,
                                             &collector->err);
            if (!collector->fbuf) {
                pthread_mutex_unlock(&collector->mutex);
                error = TRUE;
                break;
            }

            /* automatically move to the next fixbuf dataset */
            fBufSetAutomaticInsert(collector->fbuf, &collector->err);
            /* automatically attach received metadata to the session
             * this prevents TMD records from being returned by fBufNext */
            fBufSetAutomaticMetadataAttach(collector->fbuf, &collector->err);
            /* it's a file, so we know there's data */
            collector->data = TRUE;

            /* STATS COL filesRead */
            collector->colStats.filesRead++;

            /* signal to main thread we have a file */
            pthread_mutex_lock(&global_listener_mutex);
            pthread_cond_signal(&global_listener_cond);
            pthread_mutex_unlock(&global_listener_mutex);

            while (collector->fbuf) {
               pthread_cond_wait(&collector->cond, &collector->mutex);
            }

            pthread_mutex_unlock(&collector->mutex);
        }
        g_dir_close(dir);

        if (error) {
            break;
        }

        sleep(collector->pollingInterval);
    }

    if (collector->fname_lock) {
        g_string_free(collector->fname_lock, TRUE);
        collector->fname_lock = NULL;
    }

    collector->active = FALSE;
    pthread_mutex_lock(&global_listener_mutex);
    pthread_cond_signal(&global_listener_cond);
    pthread_mutex_unlock(&global_listener_mutex);

    g_string_free(fullpath, TRUE);
    return NULL;
}

/**
 * mdCollectorOpenListener
 *
 *  Function called by pthread_create() to listen for connections and data on
 *  the given collector's socket.
 *
 */
static void *
mdCollectorOpenListener(
    void   *v_collector)
{
    mdCollector_t *collector = (mdCollector_t *)v_collector;

    if (collector->collectionMethod == CM_UDP) {
        if (!fbListenerGetCollector(collector->listener,
                                    &collector->collector,
                                    &collector->err))
        {
            return NULL;
        }
        fbCollectorSetUDPMultiSession(collector->collector, TRUE);
    }

    while (!md_quit) {

        pthread_mutex_lock(&collector->mutex);
        collector->fbuf = NULL;
        /* wait for a connection or data */
        collector->fbuf = fbListenerWait(collector->listener, &collector->err);
        if (md_quit) {
            g_clear_error(&collector->err);
            pthread_mutex_unlock(&collector->mutex);
            /* exit immediately if interrupted*/
            break;
        }
        if (collector->fbuf) {
            pthread_mutex_lock(&(collector->cfg->log_mutex));
            if (!fBufSetAutomaticElementInsert(collector->fbuf,
                                                &(collector->err)))
            {
                g_warning("%s: fBufSetAutomaticElementInsert failed: %s",
                          collector->name, collector->err->message);
            }
            if (!fBufSetAutomaticMetadataAttach(collector->fbuf,
                                               &(collector->err)))
            {
                g_warning("%s: fBufSetAutomaticMetadataAttach failed: %s",
                          collector->name, collector->err->message);
            }
            pthread_mutex_unlock(&(collector->cfg->log_mutex));
            collector->data = TRUE;
            /* turn off automatic mode to ensure we switch between connections
             * with data */
            fBufSetAutomaticMode(collector->fbuf, FALSE);
            collector->session = fBufGetSession(collector->fbuf);
        }
        /* signal to main thread that we have an active fbuf */
        pthread_mutex_lock(&global_listener_mutex);
        pthread_cond_signal(&global_listener_cond);
        pthread_mutex_unlock(&global_listener_mutex);

        pthread_cond_wait(&collector->cond, &collector->mutex);
        pthread_mutex_unlock(&collector->mutex);

    }
    collector->active = FALSE;

    return NULL;
}

/**
 * mdCollectorsInit
 * Called once from mediator_main before data is received
 * Setup whatever one-time stuff on the collectors
 *
 * TCP/UDP - allocate listener
 * FILEHANDLER - open file and init session
 * DIRECTORY - setup mutexes and do nothing else
 *
 */
gboolean
mdCollectorsInit(
    mdConfig_t         *cfg,
    mdCollector_t      *firstCol,
    GError            **err)
{
    mdCollector_t *collector = NULL;

    for (collector = firstCol; collector; collector = collector->next) {
        /* set the global config on the collectors so they have a reference */
        collector->cfg = cfg;

        if (COLLMETHOD_IS_SOCKET(collector->collectionMethod)) {
            collector->session = NULL;
            /* allocate session and assign callback */
            mdCollectorCreateSession(collector);

            if (collector->session == NULL) {
                return FALSE;
            }

            /* build listener based on user config */
            collector->listener = fbListenerAlloc(&(collector->connspec),
                                                    collector->session,
                                                    mdListenerConnect, NULL,
                                                    err);
            if (collector->listener == NULL) {
                g_prefix_error(err, "%s: ", collector->name);
                return FALSE;
            }
            collector->listenerSession = collector->session;
            collector->session = NULL;

            pthread_mutex_init(&collector->mutex, NULL);
            pthread_cond_init(&collector->cond, NULL);
        } else if (collector->collectionMethod == CM_SINGLE_FILE) {
            collector->fbuf = mdCollectorOpenFileAndInitSession(
                                              collector,
                                              collector->inspec,
                                              err);
            if (collector->fbuf == NULL) {
                g_prefix_error(err, "%s: ", collector->name);
                return FALSE;
            }

            collector->colStats.filesRead++;
            /* automatically insert IEs that arrive */
            fBufSetAutomaticInsert(collector->fbuf, err);
            /* automatically consume TMD that arrives */
            fBufSetAutomaticMetadataAttach(collector->fbuf, err);
            /* set active here because we don't start up a thread for files */
            collector->active = TRUE;
            collector->data = TRUE;
            pthread_mutex_init(&collector->mutex, NULL);
            pthread_cond_init(&collector->cond, NULL);
        } else if (collector->collectionMethod == CM_DIR_POLL) {
            /* file will be opened by mdCollectorFileNext */
            pthread_mutex_init(&collector->mutex, NULL);
            pthread_cond_init(&collector->cond, NULL);
        }
    }

    return TRUE;
}

static int
mdOpenCollectors(
    mdCollector_t      *firstCol)
{
    mdCollector_t *collector = NULL;
    int active = 0;

    for (collector = firstCol; collector; collector = collector->next) {
        if (collector->active) {
            active++;
            /* PODO...GNCT to read the templates
             * make sure this doesn't block out socket collectors
             * and we can be sure we get up to the data
             * Although this doesn't guarantee every template ever,
             * it gives a pretty good idea, and we can log bad situations */
            /* see when this gets called...new sockets? new file? lots and
             * lots of times? */
        }
    }

    return active;
}


/**
 * mdCollectFBuf()
 *
 *  The primary mechanism to collect and export flows.
 */
static gboolean
mdCollectFBuf(
    mdContext_t        *ctx,
    mdCollector_t      *collector, /* fill rec */
    GError            **err)
{
    int                         i                   = 0;
    /* external template for record to process. Set by fBufNCT() */
    uint16_t                    extTid;                     /* fill rec */
    /* local variable for easier access to session */
    fbSession_t                *session             = NULL;
    /* whether to reset and flush the exporters for certain errors */
    gboolean                    reset;
    /* whether "everything is ok", even if we didn't read a record, or if an
     * "error" condition like end of file is encountered */
    gboolean                    rv;
    gboolean                    rc;
    /* flag to break out of record processing loop
     * triggered by processing a record where something isn't right */
    gboolean                    done;
    /* external template of incoming record from fBufNCT() */
    fbTemplate_t               *extTmpl             = NULL; /* fill rec */
    /* internal template defining record returned. From extTmpl context */
    const fbTemplate_t         *intTmpl             = NULL; /* fill rec */
    mdDefaultTmplCtx_t         *defExtTmplCtx       = NULL; /* fill rec */
    mdDefaultTmplCtx_t         *defIntTmplCtx       = NULL; /* fill rec */
    /* holder for the read record */
    fbRecord_t                  record;                     /* fill rec */
    /* if record is a flow, use this struct to pass it around */
    mdFullFlow_t                flow;
    /* struct to "hold" non-flow records (pointer to flow) */
    mdGenericRec_t             *genRec = (mdGenericRec_t *)&flow;
    /* struct to put timestamp val in */
    fbRecordValue_t             timestampVal        = FB_RECORD_VALUE_INIT;
    /* when using export time, put here initially */
    uint32_t                    fBufExportTimeSecs  = 0;
    /* timestamp ends up here */
    uint64_t                    recTimestamp        = 0;
    /* whether or not the current record is the same template as last one */
    gboolean                    sameTmpl            = FALSE;
    /* use export time for this record */
    gboolean                    useExportTimeAgain  = FALSE;
    /* sameTmpl==TRUE:the template field for the last IE to give us ctime */
    const fbTemplateField_t    *lastCTimeIE         = NULL;
    /* lastExtTid, used to determine sameTmpl */
    uint16_t                    lastExtTid          = 0;
    /* holder for template contents for the template for this record */
    mdUtilTemplateContents_t    templateContents    = MD_TC_INIT;
    fbSubTemplateMultiList_t   *stmlToClear         = NULL;

    memset(&flow, 0, sizeof(mdFullFlow_t));

    done    = FALSE;
    rv      = TRUE;
    reset   = FALSE;

    if (collector->data == FALSE) {
        /* no data yet - don't call NextCollectionTemplate */
        return TRUE;
    }

    /* Log new filenames, nothing to log for sockets, already logged */
    if (collector->collectionMethod == CM_SINGLE_FILE) {
        pthread_mutex_lock(&ctx->cfg->log_mutex);
        g_message("%s: Opening file: %s", collector->name, collector->inspec);
        pthread_mutex_unlock(&ctx->cfg->log_mutex);
    } else if (collector->collectionMethod == CM_DIR_POLL) {
        pthread_mutex_lock(&ctx->cfg->log_mutex);
        g_message("%s: Opening file: %s", collector->name,
                  collector->fname_in->str);
        pthread_mutex_unlock(&ctx->cfg->log_mutex);
    }

    /* set the current collector's name */
    ctx->cfg->collector_name = collector->name;
    ctx->cfg->collector_id = collector->id;

    while (!done) {
        /* get the TID and tmpl that defines the next record
         * This will trigger template processing, which calls the template
         * callback.
         * A null extTmpl indicates and error, end of message, or end of data*/
        extTmpl = fBufNextCollectionTemplate(collector->fbuf, &extTid, err);
        if (!extTmpl) {
            /* error getting next collection template, or no more data */
            /* end of message, stop reading data and exit function */
            /* each of these has to end with a break */
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOM)) {
                /* everything's fine, end of ipfix message */
                g_clear_error(err);
                /* mark that there is no more data and break out */
                collector->data = FALSE;
                break; /* out of loop */
            }

            /* data isn't IPFIX error, ignore, close conn and exit */
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX)) {
                pthread_mutex_lock(&ctx->cfg->log_mutex);
                g_warning("%s: Ignoring Packet: %s", collector->name,
                          (*err)->message);
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                g_clear_error(err);
                /* null out the fbuf as it's not IPFIX */
                /* if it's a socket, the fbuf will get reset with connection */
                /* fbuf freed by listener eventually */
                collector->fbuf = NULL;
                /* mark that there's no data */
                collector->data = FALSE;

                break; /* out of loop */
            }
            if (g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD)) {
                /* can really only happen with TCP or UDP */
                /* no data to read from connection */
                pthread_mutex_lock(&ctx->cfg->log_mutex);
                g_warning("%s: Ignoring Connection: %s",
                          collector->name, (*err)->message);
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                g_clear_error(err);
                /* no data, clear out fbuf. fbuf is maintained by listener */
                collector->fbuf = NULL;
                /* no data to read */
                collector->data = FALSE;
                break; /* out of loop */
            } else {
                /* catch-all error block
                 * means to close the connection */
                pthread_mutex_lock(&ctx->cfg->log_mutex);
                if (!(g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOF))) {
                    g_warning("%s: Closing Connection: %s",
                              collector->name, (*err)->message);
                } else {
                   g_message("%s: Closing Connection: %s",
                             collector->name, (*err)->message);
                }
                collector->data = FALSE;
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                g_clear_error(err);
                mdfBufFree(collector);
                rv = TRUE;
                reset = TRUE;
                break; /* out of loop */
            }
        } /* end of !extTmpl */

        /* all errors are handled. If we get here, we have a record to process
         * with the TID stored in extTid, and template in extTmpl */


        /* based on the type of record defined by the template, pass to the
         * appropriate processing function. The processing functions are
         * housed in mediator_core.c
         */


        /* Do some setup if it's a different template than last time */
        sameTmpl = (lastExtTid == extTid);

        if (sameTmpl) {
            /* we have the tids, tmpls, contexts and record already set up */
        } else {
            /* pthread_mutex_lock(&ctx->cfg->log_mutex);
            g_message("Processing template %#x", extTid);
            pthread_mutex_unlock(&ctx->cfg->log_mutex); */
            lastExtTid = extTid;
            /* no matter the template type, there's at least a default
             * template context for it */
            defExtTmplCtx = fbTemplateGetContext(extTmpl);
            if (!defExtTmplCtx) {
                /* This is unexpected since we assign a context to every
                 * top-level template. This is either a programmer/logic
                 * error, or a template we assumed was only for DPI appears as
                 * a top level record. Log a warning and ignore these
                 * records. */
                /* FIXME: Make this not abort the program.  Either assign the
                 * template context now, or read the record using some minimal
                 * internal template, drop the record on the floor, and loop
                 * back to the beginning of the while loop. */
                pthread_mutex_lock(&ctx->cfg->log_mutex);
                g_error("%s(%d): No template context for received"
                        " template %#06x",
                        collector->name, collector->id, extTid);
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
            }

            templateContents = defExtTmplCtx->templateContents;

            /* build the record struct to receive the record */
            /* collector has appropriately sized buffer ready */
            record.rec = collector->recBuf;
            record.reccapacity  = collector->largestRecTemplateSize;

            /* set the internal template based on the coupled intTid built
             * during template callback and stored in template context */
            record.tid = defExtTmplCtx->associatedIntTid;

            /* needed to get context, and to fill Generic/Flow Rec struct */
            intTmpl = fbSessionGetTemplate(collector->session, TRUE,
                                           record.tid, err);

            /* get the internal template context so we can use it to clear */
            defIntTmplCtx = fbTemplateGetContext(intTmpl);
            /* clear all of the places in the record getting a list transcoded
             * into them */
            /* we only have to do this here when there is a new template.
             * when it's the same template, FreeLists() takes care of it */
            for (i = 0; i < defIntTmplCtx->blCount; i++) {
                fbBasicListCollectorInit((fbBasicList_t*)
                                    (record.rec + defIntTmplCtx->blOffsets[i]));
            }

            for (i = 0; i < defIntTmplCtx->stlCount; i++) {
                fbSubTemplateListCollectorInit((fbSubTemplateList_t*)
                                (record.rec + defIntTmplCtx->stlOffsets[i]));
            }

            /* no fbSTMLCollectorInit(), do it by hand */
            for (i = 0; i < defIntTmplCtx->stmlCount; i++) {
                stmlToClear = (fbSubTemplateMultiList_t*)
                                (record.rec + defIntTmplCtx->stmlOffsets[i]);
                stmlToClear->numElements    = 0;
                stmlToClear->firstEntry     = NULL;
            }
        }

        /* set observation domain of active session */
        session = fBufGetSession(collector->fbuf);

        ctx->cfg->current_domain = fbSessionGetDomain(session);

        /* read the record */
        if (!fBufNextRecord(collector->fbuf, &record, err)) {
            if (!(g_error_matches(*err, FB_ERROR_DOMAIN, FB_ERROR_EOM))) {
                mdfBufFree(collector);
                pthread_mutex_lock(&ctx->cfg->log_mutex);
                g_warning("%s: Error Receiving Flow for tid %#x: %s",
                          collector->name, extTid, (*err)->message);
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                reset = TRUE;
                rv = FALSE;
                collector->data = FALSE;
                break; /* out of loop */
            }
            g_clear_error(err);
            rv = TRUE;
            collector->data = FALSE;
            break; /* out of loop */
        }

        /* have a successfully read record at this point */
        /* record record size
         * need to get all bytes read, not just top level to really work
         * STATS COL bytesRead */
/*        collector->colStats.bytesRead += record.recsize;*/
        /* record record type count. Affects totalRecordsRead
         * STAT COL recordsReadByType*/
        collector->colStats.recordsReadByType[templateContents.general]++;

        pthread_mutex_lock(&ctx->cfg->log_mutex);

        if (sameTmpl) {
            /* if it's the same record, then the timestamp IE is the same
             * either use the IE, or get the export time from the fbuf */
            if (lastCTimeIE) {
                if (!fbRecordGetValueForField(&record,
                                              lastCTimeIE,
                                              &timestampVal))
                {
                    g_warning("%s: Couldn't get repeated time value for id %#x",
                              collector->name, extTid);
                    recTimestamp = 0;
                } else {
                    recTimestamp = TIMESPEC_TO_MILLI(timestampVal.v.dt);
                }
            } else if (useExportTimeAgain) {
                fBufExportTimeSecs = fBufGetExportTime(collector->fbuf);
                recTimestamp = fBufExportTimeSecs * 1000;
            }
        } else {
            /* new template, get the timestamp IE from the template context
             * set all state variables so we can do it again if sameTmpl */
            lastCTimeIE = NULL;
            useExportTimeAgain = FALSE;

            /* if there's a timestamp field, use it versus runtime field */
            if (collector->hasTimestampField) {
                if (collector->hasDataTimestampField) {
                    /* get the timestamp from the record, convert to epoch
                     * miiliseconds */
                    if (defIntTmplCtx->dataCTimeIE) { /* could remove later */
                        if (!fbRecordGetValueForField(&record,
                                        defIntTmplCtx->dataCTimeIE,
                                        &timestampVal))
                        {
                            g_warning("%s: Couldn't get time value for tid %#x",
                                      collector->name, extTid);
                            recTimestamp = 0;
                        } else {
                            recTimestamp = TIMESPEC_TO_MILLI(timestampVal.v.dt);
                            lastCTimeIE = defIntTmplCtx->dataCTimeIE;
                        }
                    } else {
                        g_debug("%s: No time field for tid %#x",
                                collector->name, record.tid);
                    }
                } else {
                    /* use a sourceRuntime IE from the record if no data TS */
                    if (defIntTmplCtx->sourceRuntimeCTimeIE) {
                        if (!fbRecordGetValueForField(&record,
                                        defIntTmplCtx->sourceRuntimeCTimeIE,
                                        &timestampVal))
                        {
                            g_warning("%s: couldn't get time value for tid %#x",
                                      collector->name, extTid);
                            recTimestamp = 0;
                        } else {
                            recTimestamp = TIMESPEC_TO_MILLI(timestampVal.v.dt);
                            lastCTimeIE = defIntTmplCtx->sourceRuntimeCTimeIE;
                        }
                    }
                }
            } else {
                /* no timestamp field, use export time */
                useExportTimeAgain = TRUE;
                fBufExportTimeSecs = fBufGetExportTime(collector->fbuf);
                recTimestamp = fBufExportTimeSecs * 1000;
            }
        }

        /* if the timestamp used is later, adjust the internal time */
        if (recTimestamp > ctx->cfg->ctime) {
            ctx->cfg->ctime = recTimestamp;
            /* check if it's a new day or new hour
             * if so...tell the world   */
        }

        /* Fill the elements of the genRec (which points to flow). */
        genRec->fbRec           = &record;
        genRec->extTmplCtx      = defExtTmplCtx;
        genRec->intTmplCtx      = defIntTmplCtx;
        genRec->extTmpl         = extTmpl;
        genRec->intTmpl         = intTmpl;
        genRec->extTid          = extTid;
        genRec->intTid          = record.tid;
        genRec->collector       = collector;

        /* depending on the general record type, pass the record along to the
         * correct processer.
         * Prepare the record struct with everything that's needed
         * update stats */

        switch (templateContents.general) {
          case TC_FLOW:
            /* FIXME: Why are we only running the filters here, for TC_FLOW
             * records?  Why not do it for ALL records? */

            /* run the collector's filter */
            if (collector->filter) {
                rc = mdFilterCheck(collector->filter, &flow, 0);
                if (rc == FALSE) {
                    /* STAT COL recordsFilteredOutByType */
                    collector->colStats.recordsFilteredOutByType[
                            templateContents.general]++;
                    /* will get freed by FreeLists, no need to align */
                    break; /* out of switch */
                }
            }

            /* run the FILTER block's filter */
            if (ctx->cfg->sharedFilter) {
                if (FALSE == mdFilterCheck(ctx->cfg->sharedFilter, &flow, 0)) {
                    /* STAT COL recordsFilteredOutByType */
                    collector->colStats.recordsFilteredOutByType[
                            templateContents.general]++;
                    break; /* out of switch */
                }
            }

            /* depending on the YAF version, call process flow function
             * with appropriate parameters */
            /* should change this to use the value directly once we have
             * enums and explicit value and types */
            if (templateContents.yafVersion & TC_YAF_VERSION_3) {
                if (!mdProcessFlow(ctx, &flow, 3, err)) {
                    g_warning("%s: Error Forwarding Flow...%s",
                                collector->name, (*err)->message);
                    rv = FALSE;
                    done = TRUE; /* out of loop */
                    break; /* out of switch */
                }
            } else {
                if (!mdProcessFlow(ctx, &flow, 2, err)) {
                    g_warning("%s: Error Forwarding Flow...%s",
                              collector->name, (*err)->message);
                    rv = FALSE;
                    done = TRUE; /* out of loop */
                    break; /* out of switch */
                }
            }
            break; /* out of switch */

          case TC_DPI:
            /* something labeled DPI is a nested record, so it should never
             * be what comes out of NextRecord as a top level record */
            g_warning("%s: got DPI in collect fbuf %#x",
                      collector->name, extTid);
            rv = FALSE;
            done = TRUE; /* out of loop */
            break; /* out of switch */

          case TC_TMD_OR_IE:
            /* these records should be consumed automatically by fixbuf */
            g_warning("%s: got TMD or IE in collect fbuf %#x, ignoring",
                      collector->name, extTid);
            break; /* out of switch */

          case TC_DNS_DEDUP:
            /* standard processing stuff */
            rc = mdProcessDNSDedup(ctx, genRec, err);
            if (!rc) {
                g_warning("%s: Error Processing DNS Dedup Rec: %s",
                          collector->name, (*err)->message);
                rv = FALSE;
                done = TRUE; /* out of loop */
                break; /* out of switch */
            }
            break; /* out of switch */

          case TC_SSL_DEDUP:
            /* standard processing stuff */
            rc = mdProcessSSLDedup(ctx, genRec, err);
            if (!rc) {
                g_warning("%s: Error Forwarding SSL DEDUP Rec: %s",
                          collector->name, (*err)->message);
                rv = FALSE;
                done = TRUE; /* out of loop */
                break; /* out of switch */
            }
            break; /* out of switch */

          case TC_GENERAL_DEDUP:
            /* standard processing stuff */
            rc = mdProcessGeneralDedup(ctx,
                                       (mdGeneralDedupTmplCtx_t*)defExtTmplCtx,
                                       genRec,
                                       err);
            if (!rc) {
                g_warning("%s: Error Forwarding DEDUP Rec: %s",
                          collector->name, (*err)->message);
                rv = FALSE;
                done = TRUE; /* out of loop */
                break; /* out of switch */
            }
            break; /* out of switch */

          case TC_DNS_RR:
            /* standard processing stuff */
            rc = mdProcessDNSRR(ctx, genRec, err);
            if (!rc) {
                g_warning("%s: Error Forwarding DNS RR Rec: %s",
                          collector->name, (*err)->message);
                rv = FALSE;
                done = TRUE; /* out of loop */
                break; /* out of switch */
            }
            break; /* out of switch */

          case TC_YAF_STATS:
            /* standard processing stuff */
            if (!mdProcessYafStats(ctx, collector, genRec, err)) {
                g_warning("%s: Error Forwarding Stats: %s",
                          collector->name, (*err)->message);
                rv = FALSE;
                done = TRUE; /* out of loop */
                break; /* out of switch */
            }
            break; /* out of switch */

          case TC_TOMBSTONE:
            /* standard processing stuff */
            if (!mdProcessTombstone(ctx, collector, genRec, err)) {
                g_warning("%s: Error Forwarding Tombstone: %s",
                          collector->name, (*err)->message);
                rv = FALSE;
                done = TRUE; /* out of loop */
                break; /* out of switch */
            }
            break; /* out of switch */

          case TC_UNKNOWN_DATA:
            if (templateContents.specCase.dpi == TC_APP_DPI_SSL_L2 ||
                templateContents.specCase.dpi == TC_APP_DPI_SSL_RW_L2)
            {
#if 0
                g_warning("%s: Got %s SSL CERT for tid %#x...will process",
                          collector->name,
                          ((templateContents.specCase.dpi
                            == TC_APP_DPI_SSL_RW_L2)
                           ? "a Flattened" : "an"), extTid);
#endif  /* 0 */
                if (!mdProcessSSLCert(ctx, genRec, err)) {
                    g_warning("%s: Error Forwarding SSL CERT: %s",
                              collector->name, (*err)->message);
                    rv = FALSE;
                    done = TRUE; /* out of loop */
                }
                break; /* out of switch */
            }
            /* FALLTHROUGH */

          case TC_UNKNOWN:
          case TC_UNKNOWN_OPTIONS:
            /* this should never happen, this is really a prorammer debug */
            /* No, it is not a programmer bug, it is a "the templates have
             * changed in a way we did not expect" issue.  If we're writing
             * this thing to be flexible, then it needs to be flexible. */
            g_warning("%s: got unknown contents for tid %#x",
                      collector->name, extTid);
            /*rv = FALSE;
              done = TRUE;*/ /* out of loop */
            break; /* out of switch */

          case TC_NUM_TYPES:
            g_error("%s: Got TC NUM TYPES in collectFBuf", collector->name);
            break;
        }

        /* the record is compltely processed. Now we clean up and go again */

        /* free all of the list memory */
        fbRecordFreeLists(&record);

        pthread_mutex_unlock(&ctx->cfg->log_mutex);
    } /* big while loop */

    /* all done processing records either in the file, or in the dataSet for
     * socket connections */

    /* if marked for reset, flush the exporter tables that are time based */
    if (reset) {
        if (!mdExporterConnectionReset(ctx->cfg, err)) {
            pthread_mutex_lock(&ctx->cfg->log_mutex);
            g_warning("%s: Error resetting connection: %s\n",
                      collector->name, (*err)->message);
            pthread_mutex_unlock(&ctx->cfg->log_mutex);
            rv = FALSE;
        }
    }

    /* if we got here, we're done with a file, handle the old one */
    if (collector->collectionMethod == CM_DIR_POLL) {
        /* Delete or move file for DIRECTORY collectors */
        if (collector->lfp) {
            if (collector->move_dir && collector->fname_in) {
                if (!mdCollectorMoveFile(collector->fname_in->str,
                                         collector->move_dir, err))
                {
                    g_string_free(collector->fname_in, TRUE);
                    return FALSE;
                }
            }
            mdFlowSourceClose(collector);
            g_remove(collector->fname_in->str);

            pthread_mutex_lock(&ctx->cfg->log_mutex);
            g_message("%s: Deleting file %s",
                      collector->name, collector->fname_in->str);
            pthread_mutex_unlock(&ctx->cfg->log_mutex);
            g_string_free(collector->fname_in, TRUE);
        }
    }
    return rv;
}


/**
 *  mdCollectorWait()
 *
 *  Overall thread and collector handling loop.  Data/flow processing loop
 */
gboolean
mdCollectorWait(
    mdContext_t      *ctx,
    GError           **err)
{
    mdCollector_t *clist = ctx->cfg->firstCol;
    mdCollector_t *collector = NULL;
    gboolean active;
    int rv;
    int collectors = 0;
    struct timeval tp;
    struct timespec to;
    /*uint16_t    extTid; used with NextCollectionTemplate commented out */

    /* right now, turns them all to active */
    collectors = mdOpenCollectors(clist);

    while (collectors && !md_quit) {
        active = FALSE;
        for (collector = ctx->cfg->firstCol;
             collector;
             collector = collector->next)
        {
            if (collector->active) {
                if (collector->fbuf && collector->data) {
                    active = TRUE;
                    rv = pthread_mutex_trylock(&collector->mutex);
                    if (rv != 0) continue;

                    /* call GNCT to kick off template gathering for a sanity
                     * check */
/*                    if (!fBufNextCollectionTemplate(collector->fbuf,
                                                    &extTid, err))
                    {
                        if (g_error_matches(*err,
                                            FB_ERROR_DOMAIN,
                                            FB_ERROR_EOM))
                        {
                            g_clear_error(err);
                            collector->data = FALSE;
                        } else {
                            if (!(g_error_matches(*err, FB_ERROR_DOMAIN,
                                                        FB_ERROR_EOF)))
                            {
                                g_warning("%s: Closing Connection: %s",
                                      collector->name, (*err)->message);
                            } else {
                                g_message("%s: Closing Connection: %s",
                                         collector->name, (*err)->message);
                            }
                            collector->data = FALSE;
                            g_clear_error(err);
                            mdfBufFree(collector);
                        }
                    } else {*/
                        /* TODO. Template sanity here */
/*                    }*/


                    /* process flows from this fbuf, no matter which kind */
                    if (!mdCollectFBuf(ctx, collector, err)) {
                        pthread_cond_signal(&collector->cond);
                        pthread_mutex_unlock(&collector->mutex);
                        return FALSE;
                    }

                    /* CollectFBuf for FILEHANDLER only returns when the entire
                     * file is read, so no more data, and need to restart which
                     * loads the next file, or ends */
                    if (collector->collectionMethod == CM_SINGLE_FILE) {
                        collector->active = FALSE;
                        collector->restart = TRUE;
                        collectors--;
                    }
                    pthread_cond_signal(&collector->cond);
                    pthread_mutex_unlock(&collector->mutex);
                }
            } else if (!collector->restart) {
                /* start this guy back up */
                pthread_mutex_lock(&ctx->cfg->log_mutex);
                g_warning("%s: Collector Error: %s",
                          collector->name, collector->err->message);
                collector->restart = TRUE;
                g_clear_error(&collector->err);
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                if (!mdCollectorRestartListener(ctx->cfg, collector, err)) {
                    pthread_mutex_lock(&ctx->cfg->log_mutex);
                    g_warning("%s: Error restarting collector: %s",
                              collector->name, (*err)->message);
                    pthread_mutex_unlock(&ctx->cfg->log_mutex);
                    g_clear_error(err);
                    collectors--;
                }
            } else if (collector->err) {
                /* this collector is permanently inactive */
                pthread_mutex_lock(&ctx->cfg->log_mutex);
                g_warning("%s: Could not restart collector: %s",
                          collector->name, collector->err->message);
                g_clear_error(&collector->err);
                g_warning("%s: Collector is now inactive"
                          " until program restart.", collector->name);
                pthread_mutex_unlock(&ctx->cfg->log_mutex);
                collectors--;
            }
        }
        if (!active) {
            /* wait on listeners to collect something (timeout of 1 sec)*/
            gettimeofday(&tp, NULL);
            to.tv_sec = tp.tv_sec + 1;
            to.tv_nsec = tp.tv_usec * 1000;
            pthread_mutex_lock(&global_listener_mutex);
            pthread_cond_timedwait(&global_listener_cond,
                                   &global_listener_mutex, &to);
            pthread_mutex_unlock(&global_listener_mutex);
        }
    }

    return FALSE;
}

/**
 * mdCollectorRestartListener
 *
 */
gboolean
mdCollectorRestartListener(
    mdConfig_t         *md,
    mdCollector_t      *collector,
    GError             **err)
{
    if (collector->active) {
        return TRUE;
    }

    switch (collector->collectionMethod) {
      case CM_SINGLE_FILE:
        return TRUE;
      case CM_DIR_POLL:
        pthread_mutex_lock(&md->log_mutex);
        g_message("%s: Restarting Directory Poller",
                  collector->name);
        pthread_mutex_unlock(&md->log_mutex);
        collector->active = TRUE;
        if (pthread_create(&(collector->thread), NULL,
                           mdCollectorFileNext, collector))
        {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "Couldn't open polling thread.");
            return FALSE;
        }
        break;
      default:
        collector->active = TRUE;
        pthread_mutex_lock(&md->log_mutex);
        g_message("%s: Restarting Listener on %s:%s",
                  collector->name,
                  ((collector->connspec.host) ? collector->connspec.host : "*"),
                  collector->connspec.svc);
        pthread_mutex_unlock(&md->log_mutex);

        if (pthread_create(&(collector->thread), NULL,
                           mdCollectorOpenListener, collector))
        {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                        "Couldn't open listening thread.");
            return FALSE;
        }

        break;
    }

    /* STAT COL restarts */
    collector->colStats.restarts++;

    return TRUE;
}

/**
 * mdCollectorStartListeners
 *
 */
gboolean
mdCollectorStartListeners(
    mdConfig_t         *md,
    mdCollector_t      *firstCol,
    GError             **err)
{
    mdCollector_t *collector = NULL;

    for (collector = firstCol; collector; collector = collector->next) {
        if (!collector->active) {
            switch (collector->collectionMethod) {
              case CM_DIR_POLL:
                pthread_mutex_lock(&md->log_mutex);
                g_message("%s: Starting Directory Poller", collector->name);
                pthread_mutex_unlock(&md->log_mutex);
                collector->active = TRUE;
                if (pthread_create(&(collector->thread), NULL,
                                   mdCollectorFileNext, collector))
                {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                                "Couldn't open polling thread.");
                    return FALSE;
                }
                break;
              case CM_SINGLE_FILE:
                continue;
                break;
              default:
                collector->active = TRUE;
                pthread_mutex_lock(&md->log_mutex);
                g_message("%s: Starting Listener on %s:%s",
                          collector->name,
                          ((collector->connspec.host)
                           ? collector->connspec.host : "*"),
                          collector->connspec.svc);
                pthread_mutex_unlock(&md->log_mutex);
                if (pthread_create(&(collector->thread), NULL,
                                   mdCollectorOpenListener, collector))
                {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_IO,
                                "Couldn't open listening thread.");
                    return FALSE;
                }
                break;
            }
        }
    }

    return TRUE;
}



/**
 * mdCollectorDestroy
 *
 *  Destroy the collector.  If active is FALSE, assume the collector's thread
 *  has not been started.
 *
 */
static void
mdCollectorDestroy(
    mdCollector_t      *coll,
    gboolean            active)
{
    if (coll->listenerSession) {
        fbSessionFree(coll->listenerSession);
        coll->listenerSession = NULL;
    } else if (!coll->fbuf) {
        if (coll->session) {
            fbSessionFree(coll->session);
        }
    }

    if (coll->lfp) {
        mdFlowSourceClose(coll);
    }

    if (coll->inspec) {
        g_free(coll->inspec);
    }

    if (coll->decompressWorkingDirectory) {
        g_free(coll->decompressWorkingDirectory);
    }

    if (COLLMETHOD_IS_SOCKET(coll->collectionMethod)) {
        g_free(coll->connspec.svc);
    }

    if (coll->move_dir) {
        g_free(coll->move_dir);
    }

    /* if the collector is active, and isn't a fixed file list, cancel the
     * monitoring thread (socket or dir poll) */
    if (coll->collectionMethod != CM_SINGLE_FILE && coll->active) {
        if (pthread_cancel(coll->thread)) {
            fprintf(stderr, "Error canceling %s collector thread\n",
                    coll->name);
        }
    }

    /* if destroyed due to presence of command line options,
       calling pthread_join will cause segfault. */
    if (coll->collectionMethod != CM_SINGLE_FILE && active) {
        pthread_join(coll->thread, NULL);
    }

    g_free((char *)coll->name);
    coll->name = NULL;
}


static void
mdCollectorFree(
    mdCollector_t      *collector)
{
    g_slice_free(mdCollector_t, collector);
}


/**
 *  Destroy all collectors.  If active is FALSE, assume no collectors' thread
 *  has been started.
 */
void
mdCollectorListDestroy(
    mdConfig_t    *cfg,
    gboolean      active)
{
    mdCollector_t *collector = NULL;

    while (cfg->firstCol) {
        detachHeadOfSLL((mdSLL_t **)&(cfg->firstCol), (mdSLL_t **)&collector);

        if (collector->active) {
            pthread_cond_signal(&collector->cond);
        }
        mdCollectorDestroy(collector, active);

        /* FIXME: I don't understand why mdCollectorDestroy() doesn't just
         * DESTROY THE COLLECTOR.  Why is some stuff in that function and
         * other stuff is below?  There is nothing here that checks the
         * existence of other collectors or only happens once. */

        if (collector->fbuf &&
            (NULL == collector->listener ||
                collector->collectionMethod != CM_TCP))
        {
            mdfBufFree(collector);
        }

        if (collector->recBuf) {
            g_slice_free1(collector->largestRecTemplateSize, collector->recBuf);
            collector->recBuf = NULL;
        }

        /* this collector's listener could be NULL when called during
         * configuration to deconflict CLI options and config file collectors.
         */
        if (collector->collectionMethod == CM_TCP && collector->listener) {
            fbListenerFree(collector->listener);
        }

        pthread_cond_destroy(&collector->cond);
        pthread_mutex_destroy(&collector->mutex);

        mdFilterDestroy(collector->filter);
        mdCollectorFree(collector);
    }

    /* free mdCollector_t */

}
