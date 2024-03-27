/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_main.c
 *
 *  Yaf mediator for filtering, DNS deduplication, and other mediator-like
 *  things
 *
 *  This file is responsible for handling command line options, calling
 *  the parser for the configuration file if needed, initializing the
 *  collecors and exporters, setting up the stats thread, and kicking off the
 *  main processing.
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

#define MEDIATOR_MAIN_SOURCE 1

#include "mediator_autohdr.h"
#include "mediator_inf.h"
#include "mediator_core.h"
#include "mediator_filter.h"
#include "mediator_dns.h"
#include "mediator_stat.h"
#include "mediator_log.h"
#include "mediator_dedup.h"
#include "mediator_structs.h"
#include <glib.h>
#include <time.h>
#include <sys/time.h>
#include <poll.h>
#include <pwd.h>
#include <grp.h>

#ifdef ENABLE_SKIPSET
#include SKIPSET_HEADER_NAME
#ifdef HAVE_SILK_SKIPADDR_H
#include <silk/skipaddr.h>
#endif
int                         app_registered;
mdIPSet_t                  *md_ipset = NULL;
#endif


/* This gets defined in mediator_structs.h when MEDIATOR_MAIN_SOURCE is
 * defined */
/* mdConfig_t   md_config; */


/* TODO:
 * highlight which of these globals are just for command line options parsing
 * try and move the rest into state given to collectors and exporters
 * could lead to multithreading, or at least cleaner code
 */
int                         md_stats_timeout = 300;
char                       *md_pidfile = NULL;
char                       *md_ipsetfile = NULL;
fbInfoElement_t            *user_elements = NULL;

volatile int                md_quit = 0;

static uid_t                new_user = 0;
static gid_t                new_group = 0;
static gboolean             did_become = FALSE;
static int                  emit_thread_interrupt[2];

/* command line values */
static char                *moveDir = NULL;
static gint                 pollingInterval = 0;
static gboolean             noLockedFiles = FALSE;
static gboolean             md_daemon = FALSE;
static char                *ipfixPort = NULL;
static const char          *exportPort = NULL;
static char                *md_conf_file = NULL;
static char                *ipfixInput = NULL;
static char                *outputMode = NULL;
static char               **md_export_field_list;
static int                  export_rotate = 0;
static int                  sleep_usecs = 0;
static gint                 udpTempTimeout = 0;
static const char          *outspec = NULL;
static char               **inspecs = NULL;
static char                *cmdLineLog = NULL;
static char                *cmdLineLogdir = NULL;
static gboolean             cmdLineVerbose = FALSE;
static gboolean             cmdLineQuiet = FALSE;
static gboolean             md_test_config = FALSE;
static gboolean             md_version = FALSE;
static gboolean             md_print_headers = FALSE;
static gboolean             md_disable_metadata_export = FALSE;
static char                *become_user = NULL;
static char                *become_group = NULL;

#define FLUSH_TIMEOUT   300 /* 5 minutes in seconds */

/*
 * This text gets printed by --help after the program name and before the list
 * of options.
 *
 * This text can fill the full 80-columns of the traditional terminal.
 * Instead of using 80-character text lines that would wrap in the source
 * code, use 40-character lines and include the "\n" on alternating lines.
 *
 * Text goes from column 5 to col 45, HERE---v
 */
#define MD_HELP_SUMMARY                                 \
    "Reads IPFIX by listening on sockets, by "          \
    "polling directories, or by reading\n"              \
    "files. Writes IPFIX to sockets or writes"          \
    " IPFIX, JSON, or TEXT to a file or to\n"           \
    "rotating files in directories. When "              \
    "using a config file, many comamnd line\n"          \
    "options are ignored. When not using a "            \
    "config file, all inputs must be the same\n"        \
    "type, and the default is to read from "            \
    "stdin and write to stdout."

#define WRAP "\n\t\t\t\t"
static GOptionEntry md_core_option[] = {
    {"config", 'c', 0, G_OPTION_ARG_STRING, &md_conf_file,
     "Name of a configuration file. []", "file_name"},

    {G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_STRING_ARRAY, &inspecs,
     "File, Directory, or Host/I.P. to listen to [-]", "INPUTS"},
    {"ipfix-input", 0, 0, G_OPTION_ARG_STRING, &ipfixInput,
     "Mode of import transport when INPUT is a host" WRAP
     "or an IP address (tcp, udp) []", "mode"},
    {"ipfix-port", 'p', 0, G_OPTION_ARG_STRING, &ipfixPort,
     "Listening port when --ipfix-input is given" WRAP
     "and INPUT is a host [" MD_DEFAULT_LISTEN_PORT "]", "port"},
    {"polling-interval", 0, 0, G_OPTION_ARG_INT, &pollingInterval,
     "How long to sleep between polls of the INPUT(s)" WRAP
     "which must name existing directory(ies) [30]", "secs"},
    {"move-dir", 0, 0, G_OPTION_ARG_STRING, &moveDir,
     "Where to move files in the INPUT directory(ies)" WRAP
     "after processing. If not specified, the files" WRAP
     "are deleted. []", "path"},
    {"no-locked-files", 0, 0, G_OPTION_ARG_NONE, &noLockedFiles,
     "(Unimplemented.) Disables reading files that are" WRAP
     "locked when INPUT is a directory", NULL},

    {"out", 'o', 0, G_OPTION_ARG_STRING, &outspec,
     "File, Pathname-Template, or Host/IP to write the" WRAP
     "output [-]", "OUTPUT"},
    {"output-mode", 'm', 0, G_OPTION_ARG_STRING, &outputMode,
     "Method of export transport or export format" WRAP
     "when writing to files (tcp, udp, text, json) []", "mode"},
    {"export-port", 0, 0, G_OPTION_ARG_STRING, &exportPort,
     "IPFIX export port when OUTPUT is a host [" MD_DEFAULT_LISTEN_PORT "]",
     "port"},
    {"rotate", 0, 0, G_OPTION_ARG_INT, &export_rotate,
     "How often to rotate output files when writing" WRAP
     "to a directory [3600, 1hr]. Causes OUTPUT to be" WRAP
     "treated as a pathname-template.", "sec"},
    {"fields", 'f', 0, G_OPTION_ARG_STRING_ARRAY, &md_export_field_list,
     "Flow fields to print in TEXT or JSON exporting" WRAP
     "mode. []", "fields"},
    {"print-headers", 'h', 0, G_OPTION_ARG_NONE, &md_print_headers,
     "Enables column headers for TEXT exporters.", NULL},

    {"no-stats", 0, 0, G_OPTION_ARG_NONE, &md_config.no_stats,
     "Disables decode/export of stats and tombstone" WRAP
     "records", NULL},
    {"preserve-obdomain", 0, 0, G_OPTION_ARG_NONE, &md_config.preserve_obdomain,
     "Do not overwrite the observation domain element" WRAP
     "in the incoming records", NULL},
    {"rewrite-ssl-certs", 0, 0, G_OPTION_ARG_NONE, &md_config.rewrite_ssl_certs,
     "Rewrites SSL certs for IPFIX exporters", NULL},
    {"disable-metadata-export", 0, 0, G_OPTION_ARG_NONE,
     &md_disable_metadata_export,
     "Disables information-element and template" WRAP
     "metadata in the IPFIX output", NULL},
    {"ipsetfile", 0, 0, G_OPTION_ARG_STRING, &md_ipsetfile,
#ifdef ENABLE_SKIPSET
     "Path to an IPset file used for labeling records []",
#else
     "Exits the program due to missing IPset support",
#endif
     "ipset"},
    {"sleep", 's', 0, G_OPTION_ARG_INT, &sleep_usecs,
     "Number of microseconds to sleep between" WRAP
     "exporting IPFIX messages [0]", "usec"},
    {"udp-temp-timeout", 0, 0, G_OPTION_ARG_INT, &udpTempTimeout,
     "(Unimplemented.) Template timeout period when" WRAP
     "writing to UDP [600, 10min]", "secs"},

    {"log", 'l', 0, G_OPTION_ARG_STRING, &cmdLineLog,
     "Destination for log messages and errors; one" WRAP
     "of a file name, a syslog facility, or [stderr]", "logdest"},
    {"log-dir", 0, 0, G_OPTION_ARG_STRING, &cmdLineLogdir,
     "The directory where the log files are written []", "log_path"},
    {"verbose", 'v', 0, G_OPTION_ARG_NONE, &cmdLineVerbose,
     "Changes loglevel from default WARNING to DEBUG.", NULL},
    {"quiet", 'q', 0, G_OPTION_ARG_NONE, &cmdLineQuiet,
     "Changes loglevel from default WARNING to QUIET.", NULL},
    {"daemonize", 'd', 0, G_OPTION_ARG_NONE, &md_daemon,
     "Daemonizes super_mediator", NULL},
    {"pidfile", 0, 0, G_OPTION_ARG_STRING, &md_pidfile,
     "Complete path to the process ID file when" WRAP
     "running as a daemon []", "pidpath"},
    {"become-user", 'U', 0, G_OPTION_ARG_STRING, &become_user,
     "User to become after setup if started as root []", "user"},
    {"become-group", 0, 0, G_OPTION_ARG_STRING, &become_group,
     "Group to become if started as root []", "group"},

    {"test-config", '\0', 0, G_OPTION_ARG_NONE, &md_test_config,
     "Exit after parsing the config file", NULL},
    {"version", 'V', 0, G_OPTION_ARG_NONE, &md_version,
     "Print application version and exit", NULL},
    { NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }

};

static void
mdFatal(
    const char *format,
    ...)
    __attribute__((format (printf, 1, 2)))
    __attribute__((__noreturn__));

static void
mdDaemonize(
    void);

static void
mdParseOptions(
    int *argc,
    char **argv[]);

static void
sigHandler(
    void);

static gboolean
mdPrivc_Setup(
    GError **err);

static gboolean
mdPrivc_Become(
    GError          **err);

static void
smFreeMaps(
    mdConfig_t          *cfg);

/**
 * mdPrintVersion
 *
 *
 */
static void
mdPrintVersion(
    void)
{
    GString *resultString = g_string_sized_new(512);

    g_string_append_printf(resultString, "super_mediator version %s\n"
                           "Build Configuration: \n",  VERSION);
#ifdef FIXBUF_VERSION
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "Fixbuf version:", FIXBUF_VERSION);
#endif
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "MySQL support:",
#ifdef HAVE_MYSQL
                           "YES"
#else
                           "NO"
#endif
                           );

    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "OpenSSL support:",
#ifdef HAVE_OPENSSL
                           "YES"
#else
                           "NO"
#endif
                           );
    g_string_append_printf(resultString, "    * %-32s  %s\n",
                           "SiLK IPSet support:",
#ifdef ENABLE_SKIPSET
                           "YES"
#else
                           "NO"
#endif
                           );

    g_string_append(resultString,
                    "Copyright (C) 2012-2023 Carnegie Mellon University\n"
                    "GNU General Public License (GPL) Rights "
                    "pursuant to Version 2, June 1991\n");
    g_string_append(resultString,
                    "Send bug reports, feature requests, and comments"
                    " to netsa-help@cert.org.\n");

    fprintf(stdout, "%s", resultString->str);

    g_string_free(resultString, TRUE);
}


/**
 * mdSetEmitTimer
 *
 * Separate thread that runs when the mediator is to run
 * forever.  This will emit the buffer and flush any
 * export files every 5 minutes in the case that we are not
 * receiving any data.
 * It will also print mediator stats if the mediator is
 * configured to do so.
 *
 */
static void *
mdSetEmitTimer(
    void           *data)
{
    mdContext_t       *ctx = (mdContext_t *)data;
    mdConfig_t        *cfg = ctx->cfg;
    time_t            now;
    time_t            next_flush;
    time_t            next_stats;
    time_t            next_event;
    int               rc;
    struct pollfd     poller[1];
    GError            *err = NULL;

    poller[0].fd = emit_thread_interrupt[0];
    poller[0].events = POLLIN;
    poller[0].revents = 0;

    now = time(NULL);
    next_flush = now + FLUSH_TIMEOUT;
    next_stats = now + md_stats_timeout;

    while (!md_quit) {
        next_event = MIN(next_flush, next_stats);
        while (now < next_event && !md_quit) {
            rc = poll(poller, 1, (next_event - now) * 1000);
            now = time(NULL);
            if (1 == rc || md_quit) {
                /* pipe closed or poll() interrupted and md_quit is set */
                return NULL;
            }
            if (0 == rc) {
                /* timed out */
                break;
            }
        }
        /* only flush every 5 minutes */
        if (now >= next_flush) {
            next_flush = now + FLUSH_TIMEOUT;
            mdExporterConnectionReset(cfg, &(ctx->err));
            now = time(NULL);
        }
        if (!cfg->no_stats && now >= next_stats) {
            next_stats = now + md_stats_timeout;
            if (cfg->gen_tombstone){
                mdSendTombstoneRecord(ctx, &err);
            }
            mdStatLogAllStats(ctx);
            now = time(NULL);
        }
        /* rotate log */
        if (mdLoggerCheckRotate(cfg, now)) {
            now = time(NULL);
        }
    }

    return NULL;
}


static void
mdQuit(
    int signum)
{
    MD_UNUSED_PARAM(signum);
    md_quit++;
    mdInterruptListeners(&md_config);
}


/**
 * main
 *
 *
 */
int
main(
    int      argc,
    char     *argv[])
{
    mdContext_t     ctx;
    GError         *error       = NULL;
    pthread_t       to_thread;
    char           *errmsg      = NULL;
    int             pterror;

    ctx.cfg = NULL;
    memset(&ctx.coreStats, 0, sizeof(mdCoreStats_t));
    ctx.err = NULL;

    ctx.cfg = &md_config;

    pthread_mutex_init(&(md_config.log_mutex), NULL);

    /* parse all the options */
    mdParseOptions(&argc, &argv);

    g_message("super_mediator starting");

    /* creates and starts timer for stats emission */
    mdStatInit();

    /*
     *  this program runs forever, until interrupted, handle
     *  the interrupt gracefully and exit by installing these
     *  handlers
     */
    sigHandler();

    /* build templates to use to compare received templates for exact matches */
    if (!mdCoreInit(&error)) {
        mdFatal("Fatal: Unable to initialize core: %s", error->message);
    }

    /* open input */

    /* loop through collectors to open files and create Fbufs
     * set callback, no longer adding templates
     * this does not start the collectors
     */
    if (!mdCollectorsInit(ctx.cfg, ctx.cfg->firstCol, &error)) {
        mdFatal("Fatal: Unable to initialize all collectors: %s",
                error->message);
    }

    /* create a pipe for interruption from sighandler */
    if (-1 == pipe(emit_thread_interrupt)) {
        mdFatal("Fatal: Unable to create pipe: %s", strerror(errno));
    }

    /* create the stats thread */
    if ((pterror = pthread_create(&to_thread, NULL, mdSetEmitTimer, &ctx))) {
        mdFatal("Fatal: Error starting statistics thread: %s",
                strerror(pterror));
    }

    /* creates any templates needed by this super mediator to produce records
     * and emit them, such as dedup.
     * sets up any state needed
     */
    if (!mdExportersInit(ctx.cfg, ctx.cfg->firstExp, &error)) {
        mdFatal("Fatal: Unable to initialize all exporters: %s",
                error->message);
    }

    fprintf(stderr, "Initialization Successful, starting...\n");

    /* all one-time setup work complete, now open connections and read data */

    /** wait for connections*/
    while (!md_quit) {

        /* if active
         * does nothing for SINGLE_FILE
         * creates thread for file poller if DIRECTORY
         * starts openListener thread for sockets
         * marks dir and socket as active
         */
        if (!mdCollectorStartListeners(ctx.cfg, ctx.cfg->firstCol, &error)) {
            fprintf(stderr, "Couldn't start listener threads %s\n",
                    error->message);
            md_quit = 1;
            break;
        }

        if (!mdPrivc_Become(&error)) {
            if (g_error_matches(error, MD_ERROR_DOMAIN, MD_ERROR_NODROP)) {
                g_warning("Running as root in --live mode, "
                          "but not dropping privilege");
                g_clear_error(&error);
            } else {
                md_quit = 1;
                g_warning("Cannot drop privilege: %s", error->message);
                break;
            }
        }

        /* manage threads, and process flow data */
        /* this is what really starts super mediator (in mediator_open) */
        if (!(mdCollectorWait(&ctx, &error))) {
            break;
        }
    }

    if (error) {
        errmsg = g_strdup_printf("super_mediator terminating on error: %s",
                                 error->message);
        g_clear_error(&error);
    }

    close(emit_thread_interrupt[1]);
    pthread_join(to_thread, NULL);

    mdStatLogAllStats(&ctx);

    mdCollectorListDestroy(ctx.cfg, TRUE);
    mdExporterDestroy(&ctx, &error);
    mdFilterDestroy(ctx.cfg->sharedFilter);
    ctx.cfg->sharedFilter = NULL;
    smFreeMaps(ctx.cfg);


    if (user_elements) {
        fbInfoElement_t *tie = user_elements;
        for (; tie->name; tie++) {
            /* free each name */
            g_free((char *)(tie->name));
        }
        g_free(user_elements);
    }

    fbInfoModelFree(mdInfoModel());

    pthread_mutex_destroy(&ctx.cfg->log_mutex);

    if (errmsg) {
        g_warning("%s", errmsg);
        g_free(errmsg);
    } else {
        g_debug("super_mediator Terminating");
    }

    /** finished with no problems */
    return 0;
}


#define CHK_IGNORED(switch_name, test)                                  \
    do {                                                                \
        if ( test ) {                                                   \
            fprintf(stderr, "Note: Config file given; ignoring --%s\n", \
                    switch_name);                                       \
        }                                                               \
    } while(0)

static void
warnIgnoredArgs(
    void)
{
    if (inspecs) {
        fprintf(stderr, "Note: Config file given;"
                " ignoring extra command line argument%s (%s%s)\n",
                ((inspecs[1]) ? "s" : ""), inspecs[0],
                ((inspecs[1]) ? ",..." : ""));
        g_strfreev(inspecs);
    }
    CHK_IGNORED("ipfix-port", ipfixPort);
    CHK_IGNORED("ipfix-input", ipfixInput);
    CHK_IGNORED("polling-interval", pollingInterval);
    CHK_IGNORED("move-dir", moveDir);
    CHK_IGNORED("no-locked-files", noLockedFiles);

    CHK_IGNORED("out", outspec);
    CHK_IGNORED("output-mode", outputMode);
    CHK_IGNORED("export-port", exportPort);
    CHK_IGNORED("rotate", export_rotate);
    CHK_IGNORED("fields", md_export_field_list);
    CHK_IGNORED("print-headers", md_print_headers);

    /* CHK_IGNORED("no-stats", md_config.no_stats); */
    /* CHK_IGNORED("preserve_obdomain", md_config.preserve_obdomain); */
    /* CHK_IGNORED("rewrite-ssl-certs", md_config.rewrite_ssl_certs); */
    CHK_IGNORED("disable-metadata-export", md_disable_metadata_export);
    /* CHK_IGNORED("sleep", sleep_usecs); */
    CHK_IGNORED("udp-temp-timeout", udpTempTimeout);

    /* CHK_IGNORED("log", cmdLineLog); */
    /* CHK_IGNORED("log-dir", cmdLineLogdir); */
    /* CHK_IGNORED("verbose", cmdLineVerbose); */
    /* CHK_IGNORED("quiet", cmdLineQuiet); */
    /* CHK_IGNORED("daemonize", md_daemon); */
    /* CHK_IGNORED("pidfile", md_pidfile); */
}


/*
 *  Format and print an error message to stderr with an additional newline and
 *  exit the program.
 *
 *  This is intended to be used while checking command line arguments.
 */
static void
mdFatal(
    const char *format,
    ...)
{
    va_list ap;

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}


static void
mdConfigureCommandLineCollector(
    mdCollector_t     *collector,
    const char        *inspec)
{
    GError *err = NULL;

    if (ipfixPort && !mdCollectorSetPort(collector, ipfixPort, &err)) {
        mdFatal("Error setting --port: %s", err->message);
    }
    if (pollingInterval &&
        !mdCollectorSetPollingInterval(collector, pollingInterval, &err))
    {
        mdFatal("Error setting --polling-interval: %s", err->message);
    }
    if (moveDir && !mdCollectorSetMoveDir(collector, moveDir, &err)) {
        mdFatal("Error setting --move-dir: %s", err->message);
    }
    if (noLockedFiles) {
        mdCollectorSetNoLockedFilesMode(collector);
    }

    if (!mdCollectorSetInSpec(collector, inspec, &err)) {
        mdFatal("%s", err->message);
    }

    if (CM_DIR_POLL == collector->collectionMethod) {
        if (!moveDir) {
            /* if quiet is false and log messages are not going to stderr,
             * write a message to stderr in addition to writing to log */
            if (FALSE == cmdLineQuiet &&
                !(NULL == cmdLineLogdir &&
                  (NULL == cmdLineLog || 0 == g_strcmp0("stderr", cmdLineLog))))
            {
                fprintf(stderr,
                        "No Move Directory Specified. "
                        "Incoming files will be deleted after processing.");
            }
            g_warning("No Move Directory Specified.");
            g_warning("Incoming files will be deleted after processing.");
            mdCollectorSetDeleteFiles(collector, TRUE, NULL);
        }

    } else if (CM_SINGLE_FILE == collector->collectionMethod) {
        /* ensure command line file exists */
        if (('-' == inspec[0]) && (strlen(inspec) == 1)) {
            /* stdout; assume okay */
        } else if (g_file_test(inspec, G_FILE_TEST_IS_DIR)) {
            mdFatal("Incoming path \"%s\" is a directory; must specify either"
                    " --move-dir or --polling-interval to watch a directory",
                    inspec);
        } else if (!g_file_test(inspec, G_FILE_TEST_EXISTS)) {
            mdFatal("Incoming path \"%s\" does not name an existing file",
                    inspec);
        }
    }
}

static gboolean
mdConfigureCommandLineCollectors(
    mdConfig_t *cfg)
{
    mdCollectionMethod_t collectionMethod = CM_NONE;
    const char          *defaultInspecs[] = {"-", NULL};
    mdCollector_t      **nextCol = &cfg->firstCol;
    char **iptr;

    /* To set collection method, use ipfix-input if given; otherwise assume
     * directory-poll if move-dir or polling-interval was given; otherwise
     * assume single-file */
    if (ipfixInput) {
        if (0 == g_ascii_strcasecmp(ipfixInput, "tcp")) {
            collectionMethod = CM_TCP;
        } else if (0 == g_ascii_strcasecmp(ipfixInput, "udp")) {
            collectionMethod = CM_UDP;
        } else {
            mdFatal("Unrecognized ipfix-input \"%s\"; must be tcp or udp",
                    ipfixInput);
        }
    } else if (pollingInterval || moveDir) {
        collectionMethod = CM_DIR_POLL;
    } else {
        collectionMethod = CM_SINGLE_FILE;
    }

    /* If no inputs, read from stdin */
    if (inspecs == NULL) {
        inspecs = g_strdupv((gchar **)defaultInspecs);
    }

    /* Create and configure each collector */
    for (iptr = inspecs; *iptr; ++iptr) {
        mdCollector_t *collector = mdNewCollector(collectionMethod, NULL);
        if (!collector) {
            return FALSE;
        }

        *nextCol = collector;
        mdConfigureCommandLineCollector(collector, *iptr);
        nextCol = &collector->next;
    }

    return TRUE;
}


static gboolean
mdConfigureCommandLineExporter(
    mdConfig_t *cfg)
{
    mdExportFormat_t exportFormat = EF_NONE;
    mdExportMethod_t exportMethod = EM_NONE;
    mdExporter_t *exporter;
    GError       *err = NULL;

    if (NULL == outputMode) {
        exportFormat = EF_IPFIX;
    } else if (0 == g_ascii_strcasecmp(outputMode, "tcp")) {
        exportFormat = EF_IPFIX;
        exportMethod = EM_TCP;
    } else if (0 == g_ascii_strcasecmp(outputMode, "udp")) {
        exportFormat = EF_IPFIX;
        exportMethod = EM_UDP;
    } else if (0 == g_ascii_strcasecmp(outputMode, "text")) {
        exportFormat = EF_TEXT;
    } else if (0 == g_ascii_strcasecmp(outputMode, "json")) {
        exportFormat = EF_JSON;
    } else if (0 == g_ascii_strcasecmp(outputMode, "ipfix")) {
        exportFormat = EF_IPFIX;
    } else {
        mdFatal("Unknown output-mode \"%s\"", outputMode);
    }

    /* if no --output-mode, assume single-file unless --rotate was given  */
    if (EM_NONE == exportMethod) {
        exportMethod = (export_rotate ? EM_ROTATING_FILES : EM_SINGLE_FILE);
    }

    exporter = mdNewExporter(exportFormat, exportMethod, NULL);

    /* set output location */
    if (EXPORTMETHOD_IS_SOCKET(exportMethod)) {
        /* this should never fail, but use the standard idiom */
        if (!mdExporterSetHost(exporter, outspec, &err)) {
            mdFatal("Error setting export host: %s", err->message);
        }
        /* set default port if none given */
        if (NULL == exportPort) {
            exportPort = MD_DEFAULT_EXPORT_PORT;
        }
    } else {
        /* default to stdout */
        if (NULL == outspec) {
            outspec = "-";
        }
        if (!mdExporterSetFileSpec(exporter, outspec, &err)) {
            mdFatal("Error setting output location: %s", err->message);
        }
    }

    /* Call "setter" functions based on command line arguments */

    if (exportPort && !mdExporterSetPort(exporter, exportPort, &err)) {
        mdFatal("Error setting --export-port: %s", err->message);
    }
    if (export_rotate &&
        !mdExporterSetRotateInterval(exporter, export_rotate, &err))
    {
        mdFatal("Error setting --rotate: %s", err->message);
    }
    if (md_disable_metadata_export &&
        !mdExporterSetMetadataExport(exporter, FALSE, FALSE, &err))
    {
        mdFatal("Error setting --disable-metadata-export: %s", err->message);
    }

    if (md_print_headers && !mdExporterSetPrintHeader(exporter, &err)) {
        mdFatal("Error setting --print-headers: %s", err->message);
    }
    if (udpTempTimeout) {
        if (!mdExporterSetUdpTemplateTimeout(exporter, udpTempTimeout, &err)){
            mdFatal("Error setting --udp-temp-timeout: %s", err->message);
        }
    }
    if (md_export_field_list) {
        mdFieldEntry_t *first_item = NULL;
        mdFieldEntry_t **item = &first_item;
        gboolean        dpi = FALSE;
        gchar         **sa;
        unsigned int    n;

        if (!EXPORTFORMAT_IS_TEXT_OR_JSON(exportFormat)) {
            mdFatal("Error setting --fields:"
                    " Only TEXT and JSON Exporters support setting fields");
        }

        sa = g_strsplit(*md_export_field_list, ",", -1);
        for (n = 0; sa[n] && *sa[n]; ++n) {
            /* remove any leading and trailing whitespace */
            g_strchug(sa[n]);
            g_strchomp(sa[n]);
            if (g_ascii_strcasecmp(sa[n], "DPI") == 0) {
                mdExporterCustomListDPI(exporter);
                dpi = TRUE;
                continue;
            }

            *item = mdMakeFieldEntryFromName(sa[n], FALSE, &err);
            if (!*item) {
                mdFatal("Error setting --fields: %s", err->message);
            }
            item = &((*item)->next);
        }
        if (dpi && !first_item) {
            /* FIXME: Cannot actually create a field "none" since "none"
             * is not a valid IE. */

            /* FIXME: Code to make a list of "none" exists in the
             * Exporter, and I do not think this block is needed.  It
             * certainly SHOULD be true that this logic only need to exist
             * within the Exporter. */

            /* just DPI was chosen - create list and set to None */
            first_item = mdMakeFieldEntryFromName("none", TRUE, &err);
            if (!first_item) {
                mdFatal("Error setting --fields: %s", err->message);
            }
            mdExporterEnableFlowsWithDpiOnly(exporter, NULL);
        }
        if (!mdExporterSetCustomList(exporter, first_item, &err)) {
            mdFatal("Error setting --fields: %s", err->message);
        }
        g_strfreev(sa);
    }

    cfg->firstExp = exporter;
    return TRUE;
}


/**
 * mdParseOptions
 *
 * parses the command line options
 *
 */
static void
mdParseOptions(
    int *argc,
    char **argv[])
{
    GOptionContext     *ctx;
    GError             *err = NULL;
    mdCollector_t      *collector;
    mdExporter_t       *exporter;

    ctx = g_option_context_new(" - Mediator Options");

    g_option_context_add_main_entries(ctx, md_core_option, NULL);
    g_option_context_set_help_enabled(ctx, TRUE);
    g_option_context_set_summary(ctx, MD_HELP_SUMMARY);

    if (!g_option_context_parse(ctx, argc, argv, &err)) {
        mdFatal("option parsing failed: %s", err->message);
    }

    if (md_version) {
        mdPrintVersion();
        exit(0);
    }

    /* Configuration file has precedence over all */
    if (md_conf_file) {
        if (!mdConfigfileParse(md_conf_file, &err)) {
            mdFatal("%s", err->message);
        }
        if (md_test_config) {
            if (!cmdLineQuiet) {
                fprintf(stderr,
                        "Successfully parsed configuration file \"%s\"\n",
                        md_conf_file);
            }
            exit(0);
        }
    }

    /* --become-user and --become-group cannot be set in config file */
    if (!mdPrivc_Setup(&err)) {
        mdFatal("Error: %s", err->message);
    }

    /* LOGGING OPTIONS -- Allow the user to set a location only if none is
     * given in the config file. */
    if (cmdLineLog && !mdLoggerSetDestination(cmdLineLog, &err)) {
        /* if error is not about setting multiple log destinations, exit the
         * program.  otherwise, clear the error and print a message about
         * ignoring the command line switch */
        if (0 != g_strcmp0(err->message, "multiple log")) {
            mdFatal("Cannot set --log: %s", err->message);
        }
        g_clear_error(&err);
        if (!cmdLineQuiet) {
            fprintf(stderr, "Note: Config file includes a log setting;"
                    " ignoring --log\n");
        }
    }
    if (cmdLineLogdir && !mdLoggerSetDirectory(cmdLineLogdir, &err)) {
        /* if error is not about setting multiple log destinations, exit the
         * program.  also exit if --log was given.  otherwise, clear the error
         * and print a message about ignoring the command line switch */
        if (0 != g_strcmp0(err->message, "multiple log") || cmdLineLog) {
            mdFatal("Cannot set --log-dir: %s", err->message);
        }
        g_clear_error(&err);
        if (!cmdLineQuiet) {
            fprintf(stderr, "Note: Config file includes a log setting;"
                    " ignoring --log-dir\n");
        }
    }

    if (!md_conf_file) {
        /* COLLECTOR OPTIONS */
        if (!mdConfigureCommandLineCollectors(&md_config)) {
            exit(1);
        }
        g_strfreev(inspecs);

        /* EXPORTER OPTIONS */
        if (!mdConfigureCommandLineExporter(&md_config)) {
            exit(1);
        }

    } else if (!cmdLineQuiet) {
        warnIgnoredArgs();
    }

    /* Logging options */
    if (!mdLoggerStart(cmdLineVerbose, cmdLineQuiet, md_daemon, &err)) {
        mdFatal("Error starting logging: %s", err->message);
    }

    /* --sleep cannot be set in config file */
    if (sleep_usecs < 1000000) {
        md_config.usec_sleep = sleep_usecs;
    } else {
        g_warning("Maximum sleep time is 1000000");
        md_config.usec_sleep = sleep_usecs;
    }

    if (md_ipsetfile) {
#ifdef ENABLE_SKIPSET
        md_ipset = mdUtilIPSetOpen(md_ipsetfile, &err);
        if (NULL == md_ipset) {
            mdFatal("Error with --ipsetfile=\"%s\": %s",
                    md_ipsetfile, err->message);
        }
#else
        mdFatal("NO SUPPORT FOR IPSETs.  Please Install SiLK IPSet Library.");
#endif  /* ENABLE_SKIPSET */
    }

    for (collector = md_config.firstCol; collector; collector = collector->next)
    {
        if (!mdCollectorVerifySetup(collector, &err)) {
            mdFatal("Error verifying Collector %s: %s",
                    mdCollectorGetName(collector), err->message);
        }
    }

    md_config.flowDpiStrip = FALSE;
    for (exporter = md_config.firstExp; exporter; exporter = exporter->next) {
        if (!mdExporterVerifySetup(exporter, &err)) {
            mdFatal("Error verifying Exporter %s: %s",
                    mdExporterGetName(exporter), err->message);
        }
        if (exporter->flowDpiStrip) {
            md_config.flowDpiStrip = TRUE;
        }
    }

    /* md_stats_timeout is only set via the config file */
    if (md_stats_timeout == 0) {
        g_warning("Turning off stats export.");
        md_stats_timeout = 300;
        md_config.no_stats = TRUE;
    }

    /* --daemon is only supported from the command line */
    if (md_daemon) {
        mdDaemonize();
    }

    g_option_context_free(ctx);
}


/**
 * smExit
 *
 * exit handler for super_mediator
 *
 */
static void
mdExit(
    void)
{
    if (md_pidfile) {
        unlink(md_pidfile);
    }
}


/**
 * sigHandler
 *
 * this gets called from various system signal handlers.  It is used to
 * provide a way to exit this program cleanly when the user wants to
 * kill this program
 *
 * @param signalNumber the number of the signal that this handler is
 *        getting called for
 *
 */

static void
sigHandler(
    void)
{
    struct sigaction sa, osa;

    sa.sa_handler = mdQuit;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGINT,&sa,&osa)) {
        g_error("sigaction(SIGINT) failed: %s", strerror(errno));
    }

    sa.sa_handler = mdQuit;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM,&sa,&osa)) {
        g_error("sigaction(SIGTERM) failed: %s", strerror(errno));
    }
}

static void
mdDaemonize(
    void)
{
    pid_t pid;
    int rv = -1;
    char str[256];
    int fp;

    if (chdir("/") == -1) {
        rv = errno;
        g_warning("Cannot change directory: %s", strerror(rv));
        exit(-1);
    }

    if ((pid = fork()) == -1) {
        rv = errno;
        g_warning("Cannot fork for daemon: %s", strerror(rv));
        exit(-1);
    } else if (pid != 0) {
        g_debug("Forked child %ld.  Parent exiting", (long)pid);
        _exit(EXIT_SUCCESS);
    }

    setsid();

    umask(0022);

    rv = atexit(mdExit);
    if (rv == -1) {
        g_warning("Unable to register function with atexit(): %s",
                  strerror(rv));
        exit(-1);
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);

    if (md_pidfile) {
        fp = open(md_pidfile, O_WRONLY|O_CREAT|O_TRUNC, 0640);
        if (fp < 0) {
            g_warning("Unable to open pid file \"%s\": %s",
                      md_pidfile, strerror(errno));
            exit(1);
        }
        sprintf(str, "%d\n", getpid());
        if (write(fp, str, strlen(str)) <= 0) {
            g_warning("Unable to write pid to file \"%s\": %s",
                      md_pidfile, strerror(errno));
        }
        if (close(fp) == -1) {
            g_warning("Unable to close pid file \"%s\": %s",
                      md_pidfile, strerror(errno));
        }
    } else {
        g_debug("pid: %d", getpid());
    }
}

static void
smFreeMaps(
    mdConfig_t *cfg)
{
    unsigned int i = 0;

    if (cfg->maps) {
        smFieldMap_t *cmap = NULL;
        smFieldMap_t *nmap = NULL;
        for (cmap = cfg->maps; cmap; cmap = cmap->next) {
            smHashTableFree(cmap->table);
            g_free(cmap->name);
            for (i = 0; i < cmap->count; i++) {
                g_free(cmap->labels[i]);
            }
            free(cmap->labels);
        }
        cmap = cfg->maps;
        while (cmap) {
            detachHeadOfSLL((mdSLL_t **)&(cfg->maps),
                            (mdSLL_t **)&cmap);
            nmap = cmap->next;
            g_slice_free(smFieldMap_t, cmap);
            cmap = nmap;
        }
     }
}


/**
 *  Check configuration of --become-user and --become-group.
 */
static gboolean
mdPrivc_Setup(
    GError **err)
{
    struct passwd *pwe = NULL;
    struct group *gre = NULL;

    if (geteuid() == 0) {
        /* We're root. Parse user and group names. */
        if (become_user) {
            if (!(pwe = getpwnam(become_user))) {
                g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                            "Cannot become user %s: %s.",
                            become_user, strerror(errno));
                return FALSE;
            }

            /* By default, become new user's user and group. */
            new_user = pwe->pw_uid;
            new_group = pwe->pw_gid;
            if (become_group) {
                if (!(gre = getgrnam(become_group))) {
                    g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                                "Cannot become group %s: %s.",
                                become_group, strerror(errno));
                    return FALSE;
                }

                /* Override new group if set */
                new_group = gre->gr_gid;
            }
        }
    } else {
        /* We're not root. If we have options, the user is confused, and
           we should straighten him out by killing the process. */
        if (become_user) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Cannot become user %s: not root.",
                        become_user);
            return FALSE;
        }
        if (become_group) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "Cannot become group %s: not root.",
                        become_group);
            return FALSE;
        }
    }

    /* All done. */
    return TRUE;
}


/**
 *  Change identity to those in --become-user and --become-group.
 */
static gboolean
mdPrivc_Become(
    GError          **err)
{
    /* Die if we've already become */
    if (did_become) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "not dropping privileges, already did so");
        return FALSE;
    }

    /* Short circuit if we're not root */
    if (geteuid() != 0) return TRUE;

    /* Allow app to warn if not dropping */
    if (new_user == 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_NODROP,
                    "not dropping privileges (use --become-user to do so)");
        return FALSE;
    }

    /* Okay. Do the drop. */

    /* Drop ancillary group privileges while we're still root */
    if (setgroups(1, &new_group) < 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "couldn't drop ancillary groups: %s", strerror(errno));
        return FALSE;
    }
#ifdef LINUX_PRIVHACK
    /* Change to group */
    if (setregid(new_group, new_group) < 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "couldn't become group %u: %s", new_group, strerror(errno));
        return FALSE;
    }

    /* Lose root privileges */
    if (setreuid(new_user, new_user) < 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "couldn't become user %u: %s", new_user, strerror(errno));
        return FALSE;
    }
#else  /* LINUX_PRIVHACK */
    /* Change to group */
    if (setgid(new_group) < 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "couldn't become group %u: %s", new_group, strerror(errno));
        return FALSE;
    }

    /* Lose root privileges */
    if (setuid(new_user) < 0) {
        g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                    "couldn't become user %u: %s", new_user, strerror(errno));
        return FALSE;
    }
#endif  /* LINUX_PRIVHACK */
    /* All done. */
    did_become = TRUE;
    return TRUE;
}
