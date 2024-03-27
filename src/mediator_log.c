/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_log.c
 *  glib-based logging support for super_mediator (taken from libairfame)
 *
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

#include "mediator_log.h"
#include "mediator_util.h"

/*#define MDLOG_TESTING_LOG 0*/

/* Log level; may be modified by mdLoggerSetLevel(). */
static mdLogLevel_t     md_log_level = WARNING;

/* The log file or syslog facility set by mdLoggerSetDestination() */
static char            *md_logfile = NULL;

/* Directory for log files set by mdLoggerSetDirectory() */
static char            *md_logdir = NULL;

/* Result of converting md_log_level to a GLib log level */
static GLogLevelFlags   log_flags = 0;

/* The current stream for log messages */
static GIOChannel      *logfile = NULL;

/* Name of the previous log file, when logging into a directory */
static char            *last_logfile = NULL;

/* Name of the current log file, when logging into a directory */
static char            *cur_logfile = NULL;

/* Next time when log file should be rotated when logging into a directory */
static time_t           md_log_rolltime;


/* Convert GLib log level to syslog log level */
static gint
md_logc_syslog_level(
    GLogLevelFlags  level)
{
    if (level & G_LOG_LEVEL_DEBUG) return LOG_DEBUG;
    if (level & G_LOG_LEVEL_INFO) return LOG_INFO;
    if (level & G_LOG_LEVEL_MESSAGE) return LOG_NOTICE;
    if (level & G_LOG_LEVEL_WARNING) return LOG_WARNING;
    if (level & G_LOG_LEVEL_CRITICAL) return LOG_ERR;
    if (level & G_LOG_LEVEL_ERROR) return LOG_ERR;

    return LOG_DEBUG;
}

/* Convert SM log level to a GLib log level */
static GLogLevelFlags
md_parse_log_level(
    mdLogLevel_t        log_level,
    gboolean            debug,
    gboolean            quiet)
{
    GLogLevelFlags      level;

    switch (log_level) {
      case ERROR:
        level = G_LOG_FLAG_RECURSION |
            G_LOG_FLAG_FATAL |
            G_LOG_LEVEL_ERROR;
        break;
      case WARNING:
        level = G_LOG_FLAG_RECURSION |
            G_LOG_FLAG_FATAL |
            G_LOG_LEVEL_ERROR |
            G_LOG_LEVEL_CRITICAL |
            G_LOG_LEVEL_WARNING;
        break;
      case MD_DEBUG:
        level = G_LOG_FLAG_RECURSION |
            G_LOG_FLAG_FATAL |
            G_LOG_LEVEL_ERROR |
            G_LOG_LEVEL_CRITICAL |
            G_LOG_LEVEL_WARNING |
            G_LOG_LEVEL_MESSAGE |
            G_LOG_LEVEL_INFO |
            G_LOG_LEVEL_DEBUG;
        break;
      case QUIET:
        level = 0;
        break;
      case MESSAGE:
      default:
        level = G_LOG_FLAG_RECURSION |
                G_LOG_FLAG_FATAL |
                G_LOG_LEVEL_ERROR |
                G_LOG_LEVEL_CRITICAL |
                G_LOG_LEVEL_WARNING |
                G_LOG_LEVEL_MESSAGE |
                G_LOG_LEVEL_INFO;
        break;
    }

    if (debug) {
        level = G_LOG_FLAG_RECURSION |
                G_LOG_FLAG_FATAL |
                G_LOG_LEVEL_ERROR |
                G_LOG_LEVEL_CRITICAL |
                G_LOG_LEVEL_WARNING |
                G_LOG_LEVEL_MESSAGE |
                G_LOG_LEVEL_INFO |
                G_LOG_LEVEL_DEBUG;
    }
    if (quiet) {
        level = 0;
    }

    return level;
}


/* Convert a string to a syslog facility and return TRUE.  Return FALSE if
 * there is no facility with that name. */
static gboolean
md_parse_syslog_facility(
    const char      *facstr,
    gint            *facility)
{

#ifdef LOG_AUTH
    if (strcmp("auth",facstr) == 0) {
        *facility = LOG_AUTH;
        return TRUE;
    }
#endif

#ifdef LOG_AUTHPRIV
    if (strcmp("authpriv",facstr) == 0) {
        *facility = LOG_AUTHPRIV;
        return TRUE;
    }
#endif

#ifdef LOG_CONSOLE
    if (strcmp("console",facstr) == 0) {
        *facility = LOG_CONSOLE;
        return TRUE;
    }
#endif

#ifdef LOG_CRON
    if (strcmp("cron",facstr) == 0) {
        *facility = LOG_CRON;
        return TRUE;
    }
#endif

#ifdef LOG_DAEMON
    if (strcmp("daemon",facstr) == 0) {
        *facility = LOG_DAEMON;
        return TRUE;
    }
#endif

#ifdef LOG_FTP
    if (strcmp("ftp",facstr) == 0) {
        *facility = LOG_FTP;
        return TRUE;
    }
#endif

#ifdef LOG_LPR
    if (strcmp("lpr",facstr) == 0) {
        *facility = LOG_LPR;
        return TRUE;
    }
#endif

#ifdef LOG_MAIL
    if (strcmp("mail",facstr) == 0) {
        *facility = LOG_MAIL;
        return TRUE;
    }
#endif

#ifdef LOG_NEWS
    if (strcmp("news",facstr) == 0) {
        *facility = LOG_NEWS;
        return TRUE;
    }
#endif

#ifdef LOG_SECURITY
    if (strcmp("security",facstr) == 0) {
        *facility = LOG_SECURITY;
        return TRUE;
    }
#endif

#ifdef LOG_USER
    if (strcmp("user",facstr) == 0) {
        *facility = LOG_USER;
        return TRUE;
    }
#endif

#ifdef LOG_UUCP
    if (strcmp("uucp",facstr) == 0) {
        *facility = LOG_UUCP;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL0
    if (strcmp("local0",facstr) == 0) {
        *facility = LOG_LOCAL0;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL1
    if (strcmp("local1",facstr) == 0) {
        *facility = LOG_LOCAL1;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL2
    if (strcmp("local2",facstr) == 0) {
        *facility = LOG_LOCAL2;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL3
    if (strcmp("local3",facstr) == 0) {
        *facility = LOG_LOCAL3;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL4
    if (strcmp("local4",facstr) == 0) {
        *facility = LOG_LOCAL4;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL5
    if (strcmp("local5",facstr) == 0) {
        *facility = LOG_LOCAL5;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL6
    if (strcmp("local6",facstr) == 0) {
        *facility = LOG_LOCAL6;
        return TRUE;
    }
#endif

#ifdef LOG_LOCAL7
    if (strcmp("local7",facstr) == 0) {
        *facility = LOG_LOCAL7;
        return TRUE;
    }
#endif

    return FALSE;
}

/**
 * mdLogger
 *
 */
static void
mdLogger(
    const char      *domain,
    GLogLevelFlags   level,
    const char      *message,
    gpointer         user_data)
{
    gsize            sz;
    char             timebuf[80];
    struct tm        time_tm;
    time_t           cur_time= time(NULL);

    MD_UNUSED_PARAM(domain);
    MD_UNUSED_PARAM(level);
    MD_UNUSED_PARAM(user_data);

    gmtime_r(&cur_time, &time_tm);
    snprintf(timebuf, sizeof(timebuf), "[%04u-%02u-%02u %02u:%02u:%02u] ",
             time_tm.tm_year + 1900,
             time_tm.tm_mon + 1,
             time_tm.tm_mday,
             time_tm.tm_hour,
             time_tm.tm_min,
             time_tm.tm_sec);

    g_io_channel_write_chars(logfile, timebuf, -1, &sz, NULL);
    g_io_channel_write_chars(logfile, message, -1, &sz, NULL);
    g_io_channel_write_chars(logfile,"\n", 1, &sz, NULL);
    g_io_channel_flush(logfile, NULL);
}

static void
md_logger_syslog(
    const char     *domain,
    GLogLevelFlags  level,
    const char     *message,
    gpointer        user_data)
{
    MD_UNUSED_PARAM(domain);
    MD_UNUSED_PARAM(user_data);

    syslog(md_logc_syslog_level(level), "%s", message);
}

static void
md_logger_null(
    const char     *domain,
    GLogLevelFlags  level,
    const char     *message,
    gpointer        user_data)
{
    MD_UNUSED_PARAM(domain);
    MD_UNUSED_PARAM(level);
    MD_UNUSED_PARAM(message);
    MD_UNUSED_PARAM(user_data);
    return;
}

/*
 *  Opens the file in `dest` as either a log file or a syslog utility.
 */
static GIOChannel *
md_log_setup(
    const char     *dest,
    int            *usingSyslog,
    GError        **err)
{
    GIOChannel      *iochan = NULL;
    int             facility;

    if (!dest || (strcmp(dest, "stderr") == 0)) {
        /* set log file to stderr */
        iochan = g_io_channel_unix_new(fileno(stderr));

    } else if (md_parse_syslog_facility(dest, &facility)) {
        /* open log socket */
        openlog("super_mediator", LOG_CONS | LOG_PID, facility);

        /* use syslog logger */
        g_log_set_handler(G_LOG_DOMAIN, log_flags, md_logger_syslog, NULL);

        *usingSyslog = 1;

    } else {
        /* open log file */
        iochan = g_io_channel_new_file(dest, "a", err);
        if (iochan == NULL) {
            fprintf(stderr, "Can't open log file '%s' or syslog(3) facility "
                    "not recognized: %s\n", dest, (*err)->message);
            return NULL;
        }
    }

    /* set default log handler to eat messages */
    g_log_set_default_handler(md_logger_null, NULL);

    return iochan;
}

static void
md_log_compress(
    char         *file)
{
    if (file == NULL) {
        g_warning("md_log_compress passed NULL pointer");
        return;
    }

    md_util_compress_file(file, NULL);
}


/*
 *  Builds a log file path using the current time and `md_logdir`.  Stores
 *  that name in `cur_logfile` after moving its previous contents to
 *  `last_logfile`.  Finally, calls md_log_setup() to open the file.
 */
static GIOChannel *
mdRotateLog(
    GError        **err)
{
    gchar *path;
    char date[32];
    time_t t;
    struct tm ts;
    int slog = 0;

    /* get current time */
    t = time(NULL);
    localtime_r(&t, &ts);
    snprintf(date, sizeof(date), "%04u%02u%02u",
             ts.tm_year + 1900,
             ts.tm_mon + 1,
             ts.tm_mday);

#ifndef MDLOG_TESTING_LOG
    ts.tm_hour = 23;
    ts.tm_min = 59;
    ts.tm_sec = 59;
    md_log_rolltime = mktime(&ts) + 1;
#else
    snprintf(date, sizeof(date), "%04u%02u%02u:%02u:%02u",
             ts.tm_year + 1900,
             ts.tm_mon + 1,
             ts.tm_mday,
             ts.tm_hour,
             ts.tm_min);

    if (ts.tm_sec > 55) {
        ++ts.tm_min;
    }
    ts.tm_sec = 0;
    ++ts.tm_min;
    md_log_rolltime = mktime(&ts);
#endif
    path = g_strdup_printf("%s/sm-%s.log", md_logdir, date);
    if (cur_logfile) {
        if (last_logfile) {
            g_free(last_logfile);
        }
        last_logfile = cur_logfile;
    }
    cur_logfile = path;
    return md_log_setup(path, &slog, err);
}


/**
 *  If writing to directory and 'now' is later than the rotate time, rotate
 *  the log file and return TRUE.  Otherwise return FALSE.
 */
gboolean
mdLoggerCheckRotate(
    mdConfig_t     *cfg,
    time_t          now)
{
    GError *err = NULL;
    int rc;

    if (!(md_logdir && md_log_rolltime <= now)) {
        return FALSE;
    }

    pthread_mutex_lock(&cfg->log_mutex);
    g_message("Rotating Log File");
    pthread_mutex_unlock(&cfg->log_mutex);

    /* FIXME: It would be better to open the new file before closing the old
     * one to ensure we maintain access to a log file. */

    rc = g_io_channel_shutdown(logfile, TRUE, &err);
    if (!rc) {
        pthread_mutex_lock(&cfg->log_mutex);
        g_warning("Unable to rotate log: %s", err->message);
        pthread_mutex_unlock(&cfg->log_mutex);
        g_clear_error(&err);
    } else {
        /* open new logfile */
        logfile = mdRotateLog(&err);
        /* compress old logfile */
        md_log_compress(last_logfile);
        if (!logfile) {
            pthread_mutex_lock(&cfg->log_mutex);
            g_warning("Unable to open new log file: %s", err->message);
            pthread_mutex_unlock(&cfg->log_mutex);
            g_clear_error(&err);
        }
    }

    return TRUE;
}


/*
 *
 * User configuration functions and startup-function
 *
 */

gboolean
mdLoggerSetDestination(
    const char *dest,
    GError    **err)
{
    if (md_logdir || md_logfile) {
        g_set_error(err, G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
                    "Attempting to use multiple log locations");
        return FALSE;
    }
    md_logfile = g_strdup(dest);
    return TRUE;
}


gboolean
mdLoggerSetDirectory(
    const char *dir,
    GError    **err)
{
    if (md_logdir || md_logfile) {
        g_set_error(err, G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
                    "Attempting to use multiple log locations");
        return FALSE;
    }
    if (!g_file_test(dir, G_FILE_TEST_IS_DIR)) {
        g_set_error(err, G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
                    "Will not set log directory to a non-directory \"%s\"",
                    dir);
        return FALSE;
    }
    md_logdir = g_strdup(dir);
    return TRUE;
}


void
mdLoggerSetLevel(
    mdLogLevel_t    level)
{
    md_log_level = level;
}

gboolean
mdLoggerStart(
    gboolean    verbose,
    gboolean    quiet,
    gboolean    daemon_mode,
    GError    **err)
{
    int   slog = 0;

    /* set global GLib log level */
    log_flags = md_parse_log_level(md_log_level, verbose, quiet);

    if (daemon_mode) {
        if (!md_logfile || (strcmp(md_logfile, "stderr") == 0)) {
            g_set_error(err, MD_ERROR_DOMAIN, MD_ERROR_SETUP,
                        "May not log to stderr as daemon.");
            return FALSE;
        }
    }

    if (md_logdir) {
        logfile = mdRotateLog(err);
    } else {
        logfile = md_log_setup(md_logfile, &slog, err);
    }

    if (!logfile && (slog == 0)) {
        return FALSE;
    }

    if (!slog) {
        /* if not syslog, set default handler */
        g_log_set_handler(G_LOG_DOMAIN, log_flags, mdLogger, NULL);
    }

    return TRUE;
}
