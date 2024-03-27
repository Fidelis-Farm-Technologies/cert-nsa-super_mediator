/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_mysql.c
 *
 *  This sets up the default database tables for super_mediator.
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

#include "mediator_autohdr.h"

#ifdef HAVE_MYSQL

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <glib.h>
#include <unistd.h>
#include <mysql.h>

#define MD_MYSQL_HOST  "localhost"
#define MD_MYSQL_USER  "root"
#define MD_MYSQL_PASS  ""
#define MD_MYSQL_DB    "super"

static const char  *md_mysql_host = MD_MYSQL_HOST;
static const char  *md_mysql_user = MD_MYSQL_USER;
static const char  *md_mysql_pass = MD_MYSQL_PASS;
static const char  *md_mysql_db = MD_MYSQL_DB;
static gboolean     md_version = FALSE;
static gboolean     md_no_index = FALSE;
static gboolean     md_flow_only = FALSE;
static gboolean     md_dns_dedup = FALSE;
static gboolean     md_dedup_last = FALSE;
static gboolean     md_flow_stats = FALSE;
static gboolean     md_yaf_stats = FALSE;
static gboolean     md_dedup_flow = FALSE;
static gboolean     md_ssl_dedup = FALSE;
static gboolean     md_ssl_cert = FALSE;
static const char  *md_dedup = NULL;

#define WRAP  "\n\t\t\t\t"

static GOptionEntry md_core_option[] = {
    {"out", 'o', 0, G_OPTION_ARG_STRING, &md_mysql_host,
     "Select Hostname or IP where MySQL DB" WRAP
     "exists [" MD_MYSQL_HOST "]", "host"},
    {"name", 'n', 0, G_OPTION_ARG_STRING, &md_mysql_user,
     "Specify MySQL user name [" MD_MYSQL_USER "]", "username"},
    {"pass", 'p', 0, G_OPTION_ARG_STRING, &md_mysql_pass,
     "Specify MySQL password [" MD_MYSQL_PASS "]", "password"},
    {"database", 'd', 0, G_OPTION_ARG_STRING, &md_mysql_db,
     "Specify name of the database to create or" WRAP
     "use [" MD_MYSQL_DB "]", "database"},
    {"version", 0, 0, G_OPTION_ARG_NONE, &md_version,
     "Print the version of this program and exit", NULL},
    {"flow-only", 'f', 0, G_OPTION_ARG_NONE, &md_flow_only,
     "Create full flow table and exit, for use with" WRAP
     "super_mediator's FLOW_ONLY config file setting", NULL},
    {"no-index", 0, 0, G_OPTION_ARG_NONE, &md_no_index,
     "Put flow index into each table, for use with" WRAP
     "super_mediator's NO_INDEX config file setting", NULL},
    {"dns-dedup", 0, 0, G_OPTION_ARG_NONE, &md_dns_dedup,
     "Create DNS dedup default table and exit", NULL},
    {"dedup-last-seen", 0, 0, G_OPTION_ARG_NONE, &md_dedup_last,
     "Create DNS dedup table with LAST_SEEN option" WRAP
     "and exit", NULL},
    {"flow-stats", 's', 0, G_OPTION_ARG_NONE, &md_flow_stats,
     "Create flow statistics table and exit", NULL },
    {"yaf-stats", 'y', 0, G_OPTION_ARG_NONE, &md_yaf_stats,
     "Create yaf statistics table and exit", NULL},
    {"dedupflow", 0, 0, G_OPTION_ARG_NONE, &md_dedup_flow,
     "Add count column to tables for DEDUP_PER_FLOW", NULL},
    {"dedup", 0, 0, G_OPTION_ARG_STRING, &md_dedup,
     "Specify dedup table name to create and exit", "name"},
    {"ssl-certs", 0, 0, G_OPTION_ARG_NONE, &md_ssl_cert,
     "Create ssl certificate de-dup tables and exit", NULL},
    {"ssl-dedup", 0, 0, G_OPTION_ARG_NONE, &md_ssl_dedup,
     "Create ssl IP, certificate chain de-dup table" WRAP
     "and exit", NULL},
    { NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL }
};


static void
mdInsertDPIValues(
    MYSQL      *conn,
    GString    *query);


/**
 * mdPrintVersion
 *
 *
 */
static void
mdPrintVersion(
    void)
{
    fprintf(stdout, "super_table_creator version %s\n", VERSION);
    fprintf(stdout,
            "Copyright 2012-2023 Carnegie Mellon University.\n"
            "GNU General Public License (GPL) Rights "
            "pursuant to Version 2, June 1991\n"
            "Send bug reports, feature requests, and comments to "
            "netsa-help@cert.org.\n");
}



/**
 * mdParseOptions
 *
 * parses the command line options
 *
 */
static void
mdParseOptions(
    int    *argc,
    char  **argv[])
{

    GOptionContext *ctx = NULL;
    GError *err = NULL;

    ctx = g_option_context_new(" - super_table_creator Options");
    g_option_context_add_main_entries(ctx, md_core_option, NULL);
    g_option_context_set_help_enabled(ctx, TRUE);

    if (!g_option_context_parse(ctx, argc, argv, &err)) {
        fprintf(stderr, "option parsing failed: %s\n", err->message);
        g_clear_error(&err);
        exit(1);
    }

    if (md_version) {
        mdPrintVersion();
        exit(0);
    }

    g_option_context_free(ctx);
}


/**
 * main
 *
 *
 */
int
main(
    int     argc,
    char   *argv[])
{
    MYSQL    *conn = NULL;
    GString  *query = g_string_sized_new(1400);
    int       rv;


    /* parse all the options */
    mdParseOptions(&argc, &argv);

    conn = mysql_init(NULL);
    if (conn == NULL) {
        fprintf(stderr, "Error Initializing Connection: [%u] %s\n",
                mysql_errno(conn), mysql_error(conn));
        g_string_free(query, TRUE);
        exit(1);
    }

    if (mysql_real_connect(conn, md_mysql_host, md_mysql_user, md_mysql_pass,
                           NULL, 0, NULL, 0) == NULL)
    {
        fprintf(stderr, "Error Connecting: [%u] %s\n",
                mysql_errno(conn), mysql_error(conn));
        g_string_free(query, TRUE);
        mysql_close(conn);
        exit(1);
    }

    g_string_printf(query, "CREATE DATABASE %s", md_mysql_db);
    if (mysql_query(conn, query->str)) {
        fprintf(stderr, "Ignoring error from '%s': [%u] %s\n",
                query->str, mysql_errno(conn), mysql_error(conn));
    }

    g_string_printf(query, "USE %s", md_mysql_db);
    if (mysql_query(conn, query->str)) {
        fprintf(stderr, "Error executing '%s': [%u] %s\n",
                query->str, mysql_errno(conn), mysql_error(conn));
        g_string_free(query, TRUE);
        mysql_close(conn);
        exit(1);
    }

    if (md_flow_only) {
        if (mysql_query(conn,
                        "CREATE TABLE flow("
                        "stime DATETIME,"
                        "etime DATETIME,"
                        "duration DECIMAL(10,3),"
                        "rtt DECIMAL(10,3),"
                        "protocol TINYINT,"
                        "sip VARCHAR(40),"
                        "sport MEDIUMINT,"
                        "pkt BIGINT,"
                        "oct BIGINT,"
                        "att MEDIUMINT,"
                        "mac VARCHAR(18),"
                        "dip VARCHAR(40),"
                        "dport MEDIUMINT,"
                        "rpkt BIGINT,"
                        "roct BIGINT,"
                        "ratt MEDIUMINT,"
                        "rmac VARCHAR(18),"
                        "iflags VARCHAR(10),"
                        "uflags VARCHAR(10),"
                        "riflags VARCHAR(10),"
                        "ruflags VARCHAR(10),"
                        "isn VARCHAR(10),"
                        "risn VARCHAR(10),"
                        "ingress INT,"
                        "egress INT,"
                        "vlan VARCHAR(3),"
                        "app MEDIUMINT,"
                        "tos VARCHAR(3),"
                        "reason VARCHAR(10),"
                        "collector VARCHAR(100))"))
        {
            fprintf(stderr, "Error creating full flow table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "Successfully created full flow table.\n");
        }
        g_string_free(query, TRUE);
        mysql_close(conn);
        exit(0);
    }

    if (md_dns_dedup) {
        if (mysql_query(conn,
                        "CREATE TABLE dns_dedup("
                        "first_seen DATETIME,"
                        "rrtype MEDIUMINT,"
                        "rrname VARCHAR(270),"
                        "rrval VARCHAR(300))"))
        {
            fprintf(stderr, "Error creating DNS dedup default table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "Successfully created DNS dedup table.\n");
        }
        g_string_free(query, TRUE);
        mysql_close(conn);
        exit(0);
    }

    if (md_dedup_last) {
        if (mysql_query(conn,
                        "CREATE TABLE dns_dedup("
                        "first_seen DATETIME,"
                        "last_seen DATETIME,"
                        "rrtype MEDIUMINT,"
                        "rrname VARCHAR(270),"
                        "hitcount INT,"
                        "rrval VARCHAR(300))"))
        {
            fprintf(stderr, "Error Creating DNS dedup last seen table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr,
                    "Successfully created DNS dedup last seen table.\n");
        }
        g_string_free(query, TRUE);
        mysql_close(conn);
        exit(0);
    }

    if (md_dedup) {
        g_string_printf(query,
                        "CREATE TABLE %s("
                        "first_seen DATETIME,"
                        "last_seen DATETIME,"
                        "ip VARCHAR(40),"
                        "hash INT unsigned,"
                        "hitcount BIGINT unsigned,"
                        "data VARCHAR(500))",
                        md_dedup);
        rv = mysql_query(conn, query->str);
        if (rv) {
            fprintf(stderr, "Error creating dedup %s table: %s\n",
                    md_dedup, mysql_error(conn));
        } else {
            fprintf(stderr, "%s table successfully created\n", md_dedup);
        }
        g_string_free(query, TRUE);
        mysql_close(conn);
        exit(0);
    }

    if (md_ssl_cert) {
        rv = mysql_query(conn,
                         "CREATE TABLE certs("
                         "serial VARCHAR(150),"
                         "issuer VARCHAR(500),"
                         "stime DATETIME,"
                         "id INT,"
                         "ISE VARCHAR(2),"
                         "cert_no SMALLINT,"
                         "data VARCHAR(500))");
        if (rv) {
            fprintf(stderr, "Error creating ssl certs table: %s\n",
                    mysql_error(conn));
        } else {
           fprintf(stderr, "certs table successfully created\n");
        }
        rv = mysql_query(conn,
                         "CREATE TABLE certs_dedup("
                         "first_seen DATETIME,"
                         "last_seen DATETIME,"
                         "serial VARCHAR(150),"
                         "hitcount BIGINT unsigned,"
                         "issuer VARCHAR(500))");
        if (rv) {
            fprintf(stderr, "Error creating certs_dedup table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "certs_dedup table successfully created\n");
        }
        g_string_free(query, TRUE);
        mysql_close(conn);
        exit(0);
    }

    if (md_ssl_dedup) {
        rv = mysql_query(conn,
                         "CREATE TABLE ssl_ip_dedup("
                         "first_seen DATETIME,"
                         "last_seen DATETIME,"
                         "ip VARCHAR(40),"
                         "hash INT unsigned,"
                         "hitcount BIGINT,"
                         "serial1 VARCHAR(150),"
                         "issuer1 VARCHAR(500),"
                         "serial2 VARCHAR(150),"
                         "issuer2 VARCHAR(500))");
        if (rv) {
            fprintf(stderr, "Error creating ssl_ip_dedup table: %s\n",
                    mysql_error(conn));
        } else {
           fprintf(stderr, "ssl_ip_dedup table successfully created\n");
        }
        g_string_free(query, TRUE);
        mysql_close(conn);
        exit(0);
    }

    if (md_flow_stats) {
        if (!md_no_index) {
            if (mysql_query(conn,
                            "CREATE TABLE flowstats("
                            "flow_key INT unsigned,"
                            "stime BIGINT unsigned,"
                            "obid INT unsigned,"
                            "tcpurg BIGINT unsigned,"
                            "smallpkt BIGINT unsigned,"
                            "nonempty BIGINT unsigned,"
                            "datalen BIGINT unsigned,"
                            "avgitime BIGINT unsigned,"
                            "firstpktlen INT unsigned,"
                            "largepktct BIGINT unsigned,"
                            "maxpktsize INT unsigned,"
                            "firsteight SMALLINT unsigned,"
                            "stddevlen BIGINT unsigned,"
                            "stddevtime BIGINT unsigned,"
                            "avgdata BIGINT unsigned,"
                            "revtcpurg BIGINT unsigned,"
                            "revsmallpkt BIGINT unsigned,"
                            "revnonempty BIGINT unsigned,"
                            "revdatalen BIGINT unsigned,"
                            "revavgitime BIGINT unsigned,"
                            "revfirstpktlen INT unsigned,"
                            "revlargepktct BIGINT unsigned,"
                            "revmaxpktsize INT unsigned,"
                            "revstddevlen BIGINT unsigned,"
                            "revstddevtime BIGINT unsigned,"
                            "revavgdata BIGINT unsigned)"))
            {
                fprintf(stderr, "Error creating flow statistics table: %s\n",
                        mysql_error(conn));
            } else {
               fprintf(stderr,"Successfully created Flow Statistics Table.\n");
            }
        } else {
            if (mysql_query(conn,
                            "CREATE TABLE flowstats("
                            "stime DATETIME,"
                            "sip VARCHAR(40),"
                            "dip VARCHAR(40),"
                            "protocol TINYINT unsigned,"
                            "sport MEDIUMINT unsigned,"
                            "dport MEDIUMINT unsigned,"
                            "vlan INT unsigned,"
                            "obid INT unsigned,"
                            "tcpurg BIGINT unsigned,"
                            "smallpkt BIGINT unsigned,"
                            "nonempty BIGINT unsigned,"
                            "datalen BIGINT unsigned,"
                            "avgitime BIGINT unsigned,"
                            "firstpktlen INT unsigned,"
                            "largepktct BIGINT unsigned,"
                            "maxpktsize INT unsigned,"
                            "firsteight SMALLINT unsigned,"
                            "stddevlen BIGINT unsigned,"
                            "stddevtime BIGINT unsigned,"
                            "avgdata BIGINT unsigned,"
                            "revtcpurg BIGINT unsigned,"
                            "revsmallpkt BIGINT unsigned,"
                            "revnonempty BIGINT unsigned,"
                            "revdatalen BIGINT unsigned,"
                            "revavgitime BIGINT unsigned,"
                            "revfirstpktlen INT unsigned,"
                            "revlargepktct BIGINT unsigned,"
                            "revmaxpktsize INT unsigned,"
                            "revstddevlen BIGINT unsigned,"
                            "revstddevtime BIGINT unsigned,"
                            "revavgdata BIGINT unsigned)"))
            {
                fprintf(stderr, "Error creating flow statistics table: %s\n",
                        mysql_error(conn));
            } else {
              fprintf(stderr, "Successfully created Flow Statistics Table.\n");
            }
        }
        g_string_free(query, TRUE);
        mysql_close(conn);
        exit(0);
    }

    if (md_yaf_stats) {
        if (mysql_query(conn,
                        "CREATE TABLE yaf_stats("
                        "ts TIMESTAMP,"
                        "flows BIGINT unsigned,"
                        "packets BIGINT unsigned,"
                        "dropped BIGINT unsigned,"
                        "ignored BIGINT unsigned,"
                        "expired_frags BIGINT unsigned,"
                        "assembled_frags BIGINT unsigned,"
                        "flush_events INT unsigned,"
                        "table_peak INT unsigned,"
                        "yaf_ip VARCHAR(40),"
                        "yaf_id INT unsigned,"
                        "flow_rate INT unsigned,"
                        "packet_rate INT unsigned,"
                        "collector VARCHAR (100))"))
        {
            fprintf(stderr, "Error creating yaf_stats table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "Successfully created yaf_stats Table.\n");
        }

        g_string_free(query, TRUE);
        mysql_close(conn);
        exit(0);
    }

    if (!md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE flow("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned)"))
        {
            fprintf(stderr, "Error creating flow index table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "Flow Index Table Created Successfully\n");
        }
    } else {
        fprintf(stderr,"Not creating flow index table [in --no-index mode]\n");
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE dns("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "qr VARCHAR(1),"
                        "id INT unsigned,"
                        "section TINYINT unsigned,"
                        "nx TINYINT unsigned,"
                        "auth TINYINT unsigned,"
                        "type MEDIUMINT unsigned,"
                        "ttl INT unsigned,"
                        "name VARCHAR(255),"
                        "val VARCHAR(255))"))
        {
            fprintf(stderr, "Error creating DNS table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "DNS Table Created Successfully\n");
        }
    } else {
        if (mysql_query(conn,
                        "CREATE TABLE dns("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "qr VARCHAR(1),"
                        "id INT unsigned,"
                        "section TINYINT unsigned,"
                        "nx TINYINT unsigned,"
                        "auth TINYINT unsigned,"
                        "type MEDIUMINT unsigned,"
                        "ttl INT unsigned,"
                        "name VARCHAR(255),"
                        "val VARCHAR(255))"))
        {
            fprintf(stderr, "Error creating DNS table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "DNS Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        rv = mysql_query(conn,
                         "CREATE TABLE http("
                         "stime DATETIME,"
                         "sip VARCHAR(40),"
                         "dip VARCHAR(40),"
                         "protocol TINYINT unsigned,"
                         "sport MEDIUMINT unsigned,"
                         "dport MEDIUMINT unsigned,"
                         "vlan INT unsigned,"
                         "obid INT unsigned,"
                         "id MEDIUMINT unsigned,"
                         "data VARCHAR(500))");
    } else {
        rv = mysql_query(conn,
                         "CREATE TABLE http("
                         "flow_key INT unsigned,"
                         "stime BIGINT unsigned,"
                         "obid INT unsigned,"
                         "id MEDIUMINT unsigned,"
                         "data VARCHAR(500))");
    }

    if (rv) {
        fprintf(stderr, "Error creating http table: %s\n",
                mysql_error(conn));
    } else {
        fprintf(stderr, "HTTP Table Created Successfully\n");
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn,
                         "ALTER TABLE http ADD "
                         "count INT unsigned"
                         " AFTER id");
        if (rv) {
            fprintf(stderr,
                    "Error modifying http table for DEDUP PER FLOW: %s\n",
                    mysql_error(conn));
        }
    }

    if (md_no_index) {
        rv = mysql_query(conn,
                         "CREATE TABLE tls("
                         "stime DATETIME,"
                         "sip VARCHAR(40),"
                         "dip VARCHAR(40),"
                         "protocol TINYINT unsigned,"
                         "sport MEDIUMINT unsigned,"
                         "dport MEDIUMINT unsigned,"
                         "vlan INT unsigned,"
                         "obid INT unsigned,"
                         "id MEDIUMINT unsigned,"
                         "cert_type VARCHAR(500),"
                         "cert_no TINYINT unsigned,"
                         "data VARCHAR(500))");
    } else {
        rv = mysql_query(conn,
                         "CREATE TABLE tls("
                         "flow_key INT unsigned,"
                         "stime BIGINT unsigned,"
                         "obid INT unsigned,"
                         "id MEDIUMINT unsigned,"
                         "cert_type VARCHAR(5),"
                         "cert_no TINYINT unsigned,"
                         "data VARCHAR(500))");

    }

    if (rv) {
        fprintf(stderr, "Error creating tls table: %s\n",
                mysql_error(conn));
    } else {
        fprintf(stderr, "TLS Table Created Successfully\n");
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE slp("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating SLP table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "SLP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE slp("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating slp table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "SLP Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn,
                         "ALTER TABLE slp ADD "
                         "count INT unsigned"
                         " AFTER id");
        if (rv) {
            fprintf(stderr,
                    "Error modifying SLP table for DEDUP PER FLOW: %s\n",
                    mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE imap("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating imap table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "IMAP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE imap("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating imap table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "IMAP Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn,
                         "ALTER TABLE imap ADD "
                         "count INT unsigned"
                         " AFTER id");
        if (rv) {
            fprintf(stderr,
                    "Error modifying imap table for DEDUP PER FLOW: %s\n",
                    mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE smtp("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating smtp table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "SMTP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE smtp("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating smtp table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "SMTP Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn,
                         "ALTER TABLE smtp ADD "
                         "count INT unsigned"
                         " AFTER id");
        if (rv) {
            fprintf(stderr,
                    "Error modifying smtp table for DEDUP PER FLOW: %s\n",
                    mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE pop3("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating pop3 table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "POP3 Table Created Successfully\n");
        }
    } else {
        if (mysql_query(conn,
                        "CREATE TABLE pop3("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating pop3 table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "POP3 Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn,
                         "ALTER TABLE pop3 ADD "
                         "count INT unsigned"
                         " AFTER id");
        if (rv) {
            fprintf(stderr,
                    "Error modifying pop3 table for DEDUP PER FLOW: %s\n",
                    mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE irc("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating irc table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "IRC Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE irc("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating irc table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "IRC Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn,
                         "ALTER TABLE irc ADD "
                         "count INT unsigned"
                         " AFTER id");
        if (rv) {
            fprintf(stderr,
                    "Error modifying irc table for DEDUP PER FLOW: %s\n",
                    mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE ftp("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating ftp table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "FTP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE ftp("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating ftp table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "FTP Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn,
                         "ALTER TABLE ftp ADD "
                         "count INT unsigned"
                         " AFTER id");
        if (rv) {
            fprintf(stderr,
                    "Error modifying ftp table for DEDUP PER FLOW: %s\n",
                    mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE tftp("
                        "stime TIMESTAMP,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating tftp table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "TFTP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE tftp("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating tftp table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "TFTP Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE sip("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating sip table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "SIP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE sip("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating sip table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "SIP Table Created Successfully\n");
        }

    }

    if (md_dedup_flow) {
        rv = mysql_query(conn,
                         "ALTER TABLE sip ADD "
                         "count INT unsigned"
                         " AFTER id");
        if (rv) {
            fprintf(stderr,
                    "Error modifying sip table for DEDUP PER FLOW: %s\n",
                    mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE rtsp("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating rtsp table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "RTSP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE rtsp("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating rtsp table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "RTSP Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn,
                         "ALTER TABLE rtsp ADD "
                         "count INT unsigned"
                         " AFTER id");
        if (rv) {
            fprintf(stderr,
                    "Error modifying rtsp table for DEDUP PER FLOW: %s\n",
                    mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE mysql("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating mysql table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "MySQL Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE mysql("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating mysql table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "MYSQL Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE p0f("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating p0f table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "p0f Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE p0f("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating p0f table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "P0F Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE dhcp("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating dhcp table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "DHCP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE dhcp("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating dhcp table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "DHCP Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE ssh("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating ssh table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "SSH Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE ssh("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating ssh table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "SSH Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn,
                         "ALTER TABLE ssh ADD "
                         "count INT unsigned"
                         " AFTER id");
        if (rv) {
            fprintf(stderr,
                    "Error modifying ssh table for DEDUP PER FLOW: %s\n",
                    mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE nntp("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating nntp table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "NNTP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE nntp("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating nntp table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "NNTP Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE rtp("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "paytype INT unsigned,"
                        "revpaytype INT unsigned)"))
        {
            fprintf(stderr, "Error creating rtp table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "RTP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE rtp("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "paytype INT unsigned,"
                        "revpaytype INT unsigned)"))
        {
            fprintf(stderr, "Error creating rtp table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "RTP Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE modbus("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating modbus table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "Modbus Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE modbus("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating modbus table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "Modbus Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn,
                         "ALTER TABLE modbus ADD "
                         "count INT unsigned"
                         " AFTER id");
        if (rv) {
            fprintf(stderr,
                    "Error modifying modbus table for DEDUP PER FLOW: %s\n",
                    mysql_error(conn));
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE dnp3("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "src MEDIUMINT unsigned,"
                        "dst MEDIUMINT unsigned,"
                        "function TINYINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating dnp3 table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "DNP3 Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE dnp3("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "src MEDIUMINT unsigned,"
                        "dst MEDIUMINT unsigned,"
                        "function TINYINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating dnp3 table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "DNP3 Table Created Successfully\n");
        }
    }

    if (md_no_index) {
        if (mysql_query(conn,
                        "CREATE TABLE enip("
                        "stime DATETIME,"
                        "sip VARCHAR(40),"
                        "dip VARCHAR(40),"
                        "protocol TINYINT unsigned,"
                        "sport MEDIUMINT unsigned,"
                        "dport MEDIUMINT unsigned,"
                        "vlan INT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating enip table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "ENIP Table Created Successfully\n");
        }
    } else {

        if (mysql_query(conn,
                        "CREATE TABLE enip("
                        "flow_key INT unsigned,"
                        "stime BIGINT unsigned,"
                        "obid INT unsigned,"
                        "id MEDIUMINT unsigned,"
                        "data VARCHAR(500))"))
        {
            fprintf(stderr, "Error creating enip table: %s\n",
                    mysql_error(conn));
        } else {
            fprintf(stderr, "ENIP Table Created Successfully\n");
        }
    }

    if (md_dedup_flow) {
        rv = mysql_query(conn,
                         "ALTER TABLE enip ADD "
                         "count INT unsigned "
                         "AFTER id");
        if (rv) {
            fprintf(stderr,
                    "Error modifying enip table for DEDUP PER FLOW: %s\n",
                    mysql_error(conn));
        }
    }

    /* create the dpi id table */
    if (mysql_query(conn,
                    "CREATE TABLE dpi_id("
                    "id int NOT NULL,"
                    "tab VARCHAR(30) NOT NULL,"
                    "description VARCHAR(255) NOT NULL)"))
    {
        fprintf(stderr, "Error creating dpi_id table: %s\n",
                mysql_error(conn));
    } else {
        fprintf(stderr, "DPI_ID table successfully created.\n");
        mdInsertDPIValues(conn, query);
    }

    g_string_free(query, TRUE);
    mysql_close(conn);
    return 0;
}



/**
 * mdInsertDPIValues
 *
 */
static void
mdInsertDPIValues(
    MYSQL      *conn,
    GString    *query)
{
    const struct dpi_id_st {
        int         id;
        const char *tab;
        const char *desc;
    } dpi_ids[] = {
        { 1, "dns", "ARecord"},
        { 2, "dns", "NSRecord"},
        { 5, "dns", "CNAMERecord"},
        { 6, "dns", "SOARecord"},
        {12, "dns", "MXRecord"},
        {15, "dns", "PTRRecord"},
        {16, "dns", "TXTRecord"},
        {28, "dns", "AAAARecord"},
        {33, "dns", "SRVRecord"},
        {43, "dns", "DSRecord"},
        {46, "dns", "RRSIGRecord"},
        {47, "dns", "NSECRecord"},
        {48, "dns", "DNSKEYRecord"},
        {50, "dns", "NSEC3Record"},
        {51, "dns", "NSEC3PARAMRecord"},

        {  3, "tls", "commonname"},
        {  6, "tls", "countryName"},
        {  7, "tls", "localityName"},
        {  8, "tls", "stateOrProvinceName"},
        {  9, "tls", "streetAddress"},
        { 10, "tls", "organization"},
        { 11, "tls", "organizationalunit"},
        { 12, "tls", "title"},
        { 17, "tls", "postalCode"},
        { 41, "tls", "name"},
        {185, "tls", "sslCipher"},
        {186, "tls", "sslClientVersion"},
        {187, "tls", "sslServerCipher"},
        {188, "tls", "sslCompressionMethod"},
        {189, "tls", "sslCertVersion"},
        {190, "tls", "sslCertSignature"},
        {247, "tls", "sslCertValidityNotBefore"},
        {248, "tls", "sslCertValidityNotAfter"},
        {249, "tls", "sslPublicKeyAlgorithm"},
        {250, "tls", "sslPublicKeyLength"},
        {289, "tls", "sslCertVersion"},

        { 36, "p0f", "osName"},
        { 37, "p0f", "osVersion"},
        {107, "p0f", "osFingerprint"},

        {110, "http", "httpServerString"},
        {111, "http", "httpUserAgent"},
        {112, "http", "httpGet"},
        {113, "http", "httpConnection"},
        {114, "http", "httpVersion"},
        {115, "http", "httpReferer"},
        {116, "http", "httpLocation"},
        {117, "http", "httpHost"},
        {118, "http", "httpContentLength"},
        {119, "http", "httpAge"},
        {120, "http", "httpAccept"},
        {121, "http", "httpAcceptLanguage"},
        {122, "http", "httpContentType"},
        {123, "http", "httpResponse"},
        {220, "http", "httpCookie"},
        {221, "http", "httpSetCookie"},
        {257, "http", "httpIMEI"},
        {258, "http", "httpIMSI"},
        {259, "http", "httpMSISDN"},
        {260, "http", "httpSubscriber"},
        {255, "http", "httpExpires"},
        {261, "http", "httpAcceptCharset"},
        {262, "http", "httpAcceptEncoding"},
        {263, "http", "httpAllow"},
        {264, "http", "httpDate"},
        {265, "http", "httpExpect"},
        {266, "http", "httpFrom"},
        {267, "http", "httpProxyAuthentication"},
        {268, "http", "httpUpgrade"},
        {269, "http", "httpWarning"},
        {270, "http", "httpDNT"},
        {271, "http", "httpXForwardedProto"},
        {272, "http", "httpXForwardedHost"},
        {273, "http", "httpXForwardedServer"},
        {274, "http", "httpXDeviceID"},
        {275, "http", "httpProfile"},
        {276, "http", "httpLastModified"},
        {277, "http", "httpContentEncoding"},
        {278, "http", "httpContentLanguage"},
        {279, "http", "httpContentLocation"},
        {280, "http", "httpXUACompatible"},

        {124, "pop3", "pop3TextMessage"},

        {125, "irc", "ircTextMessage"},

        {126, "tftp", "tftpFilename"},
        {127, "tftp", "tftpMode"},

        {128, "slp", "slpVersion"},
        {129, "slp", "slpMessageType"},
        {130, "slp", "slpString"},

        {131, "ftp", "ftpReturn"},
        {132, "ftp", "ftpUser"},
        {133, "ftp", "ftpPass"},
        {134, "ftp", "ftpType"},
        {135, "ftp", "ftpRespCode"},

        {136, "imap", "imapCapability"},
        {137, "imap", "imapLogin"},
        {138, "imap", "imapStartTLS"},
        {139, "imap", "imapAuthenticate"},
        {140, "imap", "imapCommand"},
        {141, "imap", "imapExists"},
        {142, "imap", "imapRecent"},

        {143, "rtsp", "rtspURL"},
        {144, "rtsp", "rtspVersion"},
        {145, "rtsp", "rtspReturnCode"},
        {146, "rtsp", "rtspContentLength"},
        {147, "rtsp", "rtspCommand"},
        {148, "rtsp", "rtspContentType"},
        {149, "rtsp", "rtspTransport"},
        {150, "rtsp", "rtspCSeq"},
        {151, "rtsp", "rtspLocation"},
        {152, "rtsp", "rtspPacketsReceived"},
        {153, "rtsp", "rtspUserAgent"},
        {154, "rtsp", "rtspJitter"},

        {155, "sip", "sipInvite"},
        {156, "sip", "sipCommand"},
        {157, "sip", "sipVia"},
        {158, "sip", "sipMaxForwards"},
        {159, "sip", "sipAddress"},
        {160, "sip", "sipContentLength"},
        {161, "sip", "sipUserAgent"},

        {162, "smtp", "smtpHello"},
        {163, "smtp", "smtpFrom"},
        {164, "smtp", "smtpTo"},
        {165, "smtp", "smtpContentType"},
        {166, "smtp", "smtpSubject"},
        {167, "smtp", "smtpFilename"},
        {168, "smtp", "smtpContentDisposition"},
        {169, "smtp", "smtpResponse"},
        {170, "smtp", "smtpEnhanced"},
        {222, "smtp", "smtpSize"},
        {251, "smtp", "smtpDate"},

        {171, "ssh", "sshVersion"},

        {172, "nntp", "nntpResponse"},
        {173, "nntp", "nntpCommand"},

        {223, "mysql", "mysqlUsername"},
        {225, "mysql", "mysqlCommandText"},

        {242, "dhcp", "dhcpFingerprint"},
        {243, "dhcp", "dhcpVendorCode"},

        {281, "dnp3", "dnp3SourceAddress"},
        {282, "dnp3", "dhp3DestinationAddress"},
        {283, "dnp3", "dhp3Function"},
        {284, "dnp3", "dhp3Object"},

        {285, "modbus", "modbusData"},

        {286, "enip", "enipData"},

        {287, "rtp", "rtpPayloadType"},

        {0, NULL, NULL}
    };
    unsigned int i;

    for (i = 0; dpi_ids[i].tab != NULL; ++i) {
        g_string_printf(query,
                        "insert into dpi_id (id,tab,description) values "
                        "('%d', '%s', '%s')",
                        dpi_ids[i].id, dpi_ids[i].tab, dpi_ids[i].desc);
        mysql_query(conn, query->str);
    }
}


#endif  /* HAVE_MYSQL */
