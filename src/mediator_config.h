/*
 *  Copyright 2012-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/**
 *  @file mediator_config.h
 *
 *  Contains definitions needed for the .c files generated by lex and yacc.
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

#ifndef _MEDIATOR_CONFIG_H
#define _MEDIATOR_CONFIG_H

#include <stdarg.h>

typedef enum mdConfTransport_en {
    MD_CONF_TPORT_NONE,
    MD_CONF_TPORT_DIRECTORY_POLL,
    MD_CONF_TPORT_ROTATING_FILES,
    MD_CONF_TPORT_SINGLE_FILE,
    MD_CONF_TPORT_TCP,
    MD_CONF_TPORT_UDP
} mdConfTransport_t;

extern int lineNumber;

/**
 *  Prints an error message and exits the program.  The message includes the
 *  line number where the lexer is in the configuration file.
 */
int
mediator_config_error(
    const char *fmt,
    ...)
    __attribute__((format (printf, 1, 2)))
    __attribute__((__noreturn__));

/**
 *  Prints an warning message.  The message includes the line number where the
 *  lexer is in the configuration file.
 */
void
mediator_config_warn(
    const char *fmt,
    ...)
    __attribute__((format (printf, 1, 2)));

/**
 *  Opens and parses the configuration file.  Returns TRUE if the file is
 *  successfully opened and parsed.  Returns FALSE and sets `err` only if the
 *  file cannot be opened.  Exits the application if the file is successfully
 *  opened but contains errors.
 */
gboolean
mdConfigfileParse(
    const char *path,
    GError    **err);


/* Provide some grammar debugging info, if necessary */
#define YYDEBUG 1
#define YYERROR_VERBOSE 1

/* this list of definitions is from the automake info page */
#define MAX_VALUE_LIST    300
#define yymaxdepth  mediatorConfig_maxdepth
#define yyparse     mediatorConfig_parse
#define yylex       mediatorConfig_lex
#define yyerror     mediatorConfig_error
/*#define yylval      mediatorConfig_lval*/
#define yychar      mediatorConfig_char
#define yydebug     mediatorConfig_debug
#define yypact      mediatorConfig_pact
#define yyr1        mediatorConfig_r1
#define yyr2        mediatorConfig_r2
#define yydef       mediatorConfig_def
#define yychk       mediatorConfig_chk
#define yypgo       mediatorConfig_pgo
#define yyact       mediatorConfig_act
#define yyexca      mediatorConfig_exca
#define yyerrflag   mediatorConfig_errflag
#define yynerrs     mediatorConfig_nerrs
#define yyps        mediatorConfig_ps
#define yypv        mediatorConfig_pv
#define yys         mediatorConfig_s
#define yy_yys      mediatorConfig_yys
#define yystate     mediatorConfig_state
#define yytmp       mediatorConfig_tmp
#define yyv         mediatorConfig_v
#define yy_yyv      mediatorConfig_yyv
#define yyval       mediatorConfig_val
#define yylloc      mediatorConfig_lloc
#define yyreds      mediatorConfig_reds
#define yytoks      mediatorConfig_toks
#define yylhs       mediatorConfig_yylhs
#define yylen       mediatorConfig_yylen
#define yydefred    mediatorConfig_yydefred
#define yydgoto     mediatorConfig_yydgoto
#define yysindex    mediatorConfig_yysindex
#define yyrindex    mediatorConfig_yyrindex
#define yygindex    mediatorConfig_yygindex
#define yytable     mediatorConfig_yytable
#define yycheck     mediatorConfig_yycheck
#define yyname      mediatorConfig_yyname
#define yyrule      mediatorConfig_yyrule


int
yyparse(
    void);
int
yylex(
    void);
int
yyerror(
    const char *s);

extern int yydebug;
extern FILE *yyin;

#endif /* _MEDIATOR_CONFIG_H */