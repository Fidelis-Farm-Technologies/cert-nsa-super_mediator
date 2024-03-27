% Super Mediator: Documentation

<!--
    Copyright (C) 2014-2023 Carnegie Mellon University
    See license information in LICENSE.txt.
-->
<!--
    @DISTRIBUTION_STATEMENT_BEGIN@
    Super Mediator 2.0.0

    Copyright 2023 Carnegie Mellon University.

    NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
    INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
    UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
    AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
    PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
    THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
    ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
    INFRINGEMENT.

    Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
    contact permission@sei.cmu.edu for full terms.

    [DISTRIBUTION STATEMENT A] This material has been approved for public
    release and unlimited distribution.  Please see Copyright notice for
    non-US Government use and distribution.

    GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
    Contract No.: FA8702-15-D-0002
    Contractor Name: Carnegie Mellon University
    Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213

    The Government's rights to use, modify, reproduce, release, perform,
    display, or disclose this software are restricted by paragraph (b)(2) of
    the Rights in Noncommercial Computer Software and Noncommercial Computer
    Software Documentation clause contained in the above identified
    contract. No restrictions apply after the expiration date shown
    above. Any reproduction of the software or portions thereof marked with
    this legend must also reproduce the markings.

    This Software includes and/or makes use of Third-Party Software each
    subject to its own license.

    DM23-2321
    @DISTRIBUTION_STATEMENT_END@
-->

Super Mediator has the capability to route, aggregate, format, de-duplicate,
enrich, filter, and coalesce data streams of [IPFIX][rfc7011] records from
[YAF][] or another Super Mediator instance. Super Mediator has three
independent components: Collectors, Core, and Exporters. Collectors are
responsible for ingesting IPFIX records from files or sockets, and making
them available to the core processing unit. The core of Super Mediator
handles every record, processes it based on the type of record, and passes
it to the exporters. Exporters are responsible for writing records to output
streams such as files or sockets, and generating specific derived records
for that output stream, and curating outgoing records according to the
configuration file.

# [Command Line Options](#command-line) {#command-line}

## [General Options](#general-options) {#general-options}

**super\_mediator** has the following general options:

-   **--config** *CONFIG\_FILE*

    Specifies the name of the configuration file defining the collectors,
    exporters, and desired functionality. Using a configuration file is
    preferred over using command-line options. If this option is given, most
    other command line options are not allowed.

-   **--test-config**

    Causes the program to exit after parsing the configuration file.

-   **--version**

    Tells **super\_mediator** to print its version number and the set of
    features that were enabled when it was built, and then exit.

-   **--help**

    Causes **super\_mediator** to print a brief description of the command
    line arguments it accepts and exit.

## [Input: Defining the Collector(s)](#input-define-collector) {#input-define-collector}

Super Mediator's input is called a collector. From the command line, one can
create one or more collectors that listen on the network, one or more
collectors that poll a directory, or one or more collectors that read from
named files and the standard input.

### [Network Collector](#network-collector) {#network-collector}

To create network collectors, the **--ipfix-input** switch must be given.
Its takes an argument of either **tcp** or **udp** specifying the type of
network stream. The **--ipfix-port** switch specifies the port to listen on;
it is optional and if not given port 18000 is used. The host(s) to listen on
are given as arguments.

When acting as a network collector, **super\_mediator** runs until it is
signaled to stop.

The following examaples create a network collector. Output is written as
IPFIX to the standard output.

**super\_mediator** **--ipfix-input=tcp --ipfix-port=7777 localhost**

Bind to TCP port 7777 on localhost to listen for connections.

**super\_mediator** **--ipfix-input=tcp 127.0.0.1 ::1**

Bind to TCP port 18000 on IP addresses 127.0.0.1 and ::1 to listen for
connections.

### [Directory Polling Collector](#directory-polling-collector) {#directory-polling-collector}

One can configure **super\_mediator** to periodically poll directories for
files. The files found in the directory are read and then either moved to
another directory or deleted. To create a polling collector, either
**--move-dir** and/or **--polling-interval** must be given. The argument to
**--move-dir** is the directory where files are moved after being processed;
if not specified, the files are deleted. The period for polling the
directory is specified by **--polling-interval**, and defaults to 30 seconds
if not given. The directory(s) to poll are given as arguments.

**super\_mediator** periodically polls the directory until it is signaled to
terminate.

For example, the following create a directory polling collector. Output is
written as IPFIX to the standard output.

**super\_mediator** **--move=/var/sm/complete /var/sm/incoming**

Poll the directory /var/sm/incoming every 30 seconds; after processing each
file, move it to /var/sm/complete.

**super\_mediator** **--move=/var/sm/complete --polling-interval=5 /var/sm/incoming**

Similar to the previous example, except /var/sm/incoming is polled every 5
seconds.

**super\_mediator** **--polling-interval=30 /var/sm/incoming /var/sm/incoming2**

Poll the directories /var/sm/incoming and /var/sm/incoming2 every 30
seconds; delete each file after processing it.

>   **Note:** If you are coming from v1.8.0 or earlier, note that the
>   argument in v2.0.0 is a directory name. Previously, **super\_mediator**
>   took a glob pattern as an argument, but that is no longer its behavior.

### [File Collector](#file-collector) {#file-collector}

To have **super\_mediator** run as a file collector, name the files on the
command line. If no file names are given, **super\_mediator** reads from its
standard input. To have **super\_mediator** read from files and from the
standard input, use "-" as a file name. Each filename argument is treated as
a separate collector.

When running as a file collector, **super\_mediator** exits once all inputs
have been read.

As an example, the following reads files a.yaf, b.yaf, and c.yaf and writes
the result as IPFIX to the standard output.

**super\_mediator** **a.yaf b.yaf c.yaf**

### [Input Options](#input-options) {#input-options}

These command line arguments are used to define the collectors when the
configuration file is not used.

**super\_mediator** treats any command line arguments that are not
associated with an option as an *INPUT\_SPECIFIER*. Zero or more
*INPUT\_SPECIFIER*s may be specified; each is treated as an IPFIX collector,
and all specifiers must be the same type.

If **super\_mediator** is listening on the network or polling a directory,
it runs until it is signaled to stop (killed). When given a file list,
**super\_mediator** exits after processing the files.

-   **--ipfix-input** *TRANSPORT\_PROTOCOL*

    Causes **super\_mediator** to operate as an IPFIX network collector,
    listening for connections via the specified protocol
    *TRANSPORT\_PROTOCOL*, which must be either **tcp** or **udp**. UDP is
    not recommended as it is not a reliable transport protocol and cannot
    guarantee delivery of messages. The port to listen on is specified by
    the **--ipfix-port** option and defaults to 18000; the hostname to
    listen on must be specified in the *INPUT\_SPECIFIER*.

-   **--ipfix-port** *PORT*

    Requires the presence of **--ipfix-input** and specifies the TCP or UDP
    port where **super\_mediator** listens for incoming connections. If not
    present, the default port 18000 is used. The hostname to listen on is
    specified in the *INPUT\_SPECIFIER*.

-   **--polling-interval** *POLL\_TIME*

    Causes the *INPUT\_SPECIFIER*(s) to be treated as directory name(s) and
    tells **super\_mediator** to process files in the directory(s) every
    *POLL\_TIME* seconds. **super\_mediator** runs forever waiting for files
    to appear in the directory. After processing the incoming files,
    **super\_mediator** deletes the files unless a **--move-dir** is
    specified.

-   **--move-dir** *PROCESSED\_INPUT\_DIRECTORY*

    Causes the *INPUT\_SPECIFIER*(s) to be treated as directory name(s) and
    tells **super\_mediator** to process files in the directory(s)
    periodically. The default period is 30 seconds, but may be changed with
    the **--polling-interval** option. The incoming files are moved to
    *PROCESSED\_INPUT\_DIRECTORY* after processing. If
    **--polling-interval** is specified and **--move-dir** is not, the
    incoming files are deleted after they are processed.

-   **--no-locked-files**

    **Currently unimplemented.** Tells **super\_mediator** to ignore the
    presence of lock files and process all files in the incoming directory
    when either **--polling-interval** or **--move** is specified. By
    default, **super\_mediator** does not read files that are locked, which
    means they have the extension ".lock" appended to the end of the
    filename. This can be used if **super\_mediator** is reading from a
    yaf(1) export directory and yaf(1) is run with **--lock**. This will
    prevent **super\_mediator** from removing the files out from under
    yaf(1). This does not lock files that the **super\_mediator** is writing
    to. Use the **super\_mediator** configuration file to enable locking of
    output files.


## [Output: Defining the Exporter](#output-define-exporter) {#output-define-exporter}

The output from Super Mediator is called an exporter. A single exporter is
created when not using the configuration file. Super Mediator may export
IPFIX to a network host and port, or it may export IPFIX, JSON, or delimited
text to a single file or a series of files where the output file is closed
and a new file opened periodically (a rotating output file).

### [Network Exporter](#network-exporter) {#network-exporter}

To create an IPFIX network exporter, the **--output-mode** switch must be
given and have an argument of either **tcp** or **udp**. The **--out**
option names the host or IP address where the records are sent. By default,
**super\_mediator** attempts to contact that host on port 18001, but that
may be changed by using the **--export-port** switch.

The **--sleep** option may be specified to introduce a delay in how often
records are written to the output. This can be used to help reduce data loss
when transmitting IPFIX over UDP. Its argument is the number of microseconds
to delay between adding records to the output buffer.

The following examples read IPFIX from the standard input and write it over
the network.

**super\_mediator** **--output-mode=tcp --out=localhost**

Write data over TCP to port 18001 on localhost.

**super\_mediator** **--output-mode=tcp --export-port=7788 --out=127.0.0.1**

Write data over TCP to port 7788 on 127.0.0.1.

### [Rotating File Exporter](#rotating-file-exporter) {#rotating-file-exporter}

When the **--rotate** option is given, **super\_mediator** writes its output
to a series of files. The argument to **--out** is a directory and filename
prefix to use for the output files, and the suffix depends on the format of
the output being written.

If the **--output-mode** option is not given, the output is IPFIX, and the
suffix of the output files is based on the current time. The suffix is
"-*YYYYmmddHHMMSS*-*NNNNN*.med" where *YYYYmmdd* is the current year, month,
and day, *HHMMSS* is the current UTC time, and *NNNNN* is a serial number
that is incremented for each file created.

To have **super\_mediator** write JSON, specify **--output-mode=json**. In
this case, the suffix is based on the time within the flow record itself,
and the suffix is ".*YYYYmmddHHMMSS*.json", where *YYYYmmdd* and *HHMMSS* is
based on the year, month, day, and time of the flow record's
endFlowMilliseconds.

To have **super\_mediator** write delimited-separated-value text (with the
vertical bar, `|`, also called pipe, as the delimiter), specify
**--output-mode=text**. In this case, as with JSON, the suffix is based on
the time within the flow record itself, and the suffix is
".*YYYYmmddHHMMSS*.txt".

The following examples read IPFIX from the standard input.

**super\_mediator** **--rotate=30 --out=/data/fccx**

Write binary IPFIX data to files in /data. When processing the [Flaming
Cupcake Challenge (FCC) sample data][FCC] from 2015, one of the output files
is named "/data/fccx-20220222220222-02003.med".

**super\_mediator** **--rotate=30 --output-mode=json --out=/data/fccx**

Write the flows in the JSON format to files in /data. When processing the
FCC sample data, one of the output files is named
"/data/fccx.20150914235417.json"

**super\_mediator** **--rotate=30 --output-mode=text --out=/data/fccx**

Write the flows in a pipe-delimited text format to files in /data. When
processing the FCC sample data, one of the output files is named
"/data/fccx.20150914235648.txt"

### [Single File Exporter](#single-file-exporter) {#single-file-exporter}

To write to a single file do not specify **--rotate**. The argument to
**--out** is the destination file. Use **--output-mode** to produce JSON or
delimited-text output, or do not specify the option to produce IPFIX. If
**--out** is not given, output is written to the standard output.

The following examples read IPFIX from the standard input.

**super\_mediator** **--out=/data/my-file.ipfix**

Writes IPFIX to "/data/my-file.ipfix".

**super\_mediator** **--output-mode=json --out=/data/my-file.json**

Writes JSON to "/data/my-file.json".

**super\_mediator** **--output-mode=text --out=/data/my-file.txt**

Writes delimited text to "/data/my-file.txt".

### [Output Options](#output-options) {#output-options}

These options control where **super\_mediator** sends its output and the
type of output it writes. **super\_mediator** can write flows to an IPFIX
file, text file, or to an IPFIX collector over TCP or UDP. By default, if no
options are given, **super\_mediator** writes IPFIX to standard out.

-   **--out** *OUTPUT\_SPECIFIER*

    *OUTPUT\_SPECIFIER* is an output specifier. If **--output-mode** is
    present, and set to TCP or UDP, the *OUTPUT\_SPECIFIER* specifies the
    hostname or IP address of the collector to which the flows will be
    exported. If **--output-mode** is set to TEXT, *OUTPUT\_SPECIFIER* is a
    filename in which the flows will be written in pipe-delimited (C<|>)
    format. If **--output-mode** is set to JSON, *OUTPUT\_SPECIFIER* is a
    filename in which the flows will be written in pipe-delimited (C<|>)
    format. Otherwise, *OUTPUT\_SPECIFIER* is a filename in which flows will
    be written in IPFIX Format. The string **-** may be used to write to
    standard output (the default). If **--rotate** is present,
    *OUTPUT\_SPECIFIER* is the prefix name of each output file to write to.
    When writing to a network socket, **super\_mediator** must be able to
    make an initial connection to the *OUTPUT\_SPECIFIER* for
    **super\_mediator** to start. If the connection is lost after the
    initial connection, **super\_mediator** will immediately retry the
    connection after reporting a warning message to the log. If the retry is
    unsuccessful, **super\_mediator** will retry the connection every 15
    seconds until the connection is successful. Flows will be lost while the
    connection is down.

-   **--output-mode** *TRANSPORT\_PROTOCOL*

    If present, causes **super\_mediator** to operate as an IPFIX, TEXT, or
    JSON exporter, exporting via the specified protocol
    *TRANSPORT\_PROTOCOL* to a collector (e.g rwflowpack, flowcap) named in
    the *OUTPUT\_SPECIFIER*. Valid *TRANSPORT\_PROTOCOL* values are **tcp**,
    **udp**, **text**, and **json**. UDP is not recommended, as it is not a
    reliable transport protocol and cannot guarantee delivery of messages.

-   **--export-port** *PORT*

    If **--output-mode** is present and set to TCP or UDP, export flows to
    port *PORT*. If not present, the default port 18001 will be used. The
    host to export to is specified with the **--out** option.

-   **--rotate** *ROTATE\_SECONDS*

    Causes the *OUTPUT\_SPECIFIER* to be treated as the **prefix** of an
    output file name. **super\_mediator** appends a timestamp to the prefix
    and periodically closes the output file and opens a new open. This
    switch determines how often that occurs.

-   **--sleep** *MICROSECONDS*

    If present, **super\_mediator** sleeps for *MICROSECONDS* microseconds
    between each record it appends to an IPFIX message. This is useful if
    **super\_mediator** is reading an IPFIX file and transmitting IPFIX over
    UDP. **super\_mediator** may send the messages too quickly for the IPFIX
    Collector to receive them (possibly dropping messages.) This option is
    only available with one collector and one exporter when executing
    **super\_mediator** from the command line.

## [Modifying the Exported Records](#modifying-the-exported-records) {#modifying-the-exported-records}

These options control how the exported data appears or what types of records
are exported.

-   **--fields** *FIELD\_LIST*

    If present and **--output-mode=TEXT** is also present, writes only the
    fields given in *FIELD\_LIST*. *FIELD\_LIST* is a list of IPFIX element
    names, separated by a comma. The list of acceptable fields is nearly any
    IPFIX element.

-   **--print-headers**

    If present for TEXT Exporters, **super\_mediator** writes a header for
    delimited flow data. If files rotate, it writes one header at the top of
    each flow data file.

-   **--no-stats**

    If present, **super\_mediator** does not forward [YAF][] process
    statistics records or log statistics. It is possible to configure
    certain exporters to process stats while others ignore stats messages.
    This must be done with through the **super\_mediator** configuration
    file.

-   **--preserve-obdomain**

    If present, **super\_mediator** will not overwrite the observation
    domain in the incoming IPFIX records. If given and the incoming records
    do not have an observationDomainId element, the exported records will
    have a domain of zero. **super\_mediator**'s default behavior is to copy
    the observation domain ID from the incoming IPFIX messages' headers to
    the records it exports, overwriting any previous observationDomainId
    value in the records.

-   **--rewrite-ssl-certs**

    If specified, **super\_mediator** will, for IPFIX exporters, rewrite the
    incoming TLS/SSL certificate records to have explicit information
    elements for parts of the certificate's issuer, subject, and extensions
    instead of having data stored in a subTemplateList of key-value
    (sslObjectType,sslObjectValue) pairs.

-   **--disable-metadata-export**

    If present, **super\_mediator** does not include information element and
    template metadata in IPFIX output.

-   **--ipsetfile** *IPSET\_FILE*

    Exits the program due to missing IPset support.

-   **--udp-temp-timeout** *TIMEOUT\_SECS*

    **Currently unimplemented.** Set UDP template timeout in seconds if
    **--ipfix-mode** is set to *UDP*. As per RFC 5101 recommendations,
    **super\_mediator** will attempt to export templates three times within
    *TEMPLATE\_SECS*. The default template timeout period is 600 seconds (10
    minutes).

## [Logging Options](#logging-options) {#logging-options}

By default, **super\_mediator** writes log messages at levels WARNING and
ERROR to the standard error. These options change that behavior.

The command-line logging switches override the log settings set in the
configuration file.

-   **--log** *LOG\_SPECIFIER*

    Specifies the destination for log messages. *LOG\_SPECIFIER* can be a
    **syslog(3)** facility name, the special value **stderr** for standard
    error, or the absolute path to a file for file logging. To write
    messages to rotating files in a directory, use the **--log-dir** option.
    The default log specifier is **stderr**. The log level can be specified
    by the **LOGLEVEL** keyword in the **super\_mediator** configuration
    file or by using either **--verbose** or **--quiet**. The default level
    is WARNING.

-   **--log-dir** *LOG\_PATH*

    Tells **super\_mediator** to write log messages to files in *LOG\_PATH*.
    *LOG\_PATH* must be a complete directory path. The log files have the
    form LOG\_PATH/sm-YYYYMMDD.log where *YYYYMMDD* is the current date.
    The log files are rotated at midnight local time. When the log files are
    rotated a new log is opened, the previous file is closed, and
    **gzip(1)** is invoked on the previous day's log file. (Old log files
    will not be removed by **super\_mediator**.)

-   **--verbose**

    Enables logging of all messages. The default log level is **WARNING**.
    This option changes the log level to **DEBUG** and logs all **yaf(1)**
    and **super\_mediator** process statistics, along with any IO
    operations.

-   **--quiet**

    Turns off logging completely. **super\_mediator** will not log errors.

## [Daemon Options](#daemon-options) {#daemon-options}

To run **super\_mediator** as a daemon, specify the **--daemonize** option.
The configuration file does not offer a way to enable this.
**super\_mediator** refuses to run as a daemon if the log output is being
written to the standard error.

Even without the **--daemonize** option, **super\_mediator** runs until
killed when using a network or directory polling collector.

-   **--daemonize**

    Causes **super\_mediator** to become a daemon.

-   **--pidfile** *PIDFILE\_NAME*

    Sets the complete path to the file in which **super\_mediator** writes
    its process ID (pid) when running as a daemon. **--pid-file** is ignored
    if **--daemon** is not present.

## [Privilege Options](#privilege-options) {#privilege-options}

There is no need to start **super\_mediator** as the root user as it does
not require access to any privileged resources. However, if it is started as
root, use of the following are highly recommended for security purposes.

-   **--become-user** *UNPRIVILEGED\_USER*

    Tells **super\_mediator** to drop its privileges to *UNPRIVILEGED\_USER*
    after starting. Using **--become-user** requires **super\_mediator** to
    be run as root or setuid root. This option will cause all files written
    by **super\_mediator** to be owned by the user *UNPRIVILEGED\_USER* and
    the user's primary group; use **--become-group** as well to change the
    group **super\_mediator** runs as for output purposes.

-   **--become-group** *UNPRIVILEGED\_GROUP*

    Tells **super\_mediator** to change its privileges to
    *UNPRIVILEGED\_GROUP* after starting. The **--become-group** option
    allows changing the group from the default of the user given in
    **--become-user**. This option has no effect if given without the
    **--become-user** option as well.


# [Configuration File](#configuration-file) {#configuration-file}

For details of the configuration file, see the
[super_mediator.conf][sm.conf] manual page.


[//]: # (    Command line options)
[//]: # (        Some details link down below to configuration file features explanation. Things like inputs and outputs and config file things on the command line.)
[//]: # (    (The following sections discuss how super mediator works and how to configure things using the config file, with a note each time a command line options applies.))
[//]: # (    SM description)
[//]: # (        Use of configuration file)
[//]: # (        Inputs)
[//]: # (            record processing)
[//]: # (        Outputs)
[//]: # (            ipfix)
[//]: # (            json)
[//]: # (            text)
[//]: # (        Core stuff)
[//]: # (            preserve obsdomain)
[//]: # (            rewrite ssl certs)
[//]: # (        Record types)
[//]: # (        SM Record Generation)
[//]: # (            dns rr)
[//]: # (            dns dedup)
[//]: # (            ssl dedup)
[//]: # (        Data manipulation)
[//]: # (            flow only)
[//]: # (            dpi only?)
[//]: # (            dpi config)
[//]: # (    Config - Collectors)
[//]: # (        inputs)
[//]: # (        filters)
[//]: # (    Config - Core)
[//]: # (        preserve obsdomain)
[//]: # (        rewrite ssl certs)
[//]: # (    Config - Exporters)
[//]: # (        filters)
[//]: # (        generating records)
[//]: # (        manipulating records)
[//]: # (        outputs)
[//]: # (            IPFIX)
[//]: # (            JSON)
[//]: # (            TEXT)
[//]: # (    Config - Filter)
[//]: # (    Config - general)
[//]: # (        log level)
[//]: # (        stats timeout)
[//]: # (    Examples)


[rfc7011]:      https://datatracker.ietf.org/doc/html/rfc7011.html

[FCC]:          /silk/referencedata.html
[YAF]:          /yaf/index.html

[sm.conf]:      super_mediator.conf.html

[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
