% What's New in Super Mediator 2.0.

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

This page documents the new features and incompatible changes in Super
Mediator 2.0.

# [Adaptability for Changes to YAF](#adaptability) {#adaptability}

Traditionally Super Mediator contained fixed template definitions that
matched those in [YAF][]. However, this meant changes to YAF also required
changes to Super Mediator.

Super Mediator 2.0 largely uses the templates it receives as-is and passes
them along to its export streams.

When looking for a particular templates (do to de-duplication, for example),
Super Mediator 2.0 checks for particular elements instead of matching the
entire template and makes use of the exhanced template metadata exported by
YAF 3. This allows increased flexibility and should allow Super Mediator to
handle moderate changes that YAF makes to its templates. (Major changes in
YAF will still require changes to Super Mediator.)

# [New Configuration File Syntax](#new-config) {#new-config}

The configuration file has significant changes. Files from previous releases
of Super Mediator must be updated to work with this release.

-   SINGLE\_FILE replaces previous keyword FILEANDLER

    In general, places that used FILEHANDLER should instead use
    SINGLE\_FILE.

-   COLLECTOR uses DIRECTORY\_POLL in place of DIR.

    To have a COLLECTOR poll a directory, use the DIRECTORY\_POLL keyword,
    and note that the PATH argument now takes directory name and not a file
    glob. There is no way to limit which files a DIRECTORY\_POLL COLLECTOR
    processes.

-   EXPORTER statement requires two arguments plus optional name.

    The EXPORTER keyword now takes two arguments: an output format (IPFIX,
    JSON, or TEXT) and a transport (SINGLE\_FILE, TCP, UDP, or
    ROTATING\_FILES).

-   JSON is now an export format.

    The JSON keyword within an EXPORTER block is no longer supported.
    Instead, JSON should be used immediately after the EXPORTER keyword.

-   Comparison filtering statements use the information element name,
    surrounded by double quotes.

    To select only DNS traffic, you should use `"silkAppLabel" == 53` in
    place of `APPLICATION == 53`.

-   The FIELDS statement now takes double-quoted information element
    name(s), with square brackets around the list.

    Change `FIELDS hash, stime` to `FIELDS \[ "yafFlowKeyHash",
    "flowStartMilliseconds" \]`.

A new option **--test-config** has been added to allow testing the
configuration file syntax.

# [Removed Several Command Line Options](#command-line) {#command-line}

Made changes to the command line parsing and eliminated several options.
The configuration file is the preferred way to configure super_mediator.

-   Option **--in** has been removed.

    Command line arguments that are not arguments to an option are treated
    as inputs with the types of inputs depending on the argument to
    **--input-mode**. For example, the inputs are treated as hosts if
    **--input-mode** is **tcp** or **udp**.

    In **--input-mode** is not given, the inputs are either file names to
    read or directory names to poll. All inputs must be of the same type.

-   When using the configuration file, command line input files now cause an
    error. Inputs must be specified in the configuration file when it is in
    use.

-   Glob handling has been removed from **super\_mediator**. Instead, the
    shell should be used to expand the glob.

-   Option **--polling-interval** replaces **--watch**.

-   Option **--move-dir** replaces **--move**.

-   Option **--no-locked-files** replaces **--lock**.

-   Option **--dns-dedup** has been removed. This must be enabled within a
    configuration file.

In general, it is now an error to specify a value on the command line and in
the configuration file.

# [Enhanced Statistics](#enhanced-statistics) {#enhanced-statistics}

Enhanced statistics for types of records read from a collector and written
to an exporter.

# [Record and Template IDs Have Changed](#template-ids) {#template-ids}

Super Mediator processes data from [YAF][]. Since YAF 3 has changed the
[structure and IDs of its templates][yaf_templates], including the use of
[named lists][yaf_lists], Super Mediator contains these changes when reading
data from YAF 3.

# [Field Name Changes](#field-name-changes) {#field-name-changes}

Note that Super Mediator 2.0 has the same [information element name
changes as YAF 3.0][yaf_renaming].

The new names are used even if Super Mediator is processing IPFIX generated
by YAF 2. The IPFIX input contains only numeric IDs for the elements. The
mapping of IDs to names depends on the version of the software doing the
mapping.

# [Limitations](#limitations) {#limitations}

Super Mediator currently has the following limitations.

## [Delimited Text Export Is A Work-in-Progress](#text-export) {#text-export}

Exporting as delimited TEXT is lightly tested and contains bugs.

## [SiLK IPset Support Temporarily Disabled](#no-silk-ipset) {#no-silk-ipset}

SiLK IPset support is not available in this release. This will be re-enabled
in a later release.

## [MySQL Support Temporarily Disabled](#no-mysql) {#no-mysql}

MySQL and MariaDB support is not available currently. This will be
re-enabled in a later release.


[YAF]:              /yaf/index.html
[yaf_lists]:        /yaf/new_yaf3.html#named_lists
[yaf_renaming]:     /yaf/new_yaf3.html#ie-renaming
[yaf_templates]:    /yaf/new_yaf3.html#templates

[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
