% Super Mediator: Installation Instructions &amp; Dependencies

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

Super Mediator may be installed from [pre-built RPM files](#installRPM) on
supported platforms or by [compiling the source code](#fromSource).

Typically `yum` will find and install any required dependencies for you when
installing from a pre-built RPM. If not, read the next section on
dependencies.

# [Dependencies](#dependencies) {#dependencies}

Build and/or install these dependencies before installing Super Mediator.

## [Basic Build Environment](#build-dev) {#build-dev}

When building from source, ensure you have the packages needed to build
software.

-   For Redhat, Fedora, and other RPM systems, run

        sudo yum -y install gcc gcc-c++ make pkgconfig

    Alternatively, you may install the tools for a complete development
    environment:

        sudo yum -y group install "Development Tools"

-   For Debian and Ubuntu, run

        sudo apt install build-essential

-   For macOS, install Xcode from the App Store and the Xcode command line
    tools.

## [Package Dependency Note](#dev-packages) {#dev-packages}

On some systems (particularly Linux), many support libraries (for example,
`glib2`), are divided into two (or more) packages:

1.   One package satisfies a *run dependency*: It is needed to run another
     package that depends on it. This package is named glib2-*VERISON*.rpm
     on Redhat and libglib2.0-*VERSION*.deb on Ubuntu.

2.   Another package satisfies a *build dependency*: It is needed only when
     building a another piece of software, and it contains C header files
     and additional library files. This package is named
     glib2-devel-*VERSION*.rpm on Redhat and libglib2.0-dev-*VERSION*.deb on
     Ubuntu.

3.   Sometimes documentation is in a third package.

When installing dependencies to build Super Mediator from source, ensure you
install the package(s) that require the build dependencies; for example,
either `glib2-devel` or `libglib2.0-dev`. Installing these packages also
installs the packages needed for the run dependency (for example `glib2` or
`libglib2.0`).

When installing dependencies to install an RPM of Super Mediator, only the
run dependency is needed (for example `glib2`), and often the package
manager finds these packages for you.

## [Required Dependencies](#required-dependencies) {#required-dependencies}

Super Mediator requires [GLib-2.0][] 2.18 or later. Note that GLib is
included in many operating environments or ports collections.

Super Mediator requires [libfixbuf][]. Super Mediator 2.x requires libfixbuf
3.x. Consult this table for earlier versions.

| SUPER MEDIATOR VERSIONS | FIXBUF VERSIONS |
| ----------------------- | --------------- |
| 2.0                     | 3.0 |
| 1.7.x, 1.8.x            | 2.3 and any later 2.x |
| 1.6.x                   | any 2.x version |
| 1.2.x through 1.5.x     | 1.7 and any later 1.x |
| 1.1.x                   | 1.4 and any later 1.x |

## [Optional Dependencies](#optional-dependencies) {#optional-dependencies}

Super Mediator is able to read compressed IPFIX files when the [zlib][]
library is found by `configure`. Many systems have zlib installed.

>   **Note:** MySQL and SiLK IPSet support is currently disabled in Super
>   Mediator 2.0. This will be addressed in a later release.

When [YAF][]'s deep packet inspection is configured to export complete
TLS/SSL certificates, Super Mediator can be configured to compute a hash
(e.g., SHA1) of the X.509 certificate if Super Mediator has been built with
[OpenSSL][] support.

Super Mediator can be configured at run-time to load files into a MySQL
database. To enable this feature, the [MySQL][] or [MariaDB][] client
library must be found when Super Mediator is built. If the required library
is found, the [**super_table_creator**][sm_creator] program is also built
and installed.

Super Mediator can use [SiLK][]'s IPSet library when either the complete
SiLK suite or the stand-alone [SiLK IPSet library][ipsetlib] is discovered
during the build process. The IPSet library may be used to filter flow
records or to add an element to a record indicating that the record's IP
address matched an IPSet.

# [Install from the CERT Linux Forensics Tools Repository](#installRPM) {#installRPM}

On a Redhat, Fedora, or RPM-based host, the easiest way to install Super
Mediator is using the [CERT Linux Forensics Tools Repository][lifter].

If you follow the instructions to add the Tools Reposistory to the locations
your system looks for packages, you can use yum to find the Super
Mediator package and yum will install its dependencies.

An alternative is the to download the Super Mediator package, and install
Super Mediator and its dependencies manually. See the [dependency
section](#dependencies) above for the list of dependencies.

# [Install from Source](#fromSource) {#fromSource}

To install from source, first [download][download] the version of Super
Mediator you want to install.

Super Mediator uses a reasonably standard autotools-based build system.
Super Mediator uses the pkg-config facility to find libfixbuf; you may have
to set the PKG\_CONFIG\_PATH variable on the `configure` command line if
libfixbuf is installed in a nonstandard location (other than the prefix to
which you are installing Super Mediator itself).

To install Super Mediator from source you can run the following commands:

    $ tar -xvzf super_mediator-2.0.0.tar.gz
    $ cd super_mediator-2.0.0
    $ ./configure {configure_options}
    $ make
    $ make install

>   **NOTE:** Installing from source will overwrite previous versions of
>   Super Mediator's configuration file in the `/usr/local/etc` directory
>   (the location may be different depending on the options given to
>   `configure`). If you have customized the `super\_mediator.conf` file,
>   make a copy prior to installing a new version of Super Mediator.

## [Configuration Options](#configuration-options) {#configuration-options}

Super Mediator supports the following configuration options in addition to
those supplied by default via autoconf (for example, **--prefix**).

>   **Note:** MySQL and SiLK IPSet support is currently disabled in Super
>   Mediator 2.0. This will be addressed in a later release.

**--with-mysql**, **--with-mysql=MYSQL\_CONFIG**

:   Enable use the [MySQL][] or [MariaDB][] client library which allows
    Super Mediator to load files into a database. The `configure` script
    automatically looks for the `mysql\_config` program and includes this
    support if it is found. You may provide the path to that program as the
    argument to the **--with-mysql** option. Use **--without-mysql** to
    disable the automatic check.

**--with-openssl**, **--with-openssl=OPENSSL\_DIR**

:   Enable TLS/SSL certificate hashing with [OpenSSL][]; find openssl/sha1.h
    in OPENSSL\_DIR/include and libssl in OPENSSL\_DIR/lib. This feature is
    not checked for by default; it must be explicilty enabled.

**--with-skipset**, **--with-skipset=SKIPSET\_DIR**

:   Enable SiLK IPSet support. To use the library bundled with [SiLK][],
    SKIPSET\_DIR should contain include/silk/skipset.h and
    lib/libsilk.so. To use the separate [SiLK IPSet library][ipsetlib],
    SKIPSET\_DIR is expected to contain include/silk-ipset/silk-ipset.h and
    lib/libskipset.so. The `configure` script looks for these files
    automatically; provide the SKIPSET\_DIR value to help `configure` find
    it, or **--without-skipset** to disable the check.

**--with-zlib**, **--with-zlib=ZLIB\_DIR**

:   Include the ability to read compressed IPFIX files; tell configure to
    find zlib.h in ZLIB\_DIR/include and libz in ZLIB\_DIR/lib. The
    configure script automatically looks for [zlib][] and enables this
    feature when it is found.

**--with-zlib-includes=ZLIB\_INCLUDE**

:   Look for zlib.h in the ZLIB\_INCLUDE directory instead of in
    ZLIB\_DIR/include.

**--with-zlib-libraries=ZLIB\_LIB**

:   Look for libz in the ZLIB\_LIB directory instead of in ZLIB\_DIR/lib.


[GLib-2.0]:       https://docs.gtk.org/glib/
[MariaDB]:        https://www.mariadb.com/
[MySQL]:          https://www.mysql.com/
[OpenSSL]:        https://www.openssl.org/
[lifter]:         https://forensics.cert.org/
[zlib]:           https://zlib.net/

[YAF]:            /yaf/index.html
[SiLK]:           /silk/index.html
[ipsetlib]:       /silk-ipset/index.html
[libfixbuf]:      /fixbuf/index.html

[download]:       download.html
[sm_creator]:     super_table_creator.html


[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
