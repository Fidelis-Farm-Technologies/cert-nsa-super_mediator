% Quick Setup Guide for super_mediator

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

This tutorial is a step-by-step guide of setting up [YAF][] and
**super\_mediator**. For a detailed tutorial on **super\_mediator** and the
different configuration options, see [this tutorial][sm_guide]. This
particular tutorial takes the DPI data produced by **yaf** and imports the
data into a [MariaDB][] or [MySQL][] database. This also enables DNS
deduplication in **super\_mediator**. This tutorial does not include an
example of how to setup [SiLK][]; for that, see [this page][yaf_sm_silk].

# [Install Procedure](#install) {#install}

This provides a brief overview of the installation procedure when building
from source. For more detailed information see each tool's installation
instructions. To install pre-built RPMs of these tools, use the [CERT
Forensics Tools Repository][lifter].

## [Install Prerequisites](#prerequisites) {#prerequisites}

    yum groupinstall "Development Tools"
    yum install libpcap-devel pcre-devel

Install either [MariaDB][]:

    yaf install mariadb-server mariadb-devel

or [MySQL][]:

    yaf install mysql-server mysql-devel

Build and install [libfixbuf][]:

    tar -xvzf libfixbuf-3.0.0.tar.gz
    cd libfixbuf-3.0.0
    ./configure
    make
    make install

## [Install YAF and Super Mediator](#yaf-and-sm) {#yaf-and-sm}

>   **NOTE:** Installing from source will overwrite previous versions of
>   YAF's and Super Mediator's configuration files in the `/usr/local/etc`
>   directory (the location may be different depending on the options [given
>   to `configure`][sm_install]). If you have customized those files, make a
>   copy prior to installing a new versions of YAF and Super Mediator.

Build and install [YAF][]. The minimum recommended options are shown here;
see the [YAF installation page][yaf_install] for other options.

    tar -xvzf yaf-3.0.0.tar.gz
    cd yaf-3.0.0
    ./configure --enable-applabel --dpi
    make
    make install

Build and install **super\_mediator**:

    tar -xvzf super_mediator-2.0.0.tar.gz
    cd super_mediator-2.0.0
    ./configure --with-mysql
    make
    make install

## [Setup MariaDB or MySQL](#mysql) {#mysql}

Start the database service:

    service mariadb start

or

    service mysqld start

Set a password for the root user:

    /usr/bin/mysqladmin -u root password '<SuperSecretPassword>'

Login to the database. It will prompt you for the password you created in
the previous step:

    mysql -u root -p

Create the database you intend to use for **super\_mediator**:

    mysql> create database smediator;

Create a user for **super\_mediator** to access the database:

    mysql> CREATE USER 'mediator'@'localhost' IDENTIFIED BY '<SuperSecretPassword>';

Give permissions to user to access only the smediator database:

    mysql> GRANT ALL ON smediator.* TO mediator@'localhost';

## [Create MariaDB or MySQL Tables](#tables) {#tables}

Use [**super\_table\_creator**][sm_creator] to create all the tables in your
database:

    /usr/local/bin/super_table_creator --name mediator \
        --pass=<SuperSecretPassword> --database=smediator
    /usr/local/bin/super_table_creator --name mediator \
        --pass=<SuperSecretPassword> --database=smediator --dns-dedup

## [Configure **super\_mediator**](#sm) {#sm}

Create output directories:

    mkdir -p /data/smediator/dpi
    mkdir -p /data/smediator/dns

Create your `super_mediator.conf` file. One is installed by default into
/usr/local/etc. (The location may be different depending on how
**super\_mediator** is [built][sm_install].) The following one will get you
started (you should add your \<SuperSecretPassword\>):

    COLLECTOR TCP
       PORT 18000
    COLLECTOR END

    #dedup process
    EXPORTER TEXT ROTATING_FILES "dedup"
       PATH "/data/smediator/dns/yaf2dns"
       DELIMITER "|"
       ROTATE_INTERVAL 1200
       DNS_DEDUP_ONLY
       LOCK
       MYSQL_USER "mediator"
       MYSQL_PASSWORD "<SuperSecretPassword>"
       MYSQL_TABLE "dns-dedup"
       MYSQL_DATABASE "smediator"
    EXPORTER END

    #dpi 2 database
    EXPORTER TEXT ROTATING_FILES
       PATH "/data/smediator/dpi"
       ROTATE_INTERVAL 1200
       MULTI_FILES
       DPI_ONLY
       LOCK
       MYSQL_USER "mediator"
       MYSQL_PASSWORD "<SuperSecretPassword>"
       MYSQL_DATABASE "smediator"
    EXPORTER END

    DNS_DEDUP "dedup"
       MAX_HIT_COUNT 5000
    DNS_DEDUP END

    LOGLEVEL DEBUG
    LOG "/var/log/super_mediator.log"
    PIDFILE "/data/super_mediator.pid"

## [Start Tools](#start) {#start}

Start **super\_mediator**

    super_mediator -c /usr/local/etc/super_mediator.conf --daemonize

Confirm **super\_mediator** is running:

    ps -ef | grep super

If **super\_mediator** is not running, check for any errors:

    cat /var/log/super_mediator.log

Start **yaf**:

    mkdir /var/log/yaf
    export LTDL_LIBRARY_PATH=/usr/local/lib/yaf

Run **yaf** over PCAP file:

    /usr/local/bin/yaf \
        --in <PCAP FILE> \
        --ipfix tcp \
        --out localhost \
        --ipfix-port 18000 \
        --log /var/log/yaf/yaf.log \
        --verbose \
        --silk \
        --dpi --max-payload 2048

*OR* Run **yaf** on interface eth0:

    /usr/local/bin/yaf \
        --in eth0 --live pcap \
        --ipfix tcp \
        --out localhost \
        --ipfix-port 18000 \
        --log /var/log/yaf/yaf.log \
        --verbose \
        --silk \
        --dpi --max-payload 2048 \

For releases of **yaf** prior to 3.0.0, replace `--dpi` with the options
`--applabel` `--plugin-name=/usr/local/lib/yaf/dpacketplugin.so`


[MariaDB]:        https://www.mariadb.com/
[MySQL]:          https://www.mysql.com/
[lifter]:         https://forensics.cert.org/

[SiLK]:                 /silk/index.html
[YAF]:                  /yaf/index.html
[libfixbuf]:            /fixbuf/index.html
[yaf_install]:          /yaf/install.html
[yaf_sm_silk]:          /yaf/yaf_sm_silk.html

[sm_creator]:           super_table_creator.html
[sm_guide]:             sm_guide.html
[sm_install]:           install.html

[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
