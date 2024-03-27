% super_mediator SSL Certificate De-duplication Configuration Tutorial

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

Transport Layer Security (TLS) and its predecessor Secure Sockets Layer
(SSL) are cryptographic protocols that add encryption and entity
authentication to Internet communications. These protocols are commonly used
with HTTP, aka HTTPS, to secure web traffic. Servers send certificates to
clients to authenticate themselves for TLS sessions. Certificates are issued
to administrators by *certificate authorities* (CAs). The role of the CA is
to verify that the certificate holder is in control of the domain name in
question and then mathematically bind particular encryption parameters to
that domain name.

TLS connections start with an unencrypted handshake. The server presents its
authentication credentials in the form of a certificate. The certificate
contains public information about the server, such as its advertised domain
name, public key, company, and information about the CA that issued the
certificate. The certificate also contains certain characteristics that
should prove the validity and authenticity of the certificate.

Computer Network Defense (CND) analysts often want to identify certificates
used by malware command and control servers, certificates with weak
cryptographic parameters to determine at-risk connections, and forged
certificates. Collecting certificate information traversing the network can
assist analysts in comparing collected certificate attributes to known
forged or compromised certificate attributes.

Collecting TLS/SSL certificates can be very cumbersome, as they are rather
large and certificates for frequently visited sites appear often. This can
result in a lot of duplicate data, putting a strain on storage resources.
**super\_mediator** can help with de-duplicating TLS/SSL certificates by
writing certificate data captured by [**yaf**][YAF] once and caching the
certificate's serial number and issuer name in memory until either the
certificate has been seen a certain number of times (set by MAX\_HIT\_COUNT)
or the unique pair has not been seen in a certain amount of time (set by
FLUSH\_TIMEOUT). This tutorial will provide examples of **super\_mediator**
TLS/SSL de-duplication configurations.

# [Configuration File](#config) {#config}

The most important part of the configuration file for TLS/SSL de-duplication
is the SSL\_CONFIG block.  An SSL\_CONFIG block must be associated with
a single EXPORTER.  TLS/SSL de-duplication can be configured for any
type of EXPORTER (TEXT, JSON, or IPFIX).

If TLS/SSL de-duplication is enabled, **super\_mediator** exports two unique
types of records: ["certificate" records](#certRecord), and ["dedup"
records](#dedupRecord).

## [TLS/SSL Deduplification "Certificate" Record](#certRecord) {#certRecord}

"Certificate" records contain all of the data that [**yaf**][YAF] captures
for an X.509 certificate. The full list can be found on the [YAF Deep Packet
Inspection][yaf_deeppacket] page. The fields that **super\_mediator**
exports in "certificate" records is configurable in the SSL\_CONFIG block
with the ISSUER, SUBJECT, OTHER, and EXTENSION keywords. The argument
provided with each one of these keywords is a bracketed-list of object
identifier values. Specify the list as `\[*\]` to tell **super\_mediator**
to export all possible values.

Some common object IDs for certificate ISSUER and SUBJECT are listed in the
following table. By default, **super\_mediator** will export all issuer and
subject fields.

| id | description |
| -: | :---------- |
|  3 | id-at-commonName |
|  6 | id-at-countryName |
|  7 | id-at-localityName |
|  8 | id-at-stateOrProvinceName |
|  9 | id-at-streetAddress |
| 10 | id-at-organizationName |
| 11 | id-at-organizationUnitName |
| 12 | id-at-title |
| 17 | id-at-postalCode |
| 41 | id-at-name |

The OTHER list can contain any one of the following information element IDs:

| id  | Info Element             | description |
| --: | :----------------------- | :---------- |
| 186 | sslClientVersion         | ssl Client version |
| 187 | sslServerCipher          | ssl server cipher |
| 188 | sslCompressionMethod     | ssl compression method |
| 189 | sslCertVersion           | ssl cert version |
| 244 | sslCertSerialNumber      | ssl cert serial number |
| 247 | sslCertValidityNotBefore | ssl cert validity not before |
| 248 | sslCertValidityNotAfter  | ssl cert validity not after |
| 250 | sslPublicKeyLength       | ssl public key length |
| 288 | sslRecordVersion         | ssl record version |
| 294 | sslServerName            | ssl server name |
| 298 | sslCertificateSHA1       | SHA1 hash of X.509 certificate |
| 299 | sslCertificateMD5        | MD5 hash of X.509 certificate |

The SHA1 and MD5 hashes of the X.509 certificate can be generated by
**super\_mediator**. The requirements to do so are that **super\_mediator**
is [built][sm_install] with [OpenSSL][] support and that [**yaf**][YAF] is
configured to export the entire binary certificate (see the
[documentation][yaf_deeppacket] for **cert\_export\_enabled**).

The EXTENSION list can contain any of the following object identfier values.
By default, **super\_mediator** will not write any EXTENSION objects, and
these must be explicitly identified in the SSL\_CONFIG block.

| id | description |
| -: | :---------- |
| 14 | subject Key Identifier |
| 15 | key Usage |
| 16 | private Key Usage Period |
| 17 | subject Alt Name (list) |
| 18 | issuer Alt Name (list) |
| 29 | certificate Issuer (list) |
| 31 | CRL Distribution points (list) |
| 32 | certificate policies |

To force **super\_mediator** to write all TLS/SSL certificate
characteristics captured by **yaf**, use the following configuration:

    SSL_CONFIG "exportername"
       ISSUER [*]
       SUBJECT [*]
       OTHER [*]
       EXTENSIONS [*]
    SSL_CONFIG END

The "certificate" record will have the following CSV format:

    serial_number | issuer_name | first_seen | obj_id | ISE | cert_no | data

serial\_number

:   The serial number of the X.509 certificate (hexadecimal).

issuer\_name

:   The common name of the Issuer (certificate authority) in the X.509
    certificate.

first\_seen

:   The first time this certificate was seen (start time of the flow that
    contained this certificate).

obj\_id

:   The object/member ID for the X.509 RelativeDistinguishedName Sequence
    (see the tables above). Note the obj\_id by itself is not unique; it
    must be paired with the next value.

ISE

:   The source field; it denotes if the data came from an Issuer Field (I),
    Subject Field (S), or Extension Field (E)

cert\_no

:   The certificate number in the chain. It signifies which certificate the
    data came from in the certificate chain. Usually, this field will
    contain a 0, 1, or 2.

data

:   The data collected by YAF (typically a string, but may be hexadecimal).

There may be more than one of the same object IDs present for a TLS/SSL
certificate if the object is a list (e.g. issuerAltName).

The IPFIX template for the "certificate" record is as follows:

    --- Template Record --- tid: 58642 (0xe512), fields: 43, scope: 0, name: sm_ssl_cert ---
      sslCertIssuerCommonNameList         (6871/452) <bl>       [65535]
      sslCertIssuerCountryName            (6871/191) <string>   [65535]
      sslCertIssuerLocalityName           (6871/197) <string>   [65535]
      sslCertIssuerState                  (6871/195) <string>   [65535]
      sslCertIssuerStreetAddressList      (6871/453) <bl>       [65535]
      sslCertIssuerOrgNameList            (6871/450) <bl>       [65535]
      sslCertIssuerOrgUnitNameList        (6871/451) <bl>       [65535]
      sslCertIssuerZipCode                (6871/194) <string>   [65535]
      sslCertIssuerTitle                  (6871/308) <string>   [65535]
      sslCertIssuerName                   (6871/310) <string>   [65535]
      sslCertIssuerEmailAddress           (6871/312) <string>   [65535]
      sslCertIssuerDomainComponentList    (6871/458) <bl>       [65535]
      sslCertSubjectCommonNameList        (6871/456) <bl>       [65535]
      sslCertSubjectCountryName           (6871/200) <string>   [65535]
      sslCertSubjectLocalityName          (6871/206) <string>   [65535]
      sslCertSubjectState                 (6871/204) <string>   [65535]
      sslCertSubjectStreetAddressList     (6871/457) <bl>       [65535]
      sslCertSubjectOrgNameList           (6871/454) <bl>       [65535]
      sslCertSubjectOrgUnitNameList       (6871/455) <bl>       [65535]
      sslCertSubjectZipCode               (6871/203) <string>   [65535]
      sslCertSubjectTitle                 (6871/309) <string>   [65535]
      sslCertSubjectName                  (6871/311) <string>   [65535]
      sslCertSubjectEmailAddress          (6871/313) <string>   [65535]
      sslCertSubjectDomainComponentList   (6871/459) <bl>       [65535]
      sslCertExtSubjectKeyIdent           (6871/316) <octets>   [65535]
      sslCertExtKeyUsage                  (6871/317) <octets>   [65535]
      sslCertExtPrivKeyUsagePeriod        (6871/318) <octets>   [65535]
      sslCertExtSubjectAltName            (6871/319) <octets>   [65535]
      sslCertExtIssuerAltName             (6871/320) <octets>   [65535]
      sslCertExtCertIssuer                (6871/321) <octets>   [65535]
      sslCertExtCrlDistribution           (6871/322) <octets>   [65535]
      sslCertExtCertPolicies              (6871/323) <octets>   [65535]
      sslCertExtAuthorityKeyIdent         (6871/324) <octets>   [65535]
      sslCertExtExtendedKeyUsage          (6871/325) <octets>   [65535]
      sslCertSignature                    (6871/190) <octets>   [65535]
      sslCertSerialNumber                 (6871/244) <octets>   [65535]
      sslCertValidityNotBefore            (6871/247) <string>   [65535]
      sslCertValidityNotAfter             (6871/248) <string>   [65535]
      sslPublicKeyAlgorithm               (6871/249) <octets>   [65535]
      sslPublicKeyLength                  (6871/250) <uint16>       [2]
      sslCertVersion                      (6871/189) <uint8>        [1]
      paddingOctets                            (210) <octets>       [5]
      sslCertificateHash                  (6871/295) <octets>   [65535]

For the elements whose type is basicList (`<bl>`), the element they contain
is determined by removing the "List" suffix from the name. For example, the
sslCertIssuerCommonNameList (IE 6871/452) contains zero or more
sslCertIssuerCommonName (IE 6871/196) elements

## [TLS/SSL Deduplification "Dedup" Record](#dedupRecord) {#dedupRecord}

The other type of record **super\_mediator** will export when performing
TLS/SSL de-duplication is a "dedup" record. A "dedup" record is a short
record that simply provides the first and last time a certificate was seen,
the unique identifier for a certificate (serial number, issuer name), and
the number of times it was seen within that time period. The CSV format is
as follows:

    first_seen | last_seen | serial_number | count | issuer\_name

first\_seen

:   The first time this certificate was seen (start time of the flow that
    contained this certificate).

last\_seen

:   The last time this certificate was seen before the record was flushed
    (start time of the flow that contained this certificate).

serial\_number

:   The serial number of the X.509 certificate (hexadecimal).

count

:   The number of times the certificate was seen in the time period.

issuer\_name

:   The common name of the Issuer (certificate authority) in the X.509
    certificate.

The "dedup" IPFIX template is as follows:

    --- Template Record --- tid: 55983 (0xdaaf), fields: 6, scope: 0, name: sm_ssl_dedup ---
      flowStartMilliseconds               (152) <millisec>     [8]
      flowEndMilliseconds                 (153) <millisec>     [8]
      smDedupHitCount                (6871/929) <uint64>       [8]
      sslCertSerialNumber            (6871/244) <octets>   [65535]
      sslCertIssuerCommonName        (6871/196) <string>   [65535]
      observationDomainName               (300) <string>   [65535]

There are two way to enable TLS/SSL certificate de-duplication:

*   the SSL\_DEDUP\_ONLY keyword is present in the EXPORTER block

        EXPORTER TEXT SINGLE_FILE "name"
            PATH "/data/ssl/sslcerts.txt"
            SSL_DEDUP_ONLY
        EXPORTER END

*   the SSL\_DEDUP keyword is present in an SSL\_CONFIG block linked to the
    EXPORTER

        EXPORTER JSON SINGLE_FILE "exportername"
            ....
        EXPORTER END
        SSL_CONFIG "exportername"
            SSL_DEDUP
        SSL_CONFIG END

## [CERT\_FILE](#certfile) {#certfile}

By default, **super\_mediator** writes both types of records (certificate
and dedup) to the filename given to "PATH" in the EXPORTER block. However,
if the CERT\_FILE keyword is present in an SSL\_CONFIG block associated with
a TEXT EXPORTER, **super\_mediator** writes "certificate" records to the
filename given to CERT\_FILE. This file is rotated and/or locked using the
same configuration settings given in the EXPORTER block associated with the
SSL\_CONFIG block. The CERT\_FILE keyword is ignored for all exporter types
other than TEXT.

# [Example TEXT Exporter](#example) {#example}

The following is an example configuration file that enables TLS/SSL
certificate de-duplication and exports all characteristics of an TLS/SSL
certificate to the rotating file prefix "/data/ssl/sslcerts".

    EXPORTER TEXT ROTATING_FILES "e1"
      PATH "/data/ssl/certs_dedup"
      SSL_DEDUP_ONLY
      ROTATE_INTERVAL 300
      LOCK
    EXPORTER END

    SSL_CONFIG "e1"
      ISSUER [*]
      SUBJECT [*]
      OTHER [*]
      EXTENSIONS [*]
      CERT_FILE "/data/ssl/certs"
      MAX_HIT_COUNT 25000
      FLUSH_TIME 3600
    SSL_CONFIG END

The following is an example of the data that the above configuration
produces:

    $ cat /data/ssl/certs_dedup.20150408192918.txt
    2015-04-08 19:14:29.556|2015-04-08 19:28:57.914|0x008620ad42a17aea20|4|Go Daddy Secure Certificate Authority - G2
    2015-04-08 19:29:14.389|2015-04-08 19:29:14.389|0x01fe4a238b2e7ce313c506df7fd7ca4e|4|DigiCert SHA2 Secure Server CA
    2015-04-08 19:16:20.469|2015-04-08 19:29:14.389|0x01fda3eb6eca75c888438b724bcfbc91|38|DigiCert Global Root CA
    2015-04-08 19:29:14.391|2015-04-08 19:29:14.391|0x040bd4f82588c5|4|Go Daddy Secure Certificate Authority - G2
    2015-04-08 19:17:14.651|2015-04-08 19:29:14.404|0x5cc17e9b9b4933fe|10|Google Internet Authority G2


    $ cat /data/ssl/certs.20150408191312.txt

    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|6|I|0|US
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|8|I|0|Arizona
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|7|I|0|Scottsdale
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|10|I|0|GoDaddy.com, Inc.
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|11|I|0|http://certs.godaddy.com/repository/
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|3|I|0|Go Daddy Secure Certificate Authority - G2
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|11|S|0|Domain Control Validated
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|3|S|0|load.exelator.com
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|15|E|0|03 02 05 a0
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|31|E|0|http://crl.godaddy.com/gdig2s1-87.crl
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|32|E|0|60 86 48 01 86 fd 6d 01 07 17 01
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|32|E|0|http://certificates.godaddy.com/repository/
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|17|E|0|load.exelator.com
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|17|E|0|www.load.exelator.com
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|17|E|0|meta.exelator.com
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|2015-04-08 19:14:29.556|17|E|0|loadm.exelator.com

As you can see from the above example data the Go Daddy certificate with
serial number 0x008620ad42a17aea20 was seen four times within a 14 minute
time period.

# [De-duplicating IPs and Certificates](#ip) {#ip}

Now that the TLS/SSL certificates have been collected and de-duplicated, it
might be necessary to determine which IP address on the network received a
particular certificate. The TLS/SSL certificate de-duplication feature can
be combined with the DEDUP\_CONFIG block to determine which IP used a
particular certificate.

    EXPORTER TEXT ROTATING_FILES "ssl_ip_dedup"
        PATH "/data/ssl/"
        ROTATE_INTERVAL 300
        LOCK
    EXPORTER END

    DEDUP_CONFIG "ssl_ip_dedup"
        PREFIX ssl_ip_dedup [244]
    DEDUP_CONFIG END

Adding the above DEDUP\_CONFIG block and EXPORTER block to the above
configuration will configure **super\_mediator** to de-duplicate unique IP
address, certificate chain tuples. **super\_mediator** will store in memory
every unique serial number, issuer name tuple for a certificate.
Furthermore, it will maintain information about the certificate chain an IP
address receives in the TLS handshake. **super\_mediator** will export the
IP and first two certificate tuples when MAX\_HIT\_COUNT or FLUSH\_TIMEOUT
period has been met. The CSV format for these records is as follows:

    first_seen | last_seen | IP | flowkeyhash | count | serial1 | issuer1 | serial2 | issuer2

first\_seen

:   The first time the IP received this certificate chain.

last\_seen

:   The last time the IP received this certificate chain before it flushed
    the record.

IP

:   The IP address, source IP address by default. Use DIP keyword on PREFIX
    line to use the destination IP address.

flowkeyhash

:   The 32 bit hash of the last flow's 5-tuple + vlan with this unique tuple.

count

:   The number of times this IP, certificate chain tuple was seen in the
    time period.

serial1

:   The serial number of the first certificate in the TLS/SSL certificate
    chain.

issuer1

:   The issuer's common name of the first certificate in the TLS/SSL
    certificate chain.

serial2

:   The serial number of the second certificate in the TLS/SSL certificate
    chain.

issuer2

:   The issuer's common name of the second certificate in the TLS/SSL
    certificate chain.

Typically, the first certificate is an end-user certificate that cannot be
trusted as it is not embedded in the web browser or operating system. The
second certificate is the intermediate or root certificate that may be
explicitly trusted if it is issued by a CA that is embedded in the web
browser or OS.

The serial number, issuer name pair will let the analyst pivot between the
"certificate records" and the "IP dedup" records to determine when an IP saw
a particular certificate and the particular characteristics of that
certificate.

The above additions to the configuration file will produce the following
data:

    $ cat /data/ssl/ssl_ip_dedup.20150408192918.txt
    2015-04-08 19:14:29.556|2015-04-08 19:14:29.680|10.27.33.66|2154341740|2|\
    0x008620ad42a17aea20|Go Daddy Secure Certificate Authority - G2|\
    0x07|Go Daddy Root Certificate Authority - G2
    2015-04-08 19:15:24.633|2015-04-08 19:17:14.722|10.27.33.66|3741584532|6|\
    0x0754|GeoTrust SSL CA - G4|0x023a79|GeoTrust Global CA
    2015-04-08 19:14:54.239|2015-04-08 19:17:14.724|10.27.33.66|3730640023|10|\
    0x0765|GeoTrust SSL CA - G4|0x023a79|GeoTrust Global CA
    2015-04-08 19:18:10.483|2015-04-08 19:19:04.602|10.27.33.66|395876596|6|\
    0x516f2670a7991b70|Google Internet Authority G2|0x023a76|GeoTrust Global CA

# [Using MySQL](#mysql) {#mysql}

>   **Note:** MySQL support is currently disabled in Super Mediator 2.0.
>   This will be addressed in a later release.

The data produced by **super\_mediator** can easily be imported into a
[MySQL][] or [MariaDB][] database. The
[**super\_table\_creator**][sm_creator] tool will create the appropriate
tables for the data produced by the above configuration.

    $ super_table_creator -n root -p password -d ssl_database --ssl-certs
    certs table successfully created
    certs_dedup table successfully created

    $ super_table_creator -n root -p password -d ssl_database --ssl-dedup
    Ignoring Warning: Database ssl_database 1007: Can't create database 'ssl_database'; database exists
    ssl_ip_dedup table successfully created

The warning produced by **super\_table\_creator** just means that the
database already exists. **super\_table\_creator** tries to create the
database every time it is run. If it already exists, this error is ignored.

Now the data can be easily imported using the
[**mysqlimport**][mysql_import] or [**mariadb-import**][maria_import] tool:

    $ mysqlimport -u root -p --fields-terminated-by="|" ssl_database /data/ssl/certs_dedup.20150408192918.txt
    Enter password:
    ssl_database.certs_dedup: Records: 440  Deleted: 0  Skipped: 0  Warnings: 0

    $ mysqlimport -u root -p --fields-terminated-by="|" ssl_database /data/ssl/ssl_ip_dedup.20150408192918.txt
    Enter password:
    ssl_database.ssl_ip_dedup: Records: 338  Deleted: 0  Skipped: 0  Warnings: 0

    $ mysqlimport -u root -p --fields-terminated-by="|" ssl_database /data/ssl/certs.20150408192355.txt
    Enter password:
    ssl_database.certs: Records: 1540  Deleted: 0  Skipped: 0  Warnings: 0


[MariaDB]:        https://www.mariadb.com/
[MySQL]:          https://www.mysql.com/
[OpenSSL]:        https://www.openssl.org/
[maria_import]:   https://mariadb.com/kb/en/mysqlimport/
[mysql_import]:   https://dev.mysql.com/doc/refman/5.7/en/mysqlimport.html

[YAF]:              /yaf/index.html
[yaf_deeppacket]:   /yaf/deeppacketinspection.html

[sm_creator]:       super_table_creator.html
[sm_install]:       install.html

[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
