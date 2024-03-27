% super_mediator De-Duplication Tutorial

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

**super\_mediator** has always been capable of performing de-duplication of
DNS resource records: If enabled, **super\_mediator** collects all DNS
resource records captured and exported by [**yaf**][YAF] and caches unique
name, value pairs for A, AAAA, NS, CNAME, PTR, SOA, MX, TXT, SRV, NX, and
particular DNSSEC records.

The 1.1.0 release of **super\_mediator** extended the capability to other
types of deep packet inspection (DPI) data. (This is sometimes called
general de-duplication to distinguish it from the DNS and [TLS/SSL
de-duplication][sm_ssl_dedup] that **super\_mediator** also supports.) For
example, it may be of interest to determine what user agent string a
particular IP address used at any point in time or to identify unique IP,
service-string pairs on your network. This type of information can assist in
fingerprinting hosts or identifying vulnerable systems on the network.

The de-duplication feature discussed in this tutorial is different from the
DEDUP\_PER\_FLOW de-duplication that is performed within each flow record
and discussed in the [**super\_mediator** tutorial][sm_guide].

**super\_mediator** de-duplication configured within the DEDUP\_CONFIG block
is done per IP address (by default it uses the source IP).
**super\_mediator** caches all unique IP, data pairs. This unique tuple is
only flushed from memory when either the tuple is seen a certain number of
times (set by MAX\_HIT\_COUNT) or the tuple has not been seen within a
certain time window (set by FLUSH\_TIMEOUT).

# [Configuration File](#config) {#config}

De-duplication of all data types must be configured through the
[super\_mediator.conf][sm_conf] configuration file. The DEDUP\_CONFIG block
must be associated with a single EXPORTER block.

If the EXPORTER is a TEXT exporter, the PATH defined in the EXPORTER block
must be a valid directory. For each PREFIX line present within the
DEDUP\_CONFIG block, a separate file will be created with the file name
prefix defined on the PREFIX line. The EXPORTER will only perform
deduplication; no flow records are exported.

For a JSON EXPORTER, the PATH in the EXPORTER block must be a file, and both
flow records and de-duplicated records are written to that file. The key for
a flow record is "flow" and the key for a deduplicated record is "dedup".

For an IPFIX FILE EXPORTER, the PATH in the EXPORTER block is the file name
to export data to. Both flow records and de-duplicated records are written
to the file.

To have a JSON or IPFIX EXPORTER only write de-duplicated records, add
DEDUP\_ONLY to the EXPORTER block.

As usual, if ROTATE is present in the EXPORTER block for JSON or IPFIX, the
PATH will be the file prefix used and the date and serial number will be
appended to the file prefix in the form -YYYYMMDDHHMMSS-SSSSS.med.

## [Examples](#examples) {#examples}

Below are four configuration file and data examples of an EXPORTER that has
a DEDUP\_CONFIG block associated with it.

### [TEXT Exporter](#text) {#text}

The following is an example configuration for a TEXT exporter:

    EXPORTER TEXT ROTATING_FILES "dedup"
        PATH "/data/dedup"
        ROTATE_INTERVAL 300
        LOCK
    EXPORTER END

    DEDUP_CONFIG "dedup"
        PREFIX "useragent" [111]
        PREFIX "server" DIP [110, 171]
        PREFIX "host" SIP [117]
        PREFIX "dns" [179]
    DEDUP_CONFIG END

By default, the source IP address is cached, along with the data value
identified by the [CERT private enterprise information
element][certipfix] ID(s) defined within the square brackets on the
PREFIX line. For example, the first line in the DEDUP\_CONFIG block
de-duplicates based on the source IP, HTTP User-Agent (httpUserAgent) pair
and stores those in /data/dedup/useragent-YYYYMMDDHHMMSS-SSSSS.txt.

Some information elements are associated with the server, and using the
destination IP address makes more sense. For these cases, DIP must appear
between the name and the element ID list. For example, the second line
performs two de-duplicatations, one on destination IP, HTTP server response
header (httpServerString) pairs and another on destination IP, SSH version
number (sshVersion) pairs; both pairs are written to
/data/dedup/server-YYYYMMDDHHMMSS-SSSSS.txt.

The third line above de-duplicates the source IP and HTTP host header
(httpHost); the keyword SIP is allowed but unnecessary.

The fourth line de-duplicates source IP and the DNS query name (dnsName).
**The only information element ID valid for DNS is 179.** To de-duplicate on
DNS responses, refer to the [super\_mediator.conf][sm_conf] manual page,
specifically the DNS\_DEDUP block.

Also note that general deduplication is limited for records containing
TLS/SSL DPI. **The only information element ID valid for TLS/SSL is 244
(sslCertSerialNumber).** See the [SSL de-duplication article][sm_ssl_dedup]
for more information.

As a reminder, normal flow records are not written in this configuration. If
that is desired, a separate EXPORTER block must be added.

The CSV data format for de-duplicated data values configured in the
DEDUP\_CONFIG block is:

    first_seen | last_seen | IP_address | flowkeyhash | count | data

first\_seen

:   The flowStartMilliseconds of the first flow that contained this unique
    pair. first\_seen is a timestamp in the form "2012-01-23 04:45:13.897."


last\_seen

:   The flowStartMilliseconds of the last flow before the record was flushed
    that contained this unique pair. last\_seen is a timestamp in the form
    "2012-01-23 04:45:13.897."

IP\_address

:   The IP address used in the unique key. By default this is the
    sourceIPv4Address or sourceIPv6Address of the flow. This behavior can be
    changed by adding "DIP" to the PREFIX line in the DEDUP\_CONFIG block.

flowkeyhash

:   The 32-bit hash of the 5-tuple + vlan of the last flow that contained
    this unique pair. This value can be used to pivot into a PCAP data
    repository, if available. See [this YAF PCAP tutorial][yaf_pcap] for
    more information.

count

:   The number of times this unique pair was seen within the first\_seen,
    last\_seen time period.

data

:   The value retrieved from the incoming IPFIX stream identified by (one
    of) the information element ID defined in the square brackets on the
    PREFIX line within the DEDUP\_CONFIG block. Be aware when using multiple
    IDs on a PREFIX line that CSV output file does not indicate which
    element was matched.

**TLS/SSL de-duplicated data has a slightly different format. See [this
article][sm_ssl_dedup] for more information about TLS/SSL de-duplication.**

See the following example data (lines wrapped for readability):

    $ head -n 5 /data/dedup/host.20110128220025.txt
    2011-01-28 21:45:34.904|2011-01-28 21:45:34.995|10.10.1.60|2640424260|4|www.google.com
    2011-01-28 21:45:37.636|2011-01-28 21:45:37.636|10.10.0.205|696160288|1|api.twitter.com
    2011-01-28 21:45:27.349|2011-01-28 21:45:43.933|10.10.0.196|2697798766|2|www.funtrivia.com
    2011-01-28 21:45:40.508|2011-01-28 21:45:40.508|10.11.0.139|3092428228|1|ajax.googleapis.com
    2011-01-28 21:46:51.836|2011-01-28 21:46:51.836|10.10.1.33|741168033|1|mirror.liberty.edu

    $ head -n 5 /data/dedup/useragent.20110128220025.txt
    2011-01-28 21:45:34.904|2011-01-28 21:45:34.995|10.10.1.60|2640424260|4|Mozilla/5.0 \
    (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko/2009033100 Ubuntu/9.04 (jaunty) Firefox/3.0.8
    2011-01-28 21:45:37.636|2011-01-28 21:45:37.636|10.10.0.205|696160288|1|TwitterAndroid/1.0.5 \
    (109) Nexus One/8 (HTC;passion)
    2011-01-28 21:46:23.366|2011-01-28 21:46:23.426|10.13.0.63|3301408776|2|urlgrabber/3.9.1 yum/3.2.28
    2011-01-28 21:46:06.001|2011-01-28 21:47:06.736|10.11.0.139|671893917|4|OpenTable/3.2 \
    CFNetwork/485.12.7 Darwin/10.4.0
    2011-01-28 21:47:06.458|2011-01-28 21:47:15.766|10.13.0.65|2005639129|6|ChessWithFriendsPaid/3.07 \
    CFNetwork/485.12.7 Darwin/10.4.

    $ head -n 5 /data/dedup/dns.20110128220025.txt
    2011-01-28 21:50:31.285|2011-01-28 21:50:31.285|10.10.1.60|1463750989|1|suggestqueries.google.com.
    2011-01-28 21:50:31.285|2011-01-28 21:50:31.285|10.10.1.60|739184970|1|id.google.com.
    2011-01-28 21:50:36.205|2011-01-28 21:50:36.205|10.10.0.251|428413069|1|14-courier.push.apple.com.
    2011-01-28 21:50:36.205|2011-01-28 21:50:36.205|10.10.1.31|1604129129|1|reviews-cdn.northerntool.com.
    2011-01-28 21:50:36.205|2011-01-28 21:50:36.205|10.10.1.31|1247744361|1|answers.northerntool.com.

In the above examples, **yaf** generated an IPFIX file from a large PCAP
file captured at a conference in 2011. **super_mediator** used the IPFIX
file as input and de-duplicated unique IP, data pairs defined in the
DEDUP\_CONFIG block. Perhaps you are curious about the particular DNS query
made by IP 10.10.1.60 to "id.google.com" and would like to see the PCAP of
this particular DNS transaction. You can simply provide the flow key hash to
**yaf** to generate the PCAP file for this particular flow:

    $ yaf --in big.pcap --no-output --pcap=mydns.pcap --max-payload=2000 \
    --hash=739184970 --verbose

    $ tcpdump -r mydns.pcap
    reading from file mydns.pcap, link-type EN10MB (Ethernet)
    17:45:29.409353 IP 10.10.1.60.53168 > resolver1.level3.net.domain: 28965+ A? id.google.com. (31)
    17:45:29.412611 IP resolver1.level3.net.domain > 10.10.1.60.53168: 28965 5/0/0 \
    CNAME id.l.google.com., A 72.14.204.101, A 72.14.204.102, A 72.14.204.113, A 72.14.204.100 (114)

### [JSON Exporter](#json) {#json}

The following is an example configuration for a JSON exporter:

    EXPORTER JSON SINGLE_FILE "dedup"
        PATH "/data/dedup"
    EXPORTER END

    DEDUP_CONFIG "dedup"
        PREFIX "useragent" [111]
        PREFIX "server" DIP [110, 171]
        PREFIX "host" [117]
        PREFIX "dns" [179]
        MAX_HIT_COUNT 10000
        FLUSH_TIMEOUT 600
    DEDUP_CONFIG END

JSON exporters configured with a DEDUP\_CONFIG block use the top-level key
"dedup" for the de-duplicated records. The same columns defined above for
TEXT (CSV) export will be present in the JSON record. **super\_mediator**
will use the PREFIX name for the data keyword.

    $ cat /data/dedup/host.txt
    {"dedup":{"firstSeen":"2011-01-28 21:46:13.580","lastSeen":"2011-01-28 21:47:45.852",\
    "sourceIPv4Address":"10.13.0.70","yafFlowKeyHash":574225501,"smDedupHitCount":8,\
    "host":"search.twitter.com"}}
    {"dedup":{"firstSeen":"2011-01-28 21:47:46.994","lastSeen":"2011-01-28 21:47:46.994",\
    "sourceIPv4Address":"10.10.1.59","yafFlowKeyHash":3289550532,"smDedupHitCount":1,\
    "host":"ocsp.godaddy.com"}}
    {"dedup":{"firstSeen":"2011-01-28 21:47:47.073","lastSeen":"2011-01-28 21:47:47.073",\
    "sourceIPv4Address":"10.10.1.59","yafFlowKeyHash":2310975606,"smDedupHitCount":1,\
    "host":"en-us.fxfeeds.mozilla.com"}}
    {"dedup":{"firstSeen":"2011-01-28 21:47:47.073","lastSeen":"2011-01-28 21:47:47.073",\
    "sourceIPv4Address":"10.10.1.59","yafFlowKeyHash":2310910070,"smDedupHitCount":1,\
    "host":"fxfeeds.mozilla.com"}}
    {"dedup":{"firstSeen":"2011-01-28 21:47:30.433","lastSeen":"2011-01-28 21:47:31.174",\
    "sourceIPv4Address":"10.10.1.4","yafFlowKeyHash":1147488830,"smDedupHitCount":2,\
    "host":"chibis.adotube.com"}}

### [IPFIX File Exporter](#ipfix) {#ipfix}

The following is an example configuration for a IPFIX file exporter:

    EXPORTER IPFIX ROTATING_FILES "dedup"
        PATH "/data/dedup"
        ROTATE_INTERVAL 120
        LOCK
    EXPORTER END

    DEDUP_CONFIG "dedup"
        PREFIX "useragent" [111]
        PREFIX "server" DIP [110, 171]
        PREFIX "host" [117]
        PREFIX "dns" [179]
    DEDUP_CONFIG END

The IPFIX file uses a separate template for each de-duplicated element. Here
are two of the templates (output produced by [**ipfixDump**][ipfixDump]):

    --- Template Record --- tid:   261 (0x0105), fields: 9, scope: 0, name: md_dedup_httpUserAgent ---
      monitoringIntervalStartMilliSeconds        (359) <millisec>     [8]
      monitoringIntervalEndMilliSeconds          (360) <millisec>     [8]
      flowStartMilliseconds                      (152) <millisec>     [8]
      smDedupHitCount                       (6871/929) <uint64>       [8]
      sourceIPv6Address                           (27) <ipv6>        [16]
      sourceIPv4Address                            (8) <ipv4>         [4]
      yafFlowKeyHash                        (6871/106) <uint32>       [4]
      observationDomainName                      (300) <string>   [65535]
      httpUserAgent                         (6871/111) <string>   [65535]

    --- Template Record --- tid:   258 (0x0102), fields: 9, scope: 0, name: md_dedup_httpHost ---
      monitoringIntervalStartMilliSeconds        (359) <millisec>     [8]
      monitoringIntervalEndMilliSeconds          (360) <millisec>     [8]
      flowStartMilliseconds                      (152) <millisec>     [8]
      smDedupHitCount                       (6871/929) <uint64>       [8]
      sourceIPv6Address                           (27) <ipv6>        [16]
      sourceIPv4Address                            (8) <ipv4>         [4]
      yafFlowKeyHash                        (6871/106) <uint32>       [4]
      observationDomainName                      (300) <string>   [65535]
      httpHost                              (6871/117) <string>   [65535]

**super\_mediator** can read the IPFIX file it created:

    $ super_mediator -o - -m TEXT /data/dedup-20150630135338-00000.med
    2011-01-28 21:46:06.001|2011-01-28 21:47:06.736|10.11.0.139|671893917|4|OpenTable/3.2 \
    CFNetwork/485.12.7 Darwin/10.4.0
    2011-01-28 21:45:40.508|2011-01-28 21:47:04.890|10.11.0.139|3000427195|10|www.opentable.com
    2011-01-28 21:47:06.736|2011-01-28 21:47:06.736|10.11.0.139|671893917|1|data.flurry.com
    2011-01-28 21:47:08.890|2011-01-28 21:47:08.890|10.13.0.65|1959568909|1|ads.mobclix.com
    2011-01-28 21:47:06.977|2011-01-28 21:47:08.985|10.13.0.65|2005835719|3|newtoyinc.com
    2011-01-28 21:47:09.036|2011-01-28 21:47:09.036|10.13.0.65|379960495|1|s.mobclix.com


### [TCP Exporter](#tcp) {#tcp}

The following is an example configuration for a TCP exporter:

    EXPORTER IPFIX TCP "dedup"
       HOSTNAME "localhost"
       PORT 18000
    EXPORTER END

    DEDUP_CONFIG "dedup"
        PREFIX "useragent" [111]
        PREFIX "server" DIP [110, 171]
        PREFIX "host" [117]
        PREFIX "dns" [179]
    DEDUP_CONFIG END

To collect this information via TCP, another **super\_mediator** can be used
to listen for TCP connections on port 18000:

    $ super_mediator -o - -m TEXT --ipfix-input=TCP --ipfix-port=18000 localhost
    2011-01-28 21:59:00.189|2011-01-28 21:59:00.189|10.10.0.188|970020836|1|securityd \
    (unknown version) CFNetwork/485.2 Darwin/10.3.1
    2011-01-28 21:59:06.491|2011-01-28 21:59:12.815|10.10.0.188|4017770420|19|Apple%20Store/1.2.1 \
    CFNetwork/485.2 Darwin/10.3.1
    2011-01-28 21:59:12.815|2011-01-28 22:00:06.234|10.10.0.188|4016590772|4|CMC
    2011-01-28 21:59:12.731|2011-01-28 22:00:25.761|10.10.0.188|3069422788|9|Apple iPhone v8A306 Maps v4.0.1
    2011-01-28 21:58:57.019|2011-01-28 21:58:57.019|10.13.0.72|4253820902|2|Microsoft-CryptoAPI/5.131.2600.5512

## [MERGE\_TRUNCATED](#merge) {#merge}

Sometimes the values in the DPI fields produced by **yaf** are truncated.
This can occur because **yaf** collects a limited amount of payload data per
flow record (as determined by the **--max-payload** option). It can also occur
when reading a PCAP file if the snaplen argument is not large enough.
Finally, **yaf** is limited by the amount of data it exports as DPI; these
limits are set with the per\_field\_limit and per\_record\_limit values in
the [yafDPIRules.conf][yaf_deeppacket] file.

To accommodate this truncation, **super\_mediator** provides the
MERGE\_TRUNCATED keyword. When the DEDUP\_CONFIG block contains that
keyword, **super\_mediator** treats DPI values as equal if they begin with
the same substring.

For example, the following is the output for a TEXT EXPORTER that does not
have the MERGE\_TRUNCATED keyword present:

    2011-01-28 21:46:40.534|2011-01-28 21:46:40.534|10.13.0.69|3132439844|1|Mozilla/5.0 (Macintosh; U; \
    Intel Mac OS X 10_6_6; en-us) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.1
    2011-01-28 21:47:49.400|2011-01-28 21:47:49.400|10.13.0.69|3038288354|1|Mozilla/5.0 (Macintosh; U; \
    Intel Mac OS X 10_6_6; en-us) Apple
    2011-01-28 21:47:49.400|2011-01-28 21:47:49.400|10.13.0.69|3038484962|1|Mozilla/5.0 (Macintosh; U; \
    Intel Mac OS X 10_6_6; en-us) AppleWebKit/53
    2011-01-28 21:47:49.401|2011-01-28 21:47:49.401|10.13.0.69|3038419426|1|Mozilla/5.0 (Macintosh; U; \
    Intel Mac OS X 10_6_6; e
    2011-01-28 21:47:49.402|2011-01-28 21:47:49.402|10.13.0.69|3038747106|1|Mozilla/5.0 (Macintosh; U;
    2011-01-28 21:46:40.519|2011-01-28 21:47:49.402|10.13.0.69|3038616034|26|Mozilla/5.0 (Macintosh; U; \
    Intel Mac OS X 10_6_6; en-us) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4

Using the MERGE\_TRUNCATED keyword will collapse all of the above records into:

    2011-01-28 21:46:40.519|2011-01-28 21:47:49.402|10.13.0.69|3038616034|31|Mozilla/5.0 (Macintosh; U; \
    Intel Mac OS X 10_6_6; en-us) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.3 Safari/533.19.4


[YAF]:                  /yaf/index.html
[certipfix]:            /cert-ipfix-registry/cert_ipfix_formatted.html
[ipfixDump]:            /fixbuf/ipfixDump.html
[yaf_deeppacket]:       /yaf/deeppacketinspection.html
[yaf_pcap]:             /yaf/yaf_pcap.html

[sm_conf]:              super_mediator.conf.html
[sm_guide]:             sm_guide.html
[sm_ssl_dedup]:         sm_ssl_dedup.html

[//]: # (Local variables:)
[//]: # (fill-column: 76)
[//]: # (indent-tabs-mode: nil)
[//]: # (sentence-end-double-space: nil)
[//]: # (tab-width: 8)
[//]: # (End:)
