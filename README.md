# my_ping
**Description**
<br/>ICMP-based diagnostic for the round-trip time of a connection between the local host and an IP address.  Developed in accordance with RFC 792.

**Implementation Details**
* Hostname/IP address is positional terminal argument.
* Supports IPv4 and IPv6 (due to quarantine, IPv6 version has not been tested. My home WiFi does not support IPv6).
* Specifying TTL is only supported for IPv4 (due to the reason stated above).
* Also supports specifying the number of ICMP packets to send and the delay between packets

**Commandline Arguments**
* "-v"  verbose.  Outputs getaddrinfo results, and a list of all protocols found for the given address/hostname.
* "-d"  debug. Outputs timeval information and raw contents of sent/received ICMP packets.
* "-i"  force IPv6. Adds the use of "hints" struct addrinfo parameter to getaddrinfo. Only gets IPv6 addresses
* "-c"  followed by the number of ICMP packets to send.
* "-s"  followed by the number of seconds to delay between sending ICMP packets
* "-t"  followed by the TTL value for the ICMP packets (only works with IPv4)
*       final positional argument is the hostname or address to ping
