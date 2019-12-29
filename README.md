# my_ping
**Description**
<br/>ICMP-based diagnostic for the round-trip time of a connection between the local host and an IP address.  Developed in accordance with RFC 792 using UNIX Network Programming by Richard Stevens as guidance.

**Implementation Details**
<br/>Implementation of the well-known ping diagnostic tool.  The program sends an ICMP message containing the time the packet is sent to the specified IP address.  This time value is compared with the time the packet is received to calculate the round trip time.  No connection is used between addresses.  This implementation is multithreaded with a thread for sending ICMP messages every one second and another thread for receiving packets and performing calculations.

**Commandline Usage**
<br/>Usage: ./{ executable_name } { -options } { IP address or name }
<br/>Program must be run with super user priviledges in order to create a raw socket.
<br/>'-d'  debug option.  Print contents of the ICMP packet (excluding IP header) that is sent by one thread and received by another.  Print raw contents of timeval structures used in round-trip time calculations.
<br/>'-v'  verbose option.  Print all addresses returned by getaddrinfo call (display all available IPv4 and IPv6 addresses).  Print average round-trip time after each packet received.
