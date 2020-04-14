/*
 *
 *      Andrew Stange, Cloudflare Internship Application: Systems
 *      Developed for MacOS (using C)
 *
 *      Usage:
 *          * Hostname/IP address is positional terminal argument.
 *          * Supports IPv4 and IPv6 (due to quarantine, IPv6 version has not been tested. My home WiFi does not support IPv6).
 *          * Specifying TTL is only supported for IPv4 (due to the reason stated above).
 *
 *      Command Line Arguments:
 *          * "-v"  verbose.  Outputs getaddrinfo results, and a list of all protocols found for the given address/hostname.
 *          * "-d"  debug. Outputs timeval information and raw contents of sent/received ICMP packets.
 *          * "-i"  force IPv6. Adds the use of "hints" struct addrinfo parameter to getaddrinfo. Only gets IPv6 addresses
 *          * "-c"  followed by the number of ICMP packets to send.
 *          * "-s"  followed by the number of seconds to delay between sending ICMP packets
 *          * "-t"  followed by the TTL value for the ICMP packets (only works with IPv4)
 *          *       final positional argument is the hostname or address to ping
 *
 */



// preprocessor directives
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/time.h>           // timeval and gettimeofday support
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/types.h>          // socket struct headers
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/icmp6.h>
#include <string.h>         // need for bzero
#include <netinet/in.h>     // some socket structures
#include <netinet/ip.h>     // some socket structures
#include <netinet/ip_icmp.h>
#include <pthread.h>        // include multithreading support

#define MSG_BUF_SIZE    1500
#define PACK_SIZE       56

// struct and global variables
struct argument_info {      // for passing relevant information to message-sending thread
    struct sockaddr_in dest_addr;
    int sockfd;
};

pthread_mutex_t socket_lock = PTHREAD_MUTEX_INITIALIZER;    // must be accessible in all functions
pthread_mutex_t pack_counter_loc = PTHREAD_MUTEX_INITIALIZER;
bool debug = false, verbose = false, force_ipv6 = false, ttl_set = false, set_pings = false;    // commandline option selection
double avg_rtt = 0, num_pac = 0, num_pac_sent = 0;          // diagnostic information accessed by multiple threads
int sec_delay = 1, num_pings = 0;                           // set on command line


// function declarations
void* proto4(void*);    // send functions called in new thread
void* proto6(void*);
float interpret_v4(char* buf, ssize_t len, struct timeval* tv_received, char* dest);    // interpret received msg
float interpret_v6(char* buf, ssize_t len, struct timeval* tv_received, char* dest);
void sigint_handler(int signo);     // called on SIGINT
uint16_t icmp_cksum (uint16_t* addr, int len);


// main function
int main(int argc, char** argv) {

    // commandline argument and option handling
    int c, ttl_value = -1;
    opterr = 0;     // suppress error messages
    while ( (c = getopt(argc, argv, "vdic:s:t:")) != -1 ) {
        switch(c) {
            case 'd':
                debug = true;
                break;
            case 'v':
                verbose = true;
                break;
            case 'i':
                force_ipv6 = true;
                break;
            case 'c':
                set_pings = true;
                num_pings = atoi(optarg);
                break;
            case's':
                sec_delay = atoi(optarg);
                break;
            case 't':
                ttl_set = true;
                ttl_value = atoi(optarg);
                break;
            default:
                printf("ERROR: invalid commandline option: %c\n", c);
                exit(-1);
        }
    }
    if ( optind != argc-1 ) {
        printf("ERROR: usage: ping [ -d -v -i -t ] hostname.\n");
        exit(-1);
    }


    // general set up   (threads, socket-related info, addresses, etc.)
    char* input = argv[optind];   // "if getopt returns -1, optind is the argv-index that stores the first non-option element"
    struct addrinfo* results = NULL;
    struct addrinfo* addr_to_use = NULL;
    struct sockaddr_in* addr_helper = NULL;
    struct argument_info* arg = NULL;
    pthread_t thread_id;
    int sockfd;
    ssize_t s = 0;
    float (*func)(char*, ssize_t, struct timeval*, char*);



    // determine protocol of destination address (naming function calls here)
    int error = 0;
    if ( force_ipv6 ){        // commandline option to force an ipv6 address (populate hints struct)
        struct addrinfo hints;
        hints.ai_protocol = IPPROTO_IPV6;
        error = getaddrinfo(input, NULL, &hints, &results);
    }
    else{
        error = getaddrinfo(input, NULL, NULL, &results);
    }

    if ( error != 0 ) {   // naming function error handling
        if ( error == EAI_SYSTEM ) {      // needed here to catch EAI_NONAME, EAI_NODATA, EAI_FAIL, EAI_SYSTEM correctly
            perror("ERROR: getaddrinfo\n");
        } else {        // getaddrinfo does not report most errors through errno (perror ineffective in many cases)
            fprintf(stderr, "ERROR: getaddrinfo %s\n", gai_strerror(error));
        }
        exit(-1);
    }

    if ( !results ) {  // results may still null after getaddrinfo function call
        printf("ERROR: getaddrinfo %s\n", gai_strerror(error));
        exit(-1);
    }
    else {
        addr_to_use = results;      // by default, select the first available address
        addr_helper = (struct sockaddr_in *) addr_to_use->ai_addr;
        if ( verbose ) {
            printf("/*** getaddrinfo diagnostics (addr, protocol, family) ***/\n");
            printf("TCP: %d\tUDP: %d\tv4: %d\tv6: %d\n", IPPROTO_TCP, IPPROTO_UDP, AF_INET, AF_INET6);      // output constant values
            while(addr_to_use != NULL) {        // output contents from getaddrinfo
                // addr_helper = (struct sockaddr_in *) addr_to_use->ai_addr;
                char output_addr[addr_helper->sin_len];
                inet_ntop(addr_helper->sin_family, &addr_helper->sin_addr, output_addr, addr_helper->sin_len);
                printf("%s\t\t%d\t%d\n", output_addr, addr_to_use->ai_protocol, addr_to_use->ai_family);
                addr_to_use = addr_to_use->ai_next;
            }
            printf("\n");

            addr_to_use = results;      // reset to first option
            addr_helper = (struct sockaddr_in *) addr_to_use->ai_addr;
        }
    }



    // create socket and new thread for sending of ICMP (respective version) to destination
    int icmp_proto = -1;
    if ( addr_to_use->ai_family == AF_INET )   // specify proper protocol
        icmp_proto = IPPROTO_ICMP;
    else
        icmp_proto = IPPROTO_ICMPV6;
    if ( (sockfd = socket(addr_to_use->ai_family, SOCK_RAW, icmp_proto)) == -1 ) {    // create socket
        perror("ERROR: socket error\n");
        exit(-1);
    }
    s = 70000;      // suggested to allow for many replies in case that broadcast address is pinged
    if ( setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &s, sizeof(s) ) != 0) {      // increase receive buffer size
        perror("ERROR: setsockopt error.\n");
    }
    if ( ttl_set && addr_to_use->ai_family == AF_INET ) {          // set TTL for IPv4 if specified on commandline
        setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl_value, sizeof(ttl_value));
    }

    // wrap information needed in threads into a struct to pass to thread
    arg = (struct argument_info*) malloc(sizeof(struct argument_info));
    arg->dest_addr = *addr_helper;
    arg->sockfd = sockfd;


    // determine proper thread function call and ICMP filtering
    char* addr = NULL;
    if ( addr_to_use->ai_family == AF_INET ) {     // v4
        pthread_create(&thread_id, NULL, proto4, arg);
        func = &interpret_v4;
        addr = (char*) malloc(INET_ADDRSTRLEN);     // get presentation name for destination
        inet_ntop(AF_INET, &arg->dest_addr.sin_addr, addr, INET_ADDRSTRLEN);
    }
    else {                                      // v6
        pthread_create(&thread_id, NULL, proto6, arg);
        func = &interpret_v6;
        addr = (char*) malloc(INET6_ADDRSTRLEN);    // get presentation name for destination
        inet_ntop(AF_INET6, &arg->dest_addr.sin_addr, addr, INET6_ADDRSTRLEN);
        struct icmp6_filter filt;           // ICMPv6 filtering (only accept echo replies)
        ICMP6_FILTER_SETBLOCKALL(&filt);
        ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filt);

        pthread_mutex_lock(&socket_lock);       // apply IPv6 filter to socket
        if ( setsockopt(sockfd, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt)) == -1 ) {
            perror("EROR: ICMPv6 filter error.\n");
            exit(-1);
        }
        pthread_mutex_unlock(&socket_lock);
    }

    //  set up to receive ICMP packets from the destination
    struct msghdr message;
    struct iovec iov;
    struct timeval tv;
    int n_bytes;
    float rtt;
    char recv_buf[MSG_BUF_SIZE];

    // recvmsg set up
    iov.iov_base = recv_buf;
    iov.iov_len = sizeof(recv_buf);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_name = addr_to_use->ai_addr;
    message.msg_namelen = addr_to_use->ai_addrlen;

    // set up select call
    fd_set readfd, master;
    int maxfd = sockfd;     // only fd that is being checked here
    FD_ZERO(&readfd);
    FD_ZERO(&master);
    FD_SET(sockfd, &master);

    // set up signal handler
    signal(SIGINT, sigint_handler);

    for( ;; ) {     // infinite loop to receive packets from raw socket
        // select maintenance
        readfd = master;
        if ( select(maxfd+1, &readfd, NULL, NULL, NULL) == -1 ) {     // block here until I/O is ready.  Avoid polling
            perror("ERROR: select error in main.\n");
            continue;
        }

        // only lock socket if it can be read from (otherwise will block on socket and prevent sends)
        if ( FD_ISSET(sockfd, &readfd)) {
            pthread_mutex_lock(&socket_lock);
            if ( (n_bytes = recvmsg(sockfd, &message, 0) ) == -1) {   // read off socket
                perror("ERROR: recvmsg error.\n");
                exit(-1);
            }
            pthread_mutex_unlock(&socket_lock);

            if ( gettimeofday(&tv, NULL) == -1 ) {                    // record time packet is received
                perror("ERROR: gettimeofday error.\n");
                exit(-1);
            }

            rtt = func(recv_buf, n_bytes, &tv, addr);               // read tv from packet and calculate RTT
            if ( rtt > 0 ) {
                // for signal handler output
                pthread_mutex_lock(&pack_counter_loc);
                avg_rtt += rtt;
                pthread_mutex_unlock(&pack_counter_loc);
            }

            // check if there are more pings to send
            if ( set_pings && num_pings == 0 ) {
                raise(SIGINT);      // if all pings have been sent, end program and output statistics
            }
        }
    }

    /*
     * valgrind shows these allocations (results, arg, addr) as "still-reachable".  Doesn't make sense to deallocate in
     * the signal handler (how all runs of this program terminate) since they will be deallocated when the program calls
     *  exit a few lines later. No other memory leaks.
     */
    // free address information.  This code will never be executed, but is a good practice
    freeaddrinfo(results);
    free(addr);
    free(arg);
    return 0;
}   // END main





// interpret_v6     (IPv6 receiving function)
float interpret_v6(char* buf, ssize_t len, struct timeval* tv_recv, char* dest) {
    // extract timeval struct from the packet, calculate RTT, and print
    float rtt = 0;
    struct icmp6_hdr* icmp6 = NULL;
    struct timeval* tv_sent = NULL;

    // get icmpv6 packet
    icmp6 = (struct icmp6_hdr*) buf;
    if ( len < 8 ) {
        printf("ERROR: invalid header\n");
        return 0;
    }

    // determine ICMP type
    if ( icmp6->icmp6_type == ICMP6_ECHO_REPLY ) {
        if ( icmp6->icmp6_id != getpid() ) {
            return 0;     // ICMP packet intended for different process
        }
        if ( len < 16 ) {
            return 0;     // invalid ICMP data size
        }

        pthread_mutex_lock(&pack_counter_loc);
        num_pac++;      // a packet was received successfully
        pthread_mutex_unlock(&pack_counter_loc);

        // subtract timeval structs and store result in tv_recv
        char* helper = buf + 1; // point to front of data section (header is one bytes long)
        tv_sent = (struct timeval*) helper;  // cast pointer to front of ICMP data section
        if ( debug ) {                         // output raw timeval information
            printf("SENT: %ld %d\n", tv_sent->tv_sec, tv_sent->tv_usec);
            printf("RECV: %ld %d\n", tv_recv->tv_sec, tv_recv->tv_usec);
        }
        tv_recv->tv_sec -= tv_sent->tv_sec;     // subtract seconds
        if ( (tv_recv->tv_usec -= tv_sent->tv_usec) < 0 ) {
            --tv_recv->tv_sec;
            tv_recv->tv_usec += 1000000;
        }
        if ( debug )
            printf("RESULT: %ld %d\n", tv_recv->tv_sec, tv_recv->tv_usec);
        rtt = tv_recv->tv_sec * 1000.0 + tv_recv->tv_usec / 1000.0;

        // calculate packet loss and output relevant information
        double loss = 0;
        pthread_mutex_lock(&pack_counter_loc);
        if (num_pac_sent > 1)      // avoids issue on first packet sent
            loss = 1-num_pac/num_pac_sent;
        pthread_mutex_unlock(&pack_counter_loc);
        printf("%d bytes received from %s: rtt=%.3f ms, loss: %.2f\n", (int) len, dest, rtt, loss);
    }
    return rtt;
}   // END interpret_v6





// proto6   (IPv6sending function)
void* proto6(void* arg) {
    // every second, send an ICMPv6 packet with current timeval struct to designated IP address
    // prep structures for sending
    struct argument_info* argument = (struct argument_info*) arg;
    socklen_t s_len = sizeof(argument->dest_addr);
    char send_buf[MSG_BUF_SIZE];
    bzero(send_buf, MSG_BUF_SIZE);  // zero buffer
    int len = 8 + PACK_SIZE;    // ICMP header size is 8 bytes + data size
    struct icmp6_hdr* icmp6 = (struct icmp6_hdr*) send_buf;
    icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6->icmp6_code = 0;
    pid_t id = getpid() & 0xffff;      // ID field is 16 bits
    icmp6->icmp6_id = id;    // ID field is 16 bits

    // infinite send loop
    while (1) {
        // fill packet with pattern to help with debugging packet contents. Skip 1 byte header.
        memset((icmp6+1), 0xa5, PACK_SIZE);

        // fill data section with timeval struct
        pthread_mutex_lock(&socket_lock);
        // gettime function inside the lock in case need to block for a while
        if ( gettimeofday((struct timeval*) (icmp6+1), NULL) == -1 ) {
            perror("ERROR: gettimeofday proto6 error.\n");
            exit(-1);
        }

        // send packet (kernel fills checksum field for ICMPv6)
        if ( sendto(argument->sockfd, send_buf, len, 0, (struct sockaddr*) &argument->dest_addr, s_len) ) {
            perror("ERROR: proto6 sendto error.\n");
            exit(-1);
        }
        pthread_mutex_unlock(&socket_lock);

        pthread_mutex_lock(&pack_counter_loc);
        num_pac_sent++;     // a packet was received successfully
        pthread_mutex_unlock(&pack_counter_loc);

        if ( debug ) {     // output raw packet contents
            printf("\nSent ICMPv6: type: %x, code: %x, id: %x, seq: %x\n", icmp6->icmp6_type, icmp6->icmp6_code,
                   icmp6->icmp6_id, icmp6->icmp6_seq);
            printf("\nICMP buffer (pre-send): ");
            for(int i = 0; i < len; i++) {
                printf("%x ", (unsigned short)(send_buf[i]) );
            }
            printf("\n");
        }

        // update number of pings left to send
        if ( set_pings && num_pings > 0 ) {
            num_pings--;
            if ( num_pings == 0 ) {
                break;
            }
        }

        // wait specified number of seconds
        sleep(sec_delay);
    }
    return NULL;    // code never reached
}   // END proto6





// interpret_v4     (IPv4 receiving function)
float interpret_v4(char* buf, ssize_t len, struct timeval* tv_recv, char* dest) {
    // get timeval struct from IP packet (contains ICMP packet) and print RTT
    // prep structures
    struct ip* ip_pack;                 // pointer to IP packet
    struct icmp* icmp_pack = NULL;      // pointer to ICMP message
    struct timeval* tv_sent = NULL;     // irrelevant for this post
    int iphdr_len, icmplen;             // delimiters/sizes of the messages
    float rtt = 0;
    ip_pack = (struct ip *) buf;        // cast char buffer (recvmsg is called in the calling function)
    iphdr_len = ip_pack->ip_hl << 2;    // convert from 32 bit words to number of 8-bit bytes
    if (ip_pack->ip_p != IPPROTO_ICMP )   // confirm packet is ICMPv4
        return 0;

    char* pointer_math_helper = (char*) (ip_pack);      // use char pointer to avoid pointer math issues
    pointer_math_helper += iphdr_len;
    icmp_pack = (struct icmp *) (pointer_math_helper);   // start of ICMP header
    if ( (icmplen = len - iphdr_len ) < 8 )                // ICMP header is 8 bytes, else invalid packet
        return 0;

    if ( debug ) {     // output raw contents of the received packet
        printf("Received ICMP packet: ");        // print hex values of buf.  Cast to unsigned
        for(int i = iphdr_len; i < len; i++) {
            printf("%x ", (unsigned short)(buf[i]) );
        }
        printf("\n");
        printf("ICMP contents: type: %x, code: %x, id: %x, seq: %x\n", icmp_pack->icmp_type, icmp_pack->icmp_code,
                icmp_pack->icmp_id, icmp_pack->icmp_seq);
    }

    // classify type of ICMP packet
    if ( icmp_pack->icmp_type == ICMP_ECHOREPLY ) {       // only process if expected ICMP type
        if ( icmp_pack->icmp_id != getpid() )
            return 0;     // ICMP packet not intended for this program
        if ( icmplen < 16 )
            return 0;     // invalid size for this program
        tv_sent = (struct timeval*) icmp_pack->icmp_data;
        pthread_mutex_lock(&pack_counter_loc);
        num_pac++;
        pthread_mutex_unlock(&pack_counter_loc);

        // subtract timeval structs and store result in tv_recv
        if ( debug ) {     // output raw contents of timeval struct to help with debugging
            printf("SENT: %ld %d\n", tv_sent->tv_sec, tv_sent->tv_usec);
            printf("RECV: %ld %d\n", tv_recv->tv_sec, tv_recv->tv_usec);
        }
        tv_recv->tv_sec -= tv_sent->tv_sec;     // subtract seconds
        if ( (tv_recv->tv_usec -= tv_sent->tv_usec) < 0 ) {
            --tv_recv->tv_sec;
            tv_recv->tv_usec += 1000000;
        }
        if ( debug )
            printf("RESULT: %ld %d\n", tv_recv->tv_sec, tv_recv->tv_usec);
        rtt = tv_recv->tv_sec * 1000.0 + tv_recv->tv_usec / 1000.0;

        // calculate packet loss and output
        double loss = 0;
        pthread_mutex_lock(&pack_counter_loc);
        if ( num_pac_sent != 0 )      // avoids issue on first packet sent
            loss = 1-num_pac/num_pac_sent;
        pthread_mutex_unlock(&pack_counter_loc);
        printf("%d bytes received from %s: rtt=%.3f ms, loss rate: %.2f\n", icmplen, dest, rtt, loss);

    }
    else if ( ttl_set && icmp_pack->icmp_type == ICMP_TIMXCEED ) {        // effect of setting TTL too low
        if ( icmplen < 16 ) {
            return 0;     // invalid size for this program
        }
        printf("Time exceeded packet received...\n");
    }
    // else, do nothing.  ICMP packet not intended for this program

    return rtt;
}   // END interpret_v4





// proto4       (IPv4 sending function)
void* proto4(void* arg) {
    // every 1 second, send an ICMPv4 packet with current timeval struct to designated IP address
    struct argument_info* argument = (struct argument_info *) arg;
    socklen_t s_len = sizeof(argument->dest_addr);
    char send_buf[MSG_BUF_SIZE];
    bzero(send_buf, MSG_BUF_SIZE);      // zero buffer

    // set up ICMP packet
    struct icmp* icmp_ptr = (struct icmp*) send_buf;
    icmp_ptr->icmp_type = ICMP_ECHO;
    icmp_ptr->icmp_code = 0;
    pid_t id = getpid() & 0xffff;      // ID field is 16 bits
    icmp_ptr->icmp_id = id;

    // infinite send loop
    while(1) {
        // reset data value
        memset(icmp_ptr->icmp_data, 0xa5, PACK_SIZE);
        int len = 8 + PACK_SIZE;    // ICMP 8-byte header + data size
        icmp_ptr->icmp_cksum = 0;

        // get timeval and write into ICMP packet
        pthread_mutex_lock(&socket_lock);
        if( gettimeofday( (struct timeval*) icmp_ptr->icmp_data, NULL ) == -1 ) {
            perror("ERROR: proto4 gettimeofday error.\n");
            exit(-1);
        }

        // update ICMP packet checksum
        icmp_ptr->icmp_cksum = icmp_cksum((u_short*) icmp_ptr, len);    // fill checksum value according to convention

        // send packet
        if( sendto(argument->sockfd, send_buf, len, 0, (struct sockaddr*) &argument->dest_addr, s_len) == -1 ) {
            perror("ERROR: proto4 sendto error.\n");
            exit(-1);
        }
        pthread_mutex_unlock(&socket_lock);

        pthread_mutex_lock(&pack_counter_loc);
        num_pac_sent++;     // packet sent successfully
        pthread_mutex_unlock(&pack_counter_loc);

        if ( debug ) {     // output raw contents of ICMP packet to help with debugging
            printf("\nSent ICMPv4: type: %x, code: %x, id: %x, seq: %x\n", icmp_ptr->icmp_type, icmp_ptr->icmp_code, icmp_ptr->icmp_id, icmp_ptr->icmp_seq);
            printf("\nICMP buffer (pre-send): ");
            for(int i = 0; i < len; i++) {
                printf("%x ", (unsigned short)(send_buf[i]));
            }
            printf("\n");
        }

        // update number of pings left to send
        if ( set_pings && num_pings > 0 ) {
            num_pings--;
            if ( num_pings == 0 ) {
                break;
            }
        }

        // wait specified number of seconds
        sleep(sec_delay);
    }
    return NULL;    // code never reached
}   // END proto4





//  icmp_cksum   (handles IPv4 checksum calculations)
uint16_t icmp_cksum (uint16_t* addr, int len) {
    int num = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (num > 1) {    // sum bytes in 16 bit (2 byte) chunks
        sum += *w++;
        num -= 2;
    }
    if ( num == 1 ) {      // if an odd number of bytes
        *(unsigned char*) (&answer) = *(unsigned char*) w;
        sum += answer;
    }

    // add back carryouts from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;      // truncate to 16 bits
    return (answer);
}   // END icmp_cksum





// sigint_handler       (called on SIGINT)
void sigint_handler(int signo) {
    // output some diagnostics, then end program
    printf("\n\n\t*** Aggregate Statistics ***\n");
    printf("Average RTT: %.3f\n", avg_rtt/num_pac);
    printf("Successful packet percentage: %d\n", (int)(num_pac/num_pac_sent*100));
    printf("Number of successful packets: %.0f\n", num_pac);
    printf("Number packets sent: %.0f\n", num_pac_sent);
    exit(0);        // terminate program
}   // END sigint_handler
