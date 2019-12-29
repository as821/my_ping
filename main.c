#include <stdio.h>
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

struct argument_info {      // for passing relevant information to message-sending thread
    struct sockaddr_in dest_addr;
    int sockfd;
};

void* proto4(void*);    // send functions called in new thread
void* proto6(void*);
float interpret_v4(char* buf, ssize_t len, struct timeval* tv_received);    // interpret received msg
float interpret_v6(char* buf, ssize_t len, struct timeval* tv_received);
uint16_t icmp_cksum (uint16_t* addr, int len);
pthread_mutex_t socket_lock = PTHREAD_MUTEX_INITIALIZER;    // must be accessible in all functions
bool debug = false, verbose = false;    // commandline option selection


int main(int argc, char** argv) {    // TODO add support for argument line address passing
    // commandline argument and option handling
    int c;
    opterr = 0;     // suppress error messages
    while ( (c = getopt(argc, argv, "vd")) != -1) {
        switch(c) {
            case 'd':
                debug = true;
                break;
            case 'v':
                verbose = true;
                break;
            default:
                printf("ERROR: invalid commandline option: %c\n", c);
                exit(-1);
        }
    }
    if(optind != argc-1) {
        printf("ERROR: usage: ping [ -d -v ] hostname.\n");
        exit(-1);
    }

    // general set up   (threads, locks, socket-related info, addresses, etc.)
    char* input = argv[optind];   // "if getopt returns -1, optind is the argv-index that stores the first non-option element"
    struct addrinfo* results = NULL;
    struct addrinfo* addr_to_use = NULL;
    struct sockaddr_in* addr_helper = NULL;
    struct argument_info* arg = NULL;
    pthread_t thread_id;
    int sockfd;
    ssize_t s = 0;
    float (*func)(char*, ssize_t, struct timeval*);

    // determine protocol of destination address (naming function calls here)
    int error = getaddrinfo(input, NULL, NULL, &results);
    if (error != 0) {
        if (error == EAI_SYSTEM) {      // needed here to catch EAI_NONAME, EAI_NODATA, EAI_FAIL, EAI_SYSTEM correctly
            perror("ERROR: getaddrinfo\n");
        } else {        // getaddrinfo does not report most errors through errno (perror ineffective in many cases)
            fprintf(stderr, "ERROR: getaddrinfo %s\n", gai_strerror(error));
        }
        exit(-1);
    }

    if(!results) {  // results may still null after function call
        printf("ERROR: getaddrinfo %s\n", gai_strerror(error));
        exit(-1);
    }
    else {
        addr_to_use = results;
        addr_helper = (struct sockaddr_in *) addr_to_use->ai_addr;
        if(verbose) {
            printf("/*** getaddrinfo diagnostics (addr, protocol, family) ***/\n");
            printf("First option always selected\n");
            printf("TCP: %d\tUDP: %d\tv4: %d\tv6: %d\n", IPPROTO_TCP, IPPROTO_UDP, AF_INET, AF_INET6);
            while(addr_to_use != NULL) {     // TODO debug v6 versions
                addr_helper = (struct sockaddr_in *) addr_to_use->ai_addr;
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

    // create socket and new thread for sending of ICMP (respective version) to destination every second
    s = 70000;      // suggested to allow for many replies in case that broadcast address is pinged
    int icmp_proto = -1;
    if(addr_to_use->ai_family == AF_INET)
        icmp_proto = IPPROTO_ICMP;
    else
        icmp_proto = IPPROTO_ICMPV6;
    if( (sockfd = socket(addr_to_use->ai_family, SOCK_RAW, icmp_proto)) == -1) {
        perror("ERROR: socket error\n");
        exit(-1);
    }
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &s, sizeof(s));   // increase receive buffer size

    // wrap information needed in threads into a struct to pass in
    arg = (struct argument_info*) malloc(sizeof(struct argument_info));
    arg->dest_addr = *addr_helper;
    arg->sockfd = sockfd;

    // determine proper thread function call and ICMP filtering
    if(addr_to_use->ai_family == AF_INET) {     // v4
        pthread_create(&thread_id, NULL, proto4, arg);  // addr_to_use points to dynamic mem (getaddrinfo)
        func = &interpret_v4;
    }
    else {                                      // v6
        pthread_create(&thread_id, NULL, proto6, arg);  // addr_to_use points to dynamic mem (getaddrinfo)
        func = &interpret_v6;
        struct icmp6_filter filt;           // ICMPv6 filtering (only accept echo replies)
        ICMP6_FILTER_SETBLOCKALL(&filt);
        ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filt);

        pthread_mutex_lock(&socket_lock);
        if( setsockopt(sockfd, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt)) == -1) {
            perror("EROR: ICMPv6 filter error.\n");
            exit(-1);
        }
        pthread_mutex_unlock(&socket_lock);
    }

    // receive ICMP packets from the destination
    struct msghdr message;
    struct iovec iov;
    struct timeval tv;
    int n_bytes, suc_packs = 0;
    double sum = 0;
    float rtt;
    char recv_buf[MSG_BUF_SIZE];

    // recvmsg set up
    iov.iov_base = recv_buf;
    iov.iov_len = sizeof(recv_buf); //MSG_BUF_SIZE;
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

    for( ;; ) {     // infinite loop to receive packets from raw socket
        // select maintenance
        readfd = master;
        if( select(maxfd+1, &readfd, NULL, NULL, NULL) == -1) {     // block here until I/O is ready.  Avoid polling
            perror("ERROR: select error in main.\n");
            continue;
        }

        // only lock socket if it can be read from (otherwise will block on socket and prevent sends)
        if( FD_ISSET(sockfd, &readfd)) {
            pthread_mutex_lock(&socket_lock);
            if ((n_bytes = recvmsg(sockfd, &message, 0)) == -1) {      // recvmsg so better diagnostics can be added later
                perror("ERROR: recvmsg error.\n");
                exit(-1);
            }
            pthread_mutex_unlock(&socket_lock);

            if (gettimeofday(&tv, NULL) == -1) {       // record time packet is received
                perror("ERROR: gettimeofday error.\n");
                exit(-1);
            }
            rtt = func(recv_buf, n_bytes, &tv);     // read tv from packet and calculate RTT
            if(verbose) {
                if(rtt > 0) {   // return value of < 0 represents an error
                    sum += rtt;
                    suc_packs++;
                    printf("Average RTT: %.3f\n", sum/suc_packs);
                }
            }
        }
    }

    // free address information
    freeaddrinfo(results);
    return 0;
}   // END main



// interpret_v6
float interpret_v6(char* buf, ssize_t len, struct timeval* tv_recv) {
    // extract timeval struct from the packet, calculate RTT, and print
    float rtt = 0;
    struct icmp6_hdr* icmp6 = NULL;
    struct timeval* tv_sent = NULL;

    icmp6 = (struct icmp6_hdr*) buf;
    if(len < 8) {
        printf("ERROR: invalid header\n");
        return 0;
    }
    if(icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
        if (icmp6->icmp6_id != getpid()) {
            return 0;     // ICMP packet intended for different process
        }
        if(len < 16) {
            return 0;     // invalid ICMP data size
        }

        // subtract timeval structs and store result in tv_recv
        char* helper = buf + 1; // point to front of data section (header is one bytes long)
        tv_sent = (struct timeval*) helper;  // cast pointer to front of ICMP data section
        if(debug) {
            printf("SENT: %ld %d\n", tv_sent->tv_sec, tv_sent->tv_usec);
            printf("RECV: %ld %d\n", tv_recv->tv_sec, tv_recv->tv_usec);
        }
        tv_recv->tv_sec -= tv_sent->tv_sec;     // subtract seconds
        if((tv_recv->tv_usec -= tv_sent->tv_usec) < 0) {
            --tv_recv->tv_sec;
            tv_recv->tv_usec += 1000000;
        }
        if(debug)
            printf("RESULT: %ld %d\n", tv_recv->tv_sec, tv_recv->tv_usec);
        rtt = tv_recv->tv_sec * 1000.0 + tv_recv->tv_usec / 1000.0;
        printf("%d bytes received: rtt=%.3f ms\n", (int) len, rtt);
    }
    return rtt;
}   // END interpret_v6



// proto6
void* proto6(void* arg) {
    // every 1 second, send an ICMPv6 packet with current timeval struct to designated IP address
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
    while(1) {
        // fill with pattern to help with debugging packet contents. Skip 1 byte header.
        memset((icmp6+1), 0xa5, PACK_SIZE);

        // fill data section with timeval struct
        pthread_mutex_lock(&socket_lock);
        if( gettimeofday((struct timeval*) (icmp6+1), NULL) == -1) {
            perror("ERROR: gettimeofday proto6 error.\n");
            exit(-1);
        }

        // send packet (kernel fills checksum field for ICMPv6)
        if( sendto(argument->sockfd, send_buf, len, 0, (struct sockaddr*) &argument->dest_addr, s_len) ) {
            perror("ERROR: proto6 sendto error.\n");
            exit(-1);
        }
        pthread_mutex_unlock(&socket_lock);

        if(debug) {
            printf("\nSent ICMPv6: type: %x, code: %x, id: %x, seq: %x\n", icmp6->icmp6_type, icmp6->icmp6_code,
                   icmp6->icmp6_id, icmp6->icmp6_seq);
            printf("\nICMP buffer (pre-send): ");
            for(int i = 0; i < len; i++) {
                printf("%x ", (unsigned short)(send_buf[i]) );
            }
            printf("\n");
        }

        // wait one second
        sleep(1);
    }
    return NULL;    // code never reached
}   // END proto6



// interpret_v4
float interpret_v4(char* buf, ssize_t len, struct timeval* tv_recv) {
    // get timeval struct from IP packet (contains ICMP packet) and print RTT
    struct ip* ip_pack;                 // pointer to IP packet
    struct icmp* icmp_pack = NULL;      // pointer to ICMP message
    struct timeval* tv_sent = NULL;     // irrelevant for this post
    int iphdr_len, icmplen;             // delimiters/sizes of the messages
    float rtt = 0;

    ip_pack = (struct ip *) buf;        // cast char buffer (recvmsg is called in the calling function)
    iphdr_len = ip_pack->ip_hl << 2;    // convert from 32 bit words to number of 8-bit bytes
    if(ip_pack->ip_p != IPPROTO_ICMP)   // confirm packet is ICMPv4
        return 0;


    char* pointer_math_helper = (char*) (ip_pack);      // use char pointer to avoid pointer math issues
    pointer_math_helper += iphdr_len;
    icmp_pack = (struct icmp *) (pointer_math_helper);   // start of ICMP header
    if( (icmplen = len - iphdr_len ) < 8)                // ICMP header is 8 bytes, else invalid packet
        return 0;

    if(debug) {
        printf("Received ICMP packet: ");        // print hex values of buf.  Cast to unsigned
        for(int i = iphdr_len; i < len; i++) {
            printf("%x ", (unsigned short)(buf[i]) );
        }
        printf("\n");
        printf("ICMP contents: type: %x, code: %x, id: %x, seq: %x\n", icmp_pack->icmp_type, icmp_pack->icmp_code,
                icmp_pack->icmp_id, icmp_pack->icmp_seq);
    }

    if( icmp_pack->icmp_type == ICMP_ECHOREPLY) {       // only process if expected ICMP type
        if(icmp_pack->icmp_id != getpid())
            return 0;     // ICMP packet not intended for this program
        if(icmplen < 16)
            return 0;     // invalid size for this program
        tv_sent = (struct timeval*) icmp_pack->icmp_data;

        // subtract timeval structs and store result in tv_recv
        if(debug) {
            printf("SENT: %ld %d\n", tv_sent->tv_sec, tv_sent->tv_usec);
            printf("RECV: %ld %d\n", tv_recv->tv_sec, tv_recv->tv_usec);
        }
        tv_recv->tv_sec -= tv_sent->tv_sec;     // subtract seconds
        if((tv_recv->tv_usec -= tv_sent->tv_usec) < 0) {
            --tv_recv->tv_sec;
            tv_recv->tv_usec += 1000000;
        }
        if(debug)
            printf("RESULT: %ld %d\n", tv_recv->tv_sec, tv_recv->tv_usec);
        rtt = tv_recv->tv_sec * 1000.0 + tv_recv->tv_usec / 1000.0;

        printf("%d bytes received: rtt=%.3f ms\n", icmplen, rtt);
    }
    // else, do nothing.  ICMP packet not intended for this program
    return rtt;
}   // END interpret_v4



// proto4
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
        memset(icmp_ptr->icmp_data, 0xa5, PACK_SIZE);   // TODO try removing pattern (set to 0) once all else working
        int len = 8 + PACK_SIZE;    // ICMP 8-byte header + data size
        icmp_ptr->icmp_cksum = 0;

        // get timeval and write into ICMP packet
        pthread_mutex_lock(&socket_lock);
        if( gettimeofday( (struct timeval*) icmp_ptr->icmp_data, NULL ) == -1) {      // TODO uncomment this for time functionality
            perror("ERROR: proto4 gettimeofday error.\n");
            exit(-1);
        }

        // update ICMP packet checksum
        icmp_ptr->icmp_cksum = icmp_cksum((u_short*) icmp_ptr, len);    // fill checksum value according to convention

        // send packet
        if( sendto(argument->sockfd, send_buf, len, 0, (struct sockaddr*) &argument->dest_addr, s_len) == -1) {
            perror("ERROR: proto4 sendto error.\n");
            exit(-1);
        }
        pthread_mutex_unlock(&socket_lock);

        if(debug) {
            printf("\nSent ICMPv4: type: %x, code: %x, id: %x, seq: %x\n", icmp_ptr->icmp_type, icmp_ptr->icmp_code, icmp_ptr->icmp_id, icmp_ptr->icmp_seq);
            printf("\nICMP buffer (pre-send): ");
            for(int i = 0; i < len; i++) {
                printf("%x ", (unsigned short)(send_buf[i]));
            }
            printf("\n");
        }

        // wait one second
        sleep(1);
    }
    return NULL;    // code never reached
}   // END proto4



// icmp_cksum
uint16_t icmp_cksum (uint16_t* addr, int len) {     // taken from publicly available version of ping
    int num = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while(num > 1) {    // sum bytes in 16 bit (2 byte) chunks
        sum += *w++;
        num -= 2;
    }
    if(num == 1) {      // if an odd number of bytes
        *(unsigned char*) (&answer) = *(unsigned char*) w;
        sum += answer;
    }

    // add back carryouts from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;      // truncate to 16 bits
    return (answer);
}   // END icmp_cksum