#include <stdio.h>        // printf, fprintf, perror
#include <stdlib.h>       // calloc, malloc, free
#include <pcap.h>         // pcap_findalldevs, pcap_open_live, pcap_loop
#include <time.h>         // time_t, time(), localtime_r(), strftime()
#include <net/if_arp.h>   // ARPHRD_ETHER, ARPOP_REQUEST, ARPOP_REPLY
#include <netinet/ip.h>   // struct iphdr
#include <netinet/if_ether.h> // struct ether_header, struct ether_arp, ETHERTYPE_ARP
#include <stdbool.h>      // bool, true, false
#include <string.h>       // memcpy, memset, memcmp, strcmp, strncpy
#include <netinet/tcp.h>  // struct tcphdr
#include <ifaddrs.h>      // getifaddrs, freeifaddrs, struct ifaddrs
#include <unistd.h>       // close()
#include <net/if.h>       // struct ifreq, if_nametoindex(), IFNAMSIZ
#include <sys/ioctl.h>    // ioctl(), SIOCGIFHWADDR
#include <sys/socket.h>   // socket(), sendto(), recvfrom()
#include <netpacket/packet.h> // struct sockaddr_ll, PACKET_BROADCAST
#include <net/ethernet.h> // ETH_P_ALL, ETH_P_IP, ETH_P_ARP, ETH_ALEN
#include <arpa/inet.h>    // inet_ntop(), inet_pton(), htons(), htonl()
#include <errno.h>        // errno, strerror()

// our custom ethertype so receivers know this packet came from our program
#define PROTOCOL         62357

// maximum size of one ethernet frame in bytes, used for buffer allocation and sendto
#define ETH_FRAME_LENGTH 1500

// our team ID given by the professor, written into every ARP packet we send
// receivers check this value to know the packet belongs to our group
#define GROUP_ID         3571

// ARP opcode value 1 means this is a REQUEST packet (who has this IP?)
#define ARPOP_REQUEST    1

// return code we use when we detect ARP spoofing in response_half_cycle
#define SPOOF_DETECTED  -2

// return code we use when the host passes all our verification checks
#define SPOOF_CLEAN      0

// how many seconds we wait to collect all ARP replies after sending our probe
// the paper calls this the Threshold Interval
#define THRESHOLD_SEC    5


// this struct is never sent on the network
// it is only used to calculate the TCP checksum
// the TCP checksum must cover the TCP header plus a fake summary of IP fields
struct pseudo_header {
    u_int32_t source_address;   // source IP address in network byte order
    u_int32_t dest_address;     // destination IP address in network byte order
    u_int8_t  placeholder;      // always zero, used only for alignment
    u_int8_t  protocol;         // IP protocol number, 6 = TCP
    u_int16_t tcp_length;       // length of the TCP header in bytes
};


// one node in our linked list of ARP requests we have seen on the network
// we store every ARP request so later we can check if an ARP reply matches one
typedef struct arp_request {
    time_t   sec;           // unix timestamp of when we saw this request
    uint8_t  src_ip[4];     // IP address of the machine that sent the request
    uint8_t  dst_ip[4];     // IP address that the sender is asking about
    uint8_t  src_mac[6];    // MAC address of the machine that sent the request
    struct arp_request *next; // pointer to the next node in the linked list
} arp_request;


// one node in our linked list of verified IP to MAC mappings
// we add an entry here when a host responds to our TCP SYN probe
// meaning we confirmed that host is real and its IP and MAC are legitimate
typedef struct Verifie_relation {
    uint8_t ip[4];          // IP address of the verified host
    uint8_t mac[6];         // MAC address of the verified host
    char    add_in[30];     // timestamp string showing when we verified this host
    struct  Verifie_relation *next; // pointer to the next node in the linked list
} Verifie_relation;


// stores our own IP address as a string, filled by get_local_ip()
// used when building packets so we can set ourselves as the sender
char LOCAL_IP[INET_ADDRSTRLEN];

// stores the name of the network interface we are working on, for example eth0
// set by the user in main() and used in all functions that need the interface
char WORKING_INTERFACE[50];

// head pointer of our verified hosts linked list
// starts as NULL meaning no verified hosts yet
Verifie_relation *verified_hosts = NULL;


// get_local_ip
// reads the IP address of our working interface and stores it in LOCAL_IP
// we need this so we can put our own IP in packets we build
void get_local_ip(void) {

    // addrs will point to the head of the linked list of all interfaces
    // tmp is the pointer we use to walk through the list
    struct ifaddrs *addrs, *tmp;

    // getifaddrs fills addrs with a linked list of all network interfaces on this machine
    getifaddrs(&addrs);

    for (tmp = addrs; tmp != NULL; tmp = tmp->ifa_next) {

        // ifa_addr is the address of this interface
        // sa_family == AF_INET means this is an IPv4 address
        // we also check the interface name matches WORKING_INTERFACE
        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET &&
            strcmp(tmp->ifa_name, WORKING_INTERFACE) == 0)
        {
            // cast to sockaddr_in to access the IPv4 address field sin_addr
            struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;

            // convert the binary IP to a human readable string and store in LOCAL_IP
            // AF_INET tells inet_ntop this is IPv4
            // INET_ADDRSTRLEN is the max size of the output string (16 bytes)
            inet_ntop(AF_INET, &pAddr->sin_addr, LOCAL_IP, INET_ADDRSTRLEN);
            break;
        }
    }

    // free the linked list that getifaddrs allocated
    freeifaddrs(addrs);
}


// get_local_mac
// reads the MAC address of our working interface using ioctl
// mac_out : output buffer of 6 bytes where the MAC will be stored
// returns true on success, false on failure
bool get_local_mac(uint8_t mac_out[6]) {

    // open a temporary UDP socket just so we can call ioctl on it
    // we use AF_INET and SOCK_DGRAM because ioctl for MAC works on any socket type
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); return false; }

    // ifreq is the struct that ioctl uses to pass interface name in and get info out
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    // copy the interface name into the ifreq struct so ioctl knows which interface to query
    // IFNAMSIZ is the max interface name length (16 bytes)
    strncpy(ifr.ifr_name, WORKING_INTERFACE, IFNAMSIZ - 1);

    // SIOCGIFHWADDR asks the kernel to fill ifr.ifr_hwaddr with the MAC address
    // ifr_hwaddr.sa_data contains the 6-byte MAC after this call
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(s);
        return false;
    }

    // copy the 6-byte MAC from the ifreq struct into the output buffer mac_out
    memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);

    close(s);
    return true;
}


// verification
// checks if we have already seen an ARP request with this exact src_ip and dst_ip pair
// we use this to avoid storing duplicate ARP requests in our linked list
// ip_src   : the IP of the machine that sent the ARP request (4 bytes binary)
// ip_dst   : the IP that the sender is asking about (4 bytes binary)
// header   : pointer to the head pointer of our arp_request linked list
// returns true if the pair already exists, false if it is new
bool verification(uint8_t ip_src[4], uint8_t ip_dst[4], arp_request **header) {

    // start at the head of the list and walk through every node
    arp_request *current = *header;
    while (current != NULL) {

        // memcmp compares 4 bytes of binary IP address
        // if both src and dst match then we have seen this request before
        if (memcmp(current->dst_ip, ip_dst, 4) == 0 &&
            memcmp(current->src_ip, ip_src, 4) == 0)
            return true;

        current = current->next;
    }

    // reached end of list without finding a match so this is a new request
    return false;
}


// find_last
// walks the arp_request linked list and returns a pointer to the last node
// header : the head of the linked list
// returns NULL if the list is empty
arp_request *find_last(arp_request *header) {
    if (header == NULL) return NULL;
    arp_request *current = header;

    // keep moving forward until next is NULL meaning we are at the last node
    while (current->next != NULL)
        current = current->next;
    return current;
}


// find_last_verifie_relation
// same idea as find_last but for the Verifie_relation linked list
// header : the head of the verified hosts linked list
// returns NULL if the list is empty
Verifie_relation *find_last_verifie_relation(Verifie_relation *header) {
    if (header == NULL) return NULL;
    Verifie_relation *current = header;
    while (current->next != NULL)
        current = current->next;
    return current;
}


// add_arp_request
// creates a new arp_request node and appends it to the end of the linked list
// header  : pointer to the head pointer so we can update it if list was empty
// src_ip  : binary IP of the machine that sent the ARP request (4 bytes)
// dst_ip  : binary IP that the sender is asking about (4 bytes)
// src_mac : MAC of the machine that sent the ARP request (6 bytes)
// sec     : unix timestamp of when the request was captured
void add_arp_request(arp_request **header, uint8_t src_ip[4], uint8_t dst_ip[4],
                     uint8_t src_mac[6], time_t sec) {

    // allocate memory for the new node and zero it out
    arp_request *new_request = calloc(1, sizeof(arp_request));
    if (new_request == NULL) { fprintf(stderr, "[-] calloc failed\n"); return; }

    // fill in the new node with the information from the captured ARP request
    memcpy(new_request->src_ip,  src_ip,  4);
    memcpy(new_request->dst_ip,  dst_ip,  4);
    memcpy(new_request->src_mac, src_mac, 6);
    new_request->sec  = sec;
    new_request->next = NULL; // this node will be the last so next is NULL

    // if the list is empty make this node the head
    // otherwise append it after the last node
    if (*header == NULL)
        *header = new_request;
    else
        find_last(*header)->next = new_request;
}


// add_verifie_relation
// creates a new Verifie_relation node and appends it to the verified hosts list
// mac        : the MAC address of the verified host (6 bytes)
// ip_address : the IP address of the verified host (4 bytes binary)
// date       : timestamp string showing when we verified this host
// header     : pointer to the head pointer of the verified hosts list
void add_verifie_relation(uint8_t mac[6], uint8_t ip_address[4], const char *date,
                          Verifie_relation **header) {

    // allocate and zero a new node
    Verifie_relation *nv = calloc(1, sizeof(Verifie_relation));
    if (nv == NULL) { fprintf(stderr, "[-] calloc failed\n"); return; }

    memcpy(nv->mac, mac, 6);            // copy 6-byte MAC into the node
    memcpy(nv->ip,  ip_address, 4);     // copy 4-byte binary IP into the node

    // copy the date string safely, leaving room for the null terminator
    strncpy(nv->add_in, date, sizeof(nv->add_in) - 1);
    nv->add_in[sizeof(nv->add_in) - 1] = '\0';
    nv->next = NULL;

    if (*header == NULL)
        *header = nv;
    else
        find_last_verifie_relation(*header)->next = nv;
}


// csum
// calculates the internet checksum (RFC 1071) used for IP and TCP headers
// ptr    : pointer to the data to checksum, treated as an array of 16-bit words
// nbytes : number of bytes to checksum
// returns the 16-bit checksum value
unsigned short csum(unsigned short *ptr, int nbytes) {

    register long sum = 0;
    unsigned short oddbyte;

    // add up all 16-bit words in the data
    while (nbytes > 1) { 
        sum += *ptr++;
        nbytes -= 2; }

    // if there is one byte left over pad it to 16 bits and add it
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    // fold the 32-bit sum down to 16 bits by adding the carry bits back in
    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    // return the one's complement of the sum
    return (unsigned short)~sum;
}


// send_syn_and_recv_syn_ack
// sends a TCP SYN packet to ip_dst using mac_address as the destination MAC
// then waits 2 seconds to receive a SYN-ACK or RST response
// this is how we verify a host is real as described in paper section 2.4
// a real host will reply with SYN-ACK or RST
// a spoofing attacker using a normal stack will silently drop the packet
// ip_dst      : destination IP address as a string, buffer size INET_ADDRSTRLEN
// mac_address : destination MAC address as 6 bytes
// returns true if we received a valid TCP response, false if no response (timeout)
bool send_syn_and_recv_syn_ack(char ip_dst[INET_ADDRSTRLEN], unsigned char mac_address[6]) {

    // open a raw socket at the packet level so we can build the full ethernet frame
    // AF_PACKET : work at ethernet level
    // SOCK_RAW  : we build the headers ourselves
    // ETH_P_ALL : capture all protocol types on receive
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) { 
        perror("socket");
        return false; }

    // datagram is the buffer holding our full packet: ethernet + IP + TCP
    char datagram[4096];
    memset(datagram, 0, sizeof(datagram));

    // overlay the three header structs onto different positions in the buffer
    // eth starts at byte 0
    // iph starts right after the ethernet header (14 bytes in)
    // tcph starts right after the IP header (14 + 20 = 34 bytes in)
    struct ether_header *ethdr = (struct ether_header *)datagram;
    struct iphdr  *iph  = (struct iphdr  *)(datagram + sizeof(struct ether_header));
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ether_header)
        + sizeof(struct iphdr));

    // device is the sockaddr_ll struct that sendto() needs for raw packet sockets
    // it tells the kernel which interface to send on and the destination MAC
    struct sockaddr_ll device;
    memset(&device, 0, sizeof(device));
    device.sll_family   = AF_PACKET;            // must be AF_PACKET for raw ethernet
    device.sll_protocol = htons(ETH_P_IP);      // we are sending an IP packet
    device.sll_ifindex  = if_nametoindex(WORKING_INTERFACE); // index of our interface
    device.sll_hatype   = ARPHRD_ETHER;         // hardware type = Ethernet
    device.sll_halen    = 6;                    // MAC address length = 6 bytes
    memcpy(device.sll_addr, mac_address, 6);    // destination MAC address

    // ifreq_c is used to retrieve our own MAC address via ioctl
    struct ifreq ifreq_c;
    memset(&ifreq_c, 0, sizeof(ifreq_c));
    strncpy(ifreq_c.ifr_name, WORKING_INTERFACE, IFNAMSIZ - 1);

    // SIOCGIFHWADDR fills ifreq_c.ifr_hwaddr.sa_data with our interface MAC
    if (ioctl(s, SIOCGIFHWADDR, &ifreq_c) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(s);
        return false;
    }

    // build ethernet header
    // ether_shost = source MAC = our own MAC from ioctl
    // ether_dhost = destination MAC = mac_address argument
    // ether_type  = 0x0800 = IPv4
    memcpy(ethdr->ether_shost, ifreq_c.ifr_hwaddr.sa_data, 6);
    memcpy(ethdr->ether_dhost, mac_address, 6);
    ethdr->ether_type = htons(ETH_P_IP);

    // build IPv4 header
    iph->version  = 4;                  // IPv4
    iph->ihl      = 5;                  // header length = 5 * 4 = 20 bytes (no options)
    iph->tos      = 0;                  // type of service = normal
    iph->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr)); // total packet length
    iph->id       = htons(rand() % 65535); // random identification number
    iph->frag_off = 0;                  // no fragmentation
    iph->ttl      = 64;                 // time to live = 64 hops
    iph->protocol = IPPROTO_TCP;        // payload is TCP
    iph->check    = 0;                  // set to 0 before calculating checksum
    iph->saddr    = inet_addr(LOCAL_IP); // source IP = our own IP
    iph->daddr    = inet_addr(ip_dst);  // destination IP = the host we are probing

    // random source port so our SYN is identifiable when the reply comes back
    uint16_t src_port  = htons(1024 + rand() % 64511);

    // build TCP header
    tcph->source   = src_port;          // our source port (random)
    tcph->dest     = htons(443);        // destination port 443 = HTTPS, common open port
    tcph->seq      = htonl(rand());     // random sequence number
    tcph->ack_seq  = 0;                 // acknowledgement = 0 because this is a SYN not ACK
    tcph->doff     = 5;                 // data offset = 5 * 4 = 20 bytes (no TCP options)
    tcph->syn      = 1;                 // SYN flag = 1, this is a connection request
    tcph->window   = htons(65535);      // window size = maximum
    tcph->check    = 0;                 // set to 0 before calculating checksum
    tcph->urg_ptr  = 0;                 // no urgent data

    // build the pseudo header used only for TCP checksum calculation
    // TCP checksum covers: pseudo header + TCP header
    struct pseudo_header psh;
    psh.source_address = iph->saddr;    // our source IP
    psh.dest_address   = iph->daddr;    // destination IP
    psh.placeholder    = 0;             // always zero
    psh.protocol       = IPPROTO_TCP;   // protocol = 6 for TCP
    psh.tcp_length     = htons(sizeof(struct tcphdr)); // TCP header size

    // allocate a temporary buffer combining pseudo header + TCP header for checksum
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);
    if (pseudogram == NULL) {
        fprintf(stderr, "[-] malloc failed\n");
        close(s);
        return false;
    }
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    // calculate and fill in the TCP checksum
    tcph->check = csum((unsigned short *)pseudogram, psize);
    free(pseudogram); // free the temporary checksum buffer

    // calculate and fill in the IP header checksum
    iph->check = csum((unsigned short *)iph, sizeof(struct iphdr));

    // total bytes to send = ethernet header + IP header + TCP header
    int pkt_size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr);

    // send the packet out on the raw socket
    if (sendto(s, datagram, pkt_size, 0,(struct sockaddr *)&device, sizeof(device)) < 0) {
        perror("sendto"); 
        close(s); 
        return false;
    }

    printf("[*] SYN sent to %s >> %02x:%02x:%02x:%02x:%02x:%02x\n", ip_dst,
           mac_address[0], mac_address[1], mac_address[2],
           mac_address[3], mac_address[4], mac_address[5]);

    // receive buffer to hold incoming packets
    char recv_buf[4096];

    // deadline = current time + 2 seconds, we stop waiting after this
    time_t deadline = time(NULL) + 2;

    // minimum valid packet size = ethernet + IP + TCP headers
    const int MIN_PKT_LEN = (int)(sizeof(struct ether_header) + sizeof(struct iphdr) +
                                  sizeof(struct tcphdr));

    // wait and read incoming packets until deadline expires
    while (time(NULL) < deadline) {

        // use select() to wait for data with a timeout
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(s, &readfds); // watch our socket for incoming data

        struct timeval tv;
        time_t remaining = deadline - time(NULL);
        tv.tv_sec  = remaining > 0 ? remaining : 0; // remaining seconds until deadline
        tv.tv_usec = 0;

        // select returns 0 on timeout or negative on error, both mean stop waiting
        if (select(s + 1, &readfds, NULL, NULL, &tv) <= 0) break;

        struct sockaddr_ll from;
        socklen_t addr_len = sizeof(from);

        // receive one packet from the socket
        int len = recvfrom(s, recv_buf, sizeof(recv_buf), 0,
                           (struct sockaddr *)&from, &addr_len);
        if (len <= 0) continue;

        // skip packets that are too short to contain all three headers
        if (len < MIN_PKT_LEN) continue;

        // overlay header structs onto the received buffer
        struct ether_header *ethdr_recv = (struct ether_header *)recv_buf;
        struct iphdr  *iphrcv  = (struct iphdr  *)(recv_buf + sizeof(struct ether_header));

        // ihl * 4 gives the actual IP header size in bytes (may have options)
        int ip_hdr_len = iphrcv->ihl * 4;

        // skip if packet is too short for the actual IP header size
        if (len < (int)(sizeof(struct ether_header) + ip_hdr_len + sizeof(struct tcphdr)))
            continue;

        // TCP header starts right after the ethernet and IP headers
        struct tcphdr *tcphrcv = (struct tcphdr *)(recv_buf + sizeof(struct ether_header)
                                                             + ip_hdr_len);

        // convert source IP from binary to string for comparison
        char ip_rcv[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iphrcv->saddr, ip_rcv, sizeof(ip_rcv));

        // format source MAC as a readable string for printing
        char s_mac[18];
        snprintf(s_mac, sizeof(s_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 ethdr_recv->ether_shost[0], ethdr_recv->ether_shost[1],
                 ethdr_recv->ether_shost[2], ethdr_recv->ether_shost[3],
                 ethdr_recv->ether_shost[4], ethdr_recv->ether_shost[5]);

        // check all 4 conditions to confirm this reply belongs to our SYN:
        // 1. source IP of reply == ip_dst we sent to
        // 2. destination port of reply == our source port src_port
        // 3. destination MAC of reply == our own MAC
        // 4. reply flags are SYN-ACK (connection accepted) or RST (port closed)
        //    both SYN-ACK and RST prove the host is real and received our SYN
        if (strcmp(ip_dst, ip_rcv) == 0 && tcphrcv->dest == src_port &&
            memcmp(ethdr_recv->ether_dhost, ethdr->ether_shost, 6) == 0 &&
            ((tcphrcv->syn && tcphrcv->ack) || tcphrcv->rst))
        {
            printf("[+] SYN-ACK/RST from %s >> %s\n", ip_rcv, s_mac);

            // build a timestamp string for the verified host record
            time_t now = time(NULL);
            char date_buf[30];
            struct tm tm_info;
            localtime_r(&now, &tm_info);
            strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

            // add this IP and MAC to our verified hosts list
            // ether_shost is the MAC of the host that replied
            // iphrcv->saddr is its IP in binary form
            add_verifie_relation(ethdr_recv->ether_shost, (uint8_t *)&iphrcv->saddr,
                                 date_buf, &verified_hosts);
            close(s);
            return true; // host is real, verification passed
        }
    }

    printf("[-] No SYN-ACK (timeout) from %s\n", ip_dst);
    close(s);
    return false; // no response received within 2 seconds
}


// mac_addresses_match
// checks that the source MAC in the ethernet header matches the source MAC in the ARP header
// in a legitimate ARP packet these two values must be identical
// if they differ the packet headers are inconsistent which means it is definitely spoofed
// eth : pointer to the ethernet header of the received packet
// arp : pointer to the ARP header of the received packet
// returns true if they match, false if there is a contradiction
bool mac_addresses_match(struct ether_header *eth, struct ether_arp *arp) {
    // ether_shost = source MAC in ethernet header
    // arp_sha     = sender hardware address = source MAC in ARP header
    // memcmp returns 0 if equal so == 0 means they match
    return memcmp(eth->ether_shost, arp->arp_sha, 6) == 0;
}


// delete_head
// removes and frees the first node from the arp_request linked list
// we call this to expire ARP requests that are older than 5 seconds
// header : pointer to the head pointer of the list
void delete_head(arp_request **header) {
    if (*header == NULL) return;

    // save a pointer to the current head so we can free it after moving the head forward
    arp_request *tmp = *header;

    // move the head pointer forward to the next node
    *header = tmp->next;

    // free the memory of the old head node
    free(tmp);
}


// is_verifie_relation
// checks if a given IP and MAC pair is already in our verified hosts list
// we use this to quickly recognize legitimate hosts without re-probing them
// s_ip  : IP address to check (4 bytes binary)
// s_mac : MAC address to check (6 bytes)
// returns true if the pair is verified, false if not found
bool is_verifie_relation(uint8_t s_ip[4], uint8_t s_mac[6]) {
    Verifie_relation *current = verified_hosts;
    if (current == NULL) return false; // list is empty, nothing verified yet

    while (current != NULL) {
        // check if both the IP and MAC match this node
        if (memcmp(current->ip,  s_ip,  4) == 0 &&
            memcmp(current->mac, s_mac, 6) == 0)
            return true; // found a match
        current = current->next;
    }
    return false; // no match found in the entire list
}


// is_reply
// checks if a received ARP reply matches any ARP request we previously stored
// if a match is found, that request is removed from the list since it was answered
// header : pointer to the head pointer of our stored ARP requests list
// arp    : pointer to the ARP header of the received reply
// returns true if this reply matches a stored request (legitimate reply)
// returns false if no matching request was found (unsolicited reply = suspicious)
bool is_reply(arp_request **header, struct ether_arp *arp) {

    arp_request *current = *header;
    arp_request *prev    = NULL; // tracks the node before current for list removal

    while (current != NULL) {
        // arp_tha = target hardware address = the MAC the reply is addressed to
        // arp_tpa = target protocol address = the IP the reply is addressed to
        // these should match the src_mac and src_ip of a request we stored
        if (memcmp(current->src_mac, arp->arp_tha, 6) == 0 &&
            memcmp(current->src_ip,  arp->arp_tpa, 4) == 0)
        {
            // found a match, remove this node from the list
            // if it is the head node update the head pointer
            // otherwise link the previous node to the next node, skipping this one
            if (prev == NULL)
                *header = current->next;
            else
                prev->next = current->next;

            free(current); // free the matched node memory
            return true;   // this reply is legitimate
        }
        prev = current;
        current = current->next;
    }
    return false; // no matching request found
}


// send_arp_request
// builds and sends a broadcast ARP request asking who has resolve_ip
// resolve_ip : the IP address we want to find the MAC for, as a string
// src_ip     : our own IP address as a string, used as the sender IP
// src_mac    : our own MAC address as 6 bytes, used as the sender MAC
// if_index   : the index number of the network interface to send on
// returns 0 on success, -1 on failure
int send_arp_request(const char *resolve_ip,
                     const char *src_ip,
                     const uint8_t src_mac[6],
                     int if_index)
{
    // guard against NULL pointers to avoid segfault
    if (!resolve_ip || !src_ip || !src_mac) {
        fprintf(stderr, "[ARP] send_arp_request: NULL argument\n");
        return -1;
    }

    // open a raw socket at ethernet level so we can send our own ARP frame
    // PF_PACKET  : work at the packet/ethernet level
    // SOCK_RAW   : we build all headers ourselves
    // ETH_P_ARP  : we are sending ARP packets (ethertype 0x0806)
    int pf_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (pf_sock < 0) {
        fprintf(stderr, "[ARP] socket: %s\n", strerror(errno));
        return -1;
    }

    // allocate a zeroed buffer big enough for a full ethernet frame
    // calloc zeroes the memory so unused bytes are all zero automatically
    uint8_t *buffer = calloc(1, ETH_FRAME_LENGTH);
    if (!buffer) {
        perror("[ARP] calloc");
        close(pf_sock);
        return -1;
    }

    // overlay the ethernet header struct at the start of the buffer
    struct ether_header *eth = (struct ether_header *)buffer;

    // overlay the ARP header struct right after the ethernet header
    // sizeof(struct ether_header) = 14 bytes (6 dst + 6 src + 2 type)
    struct ether_arp *arp = (struct ether_arp *)(buffer + sizeof(struct ether_header));

    // build ethernet header
    // destination = broadcast because we don't know the target MAC yet
    const uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(eth->ether_dhost, broadcast, 6); // ff:ff:ff:ff:ff:ff = all machines receive this
    memcpy(eth->ether_shost, src_mac,   6); // our own MAC as the source
    eth->ether_type = htons(ETHERTYPE_ARP); // 0x0806 = ARP ethertype

    // build ARP payload using the standard ether_arp struct
    arp->arp_hrd = htons(ARPHRD_ETHER);     // hardware type 1 = Ethernet
    arp->arp_pro = htons(ETH_P_IP);         // protocol type 0x0800 = IPv4
    arp->arp_hln = 6;                       // hardware (MAC) address length = 6 bytes, 1 byte field no htons
    arp->arp_pln = 4;                       // protocol (IP) address length = 4 bytes, 1 byte field no htons
    arp->arp_op  = htons(ARPOP_REQUEST);    // opcode 1 = REQUEST (who has this IP?)

    // sender fields = our own information
    memcpy(arp->arp_sha, src_mac, 6);              // our MAC as sender hardware address
    inet_pton(AF_INET, src_ip, arp->arp_spa);      // convert our IP string to binary and store as sender IP

    // target fields = who we are looking for
    memset(arp->arp_tha, 0, 6);                    // target MAC = all zeros because we don't know it yet
    inet_pton(AF_INET, resolve_ip, arp->arp_tpa);  // convert target IP string to binary

    // build sockaddr_ll needed by sendto() for raw packet sockets
    struct sockaddr_ll sa = {0};
    sa.sll_family   = AF_PACKET;            // address family for raw ethernet
    sa.sll_protocol = htons(ETH_P_ARP);     // ARP protocol
    sa.sll_ifindex  = if_index;             // which interface to send on
    sa.sll_hatype   = ARPHRD_ETHER;         // hardware type = Ethernet
    sa.sll_pkttype  = PACKET_BROADCAST;     // this is a broadcast packet
    sa.sll_halen    = ETH_ALEN;             // MAC address length = 6 bytes
    memset(sa.sll_addr, 0xff, 6);           // broadcast destination MAC

    // send the fully built frame
    ssize_t sent = sendto(pf_sock, buffer, ETH_FRAME_LENGTH, 0,
                          (struct sockaddr *)&sa, sizeof(sa));
    if (sent < 0) {
        fprintf(stderr, "[ARP] sendto failed: %s\n", strerror(errno));
        free(buffer);
        close(pf_sock);
        return -1;
    }

    printf("[ARP] REQUEST sent: who has %s? Tell %s (%zd bytes)\n",
           resolve_ip, src_ip, sent);

    free(buffer);    // free the frame buffer
    close(pf_sock);  // close the socket
    return 0;
}


// response_half_cycle
// implements paper section 2.4.3
// called when we detect an unsolicited ARP reply (a reply with no matching request)
// this is suspicious because legitimate ARP replies only come after a request
// we probe back by sending our own broadcast ARP request to the suspicious IP
// then we collect all replies within THRESHOLD_SEC and analyse them:
//   0 replies  = real host is not on the network = original reply was SPOOFED
//   1 reply    = compare MAC with original, then verify with TCP SYN
//   2+ replies = multiple machines claiming the same IP = SPOOFING DETECTED
// suspicious_ip  : binary IP of the host that sent the unsolicited reply (4 bytes)
// suspicious_mac : MAC of the host that sent the unsolicited reply (6 bytes)
// returns SPOOF_DETECTED (-2) if spoofing is found, SPOOF_CLEAN (0) if host is legitimate
int response_half_cycle(uint8_t suspicious_ip[4], uint8_t suspicious_mac[6])
{
    // convert binary IP to string so we can pass it to send_arp_request and printf
    // FIX: changed from char ip_str[INET_ADDRSTRLEN] (16 bytes) to match
    //      send_syn_and_recv_syn_ack's parameter declaration char ip_dst[INET_ADDRSTRLEN]
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, suspicious_ip, ip_str, sizeof(ip_str));

    printf("[RHC] Response Half Cycle detected from %s\n", ip_str);
    printf("[RHC] Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           suspicious_mac[0], suspicious_mac[1], suspicious_mac[2],
           suspicious_mac[3], suspicious_mac[4], suspicious_mac[5]);

    // get our own MAC so we can set ourselves as the sender in the ARP request
    uint8_t our_mac[6];
    if (!get_local_mac(our_mac)) {
        fprintf(stderr, "[RHC] Failed to get local MAC\n");
        return -1;
    }

    // get the interface index number needed by send_arp_request
    // if_nametoindex converts the interface name like eth0 to its integer index
    int if_index = if_nametoindex(WORKING_INTERFACE);
    if (if_index == 0) {
        fprintf(stderr, "[RHC] if_nametoindex failed\n");
        return -1;
    }

    // step 1: send a broadcast ARP request asking who has suspicious_ip
    // by Rule B from the paper: even if an attacker is spoofing, the REAL host
    // cannot be stopped from replying to a broadcast ARP request
    printf("[RHC] Probing %s with ARP request to verify sender...\n", ip_str);
    if (send_arp_request(ip_str, LOCAL_IP, our_mac, if_index) < 0) {
        fprintf(stderr, "[RHC] send_arp_request failed\n");
        return -1;
    }

    // step 2: open a raw socket to listen for ARP replies after our probe
    // ETH_P_ARP makes the socket receive only ARP packets
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (s < 0) { 
        perror("[RHC] socket");
        return -1; 
    }

    // set the socket receive timeout to THRESHOLD_SEC seconds
    struct timeval timeout;
    timeout.tv_sec  = THRESHOLD_SEC;
    timeout.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // array to store MAC addresses from all replies we receive
    uint8_t reply_macs[10][6];
    int     reply_count = 0;

    uint8_t rcvbuf[ETH_FRAME_LENGTH];

    while (reply_count < 10)
    {
        memset(rcvbuf, 0, sizeof(rcvbuf));

        struct sockaddr_ll from = {0};
        socklen_t fromlen = sizeof(from);

        int len = recvfrom(s, rcvbuf, sizeof(rcvbuf), 0,
                           (struct sockaddr *)&from, &fromlen);
        if (len < 0) {
            printf("[RHC] Threshold interval expired. Replies collected: %d\n", reply_count);
            break;
        }

        if (len < (int)(sizeof(struct ether_header) + sizeof(struct ether_arp)))
            continue;

        struct ether_arp *arp = (struct ether_arp *)(rcvbuf + sizeof(struct ether_header));

        if (ntohs(arp->arp_op) != ARPOP_REPLY)
            continue;

        if (memcmp(arp->arp_spa, suspicious_ip, 4) != 0)
            continue;

        memcpy(reply_macs[reply_count], arp->arp_sha, 6);

        char reply_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp->arp_spa, reply_ip_str, sizeof(reply_ip_str));

        printf("[RHC] Reply %d from %s MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               reply_count + 1, reply_ip_str,
               arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
               arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);

        reply_count++;
    }

    close(s);

    if (reply_count == 0) {
        printf("[RHC] SPOOF ALARM: no reply to our ARP probe for %s\n", ip_str);
        printf("[RHC] Original reply was likely SPOOFED\n");
        return SPOOF_DETECTED;
    }

    if (reply_count == 1) {
        printf("[RHC] Single reply received - checking MAC match...\n");

        if (memcmp(reply_macs[0], suspicious_mac, 6) == 0) {
            printf("[RHC] MAC matches - verifying with TCP SYN...\n");

            // ip_str is now INET_ADDRSTRLEN bytes, matching the function parameter size
            if (send_syn_and_recv_syn_ack(ip_str, reply_macs[0])) {
                printf("[RHC] TCP SYN verification passed\n");
                return SPOOF_CLEAN;
            } else {
                printf("[RHC] TCP SYN verification failed\n");
                return SPOOF_DETECTED;
            }
        } else {
            printf("[RHC] MAC does not match - SPOOF detected\n");
            return SPOOF_DETECTED;
        }
    }

    if (reply_count >= 2) {
        printf("[RHC] Multiple replies (%d) detected for %s - SPOOFING DETECTED\n",
               reply_count, ip_str);
        return SPOOF_DETECTED;
    }

    return SPOOF_CLEAN;
}

// callback
// called by pcap_loop() every time a packet is captured on the network
// useless  : we reuse this pointer to pass our arp_request linked list head
// pkthdr   : pcap metadata including the capture timestamp
// packet   : the raw bytes of the captured packet
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr,
              const u_char *packet)
{
    // overlay ethernet and ARP header structs onto the raw packet bytes
    struct ether_header *eth = (struct ether_header *)packet;
    struct ether_arp    *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));

    // recover our arp_request linked list head pointer from the useless argument
    arp_request **arp_header = (arp_request **)useless;

    // we only process ARP packets, skip everything else
    if (ntohs(eth->ether_type) != ETHERTYPE_ARP) return;

    // check for header inconsistency
    // in a real ARP packet the source MAC in ethernet header and ARP header must match
    // if they differ the packet is definitely spoofed (Inconsistent Header ARP packet)
    if (!mac_addresses_match(eth, arp))
        printf("[-] MAC contradiction: Ethernet src != ARP src MAC\n");

    // format the packet capture time as a human readable string for log messages
    char timestr[15];
    struct tm ltime;
    time_t local_tv_sec = (time_t)pkthdr->ts.tv_sec; // unix timestamp of capture
    localtime_r(&local_tv_sec, &ltime);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

    if (ntohs(arp->arp_op) == ARPOP_REPLY) {

        // is_reply checks if this reply matches any ARP request we stored
        // if yes it removes that request from the list and returns true
        bool replied = is_reply(arp_header, arp);

        // is_verifie_relation checks if this IP and MAC pair is already verified
        bool known   = is_verifie_relation(arp->arp_spa, arp->arp_sha);

        if (replied || known) {
            // reply was expected or sender is already verified = legitimate
            printf("[+] [%s] Legit ARP reply.\n", timestr);
        } else {
            // reply was not expected and sender is not verified = suspicious
            // this is a Response Half Cycle as described in paper section 2.4.3
            char ip_src[INET_ADDRSTRLEN];
            unsigned char mac_src[6];
            inet_ntop(AF_INET, arp->arp_spa, ip_src, sizeof(ip_src));
            memcpy(mac_src, arp->arp_sha, 6);

            printf("[-] [%s] Unsolicited ARP reply from %s - running Response Half Cycle\n",
                   timestr, ip_src);

            // run the full Response Half Cycle detection algorithm from paper section 2.4.3
            // arp_spa = sender protocol address = IP of the suspicious host (4 bytes binary)
            // arp_sha = sender hardware address = MAC of the suspicious host (6 bytes)
            int rhc_result = response_half_cycle(arp->arp_spa, arp->arp_sha);

            if (rhc_result == SPOOF_DETECTED)
                printf("[!] [%s] ARP SPOOFING DETECTED from %s\n", timestr, ip_src);
            else
                printf("[+] [%s] Host %s verified as legitimate\n", timestr, ip_src);
        }
    }

    if (ntohs(arp->arp_op) == ARPOP_REQUEST) {

        // verification checks if we already have this src/dst IP pair in our list
        // we skip duplicates to avoid storing the same request multiple times
        if (!verification(arp->arp_spa, arp->arp_tpa, arp_header)) {

            // store this new ARP request so we can match it with the reply later
            // arp_spa = sender IP (4 bytes binary)
            // arp_tpa = target IP (4 bytes binary)
            // arp_sha = sender MAC (6 bytes)
            add_arp_request(arp_header, arp->arp_spa, arp->arp_tpa,
                            arp->arp_sha, local_tv_sec);

            char ip_src[INET_ADDRSTRLEN], ip_dst[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp->arp_spa, ip_src, sizeof(ip_src));
            inet_ntop(AF_INET, arp->arp_tpa, ip_dst, sizeof(ip_dst));
            printf("[*] [%s] ARP request: %s asks for %s\n", timestr, ip_src, ip_dst);

            // verify the requester using TCP SYN as described in paper section 2.4.2
            // arp_sha is the MAC of the requester, already known from the ARP request
            if (send_syn_and_recv_syn_ack(ip_src, arp->arp_sha))
                printf("[+] Requester %s verified.\n", ip_src);
            else
                printf("[-] Requester %s did not respond - suspicious!\n", ip_src);
        }
    }

    // remove ARP requests from the list that are older than 5 seconds
    // these are expired requests that never received a reply
    // local_tv_sec is the timestamp of the current packet
    while (*arp_header != NULL && local_tv_sec - (*arp_header)->sec > 5)
        delete_head(arp_header);
}


// main
// entry point of the program
// lets the user choose a network interface, then starts capturing ARP packets
int main(void) {
    pcap_if_t  *alldevs, *d;    // alldevs = list of all interfaces, d = iterator
    pcap_t     *adhandle;       // pcap handle for the chosen interface
    char        errbuf[PCAP_ERRBUF_SIZE]; // buffer for pcap error messages
    int         i = 0;          // counter for listing interfaces
    char        packet_filter[] = "arp"; // BPF filter: only capture ARP packets
    bpf_u_int32 netip, netmask; // network IP and mask of the chosen interface
    struct bpf_program fcode;   // compiled BPF filter program

    // get a linked list of all available network interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "[-] pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    // print all available interfaces so the user can choose one
    printf("\nAvailable interfaces:\n");
    for (d = alldevs; d != NULL; d = d->next) {
        printf("  %d) %s", ++i, d->name);
        if (d->description) printf(" (%s)", d->description);
        printf("\n");
    }

    if (i == 0) { printf("[-] No interfaces found!\n"); return 1; }

    // ask the user to pick an interface by number
    int num;
    printf("\nChoose interface (1-%d), 0 = first: ", i);
    if (scanf("%d", &num) != 1) {
        fprintf(stderr, "[-] Invalid input.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    if (num < 0 || num > i) {
        printf("[-] Out of range.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }
    if (num == 0) num = 1; // default to first interface

    // walk the list to reach the interface the user chose
    for (d = alldevs, i = 0; i < num - 1; d = d->next, i++);

    // store the chosen interface name in WORKING_INTERFACE so all functions can use it
    strncpy(WORKING_INTERFACE, d->name, sizeof(WORKING_INTERFACE) - 1);
    WORKING_INTERFACE[sizeof(WORKING_INTERFACE) - 1] = '\0';

    // get and store our own IP address on this interface
    get_local_ip();
    printf("[+] Interface : %s\n[+] Local IP  : %s\n", WORKING_INTERFACE, LOCAL_IP);

    // get the network address and subnet mask needed to compile the BPF filter
    if (pcap_lookupnet(d->name, &netip, &netmask, errbuf) < 0) {
        fprintf(stderr, "[-] pcap_lookupnet: %s\n", errbuf);
        pcap_freealldevs(alldevs); return 1;
    }

    // open the interface for live packet capture
    // 65536 = max bytes to capture per packet (capture everything)
    // 1     = promiscuous mode, capture all packets not just ones addressed to us
    // 1000  = read timeout in milliseconds
    adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    if (!adhandle) {
        fprintf(stderr, "[-] pcap_open_live: %s\n", errbuf);
        pcap_freealldevs(alldevs); return 1;
    }

    // compile the BPF filter string "arp" so pcap only gives us ARP packets
    // then apply the compiled filter to the capture handle
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0 ||
        pcap_setfilter(adhandle, &fcode) < 0) {
        fprintf(stderr, "[-] filter error\n");
        pcap_close(adhandle);
        pcap_freealldevs(alldevs); return 1;
    }

    // free the compiled filter program now that it has been applied
    pcap_freecode(&fcode);

    printf("[+] Listening on %s ...\n\n", WORKING_INTERFACE);

    // free the interface list now that we have chosen and opened one
    pcap_freealldevs(alldevs);

    // arp_header is the head of our ARP request linked list
    // starts as NULL meaning no requests stored yet
    // we pass its address to pcap_loop so callback() can access and modify it
    arp_request *arp_header = NULL;

    // start the capture loop
    // 0           = capture forever until an error or pcap_breakloop()
    // callback    = function called for every captured packet
    // &arp_header = passed as the useless argument to callback()
    pcap_loop(adhandle, 0, callback, (u_char *)&arp_header);

    pcap_close(adhandle); // close the capture handle when done
    return 0;
}

// for my thinkpad i love my thinkpad
/*
    ما شممت الورد الا
    زادني شوقا إليك
    وإذا ما مال غصن
    خلته يحنو عليك

    إن يكن جسمي تناءى
    فالحشى باق لديك
    لست أدري ما الذي
    حل بي من مقلتيك

    رشق القلب بسهم
    قوسه من لحظيك
    إن ذاتي وذواتي
    يا حبيبي في يديك

    كل حسن في برايا
    فهو منسوب إليك
    يا حبيبي يا محمد
    ربنا صلى عليك
*/