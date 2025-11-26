
#define _DEFAULT_SOURCE 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "network.h"
#include "utils.h"

// Helper struct for checksum calculation
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Generic function to send ANY combination of flags
void send_tcp_packet(const char *target_ip, int port, int flags) {
    // 1. Create a Raw Socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Error creating socket");
        exit(1);
    }

    char packet[4096];
    memset(packet, 0, 4096); // Clear memory

    // Pointers to handle headers
    struct tcphdr *tcp = (struct tcphdr *)packet;
    struct sockaddr_in sin;
    struct pseudo_header psh;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(target_ip);

    // 2. Fill the TCP Header
    tcp->source = htons(12345);       // Random source port
    tcp->dest = htons(port);          // Target port
    tcp->seq = 0;
    tcp->ack_seq = 0;
    tcp->doff = 5;                    // Header size
    
    // --- KEY PART: Set flags based on input ---
    tcp->fin = (flags & TH_FIN) ? 1 : 0;
    tcp->syn = (flags & TH_SYN) ? 1 : 0;
    tcp->rst = (flags & TH_RST) ? 1 : 0;
    tcp->psh = (flags & TH_PUSH) ? 1 : 0;
    tcp->ack = (flags & TH_ACK) ? 1 : 0;
    tcp->urg = (flags & TH_URG) ? 1 : 0;
    // ------------------------------------------

    tcp->window = htons(5840); 
    tcp->check = 0; // Initial checksum is 0
    tcp->urg_ptr = 0;

    // 3. Calculate Checksum (Pseudo header + TCP header)
    psh.source_address = inet_addr(get_local_ip(target_ip));
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));

    tcp->check = calculate_checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);

    // 4. Send the packet!
    if (sendto(sock, packet, sizeof(struct tcphdr), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("Error sending packet");
    } else {
        printf("Packet Sent (Flags mask: %d) to %s:%d\n", flags, target_ip, port);
    }

    close(sock);
}

struct tcphdr* receive_tcp_response(const char *target_ip, int timeout_sec) {
    int sock;
    static char buffer[4096]; 
    struct sockaddr_in saddr;
    socklen_t saddr_size = sizeof(saddr);
    
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return NULL;

    // Set timeout
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    while (1) {
        int data_size = recvfrom(sock, buffer, 4096, 0, (struct sockaddr*)&saddr, &saddr_size);
        if (data_size < 0) {
            close(sock);
            return NULL; // Timeout (No reply)
        }

        // Check if the packet is from our target
        if (strcmp(inet_ntoa(saddr.sin_addr), target_ip) == 0) {
            struct iphdr *ip_header = (struct iphdr *)buffer;
            int ip_header_len = ip_header->ihl * 4;
            
           
            struct tcphdr *tcp_header = (struct tcphdr *)(buffer + ip_header_len);
            
            close(sock);
            return tcp_header;
        }
    }
}