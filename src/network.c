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

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

void send_tcp_packet(const char *target_ip, int port, int flags) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("error creating socket");
        return;
    }

    char packet[4096];
    memset(packet, 0, 4096);

    struct tcphdr *tcp = (struct tcphdr *)packet;
    struct sockaddr_in sin;
    struct pseudo_header psh;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(target_ip);

    // detect correct source ip for this target
    char source_ip[32];
    get_local_ip(source_ip, target_ip);
    
    // fill tcp header
    tcp->source = htons(54321); 
    tcp->dest = htons(port);
    tcp->seq = 0;
    tcp->ack_seq = 0;
    tcp->doff = 5;
    
    tcp->fin = (flags & TH_FIN) ? 1 : 0;
    tcp->syn = (flags & TH_SYN) ? 1 : 0;
    tcp->rst = (flags & TH_RST) ? 1 : 0;
    tcp->psh = (flags & TH_PUSH) ? 1 : 0;
    tcp->ack = (flags & TH_ACK) ? 1 : 0;
    tcp->urg = (flags & TH_URG) ? 1 : 0;

    tcp->window = htons(1024); 
    tcp->check = 0;
    tcp->urg_ptr = 0;

    // checksum calculation
    psh.source_address = inet_addr(source_ip);
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

    if (sendto(sock, packet, sizeof(struct tcphdr), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("error sending packet");
    }
    
    close(sock);
}

// receives response and fills ip header pointer if provided
struct tcphdr* receive_tcp_response(const char *target_ip, int timeout_sec, struct iphdr **ip_out) {
    int sock;
    static char buffer[4096]; 
    struct sockaddr_in saddr;
    socklen_t saddr_size = sizeof(saddr);
    
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return NULL;

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    while (1) {
        int data_size = recvfrom(sock, buffer, 4096, 0, (struct sockaddr*)&saddr, &saddr_size);
        if (data_size < 0) {
            close(sock);
            return NULL; 
        }

        if (strcmp(inet_ntoa(saddr.sin_addr), target_ip) == 0) {
            struct iphdr *ip_header = (struct iphdr *)buffer;
            int ip_header_len = ip_header->ihl * 4;
            struct tcphdr *tcp_header = (struct tcphdr *)(buffer + ip_header_len);
            
            // save pointer to ip header
            if (ip_out) {
                *ip_out = ip_header;
            }

            close(sock);
            return tcp_header;
        }
    }
}