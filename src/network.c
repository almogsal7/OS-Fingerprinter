/*
 * network.c - Network scanning functions
 * 
 * This is where we send packets and capture responses.
 * We use raw sockets to craft custom TCP packets.
 */

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#include "../include/defs.h"
#include "../include/network.h"
#include "../include/utils.h"


/* Pseudo header for TCP checksum calculation */
struct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
};


/*
 * Read TCP options from a received packet.
 * Builds both a string representation and fills the opts structure.
 */
void read_tcp_options(struct tcphdr *tcp, char *out_str, TCPOpts *opts)
{
    out_str[0] = '\0';
    memset(opts, 0, sizeof(TCPOpts));
    opts->mss = -1;
    opts->window_scale = -1;
    
    /* Options start after the fixed TCP header (20 bytes) */
    int opt_len = (tcp->doff * 4) - 20;
    if (opt_len <= 0) return;
    
    unsigned char *p = (unsigned char *)tcp + 20;
    unsigned char *end = p + opt_len;
    char tmp[32];
    int idx = 0;
    
    while (p < end) {
        unsigned char kind = *p;
        
        /* End of options */
        if (kind == 0) break;
        
        /* NOP - single byte padding */
        if (kind == 1) {
            strcat(out_str, "N");
            if (idx < 31) opts->pattern[idx++] = 'N';
            p++;
            continue;
        }
        
        /* All other options have a length byte */
        if (p + 1 >= end) break;
        int len = p[1];
        if (len < 2 || p + len > end) break;
        
        switch (kind) {
            case 2:  /* MSS */
                if (len >= 4) {
                    opts->mss = ntohs(*(uint16_t *)(p + 2));
                    sprintf(tmp, "M%X", opts->mss);
                    strcat(out_str, tmp);
                    if (idx < 31) opts->pattern[idx++] = 'M';
                }
                break;
                
            case 3:  /* Window Scale */
                if (len >= 3) {
                    opts->window_scale = p[2];
                    sprintf(tmp, "W%X", opts->window_scale);
                    strcat(out_str, tmp);
                    if (idx < 31) opts->pattern[idx++] = 'W';
                }
                break;
                
            case 4:  /* SACK Permitted */
                opts->has_sack = 1;
                strcat(out_str, "S");
                if (idx < 31) opts->pattern[idx++] = 'S';
                break;
                
            case 8:  /* Timestamp */
                opts->has_timestamp = 1;
                if (len >= 10) {
                    uint32_t ts = ntohl(*(uint32_t *)(p + 2));
                    sprintf(tmp, "T%X", ts ? 1 : 0);
                    strcat(out_str, tmp);
                }
                if (idx < 31) opts->pattern[idx++] = 'T';
                break;
        }
        
        p += len;
    }
    
    opts->pattern[idx] = '\0';
}


/*
 * Build TCP options for our SYN packets.
 * We include common options to look like a normal connection.
 */
static int build_options(unsigned char *buf)
{
    int pos = 0;
    
    /* MSS = 1460 */
    buf[pos++] = 2;
    buf[pos++] = 4;
    *(uint16_t *)(buf + pos) = htons(1460);
    pos += 2;
    
    /* SACK Permitted */
    buf[pos++] = 4;
    buf[pos++] = 2;
    
    /* Timestamp */
    buf[pos++] = 8;
    buf[pos++] = 10;
    *(uint32_t *)(buf + pos) = htonl(0xFFFFFFFF);
    pos += 4;
    *(uint32_t *)(buf + pos) = 0;
    pos += 4;
    
    /* NOP padding */
    buf[pos++] = 1;
    
    /* Window Scale = 10 */
    buf[pos++] = 3;
    buf[pos++] = 3;
    buf[pos++] = 10;
    
    /* End and padding to 4-byte boundary */
    buf[pos++] = 0;
    while (pos % 4) buf[pos++] = 0;
    
    return pos;
}


/*
 * Send a TCP packet with specified flags.
 */
void send_packet(const char *target, int port, int flags)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket");
        return;
    }
    
    char packet[4096] = {0};
    struct tcphdr *tcp = (struct tcphdr *)packet;
    unsigned char *opts = (unsigned char *)(packet + sizeof(struct tcphdr));
    
    /* Add options for SYN packets */
    int opt_len = 0;
    if (flags & TH_SYN) {
        opt_len = build_options(opts);
    }
    
    /* Destination */
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = inet_addr(target);
    
    /* Get our source IP */
    char src_ip[32];
    get_local_ip(src_ip, target);
    
    /* Fill TCP header */
    tcp->source = htons(40000 + (rand() % 10000));
    tcp->dest = htons(port);
    tcp->seq = htonl(rand());
    tcp->ack_seq = 0;
    tcp->doff = (sizeof(struct tcphdr) + opt_len) / 4;
    tcp->fin = (flags & TH_FIN) ? 1 : 0;
    tcp->syn = (flags & TH_SYN) ? 1 : 0;
    tcp->rst = (flags & TH_RST) ? 1 : 0;
    tcp->psh = (flags & TH_PUSH) ? 1 : 0;
    tcp->ack = (flags & TH_ACK) ? 1 : 0;
    tcp->urg = (flags & TH_URG) ? 1 : 0;
    tcp->window = htons(1024);
    
    /* Calculate checksum */
    struct pseudo_header ph = {0};
    ph.src = inet_addr(src_ip);
    ph.dst = dst.sin_addr.s_addr;
    ph.protocol = IPPROTO_TCP;
    ph.tcp_len = htons(sizeof(struct tcphdr) + opt_len);
    
    char csum_buf[4096];
    memcpy(csum_buf, &ph, sizeof(ph));
    memcpy(csum_buf + sizeof(ph), packet, sizeof(struct tcphdr) + opt_len);
    tcp->check = checksum(csum_buf, sizeof(ph) + sizeof(struct tcphdr) + opt_len);
    
    /* Send it */
    sendto(sock, packet, sizeof(struct tcphdr) + opt_len, 0,
           (struct sockaddr *)&dst, sizeof(dst));
    
    close(sock);
}


/*
 * Wait for a TCP response from the target.
 * Returns NULL on timeout.
 */
struct tcphdr *wait_for_response(const char *target, int timeout, struct iphdr **ip_out)
{
    static char buffer[4096];
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return NULL;
    
    /* Set timeout */
    struct timeval tv = {timeout, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    while (1) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        
        int len = recvfrom(sock, buffer, sizeof(buffer), 0,
                          (struct sockaddr *)&from, &from_len);
        
        if (len < 0) {
            close(sock);
            return NULL;
        }
        
        /* Check if it's from our target */
        if (from.sin_addr.s_addr == inet_addr(target)) {
            struct iphdr *ip = (struct iphdr *)buffer;
            struct tcphdr *tcp = (struct tcphdr *)(buffer + ip->ihl * 4);
            
            if (ip_out) *ip_out = ip;
            close(sock);
            return tcp;
        }
    }
}


/*
 * Quick check if a port is open.
 * Sends SYN, looks for SYN-ACK.
 */
int is_port_open(const char *target, int port)
{
    pid_t pid = fork();
    
    if (pid == 0) {
        /* Child: send the packet after a small delay */
        usleep(50000);
        send_packet(target, port, TH_SYN);
        exit(0);
    }
    
    /* Parent: wait for response */
    struct tcphdr *resp = wait_for_response(target, 1, NULL);
    wait(NULL);
    
    return (resp && resp->syn && resp->ack);
}


/*
 * Run all fingerprinting probes.
 * This sends several different packets and records the responses.
 */
void fingerprint_target(const char *target, int port, ScanResult *result)
{
    struct iphdr *ip = NULL;
    struct tcphdr *tcp = NULL;
    pid_t pid;
    
    memset(result, 0, sizeof(ScanResult));
    
    /*
     * Probe 1: Normal SYN packet
     * This is our main probe - we learn the most from this.
     */
    printf("   Sending SYN probe... ");
    fflush(stdout);
    
    pid = fork();
    if (pid == 0) {
        usleep(100000);
        send_packet(target, port, TH_SYN);
        exit(0);
    }
    
    tcp = wait_for_response(target, 2, &ip);
    wait(NULL);
    
    if (tcp && ip) {
        result->got_response = 1;
        result->ttl = ip->ttl;
        result->window = ntohs(tcp->window);
        result->df_flag = (ntohs(ip->frag_off) & 0x4000) ? 'Y' : 'N';
        
        /* Get flags as string */
        result->flags[0] = '\0';
        if (tcp->syn) strcat(result->flags, "S");
        if (tcp->ack) strcat(result->flags, "A");
        if (tcp->rst) strcat(result->flags, "R");
        
        read_tcp_options(tcp, result->options, &result->opts);
        
        printf("got response (TTL=%d, Win=%d)\n", result->ttl, result->window);
    } else {
        printf("timeout\n");
    }
    
    /*
     * Probe 2: NULL packet (no flags)
     * Some systems respond, others don't.
     */
    printf("   Sending NULL probe... ");
    fflush(stdout);
    
    pid = fork();
    if (pid == 0) {
        usleep(100000);
        send_packet(target, port, 0);
        exit(0);
    }
    
    result->t2_responded = (wait_for_response(target, 2, NULL) != NULL);
    wait(NULL);
    printf("%s\n", result->t2_responded ? "response" : "no response");
    
    /*
     * Probe 3: Weird flags (SYN+FIN+PSH+URG)
     * Windows typically ignores this, Linux may respond.
     */
    printf("   Sending XMAS probe... ");
    fflush(stdout);
    
    pid = fork();
    if (pid == 0) {
        usleep(100000);
        send_packet(target, port, TH_SYN | TH_FIN | TH_PUSH | TH_URG);
        exit(0);
    }
    
    result->t3_responded = (wait_for_response(target, 2, NULL) != NULL);
    wait(NULL);
    printf("%s\n", result->t3_responded ? "response" : "no response");
    
    /*
     * Probe 4: ACK packet
     * Used to check firewall behavior.
     */
    printf("   Sending ACK probe... ");
    fflush(stdout);
    
    pid = fork();
    if (pid == 0) {
        usleep(100000);
        send_packet(target, port, TH_ACK);
        exit(0);
    }
    
    result->t4_responded = (wait_for_response(target, 2, NULL) != NULL);
    wait(NULL);
    printf("%s\n", result->t4_responded ? "response" : "no response");
}
