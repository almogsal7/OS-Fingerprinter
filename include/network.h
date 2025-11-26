#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/tcp.h>
#include <netinet/ip.h>

// tcp flags definitions if not defined
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

void send_tcp_packet(const char *target_ip, int port, int flags);
struct tcphdr* receive_tcp_response(const char *target_ip, int timeout_sec, struct iphdr **ip_out);

#endif