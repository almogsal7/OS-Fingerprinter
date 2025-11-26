#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/tcp.h> // Needed for tcp headers

/**
 * Sends a raw TCP packet with custom flags.
 * target_ip: The IP address to send to.
 * port: The target port.
 * flags: A mix of flags (e.g., TH_SYN | TH_FIN).
 */
void send_tcp_packet(const char *target_ip, int port, int flags);

/**
 * Listens for a response from the target.
 * returns: The TCP header of the reply, or NULL if timed out.
 */
struct tcphdr* receive_tcp_response(const char *target_ip, int timeout_sec);

#endif