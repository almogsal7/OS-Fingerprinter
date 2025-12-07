/*
 * network.h - Network scanning function declarations
 */

#ifndef NETWORK_H
#define NETWORK_H

#include "defs.h"

/* Check if a port is open */
int is_port_open(const char *target, int port);

/* Send a TCP packet with specific flags */
void send_packet(const char *target, int port, int flags);

/* Wait for a response from target */
struct tcphdr *wait_for_response(const char *target, int timeout, struct iphdr **ip_out);

/* Read TCP options from a packet */
void read_tcp_options(struct tcphdr *tcp, char *out_str, TCPOpts *opts);

/* Run fingerprinting probes (T1, T2, T3) */
void fingerprint_target(const char *target, int port, ScanResult *result);

#endif