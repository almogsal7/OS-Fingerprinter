/*
 * network.h - Network scanning functions
 * 
 * These functions send specially crafted packets and analyze responses.
 */

#ifndef NETWORK_H
#define NETWORK_H

#include "defs.h"

/* Send a TCP packet with specific flags */
void send_packet(const char *target, int port, int flags);

/* Wait for a response from target */
struct tcphdr *wait_for_response(const char *target, int timeout, struct iphdr **ip_out);

/* Check if a port is open */
int is_port_open(const char *target, int port);

/* Run all fingerprinting probes and fill in results */
void fingerprint_target(const char *target, int port, ScanResult *result);

/* Parse TCP options from a received packet */
void read_tcp_options(struct tcphdr *tcp, char *out_str, TCPOpts *opts);

#endif