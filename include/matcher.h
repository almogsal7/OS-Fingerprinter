#ifndef MATCHER_H
#define MATCHER_H

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include "db_parser.h"

void find_best_match(SignatureNode *db, struct tcphdr *tcp, struct iphdr *ip);

#endif