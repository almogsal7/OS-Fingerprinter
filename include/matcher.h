#ifndef MATCHER_H
#define MATCHER_H

#include "db_parser.h"
#include <netinet/tcp.h>
#include <netinet/ip.h>

// struct to hold our test results from the network
typedef struct {
    int t1_open;
    int t1_ttl;
    int t1_window;
    int t3_open; // replied?
    int t7_open; // replied?
} HostResults;

void find_best_match(SignatureNode *db, HostResults *results);

#endif