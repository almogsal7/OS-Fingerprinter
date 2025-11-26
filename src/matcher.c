
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h> 
#include <math.h>
#include "matcher.h"

void find_best_match(SignatureNode *db, struct tcphdr *tcp, struct iphdr *ip) {
    SignatureNode *curr = db;
    SignatureNode *best_match = NULL;
    int max_score = 0;

    int pkt_ttl = ip->ttl;
    int pkt_win = ntohs(tcp->window);

    printf("\n   [DB Analysis] Packet TTL: %d | Window: %d\n", pkt_ttl, pkt_win);

    while (curr) {
        int score = 0;
        
        // TTL Check (Allow +/- 5 hops)
        if (curr->data->ttl != -1) {
            int diff = abs(pkt_ttl - curr->data->ttl);
            if (diff <= 5) score += 10;
        }

        // Window Check (Exact match gets huge bonus)
        if (curr->data->window_size != -1) {
            if (curr->data->window_size == pkt_win) {
                score += 50;
            }
        }

        if (score > max_score) {
            max_score = score;
            best_match = curr;
        }
        curr = curr->next;
    }

    if (best_match && max_score >= 10) { 
        printf("   [DB Match] Best database match: \033[1;36m%s\033[0m\n", best_match->data->os_name);
        printf("   (Match Score: %d)\n", max_score);
    } else {
        printf("   [DB Match] No specific signature matched in Nmap DB.\n");
    }
}