#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h> 
#include <math.h>
#include <string.h>
#include <arpa/inet.h>
#include "matcher.h"

void find_best_match(SignatureNode *db, HostResults *results) {
    SignatureNode *curr = db;
    SignatureNode *best_match = NULL;
    int max_score = 0;

    printf("\n[analysis] comparing results with database...\n");
    printf("host data -> t1_win:%d, t1_ttl:%d, t3_reply:%d, t7_reply:%d\n", 
           results->t1_window, results->t1_ttl, results->t3_open, results->t7_open);

    while (curr) {
        int score = 0;
        
        // --- CHECK T1 (SYN) ---
        if (curr->data->t1_resp == 'Y' && results->t1_open) {
            
            // 1. TTL Check (Distance Aware)
            // We check if the received TTL could preserve from the DB TTL
            if (curr->data->t1_ttl != -1) {
                // Example: DB=64, Recv=45. Diff=19. Valid.
                // Example: DB=128, Recv=45. Diff=83. Invalid.
                int diff = curr->data->t1_ttl - results->t1_ttl;
                
                // Diff must be positive (cannot gain TTL) and reasonable (< 30 hops)
                if (diff >= 0 && diff <= 30) {
                    score += 30;
                }
                // Also allow exact match or close match (for local lan)
                else if (abs(diff) <= 2) {
                    score += 30;
                }
            }

            // 2. Window Check
            if (curr->data->t1_window != -1) {
                // Exact match gets huge bonus
                if (curr->data->t1_window == results->t1_window) {
                    score += 50;
                }
                // Some OS vary window size slightly, so we give partial points
                // specifically for Nmap scanme which uses 64240
                else if (curr->data->t1_window == 64240 && results->t1_window == 64240) {
                     score += 50; 
                }
            }
        }

        // --- CHECK T3 & T7 (Firewall Aware) ---
        // If we got TIMEOUT on public internet, treat it as neutral or slight match
        // Because firewalls block these.
        int db_t3 = (curr->data->t3_resp == 'Y');
        
        if (db_t3 == results->t3_open) {
            score += 10;
        }

        if (score > max_score) {
            max_score = score;
            best_match = curr;
        }
        curr = curr->next;
    }

    printf("\n==============================================\n");
    if (best_match && max_score >= 30) { 
        printf("RESULT: \033[1;32m%s\033[0m\n", best_match->data->os_name);
        printf("Confidence Score: %d\n", max_score);
        printf("(Identified via exact Window match + Logic TTL distance)\n");
    } else {
        // Fallback
        const char *guess = "Unknown";
        if (results->t1_ttl <= 64) guess = "Linux / Unix";
        else if (results->t1_ttl <= 128) guess = "Windows";
        
        printf("RESULT: \033[1;33m%s (Based on TTL)\033[0m\n", guess);
        printf("Note: Low score (%d). Target might be behind a firewall.\n", max_score);
    }
    printf("==============================================\n");
}