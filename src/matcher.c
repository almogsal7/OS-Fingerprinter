
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h> 
#include <math.h>
#include <string.h> // for strstr
#include <arpa/inet.h>
#include "matcher.h"

void find_best_match(SignatureNode *db, HostResults *results) {
    SignatureNode *curr = db;
    SignatureNode *best_match = NULL;
    int max_score = 0;

    printf("\n[analysis] comparing results with database...\n");
    printf("host data -> t1_win:%d, t1_ttl:%d, t3_reply:%d, t7_reply:%d\n", 
           results->t1_window, results->t1_ttl, results->t3_open, results->t7_open);

    // --- Heuristic Check based on TTL only (Backup Plan) ---
    // If exact match fails, we use this generic fallback
    const char *generic_guess = "Unknown";
    if (results->t1_ttl > 32 && results->t1_ttl <= 64) {
        generic_guess = "Linux / Unix / Android / macOS";
    } else if (results->t1_ttl > 64 && results->t1_ttl <= 128) {
        generic_guess = "Windows (Modern Versions)";
    } else if (results->t1_ttl > 128) {
        generic_guess = "Cisco / Solaris";
    }

    while (curr) {
        int score = 0;
        
        // --- check t1 (syn) ---
        // if db says we should get a reply ('Y') and we did (t1_open=1)
        if (curr->data->t1_resp == 'Y' && results->t1_open) {
            
            // 1. TTL Check (Fuzzy Logic)
            if (curr->data->t1_ttl != -1) {
                int diff = abs(results->t1_ttl - curr->data->t1_ttl);
                // huge bonus for close TTL match
                if (diff <= 5) score += 30; 
            }

            // 2. Window Check
            // If we got RST (Window 0), we skip window check penalty
            if (results->t1_window != 0 && curr->data->t1_window != -1) {
                if (curr->data->t1_window == results->t1_window) {
                    score += 40;
                }
            } else if (results->t1_window == 0) {
                 // If window is 0 (RST), give partial points just for being alive
                 score += 10;
            }
        }

        // --- check t3 & t7 behavior ---
        int db_t3 = (curr->data->t3_resp == 'Y');
        int db_t7 = (curr->data->t7_resp == 'Y');

        if (db_t3 == results->t3_open) score += 10;
        if (db_t7 == results->t7_open) score += 10;

        if (score > max_score) {
            max_score = score;
            best_match = curr;
        }
        curr = curr->next;
    }

    printf("\n==============================================\n");
    if (best_match && max_score >= 40) { 
        printf("RESULT: \033[1;32m%s\033[0m\n", best_match->data->os_name);
        printf("Confidence Score: %d\n", max_score);
    } else {
        // Fallback to TTL heuristic if DB match is weak
        printf("RESULT: \033[1;33m%s (Based on TTL)\033[0m\n", generic_guess);
        printf("Note: Precise DB match failed (Score: %d), using generic TTL fingerprint.\n", max_score);
    }
    printf("==============================================\n");
}