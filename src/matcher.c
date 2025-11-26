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

    // --- DB SCANNING ---
    while (curr) {
        int score = 0;
        
        // CHECK T1 (SYN) matches
        if (curr->data->t1_resp == 'Y' && results->t1_open) {
            // TTL Logic
            if (curr->data->t1_ttl != -1) {
                int diff = curr->data->t1_ttl - results->t1_ttl;
                if (diff >= 0 && diff <= 30) score += 30; // Distance match
                else if (abs(diff) <= 2) score += 30;     // Local match
            }
            // Window Logic
            if (curr->data->t1_window != -1) {
                if (curr->data->t1_window == results->t1_window) score += 50;
            }
        }
        
        // CHECK T3/T7
        int db_t3 = (curr->data->t3_resp == 'Y');
        if (db_t3 == results->t3_open) score += 10;

        if (score > max_score) {
            max_score = score;
            best_match = curr;
        }
        curr = curr->next;
    }

    printf("\n==============================================\n");
    
    // --- DECISION LOGIC ---

    // CASE 1: Strong Database Match (Open Port)
    if (best_match && max_score >= 40) { 
        printf("RESULT: \033[1;32m%s\033[0m\n", best_match->data->os_name);
        printf("Confidence Score: %d/100 (Database Match)\n", max_score);
    } 
    // CASE 2: No DB match, but strong TTL fingerprint (Closed Port / Firewall)
    else {
        // Here we override the score because TTL is reliable
        const char *os_guess = NULL;
        int ttl_confidence = 0;

        // Windows Check (Starts at 128)
        if (results->t1_ttl > 64 && results->t1_ttl <= 128) {
            os_guess = "Windows (XP/7/10/11/Server)";
            ttl_confidence = 90; // High confidence based on TTL
        } 
        // Linux/Unix Check (Starts at 64)
        else if (results->t1_ttl <= 64) {
            os_guess = "Linux / Android / iOS / macOS";
            ttl_confidence = 85; 
        }
        // Network Gear (Cisco etc, often 255)
        else if (results->t1_ttl > 128) {
             os_guess = "Cisco / Solaris / Network Device";
             ttl_confidence = 70;
        }

        if (os_guess) {
            // Print GREEN because we are confident
            printf("RESULT: \033[1;32m%s\033[0m\n", os_guess);
            printf("Confidence Score: %d/100 (Heuristic TTL Analysis)\n", ttl_confidence);
            printf("Reason: Database match low (Score: %d) likely due to closed ports,\n", max_score);
            printf("        but TTL=%d provides a strong fingerprint.\n", results->t1_ttl);
        } else {
            printf("RESULT: Unknown OS\n");
        }
    }
    printf("==============================================\n");
}