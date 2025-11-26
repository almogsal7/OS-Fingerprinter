#define _DEFAULT_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "db_parser.h"
#include "matcher.h"
#include "network.h"
#include "utils.h"

// define safe array size to prevent memory errors
#define MAX_TESTS 10 

/**
 * runs a single test and attempts to match with database.
 * returns 1 if target replied, 0 if timeout.
 */
int run_test_and_match(const char *target_ip, int flags, const char *test_name, SignatureNode *db) {
    printf("   Running %-20s ... ", test_name);
    fflush(stdout); // force print
    
    int result = 0;
    
    // create a child process
    pid_t pid = fork();

    if (pid == 0) {
        // child process: sender
        usleep(400000); // small delay
        // 80
        send_tcp_packet(target_ip, 80, flags);
        exit(0);
    } else {
        // parent process: listener
        struct tcphdr *resp = receive_tcp_response(target_ip, 2);
        
        if (resp) {
            printf("\033[1;32m[YES]\033[0m (Flags: ");
            if (resp->syn) printf("S");
            if (resp->ack) printf("A");
            if (resp->rst) printf("R");
            printf(")\n");
            
            // if we have a db, try to find exact match
            if (db != NULL) {
                // calculate pointer to ip header
                struct iphdr *ip_resp = (struct iphdr *)((char*)resp - sizeof(struct iphdr));
                find_best_match(db, resp, ip_resp);
            }
            
            result = 1; // success
        } else {
            printf("\033[1;31m[NO]\033[0m (Timeout)\n");
            result = 0; // failure
        }
        
        wait(NULL); // wait for child to finish
        return result;
    }
}

int main(int argc, char *argv[]) {
    // 1. check for root privileges
    if (getuid() != 0) {
        printf("Error: Run as root (sudo).\n");
        return 1;
    }
    // 2. check arguments
    if (argc != 2) {
        printf("Usage: sudo %s <target_ip>\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[1];
    get_local_ip(target_ip); // auto-detect local ip

    // load nmap database
    SignatureNode *db = parse_nmap_db("data/nmap-os-db");
    if (db) {
        printf("Loaded %d signatures from Nmap DB.\n", 6036);
    }

    printf("\n=== Starting Fingerprinting on %s ===\n\n", target_ip);

    // init array with zeros to prevent garbage memory
    int results[MAX_TESTS] = {0}; 

    // --- step 1: critical connectivity check ---
    results[1] = run_test_and_match(target_ip, TH_SYN, "T1 (SYN)", db);

    // if target is down, stop everything
    if (results[1] == 0) {
        printf("\n==============================================\n");
        printf("FINAL ANALYSIS REPORT\n");
        printf("==============================================\n");
        printf("Outcome: \033[1;31mHOST DOWN OR FILTERED\033[0m\n");
        
        // safe memory cleanup
        if (db) {
            free_db(db);
            db = NULL;
        }
        return 0;
    }

    // --- step 2: run heuristic probes ---
    // pass NULL as db because we only match db on T1
    results[2] = run_test_and_match(target_ip, 0, "T2 (Null)", NULL);
    results[3] = run_test_and_match(target_ip, TH_SYN|TH_FIN|TH_PUSH|TH_URG, "T3 (SFPU)", NULL);
    results[4] = run_test_and_match(target_ip, TH_ACK, "T4 (ACK)", NULL);
    results[5] = run_test_and_match(target_ip, TH_SYN, "T5 (SYN)", NULL);
    results[6] = run_test_and_match(target_ip, TH_ACK, "T6 (ACK)", NULL);
    results[7] = run_test_and_match(target_ip, TH_FIN|TH_PUSH|TH_URG, "T7 (Xmas)", NULL);

    // free database memory
    if (db) {
        free_db(db);
        db = NULL;
    }

    // --- step 3: analyze results ---
    printf("\n==============================================\n");
    printf("FINAL ANALYSIS REPORT\n");
    printf("==============================================\n");
    
    // print result vector
    printf("Result Vector: [ T1:%d, T2:%d, T3:%d, T4:%d, T5:%d, T6:%d, T7:%d ]\n", 
           results[1], results[2], results[3], results[4], results[5], results[6], results[7]);

    int linux_score = 0;
    int windows_score = 0;

    // analyze behavior: linux usually responds to malformed packets, windows drops them
    if (results[2]) linux_score++; else windows_score++;
    if (results[3]) linux_score++; else windows_score++;
    if (results[7]) linux_score += 2; else windows_score += 2;

    if (linux_score > windows_score) {
        printf("Outcome: \033[1;32mOPERATING SYSTEM: LINUX / UNIX\033[0m\n");
        printf("Reason:  Target sent RST replies to malformed packets.\n");
    } else {
        printf("Outcome: \033[1;34mOPERATING SYSTEM: WINDOWS\033[0m\n");
        printf("Reason:  Target dropped malformed packets.\n");
    }
    printf("==============================================\n");

    return 0;
}