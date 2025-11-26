#define _DEFAULT_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "db_parser.h"
#include "matcher.h"
#include "network.h"
#include "utils.h"

// function to run a test and return if we got a packet back
// also captures ip header info if needed
int run_probe(const char *target_ip, int port, int flags, const char *test_name, struct iphdr **ip_out) {
    printf("   probing %-10s ... ", test_name);
    fflush(stdout);
    
    int success = 0;
    pid_t pid = fork();

    if (pid == 0) {
        // child sends packet
        usleep(100000); // slight delay
        send_tcp_packet(target_ip, port, flags);
        exit(0);
    } else {
        // parent listens
        struct tcphdr *resp = receive_tcp_response(target_ip, 2, ip_out);
        if (resp) {
            printf("\033[1;32m[REPLY]\033[0m\n");
            success = 1;
        } else {
            printf("\033[1;31m[TIMEOUT]\033[0m\n");
            success = 0;
        }
        wait(NULL);
    }
    return success;
}

int main(int argc, char *argv[]) {
    if (getuid() != 0) {
        printf("error: run as root (sudo).\n");
        return 1;
    }
    if (argc != 2) {
        printf("usage: sudo %s <target_ip>\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[1];
    char local_ip[32];
    get_local_ip(local_ip, target_ip); 
    
    printf("\n=== OS Fingerprint Tool ===\n");
    printf("Target: %s\n", target_ip);
    printf("Local IP detected: %s\n", local_ip); // verify we are not using 127.0.0.1

    SignatureNode *db = parse_nmap_db("data/nmap-os-db");
    if (!db) return 1;

    HostResults results = {0};
    struct iphdr *ip_header = NULL;

    // --- T1: Standard SYN Packet ---
    // if targeting google (8.8.8.8) port 80 might be filtered.
    // port 53 (dns) or 443 (https) is better for external servers.
    int target_port = 80; 
    
    if (run_probe(target_ip, target_port, TH_SYN, "T1 (SYN)", &ip_header)) {
        results.t1_open = 1;
        if (ip_header) {
            results.t1_ttl = ip_header->ttl;
            // calculate window from tcp header (pointer math needed)
            struct tcphdr *tcp = (struct tcphdr *)((char*)ip_header + (ip_header->ihl * 4));
            results.t1_window = ntohs(tcp->window);
        }
    } else {
        printf("host seems down or filtered. stopping.\n");
        free_db(db);
        return 0;
    }

    // --- T3: Malformed Packet (SYN, FIN, PUSH, URG) ---
    if (run_probe(target_ip, target_port, TH_SYN|TH_FIN|TH_PUSH|TH_URG, "T3 (SFPU)", NULL)) {
        results.t3_open = 1;
    }

    // --- T7: Xmas Packet (FIN, PUSH, URG) ---
    if (run_probe(target_ip, target_port, TH_FIN|TH_PUSH|TH_URG, "T7 (Xmas)", NULL)) {
        results.t7_open = 1;
    }

    // --- Compare All Results ---
    find_best_match(db, &results);

    free_db(db);
    return 0;
}