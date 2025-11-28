/*
 * OS Fingerprinter - Main Program
 * 
 * This tool identifies the operating system of a remote host
 * by analyzing how it responds to various TCP packets.
 * 
 * It focuses on detecting Windows, Linux, and Android devices.
 * 
 * Usage: sudo ./os_fingerprint <target_ip> [port]
 * 
 * How it works:
 * 1. Find an open port on the target (or use the one specified)
 * 2. Send various TCP probes and record the responses
 * 3. Compare against a database of known OS fingerprints
 * 4. Report the best matches
 */

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>

#include "../include/defs.h"
#include "../include/utils.h"
#include "../include/network.h"
#include "../include/db_parser.h"
#include "../include/matcher.h"


/* Common ports to scan */
static int common_ports[] = {22, 80, 443, 445, 135, 8080, 3389, 8443};
static int num_ports = 8;


/*
 * Try to find an open port on the target.
 * Returns the port number, or -1 if none found.
 */
static int find_open_port(const char *target)
{
    printf("Looking for an open port...\n");
    
    for (int i = 0; i < num_ports; i++) {
        int port = common_ports[i];
        printf("   Port %d: ", port);
        fflush(stdout);
        
        if (is_port_open(target, port)) {
            printf("open\n");
            return port;
        }
        printf("closed\n");
    }
    
    return -1;
}


/*
 * Print usage information.
 */
static void usage(const char *prog)
{
    printf("\n");
    printf("OS Fingerprinter - Identify remote operating systems\n");
    printf("\n");
    printf("Usage: sudo %s <target_ip> [port]\n", prog);
    printf("\n");
    printf("Examples:\n");
    printf("  sudo %s 192.168.1.100\n", prog);
    printf("  sudo %s 192.168.1.100 22\n", prog);
    printf("\n");
}


int main(int argc, char *argv[])
{
    /* Must run as root for raw sockets */
    if (getuid() != 0) {
        printf("Error: This tool requires root privileges.\n");
        printf("Please run with: sudo %s ...\n", argv[0]);
        return 1;
    }
    
    /* Need at least a target IP */
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    
    char *target = argv[1];
    int port = (argc > 2) ? atoi(argv[2]) : 0;
    
    /* Seed random number generator */
    srand(time(NULL));
    
    /* Print banner */
    printf("\n");
    printf("================================================\n");
    printf("  OS Fingerprinter v1.0\n");
    printf("  Target: %s\n", target);
    printf("================================================\n");
    printf("\n");
    
    /* Find an open port if not specified */
    if (port <= 0) {
        port = find_open_port(target);
        
        if (port < 0) {
            printf("\nNo open ports found.\n");
            printf("Trying port 80 anyway (limited results)...\n");
            port = 80;
        }
    }
    
    printf("\nUsing port %d for fingerprinting.\n\n", port);
    
    /* Load the fingerprint database */
    FingerprintNode *db = load_database("data/nmap-os-db");
    if (!db) {
        /* Try alternate location */
        db = load_database("/usr/share/nmap/nmap-os-db");
    }
    if (!db) {
        printf("Error: Could not load fingerprint database.\n");
        printf("Make sure nmap-os-db is in ./data/ or /usr/share/nmap/\n");
        return 1;
    }
    
    /* Run the fingerprinting probes */
    printf("Running fingerprint probes...\n");
    
    ScanResult result;
    fingerprint_target(target, port, &result);
    
    /* Analyze and show results */
    if (result.got_response) {
        find_matches(db, &result);
    } else {
        printf("\nNo response from target.\n");
        printf("The host may be:\n");
        printf("  - Behind a firewall\n");
        printf("  - Offline\n");
        printf("  - Using a different port\n");
    }
    
    /* Cleanup */
    free_database(db);
    
    printf("\n");
    return 0;
}