/*
 * defs.h - Core definitions for OS fingerprinting
 * 
 * This file contains all the basic structures we need to identify
 * operating systems based on their TCP/IP stack behavior.
 * 
 * We focus on: Windows, Linux, and Android TV devices.
 */

#ifndef DEFS_H
#define DEFS_H

#include <netinet/ip.h>
#include <netinet/tcp.h>

/* How many results to show */
#define TOP_MATCHES 3

/* Buffer sizes */
#define MAX_LINE 4096
#define MAX_OPTIONS 128

/* TCP flags - just in case they're not defined */
#ifndef TH_FIN
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#endif

/*
 * The three OS families we care about.
 * Each has a distinctive TTL value that helps identify it.
 */
typedef enum {
    OS_UNKNOWN = 0,
    OS_WINDOWS,     /* TTL around 128 */
    OS_LINUX,       /* TTL around 64 - includes Android */
    OS_OTHER        /* Everything else */
} OSType;

/*
 * TCP options tell us a lot about the OS.
 * Different systems use different combinations and values.
 */
typedef struct {
    int mss;            /* Maximum Segment Size (usually 1460) */
    int window_scale;   /* Window scaling factor */
    int has_sack;       /* Does it support Selective ACK? */
    int has_timestamp;  /* Does it use timestamps? */
    char pattern[32];   /* The order of options like "MSTNW" */
} TCPOpts;

/*
 * One entry from the nmap fingerprint database.
 * Contains the expected values for a specific OS version.
 */
typedef struct {
    char *name;         /* OS name like "Microsoft Windows 10" */
    
    /* TTL info */
    int ttl_min;
    int ttl_max;
    int ttl_guess;      /* Most likely TTL value */
    
    /* Window size */
    int window;
    int window_values[6]; /* W1-W6 from WIN section */
    
    /* Expected TCP options */
    char *options;
    TCPOpts opts;
    
    /* Behavioral tests */
    char df_flag;       /* Don't Fragment: Y or N */
    char t3_responds;   /* Does it respond to weird packets? */
    char t2_responds;   /* Does it respond to empty packets? */
    
} Fingerprint;

/* Linked list of fingerprints */
typedef struct FingerprintNode {
    Fingerprint *fp;
    struct FingerprintNode *next;
} FingerprintNode;

/*
 * What we actually observed when scanning the target.
 * We compare this against the database to find matches.
 */
typedef struct {
    int got_response;   /* Did the target respond at all? */
    
    /* From the SYN-ACK response */
    int ttl;
    int window;
    char df_flag;
    char flags[16];
    char options[MAX_OPTIONS];
    TCPOpts opts;
    
    /* Behavioral probe results */
    int t2_responded;   /* NULL packet probe */
    int t3_responded;   /* Weird flags probe */
    int t4_responded;   /* ACK probe */
    
} ScanResult;

#endif