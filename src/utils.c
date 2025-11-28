/*
 * utils.c - Helper functions
 * 
 * Basic utilities for parsing and OS detection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../include/defs.h"
#include "../include/utils.h"


/*
 * Standard internet checksum.
 * Used for TCP/IP packet validation.
 */
unsigned short checksum(void *data, int len)
{
    unsigned short *buf = data;
    unsigned int sum = 0;
    
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    if (len == 1)
        sum += *(unsigned char *)buf;
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return ~sum;
}


/*
 * Figure out our local IP address.
 * We do this by creating a dummy connection to the target.
 */
void get_local_ip(char *buffer, const char *target)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(target);
    addr.sin_port = htons(53);
    
    /* This doesn't actually send anything, just sets up routing */
    connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    getsockname(sock, (struct sockaddr *)&local, &len);
    
    strcpy(buffer, inet_ntoa(local.sin_addr));
    close(sock);
}


/*
 * Parse a hex value from a line like "W=FFFF".
 * Returns -1 if the key isn't found.
 */
int parse_hex(const char *line, const char *key)
{
    const char *p = strstr(line, key);
    if (!p) return -1;
    
    p += strlen(key);
    return (int)strtol(p, NULL, 16);
}


/*
 * Extract a string value that ends at '%' or ')'.
 * For example, from "O=M5B4%..." extract "M5B4".
 */
void parse_string(const char *line, const char *key, char *dest, int max)
{
    dest[0] = '\0';
    
    const char *p = strstr(line, key);
    if (!p) return;
    
    p += strlen(key);
    
    int i = 0;
    while (*p && *p != '%' && *p != ')' && i < max - 1) {
        dest[i++] = *p++;
    }
    dest[i] = '\0';
}


/*
 * Parse a range like "T=3B-45" into min and max values.
 * If it's a single value, both min and max get the same number.
 */
void parse_range(const char *line, const char *key, int *min, int *max)
{
    *min = *max = -1;
    
    const char *p = strstr(line, key);
    if (!p) return;
    
    p += strlen(key);
    
    /* Look for a dash that indicates a range */
    const char *dash = strchr(p, '-');
    const char *end = strpbrk(p, "%)");
    
    if (dash && (!end || dash < end)) {
        /* It's a range like "3B-45" */
        *min = (int)strtol(p, NULL, 16);
        *max = (int)strtol(dash + 1, NULL, 16);
    } else {
        /* Just a single value */
        int val = (int)strtol(p, NULL, 16);
        *min = *max = val;
    }
}


/*
 * Parse an nmap-style options string like "M5B4NW8ST11".
 * 
 * M = MSS (followed by hex value)
 * N = NOP (padding)
 * W = Window scale (followed by value)
 * S = SACK permitted
 * T = Timestamp
 */
void parse_options(const char *str, TCPOpts *opts)
{
    memset(opts, 0, sizeof(TCPOpts));
    opts->mss = -1;
    opts->window_scale = -1;
    
    if (!str || !*str) return;
    
    const char *p = str;
    int idx = 0;
    
    while (*p && idx < 31) {
        char c = *p;
        
        if (c == 'M') {
            p++;
            opts->mss = (int)strtol(p, (char **)&p, 16);
            opts->pattern[idx++] = 'M';
        }
        else if (c == 'N') {
            opts->pattern[idx++] = 'N';
            p++;
        }
        else if (c == 'W') {
            p++;
            opts->window_scale = (int)strtol(p, (char **)&p, 16);
            opts->pattern[idx++] = 'W';
        }
        else if (c == 'S') {
            opts->has_sack = 1;
            opts->pattern[idx++] = 'S';
            p++;
        }
        else if (c == 'T') {
            opts->has_timestamp = 1;
            opts->pattern[idx++] = 'T';
            p++;
            /* Skip any digits after T */
            while (isxdigit(*p)) p++;
        }
        else {
            p++;
        }
    }
    
    opts->pattern[idx] = '\0';
}


/*
 * Guess the OS type based on TTL value.
 * 
 * Windows typically uses 128
 * Linux/Android typically uses 64
 */
OSType guess_os_from_ttl(int ttl)
{
    if (ttl >= 110 && ttl <= 140) 
        return OS_WINDOWS;
    
    if (ttl >= 50 && ttl <= 70) 
        return OS_LINUX;
    
    return OS_OTHER;
}


/*
 * Guess OS type from the fingerprint name.
 */
OSType guess_os_from_name(const char *name)
{
    if (!name) return OS_UNKNOWN;
    
    /* Make a lowercase copy for easier matching */
    char lower[256];
    int i;
    for (i = 0; name[i] && i < 255; i++) {
        lower[i] = tolower((unsigned char)name[i]);
    }
    lower[i] = '\0';
    
    /* Check for Windows */
    if (strstr(lower, "windows"))
        return OS_WINDOWS;
    
    /* Check for Linux variants */
    if (strstr(lower, "linux") ||
        strstr(lower, "android") ||
        strstr(lower, "ubuntu"))
        return OS_LINUX;
    
    return OS_OTHER;
}


/*
 * Get a human-readable name for the OS type.
 */
const char *os_type_name(OSType type)
{
    switch (type) {
        case OS_WINDOWS: return "Windows";
        case OS_LINUX:   return "Linux/Android";
        case OS_OTHER:   return "Other";
        default:         return "Unknown";
    }
}