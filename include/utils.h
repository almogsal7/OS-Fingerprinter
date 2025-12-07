/*
 * utils.h - Helper function declarations
 */

#ifndef UTILS_H
#define UTILS_H

#include "defs.h"

/* Checksum for TCP/IP packets */
unsigned short checksum(void *data, int len);

/* Get our local IP address */
void get_local_ip(char *buffer, const char *target);

/* Parse values from nmap database format */
int parse_hex(const char *line, const char *key);
void parse_string(const char *line, const char *key, char *dest, int max);
void parse_range(const char *line, const char *key, int *min, int *max);
void parse_options(const char *str, TCPOpts *opts);

/* OS detection helpers */
OSType guess_os_from_ttl(int ttl);
OSType guess_os_from_name(const char *name);
const char *os_type_name(OSType type);

#endif