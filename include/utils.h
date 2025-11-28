/*
 * utils.h - Helper functions
 */

#ifndef UTILS_H
#define UTILS_H

#include "defs.h"

/* Network helpers */
unsigned short checksum(void *data, int len);
void get_local_ip(char *buffer, const char *target);

/* String parsing helpers for the database */
int parse_hex(const char *line, const char *key);
void parse_string(const char *line, const char *key, char *dest, int max);
void parse_range(const char *line, const char *key, int *min, int *max);

/* Parse TCP options string like "M5B4NW8ST11" */
void parse_options(const char *str, TCPOpts *opts);

/* OS type detection */
OSType guess_os_from_ttl(int ttl);
OSType guess_os_from_name(const char *name);
const char *os_type_name(OSType type);

#endif