#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h> // For size_t

/**
 * Calculates the Internet Checksum (standard RFC 1071).
 * Used for IP and TCP headers validation.
 */
unsigned short calculate_checksum(void *b, int len);

/**
 * Gets the source IP address of the interface connecting to the target.
 * (Simplification: For this project, we might hardcode or auto-detect).
 */
char* get_local_ip(const char *target_ip); 

#endif