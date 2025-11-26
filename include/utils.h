#ifndef UTILS_H
#define UTILS_H

unsigned short calculate_checksum(void *b, int len);
void get_local_ip(char *buffer, const char *target_ip);

#endif