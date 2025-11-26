#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "utils.h"

// standard checksum function for tcp/ip headers
unsigned short calculate_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;

    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// this function finds the real local ip address used to reach the target.
// it connects a dummy udp socket to find the routing path.
void get_local_ip(char *buffer, const char *target_ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket error");
        strcpy(buffer, "127.0.0.1"); // fallback
        return;
    }

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(target_ip);
    serv.sin_port = htons(53); // dns port (just for testing route)

    // try to connect (doesn't send packets, just checks routing table)
    if (connect(sock, (const struct sockaddr*)&serv, sizeof(serv)) < 0) {
        // if internet is down or target unreachable, fallback to localhost
        strcpy(buffer, "127.0.0.1");
    } else {
        struct sockaddr_in name;
        socklen_t namelen = sizeof(name);
        getsockname(sock, (struct sockaddr*)&name, &namelen);
        strcpy(buffer, inet_ntoa(name.sin_addr));
    }

    close(sock);
}