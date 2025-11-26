#ifndef DB_PARSER_H
#define DB_PARSER_H

#include <stdio.h>

// Max length for a line in the DB file
#define MAX_LINE_LEN 4096

// Structure to hold a single OS fingerprint
typedef struct {
    char *os_name;
    int ttl;         // Time To Live (e.g., 64, 128)
    int window_size; // TCP Window Size
} OSSignature;

// A linked list node to hold all signatures in memory
typedef struct SignatureNode {
    OSSignature *data;
    struct SignatureNode *next;
} SignatureNode;

/**
 * Loads the Nmap database from a file.
 * Returns a pointer to the head of the linked list.
 */
SignatureNode* parse_nmap_db(const char *filepath);
void free_db(SignatureNode *head);

/**
 * Frees all memory allocated for the database list.
 */
void free_db(SignatureNode *head);

#endif