#ifndef DB_PARSER_H
#define DB_PARSER_H

#define MAX_LINE_LEN 2048

// struct to hold expected values from nmap database
typedef struct {
    char *os_name;
    // t1 test expectations
    int t1_ttl;        // expected ttl
    int t1_window;     // expected window size
    char t1_resp;      // 'Y' for yes, 'N' for no
    // t3 test expectations
    char t3_resp;      // 'Y' or 'N'
    // t7 test expectations
    char t7_resp;      // 'Y' or 'N'
} OSSignature;

typedef struct SignatureNode {
    OSSignature *data;
    struct SignatureNode *next;
} SignatureNode;

SignatureNode* parse_nmap_db(const char *filepath);
void free_db(SignatureNode *head);

#endif