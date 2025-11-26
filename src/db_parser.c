#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "db_parser.h"

// helper to find a value inside a nmap test string.
// example: inside "T1(Resp=Y%DF=Y%W=1234)" find "W="
int extract_int_value(char *line, const char *key) {
    char *ptr = strstr(line, key);
    if (ptr) {
        // move pointer after key (e.g., after "W=")
        return (int)strtol(ptr + strlen(key), NULL, 16); 
    }
    return -1; // not found
}

// helper to find response flag (Y or N)
// example: find "Resp=Y"
char extract_resp_flag(char *line) {
    char *ptr = strstr(line, "Resp=");
    if (ptr) {
        return ptr[5]; // the character after "Resp="
    }
    return 'N'; // default
}

SignatureNode* create_node(const char *name) {
    SignatureNode *node = malloc(sizeof(SignatureNode));
    if (!node) return NULL;
    node->data = malloc(sizeof(OSSignature));
    node->data->os_name = strdup(name);
    
    // set defaults
    node->data->t1_ttl = -1;
    node->data->t1_window = -1;
    node->data->t1_resp = 'N';
    node->data->t3_resp = 'N';
    node->data->t7_resp = 'N';
    
    node->next = NULL;
    return node;
}

SignatureNode* parse_nmap_db(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) {
        printf("error: could not open database file at %s\n", filepath);
        return NULL;
    }

    SignatureNode *head = NULL;
    SignatureNode *current = NULL;
    char line[MAX_LINE_LEN];
    int count = 0;

    printf("loading database...\n");

    while (fgets(line, sizeof(line), file)) {
        // found a new fingerprint entry
        if (strncmp(line, "Fingerprint", 11) == 0) {
            char *os_name = line + 12;
            os_name[strcspn(os_name, "\n")] = 0; // remove newline

            SignatureNode *new_node = create_node(os_name);
            if (head == NULL) {
                head = new_node;
                current = head;
            } else {
                current->next = new_node;
                current = new_node;
            }
            count++;
        }
        // if we are currently parsing an entry, look for test details
        else if (current != NULL) {
            if (strncmp(line, "T1(", 3) == 0) {
                current->data->t1_window = extract_int_value(line, "W=");
                current->data->t1_ttl = extract_int_value(line, "TTL=");
                current->data->t1_resp = extract_resp_flag(line);
            }
            else if (strncmp(line, "T3(", 3) == 0) {
                current->data->t3_resp = extract_resp_flag(line);
            }
            else if (strncmp(line, "T7(", 3) == 0) {
                current->data->t7_resp = extract_resp_flag(line);
            }
        }
    }

    fclose(file);
    printf("successfully loaded %d os signatures.\n", count);
    return head;
}

void free_db(SignatureNode *head) {
    SignatureNode *tmp;
    while (head != NULL) {
        tmp = head;
        head = head->next;
        free(tmp->data->os_name);
        free(tmp->data);
        free(tmp);
    }
}