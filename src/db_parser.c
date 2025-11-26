#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "db_parser.h"

// Helper function to create a new node
SignatureNode* create_node(const char *name) {
    SignatureNode *node = malloc(sizeof(SignatureNode));
    if (!node) return NULL;

    node->data = malloc(sizeof(OSSignature));
    // Duplicate the name string into the struct
    node->data->os_name = strdup(name); 
    node->next = NULL;
    return node;
}

SignatureNode* parse_nmap_db(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) {
        printf("Error: Could not open database file at %s\n", filepath);
        return NULL;
    }

    SignatureNode *head = NULL;
    SignatureNode *current = NULL;
    char line[MAX_LINE_LEN];
    int count = 0;

    printf("Loading database...\n");

    // Read the file line by line
    while (fgets(line, sizeof(line), file)) {
        
        // Check if the line starts with "Fingerprint"
        // The format is: "Fingerprint <OS Name>"
        if (strncmp(line, "Fingerprint", 11) == 0) {
            
            // Skip the word "Fingerprint " (12 chars including space)
            // and remove the newline character at the end
            char *os_name = line + 12;
            os_name[strcspn(os_name, "\n")] = 0; // Remove \n

            SignatureNode *new_node = create_node(os_name);
            
            // Add to the linked list
            if (head == NULL) {
                head = new_node;
                current = head;
            } else {
                current->next = new_node;
                current = new_node;
            }
            count++;
        }
    }

    fclose(file);
    printf("Successfully loaded %d OS signatures.\n", count);
    return head;
}

void free_db(SignatureNode *head) {
    SignatureNode *tmp;
    while (head != NULL) {
        tmp = head;
        head = head->next;
        // Free the string inside the struct
        free(tmp->data->os_name);
        // Free the struct itself
        free(tmp->data);
        // Free the node
        free(tmp);
    }
}