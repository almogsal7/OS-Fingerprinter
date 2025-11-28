/*
 * database.c - Load the nmap fingerprint database
 * 
 * The database contains thousands of OS fingerprints.
 * Each fingerprint has expected values for TTL, window size,
 * TCP options, and behavioral responses.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/defs.h"
#include "../include/utils.h"


/*
 * Parse a single test line from the database.
 * These look like: T1(R=Y%DF=Y%T=80%W=FFFF%O=M5B4...)
 */
static void parse_test(const char *line, Fingerprint *fp)
{
    char tmp[MAX_OPTIONS];
    
    /* T1 = SYN probe (the most important one) */
    if (strncmp(line, "T1(", 3) == 0) {
        parse_range(line, "T=", &fp->ttl_min, &fp->ttl_max);
        
        int tg = parse_hex(line, "TG=");
        if (tg > 0) fp->ttl_guess = tg;
        
        fp->window = parse_hex(line, "W=");
        
        parse_string(line, "DF=", tmp, sizeof(tmp));
        if (tmp[0]) fp->df_flag = tmp[0];
        
        parse_string(line, "O=", tmp, sizeof(tmp));
        if (tmp[0]) {
            fp->options = strdup(tmp);
            parse_options(tmp, &fp->opts);
        }
    }
    /* T2 = NULL probe (no flags set) */
    else if (strncmp(line, "T2(", 3) == 0) {
        parse_string(line, "R=", tmp, sizeof(tmp));
        if (tmp[0]) fp->t2_responds = tmp[0];
    }
    /* T3 = Weird flags probe */
    else if (strncmp(line, "T3(", 3) == 0) {
        parse_string(line, "R=", tmp, sizeof(tmp));
        if (tmp[0]) fp->t3_responds = tmp[0];
    }
    /* WIN = Window sizes for different probes */
    else if (strncmp(line, "WIN(", 4) == 0) {
        fp->window_values[0] = parse_hex(line, "W1=");
        fp->window_values[1] = parse_hex(line, "W2=");
        fp->window_values[2] = parse_hex(line, "W3=");
        fp->window_values[3] = parse_hex(line, "W4=");
        fp->window_values[4] = parse_hex(line, "W5=");
        fp->window_values[5] = parse_hex(line, "W6=");
    }
}


/*
 * Load the nmap fingerprint database.
 * Returns a linked list of fingerprints.
 */
FingerprintNode *load_database(const char *path)
{
    FILE *file = fopen(path, "r");
    if (!file) {
        printf("Error: Can't open database at %s\n", path);
        return NULL;
    }
    
    FingerprintNode *head = NULL;
    FingerprintNode *tail = NULL;
    char line[MAX_LINE];
    int count = 0;
    
    printf("Loading fingerprint database... ");
    fflush(stdout);
    
    while (fgets(line, sizeof(line), file)) {
        /* Skip comments and blank lines */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        
        /* New fingerprint entry */
        if (strncmp(line, "Fingerprint ", 12) == 0) {
            FingerprintNode *node = malloc(sizeof(FingerprintNode));
            node->fp = calloc(1, sizeof(Fingerprint));
            node->next = NULL;
            
            /* Extract the OS name */
            char *name = line + 12;
            name[strcspn(name, "\n\r")] = '\0';
            node->fp->name = strdup(name);
            
            /* Add to list */
            if (!head) {
                head = tail = node;
            } else {
                tail->next = node;
                tail = node;
            }
            count++;
        }
        /* Parse test data for current fingerprint */
        else if (tail && (
            strncmp(line, "T1(", 3) == 0 ||
            strncmp(line, "T2(", 3) == 0 ||
            strncmp(line, "T3(", 3) == 0 ||
            strncmp(line, "WIN(", 4) == 0))
        {
            parse_test(line, tail->fp);
        }
    }
    
    printf("done (%d entries)\n", count);
    fclose(file);
    
    return head;
}


/*
 * Free all database memory.
 */
void free_database(FingerprintNode *head)
{
    while (head) {
        FingerprintNode *next = head->next;
        
        if (head->fp) {
            free(head->fp->name);
            free(head->fp->options);
            free(head->fp);
        }
        free(head);
        
        head = next;
    }
}