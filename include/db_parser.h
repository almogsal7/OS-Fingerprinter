/*
 * db_parser.h - Database loading function declarations
 */

#ifndef DB_PARSER_H
#define DB_PARSER_H

#include "defs.h"

/* Load fingerprints from nmap database file */
FingerprintNode *load_database(const char *path);

/* Free all database memory */
void free_database(FingerprintNode *head);

#endif