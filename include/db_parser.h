/*
 * database.h - Load and manage the fingerprint database
 */

#ifndef DATABASE_H
#define DATABASE_H

#include "defs.h"

/* Load fingerprints from nmap database file */
FingerprintNode *load_database(const char *path);

/* Free all memory */
void free_database(FingerprintNode *head);

#endif