/*
 * match.h - Match scan results against database
 */

#ifndef MATCH_H
#define MATCH_H

#include "defs.h"

/* Find and display the best matching OS fingerprints */
void find_matches(FingerprintNode *db, ScanResult *scan);

#endif