/*
 * matcher.h - Fingerprint matching function declarations
 */

#ifndef MATCHER_H
#define MATCHER_H

#include "defs.h"

/* Find best matching fingerprints for scan result */
void find_matches(FingerprintNode *db, ScanResult *scan);

#endif