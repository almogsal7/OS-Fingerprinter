/*
 * match.c - Match scan results against fingerprint database
 * 
 * This is where we compare what we observed against known fingerprints.
 * The goal is to find the best matches for Windows, Linux, and Android.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "../include/defs.h"
#include "../include/matcher.h"
#include "../include/utils.h"


/* A match candidate with its score */
typedef struct {
    Fingerprint *fp;
    int score;
} Match;


/*
 * Compare TCP options patterns.
 * Returns a score based on how similar they are.
 */
static int compare_options(TCPOpts *observed, TCPOpts *expected)
{
    int score = 0;
    
    /* Check if the option order matches */
    if (observed->pattern[0] && expected->pattern[0]) {
        if (strcmp(observed->pattern, expected->pattern) == 0) {
            score += 300;  /* Exact match is great */
        } else {
            /* Count matching characters */
            int matches = 0;
            int len = strlen(observed->pattern);
            for (int i = 0; i < len && expected->pattern[i]; i++) {
                if (observed->pattern[i] == expected->pattern[i])
                    matches++;
            }
            if (matches >= len * 0.8)
                score += 150;  /* Pretty close */
        }
    }
    
    /* MSS match */
    if (observed->mss > 0 && expected->mss > 0) {
        if (observed->mss == expected->mss)
            score += 100;
        else if (abs(observed->mss - expected->mss) < 100)
            score += 30;
    }
    
    /* Window scale match */
    if (observed->window_scale >= 0 && expected->window_scale >= 0) {
        if (observed->window_scale == expected->window_scale)
            score += 100;
        else if (abs(observed->window_scale - expected->window_scale) <= 2)
            score += 30;
    }
    
    /* SACK and timestamp */
    if (observed->has_sack == expected->has_sack)
        score += 20;
    if (observed->has_timestamp == expected->has_timestamp)
        score += 20;
    
    return score;
}


/*
 * Calculate how well a fingerprint matches our scan result.
 * Higher score = better match.
 */
static int calculate_score(Fingerprint *fp, ScanResult *scan)
{
    int score = 0;
    
    /* What OS type did we observe based on TTL? */
    OSType observed_os = guess_os_from_ttl(scan->ttl);
    OSType fp_os = guess_os_from_name(fp->name);
    
    /*
     * OS family match is critical.
     * If TTL says Windows but fingerprint is Linux, that's bad.
     */
    if (observed_os != OS_UNKNOWN && fp_os != OS_UNKNOWN) {
        if (observed_os == fp_os)
            score += 200;
        else
            score -= 400;  /* Big penalty for mismatch */
    }
    
    /* Skip non-Windows/Linux fingerprints entirely */
    if (fp_os == OS_OTHER)
        return -9999;
    
    /*
     * TTL matching
     */
    int ttl_target = fp->ttl_guess > 0 ? fp->ttl_guess : fp->ttl_min;
    
    if (ttl_target > 0 && scan->ttl > 0) {
        int diff = abs(scan->ttl - ttl_target);
        
        /* Check if within expected range */
        if (fp->ttl_min > 0 && fp->ttl_max > 0) {
            if (scan->ttl >= fp->ttl_min && scan->ttl <= fp->ttl_max)
                score += 100;
        }
        
        /* Close TTL match */
        if (diff <= 2)
            score += 80;
        else if (diff <= 5)
            score += 40;
        else if (diff > 30)
            score -= 50;
    }
    
    /*
     * Window size matching
     */
    if (scan->window > 0) {
        /* Check against WIN section values */
        int win_match = 0;
        for (int i = 0; i < 6; i++) {
            if (fp->window_values[i] > 0 && 
                scan->window == fp->window_values[i]) {
                win_match = 1;
                break;
            }
        }
        
        if (win_match) {
            score += 150;
        } else if (fp->window > 0) {
            if (scan->window == fp->window)
                score += 150;
            else if (abs(scan->window - fp->window) < 1000)
                score += 50;
        }
        
        /* Windows typically uses 65535 */
        if (scan->window == 65535 && fp_os == OS_WINDOWS)
            score += 50;
    }
    
    /*
     * TCP options matching
     */
    if (scan->got_response && scan->options[0] && fp->options) {
        score += compare_options(&scan->opts, &fp->opts);
    }
    
    /*
     * DF flag matching
     */
    if (scan->df_flag && fp->df_flag) {
        if (scan->df_flag == fp->df_flag)
            score += 30;
    }
    
    /*
     * Behavioral tests
     * 
     * T3 is particularly useful - Windows usually doesn't respond
     * to weird flag combinations, but Linux often does.
     */
    if (fp->t3_responds) {
        int expected = (fp->t3_responds == 'Y');
        if (expected == scan->t3_responded)
            score += 100;
        else
            score -= 50;
    }
    
    if (fp->t2_responds) {
        int expected = (fp->t2_responds == 'Y');
        if (expected == scan->t2_responded)
            score += 50;
    }
    
    return score;
}


/* Sort matches by score (highest first) */
static int compare_matches(const void *a, const void *b)
{
    const Match *ma = a;
    const Match *mb = b;
    return mb->score - ma->score;
}


/*
 * Find and display the best matching fingerprints.
 */
void find_matches(FingerprintNode *db, ScanResult *scan)
{
    if (!db || !scan) return;
    
    /* Allocate space for matches */
    int capacity = 10000;
    Match *matches = malloc(sizeof(Match) * capacity);
    int count = 0;
    
    /* What OS family does the TTL suggest? */
    OSType observed_os = guess_os_from_ttl(scan->ttl);
    
    /* Print what we observed */
    printf("\n");
    printf("============================================\n");
    printf(" Scan Results\n");
    printf("============================================\n");
    printf("TTL:     %d (%s)\n", scan->ttl, os_type_name(observed_os));
    printf("Window:  %d\n", scan->window);
    printf("Options: %s\n", scan->options);
    printf("DF flag: %c\n", scan->df_flag);
    printf("\n");
    printf("Behavioral responses:\n");
    printf("  NULL probe: %s\n", scan->t2_responded ? "yes" : "no");
    printf("  XMAS probe: %s\n", scan->t3_responded ? "yes" : "no");
    printf("  ACK probe:  %s\n", scan->t4_responded ? "yes" : "no");
    printf("\n");
    
    /* Score all fingerprints */
    FingerprintNode *node = db;
    while (node && count < capacity) {
        int score = calculate_score(node->fp, scan);
        
        /* Only keep reasonable matches */
        if (score > -100) {
            matches[count].fp = node->fp;
            matches[count].score = score;
            count++;
        }
        
        node = node->next;
    }
    
    /* Sort by score */
    qsort(matches, count, sizeof(Match), compare_matches);
    
    /* Show top matches */
    printf("============================================\n");
    printf(" Top %d Matches\n", TOP_MATCHES);
    printf("============================================\n");
    
    int shown = 0;
    for (int i = 0; i < count && shown < TOP_MATCHES; i++) {
        Match *m = &matches[i];
        OSType os = guess_os_from_name(m->fp->name);
        
        /* Skip if not Windows or Linux */
        if (os == OS_OTHER) continue;
        
        printf("\n#%d  %s\n", shown + 1, m->fp->name);
        printf("    Score: %d\n", m->score);
        printf("    Type:  %s\n", os_type_name(os));
        
        shown++;
    }
    
    /* Summary */
    printf("\n--------------------------------------------\n");
    
    if (shown > 0 && matches[0].score > 200) {
        printf("Best guess: %s\n", matches[0].fp->name);
        
        if (matches[0].score > 600)
            printf("Confidence: HIGH\n");
        else if (matches[0].score > 350)
            printf("Confidence: MEDIUM\n");
        else
            printf("Confidence: LOW\n");
    } else {
        printf("No confident match found.\n");
        printf("Based on TTL, this is likely: %s\n", os_type_name(observed_os));
    }
    
    free(matches);
}