#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h> 
#include <math.h>
#include <string.h>
#include <arpa/inet.h>
#include "matcher.h"

// פונקציית עזר להדפסת סטטוס בצבעים
void print_test_status(const char* test_name, int result, const char* detail) {
    printf("| %-12s | ", test_name);
    if (result) {
        printf("\033[1;32mPass (Reply)\033[0m | %-20s |\n", detail);
    } else {
        printf("\033[1;31mNo Reply    \033[0m | %-20s |\n", "Timeout / Filtered");
    }
}

void find_best_match(SignatureNode *db, HostResults *results) {
    SignatureNode *curr = db;
    SignatureNode *best_match = NULL;
    int max_score = 0;

    // --- שלב 1: הדפסת טבלה מסודרת ---
    printf("\n");
    printf("+--------------+--------------+----------------------+\n");
    printf("| Test Name    | Status       | Details              |\n");
    printf("+--------------+--------------+----------------------+\n");
    
    char detail_buf[64];
    
    // T1 Output
    snprintf(detail_buf, 64, "TTL=%d, Win=%d", results->t1_ttl, results->t1_window);
    print_test_status("T1 (SYN)", results->t1_open, detail_buf);

    // T3 Output
    print_test_status("T3 (SFPU)", results->t3_open, results->t3_open ? "RST/ACK Received" : "Dropped");

    // T7 Output
    print_test_status("T7 (Xmas)", results->t7_open, results->t7_open ? "RST/ACK Received" : "Dropped");
    
    printf("+--------------+--------------+----------------------+\n");


    // --- שלב 2: השוואה מול בסיס הנתונים (הקוד המקורי) ---
    while (curr) {
        int score = 0;
        
        // בדיקת T1
        if (curr->data->t1_resp == 'Y' && results->t1_open) {
            // TTL Score
            if (curr->data->t1_ttl != -1) {
                int diff = abs(curr->data->t1_ttl - results->t1_ttl);
                // מאפשרים סטייה קלה בגלל Hops ברשת
                if (diff <= 5) score += 40;
                else if (diff <= 20) score += 20;
            }

            // Window Score
            if (curr->data->t1_window != -1) {
                if (curr->data->t1_window == results->t1_window) {
                    score += 50;
                }
            }
        }
        
        // בדיקת התנהגות מול חבילות לא תקינות (T3/T7)
        // אם הדאטהבייס מצפה לתשובה (Y) וקיבלנו תשובה -> מעולה
        int db_t3 = (curr->data->t3_resp == 'Y');
        if (db_t3 == results->t3_open) score += 15;

        int db_t7 = (curr->data->t7_resp == 'Y');
        if (db_t7 == results->t7_open) score += 15;

        if (score > max_score) {
            max_score = score;
            best_match = curr;
        }
        curr = curr->next;
    }

    // --- שלב 3: קבלת החלטה (Heuristics משופר) ---
    printf("\n[Analysis Results]\n");

    // אם יש התאמה מושלמת מהדאטהבייס
    if (best_match && max_score >= 80) { 
        printf("Match Source: \033[1;33mNmap Database\033[0m\n");
        printf("OS Family:    \033[1;32m%s\033[0m\n", best_match->data->os_name);
        printf("Score:        %d/100\n", max_score);
        return;
    } 
    
    
    // זיהוי ווינדוס: TTL באזור 128 והתעלמות מחבילות זבל
    if (results->t1_ttl > 64 && results->t1_ttl <= 128) {
        printf("OS Family:    \033[1;32mWindows\033[0m\n");
        
        int confidence = 70;
        if (results->t3_open == 0 && results->t7_open == 0) {
            confidence += 20; // ווינדוס קלאסי מתעלם מחבילות כאלו
            printf("Reason:       TTL(~128) + Dropped malformed packets (Classic Windows behavior).\n");
        } else {
            printf("Reason:       TTL(~128) indicates Windows, but unexpected replies to malformed packets.\n");
        }
        printf("Confidence:   %d%%\n", confidence);
    } 
    
    // זיהוי משפחת יוניקס/לינוקס: TTL באזור 64
    else if (results->t1_ttl <= 64) {
        
        // --- בדיקת iOS ספציפית ---
        if (results->t1_window == 65535) {
             printf("OS Family:    \033[1;35mApple iOS / macOS\033[0m\n");
             printf("Reason:       TTL(~64) + TCP Window Size = 65535 (Very typical for Apple).\n");
             printf("Confidence:   90%%\n");
        }
        
        // --- בדיקת Android ---
        // אנדרואיד הוא לינוקס, אבל לרוב ה-Window לא 65535, והוא מגיב לזבל
        else if (results->t3_open == 1 || results->t7_open == 1) {
             printf("OS Family:    \033[1;32mLinux / Android\033[0m\n");
             
             // ניסיון להבדיל בין לינוקס רגיל לאנדרואיד
             // אנדרואיד בדרך כלל עם חלונות בגדלים של כפולות MSS או ערכים בינוניים
             if (results->t1_window > 8000 && results->t1_window < 60000) {
                 printf("Sub-Type:     Likely \033[1;33mAndroid Mobile\033[0m (Based on Window Size variance)\n");
             } else {
                 printf("Sub-Type:     Likely Server / Desktop Linux\n");
             }
             
             printf("Reason:       TTL(~64) + Replies to malformed packets (RST).\n");
             printf("Confidence:   85%%\n");
        }
        
        // ברירת מחדל ללינוקס
        else {
             printf("OS Family:    \033[1;32mLinux / Unix\033[0m\n");
             printf("Confidence:   60%%\n");
        }
    } 
    else {
        printf("Result:       Unknown OS (Strange TTL: %d)\n", results->t1_ttl);
    }
}