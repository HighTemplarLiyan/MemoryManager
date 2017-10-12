#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include "logger.h"

#define TIME_BUF_SIZE 22

FILE* pLogFile = NULL;

void get_time(char* buf)
{
    static time_t rawtime;
    time(&rawtime);
    static struct tm* timeinfo;
    timeinfo = localtime(&rawtime);
    strftime(buf, TIME_BUF_SIZE, "%m/%d/%Y - %T", timeinfo);
}

int init_logger(const char* sFileName)
{
    pLogFile = fopen(sFileName, "a");
    if (!pLogFile)
    {
        log_msg("Could not open log file for writing");
        return 0;
    }
    else
    {
        log_str("=============================================================");
        log_msg("===== Logger initialized =====");
        log_str("=============================================================");
        return 1;
    }
}

void terminate_logger(int sig)
{
    log_str("=============================================================");
    if (!sig)
        log_msg("===== Logger terminated =====");
    else
        log_msg("===== Logger terminated due to signal raise =====");
        log_str("=============================================================");
    fclose(pLogFile);
}

void log_str(char* str)
{
    fprintf(pLogFile, "%s\n", str);
}

void log_msg(char* str)
{
    char t[TIME_BUF_SIZE];
    get_time(t);
    fprintf(pLogFile, "%s:\t%s\n", t, str);
}

void log_msg_int(char* str, int value)
{
    char t[TIME_BUF_SIZE];
    get_time(t);
    fprintf(pLogFile, "%s:\t%s %d\n", t, str, value);
}

void log_msg_long(char* str, long value)
{
    char t[TIME_BUF_SIZE];
    get_time(t);
    fprintf(pLogFile, "%s:\t%s %ld\n", t, str, value);
}

void log_msg_addr(char* str, long addr)
{
    char t[TIME_BUF_SIZE];
    get_time(t);
    // TODO: add preceding zeros
    fprintf(pLogFile, "%s:\t%s %#lx\n", t, str, addr);
}