#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include "logger.h"

FILE* pLogFile = NULL;

void get_time(char* buf)
{
    static time_t rawtime;
    time(&rawtime);
    static struct tm* timeinfo;
    timeinfo = localtime(&rawtime);
    strftime(buf, 20, "%T_%m-%d-%Y", timeinfo);
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
        log_str("===================================================");
        log_msg("===== Logger initialized =====");
        log_str("===================================================");
        return 1;
    }
}

void terminate_logger()
{
    log_str("===================================================");
    log_msg("===== Logger terminated =====");
    log_str("===================================================");
    fclose(pLogFile);
}

void log_str(char* str)
{
    fprintf(pLogFile, "%s\n", str);
}

void log_msg(char* str)
{
    char t[20];
    get_time(t);
    fprintf(pLogFile, "%s: %s\n", t, str);
}

void log_msg_int(char* str, int value)
{
    char t[20];
    get_time(t);
    fprintf(pLogFile, "%s: %s %d\n", t, str, value);
}

void log_msg_long(char* str, long value)
{
    char t[20];
    get_time(t);
    fprintf(pLogFile, "%s: %s %ld\n", t, str, value);
}

void log_msg_addr(char* str, long addr)
{
    char t[20];
    get_time(t);
    // TODO: add preceding zeros
    fprintf(pLogFile, "%s: %s %#lx\n", t, str, addr);
}