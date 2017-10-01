#ifndef LOGGER
#define LOGGER


#ifndef NO_LOG
    #define INIT_LOGGER(file) init_logger(file)
    #define TERMINATE_LOGGER(sig) terminate_logger(sig)

    #define LOG(str) log_msg(str)
    #define LOG_INT(str, value) log_msg_int(str, value)
    #define LOG_LONG(str, value) log_msg_long(str, value)
    #define LOG_ADDR(str, addr) log_msg_addr(str, addr)
#else
    #define INIT_LOGGER(file) file
    #define TERMINATE_LOGGER

    #define LOG(str) str
    #define LOG_INT(str, value) str, value
    #define LOG_LONG(str, value) str, value
    #define LOG_ADDR(str, addr) str, addr
#endif

int init_logger(const char* sFileName);
void terminate_logger(int sig);

void log_msg(char* str);
void log_str(char* str);
void log_msg_int(char* str, int value);
void log_msg_long(char* str, long value);
void log_msg_addr(char* str, long addr);

#endif