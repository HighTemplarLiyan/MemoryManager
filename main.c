#include <stdlib.h>
#include <stdio.h>

#include "logger.h"
#include "mmemory.h"

int main()
{
    INIT_LOGGER("log.txt");

    TERMINATE_LOGGER;
    return 0;
}