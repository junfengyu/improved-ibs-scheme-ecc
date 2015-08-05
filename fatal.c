

#include <sys/types.h>

#include <stdarg.h>

#include "log.h"

/* Fatal messages.  This function never returns. */

void
fatal(const char *fmt,...)
{
     // add platform dependent log code here
    exit(255);
}
