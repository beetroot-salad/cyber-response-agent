/* Wall-clock shim for the frozen Elasticsearch (#1347 D15). LD_PRELOAD it with
 * V2_CLOCK_OFFSET_S=<seconds, may be negative>: CLOCK_REALTIME readings (clock_gettime,
 * gettimeofday, time) are shifted by that one offset, read once when the process starts.
 * Monotonic clocks are untouched, so timeouts and schedulers keep their pace.
 *
 *   gcc -shared -fPIC -O2 -o clockshim.so clockshim.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

static long offset_s;
static int offset_read;

static void read_offset(void)
{
    const char *text = getenv("V2_CLOCK_OFFSET_S");
    offset_s = text ? strtol(text, NULL, 10) : 0;
    offset_read = 1;
}

static int is_wall(clockid_t id)
{
    return id == CLOCK_REALTIME || id == CLOCK_REALTIME_COARSE;
}

int clock_gettime(clockid_t id, struct timespec *ts)
{
    static int (*real)(clockid_t, struct timespec *);
    if (!real)
        real = (int (*)(clockid_t, struct timespec *))dlsym(RTLD_NEXT, "clock_gettime");
    int rc = real(id, ts);
    if (!offset_read)
        read_offset();
    if (rc == 0 && is_wall(id))
        ts->tv_sec += offset_s;
    return rc;
}

int gettimeofday(struct timeval *tv, void *tz)
{
    static int (*real)(struct timeval *, void *);
    if (!real)
        real = (int (*)(struct timeval *, void *))dlsym(RTLD_NEXT, "gettimeofday");
    int rc = real(tv, tz);
    if (!offset_read)
        read_offset();
    if (rc == 0 && tv)
        tv->tv_sec += offset_s;
    return rc;
}

time_t time(time_t *out)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    if (out)
        *out = ts.tv_sec;
    return ts.tv_sec;
}
