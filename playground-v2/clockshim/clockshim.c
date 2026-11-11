/* Wall-clock shim for the frozen Elasticsearch (#1347 D15 revised). LD_PRELOAD it with
 * V2_CLOCK_OFFSET_FILE=<path>: CLOCK_REALTIME readings (clock_gettime, gettimeofday, time) are
 * shifted by the offset that file holds. Monotonic clocks are untouched, so timeouts and
 * schedulers keep their pace.
 *
 * The file is a fixed 24-byte record: a signed decimal number of seconds, padded with spaces,
 * ending in a newline. The lab creates it at that size before the process starts and only ever
 * rewrites it in place at byte 0 (never truncating it), so the next reading follows a rewrite
 * without a restart. The file is mapped once, on the first clock call; every call parses the
 * mapped bytes (no file access per call). A file absent or shorter than one byte at that first
 * call means no shift.
 *
 *   gcc -shared -fPIC -O2 -o clockshim.so clockshim.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define RECORD 24

static const volatile char *record;   /* the mapping, or NULL */
static long record_len;
static int mapped;                    /* the one attempt was made */

static void map_offset(void)
{
    const char *path = getenv("V2_CLOCK_OFFSET_FILE");
    int fd = path ? open(path, O_RDONLY | O_CLOEXEC) : -1;
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0 && st.st_size > 0) {
            long len = st.st_size < RECORD ? (long)st.st_size : RECORD;
            void *map = mmap(NULL, RECORD, PROT_READ, MAP_SHARED, fd, 0);
            if (map != MAP_FAILED) {
                record_len = len;
                record = map;
            }
        }
        close(fd);
    }
    __atomic_store_n(&mapped, 1, __ATOMIC_RELEASE);
}

static long offset_s(void)
{
    if (!__atomic_load_n(&mapped, __ATOMIC_ACQUIRE))
        map_offset();
    if (!record)
        return 0;
    long i = 0, value = 0;
    int negative = 0;
    while (i < record_len && record[i] == ' ')
        i++;
    if (i < record_len && (record[i] == '-' || record[i] == '+'))
        negative = record[i++] == '-';
    while (i < record_len && record[i] >= '0' && record[i] <= '9')
        value = value * 10 + (record[i++] - '0');
    return negative ? -value : value;
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
    if (rc == 0 && is_wall(id))
        ts->tv_sec += offset_s();
    return rc;
}

int gettimeofday(struct timeval *tv, void *tz)
{
    static int (*real)(struct timeval *, void *);
    if (!real)
        real = (int (*)(struct timeval *, void *))dlsym(RTLD_NEXT, "gettimeofday");
    int rc = real(tv, tz);
    if (rc == 0 && tv)
        tv->tv_sec += offset_s();
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
