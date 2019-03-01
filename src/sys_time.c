#include <stdio.h>
#include <string.h>
#include "sys_time.h"
#include "dpdk.h"

/*Notice:
 * the time zone is the value compared with the server's;
 * default is 57(beijing),supposed the server is 0(Greenwich time)
 */
static time_t g_dpvs_timer = 0;
static uint64_t g_start_cycles = 0;

static void sys_time_to_str(time_t* ts, char* time_str, int str_len)
{
    struct tm tm_time;

    localtime_r(ts, &tm_time);
    snprintf(time_str, str_len, "%04d-%02d-%02d %02d:%02d:%02d",
            tm_time.tm_year+1900, tm_time.tm_mon+1, tm_time.tm_mday,
            tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec);
}

char* cycles_to_stime(uint64_t cycles)
{
    time_t ts;
    static char time_str[SYS_TIME_STR_LEN];

    memset(time_str, 0, SYS_TIME_STR_LEN);
    ts = (cycles - g_start_cycles) / rte_get_timer_hz();
    ts += g_dpvs_timer;
    sys_time_to_str(&ts, time_str, SYS_TIME_STR_LEN);

    return time_str;
}

char* sys_localtime_str(void)
{
    static char stime[SYS_TIME_STR_LEN];
    time_t now;

    memset(stime, 0, SYS_TIME_STR_LEN);
    now = sys_current_time();
    sys_time_to_str(&now, stime, SYS_TIME_STR_LEN);

    return stime;
}

time_t sys_current_time(void)
{
    time_t now;

    now = (rte_rdtsc() - g_start_cycles) / rte_get_timer_hz();
    return now + g_dpvs_timer;
}

void sys_start_time(void)
{
    struct timeval tv;
    struct timezone tz;

    time(&g_dpvs_timer);
    gettimeofday(&tv, &tz);
    g_dpvs_timer += tz.tz_minuteswest*60;

    g_start_cycles = rte_rdtsc();

    return;
}
