
#include <stdio.h>
#include <string.h>
#include "sys_time.h"
#include "dpdk.h"

/*Notice:
 * the time zone is the value compared with the server's;
 * default is 57(beijing),supposed the server is 0(Greenwich time)
 */

static time_t g_dpvs_timer;
static uint64_t cycles = 0;

char* sys_time_to_str(time_t *ts)
{
    static char time_str[SYS_TIME_STR_LEN];
    struct tm tm_time;

    memcpy(&tm_time, localtime(ts), sizeof(tm_time));

    memset(time_str, 0, SYS_TIME_STR_LEN+1);
    snprintf(time_str, SYS_TIME_STR_LEN, "%04d-%02d-%02d %02d:%02d:%02d", 
            tm_time.tm_year+1900,tm_time.tm_mon+1, tm_time.tm_mday, 
            tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec);

    return time_str;
}

char *sys_localtime_str(void)
{
    static char time_str[SYS_TIME_STR_LEN];
    struct tm tm_time;
    time_t now;

    now = sys_current_time();
    memcpy(&tm_time, localtime(&now), sizeof(tm_time));

    memset(time_str, 0, SYS_TIME_STR_LEN+1);
    snprintf(time_str, SYS_TIME_STR_LEN, "%04d-%02d-%02d %02d:%02d:%02d", 
            tm_time.tm_year+1900,tm_time.tm_mon+1, tm_time.tm_mday, 
            tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec);

    return time_str;
}

time_t sys_current_time(void)
{
    time_t now;
    uint64_t sec = (rte_get_timer_cycles() - cycles)
                   / rte_get_timer_hz();
    now = sec + g_dpvs_timer;
    return now;
}

void sys_start_time(void)
{
    struct timeval tv;
    struct timezone tz;

    time(&g_dpvs_timer);
    gettimeofday(&tv, &tz);
    
    g_dpvs_timer += tz.tz_minuteswest*60;
    cycles = rte_get_timer_cycles();
    return;
}


