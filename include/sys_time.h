#ifndef _SYS_DPVS_TIME_H_
#define _SYS_DPVS_TIME_H_

#include <sys/time.h>
#include <time.h>

#define SYS_TIME_STR_LEN (64)

char* sys_time_to_str(time_t *ts);
char *sys_localtime_str(void);
time_t sys_current_time(void);
void sys_start_time(void);

#endif /* _SAPL_TIME_H_ */
