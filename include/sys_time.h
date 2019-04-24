#ifndef _SYS_DPVS_TIME_H_
#define _SYS_DPVS_TIME_H_
#include <sys/time.h>
#include <time.h>
#include "dpdk.h"

#define SYS_TIME_STR_LEN (64)

char* sys_localtime_str(char* stime, int len);
char* cycles_to_stime(uint64_t cycles, char* stime, int len);
time_t sys_current_time(void);
void sys_start_time(void);

#endif /* _SYS_DPVS_TIME_H_ */
