#ifndef _SYS_DPVS_TIME_H_
#define _SYS_DPVS_TIME_H_
#include <sys/time.h>
#include <time.h>
#include "dpdk.h"

#define SYS_TIME_STR_LEN (64)

void cycles_to_systime(uint64_t cycles, char* time_str, int str_len);
char* sys_localtime_str(void);
char* cycles_to_stime(uint64_t cycles);
time_t sys_current_time(void);
void sys_start_time(void);

#endif /* _SYS_DPVS_TIME_H_ */
