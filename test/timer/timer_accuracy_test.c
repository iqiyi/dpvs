#include <stdlib.h>
#include <unistd.h>
#include "dpdk.h"
#include "scheduler.h"
#include "cfgfile.h"
#include "timer.h"

#define RTE_TIMER_INT 500   /* us */
#define MAX_DELAY 16000     /* s, should be less than TIMER_MAX_TICKS/DPVS_TIMER_HZ */

static struct timeval g_start_time;
static int init_delay_sec;

static int lcore_loop(void *arg)
{
    while (1) {
        rte_timer_manage();
        usleep(RTE_TIMER_INT);
    }
    return 0;
}

static int timeup(void *arg)
{
    struct timeval tv;
    struct timeval now, elapsed, delta;
    struct dpvs_timer *tm = arg;

    gettimeofday(&now, NULL);
    timersub(&now, &g_start_time, &elapsed);
    ticks_to_timeval(tm->delay, &tv);

    if (timercmp(&tv, &elapsed, <)) {
        timersub(&elapsed, &tv, &delta);
    } else {
        timersub(&tv, &elapsed, &delta);
    }

    fprintf(stderr, "[%02d] timer timeout: %lu.%06lu, elapsed time: %lu.%06lu, "
            "diff: %lu.%06lu\n", rte_lcore_id(), tv.tv_sec, tv.tv_usec,
            elapsed.tv_sec, elapsed.tv_usec, delta.tv_sec, delta.tv_usec);

    rte_free(tm);

    return DTIMER_STOP;
}

int main(int argc, char *argv[])
{
    int i, err;
    struct timeval delay, elapsed;
    struct dpvs_timer *timer;

    gettimeofday(&delay, NULL);
    srandom(delay.tv_usec ^ getpid());
    init_delay_sec = random() % 53 + 7;

    /* init */
    err = rte_eal_init(argc, argv);
    if (err < 0) {
        fprintf(stderr, "rte_eal_init failed\n");
        return 1;
    }
    rte_timer_subsystem_init();

    err = dpvs_scheduler_init();
    if (err) {
        fprintf(stderr, "dpvs_scheduler_init failed\n");
        return 1;
    }

    err = global_data_init();
    if (err) {
        fprintf(stderr, "global_data_init failed\n");
        return 1;
    }

    err = cfgfile_init();
    if (err) {
        fprintf(stderr, "cfgfile_init failed\n");
        return 1;
    }

    err =dpvs_timer_init();
    if (err) {
        fprintf(stderr, "dpvs_timer_init failed\n");
        return 1;
    }

    rte_eal_mp_remote_launch(lcore_loop, NULL, SKIP_MAIN);

    /* delay for some time before scheduling timers */
    fprintf(stderr, "delay %d seconds ..\n", init_delay_sec);
    while (1) {
        rte_timer_manage();
        gettimeofday(&g_start_time, NULL);
        timersub(&g_start_time, &delay, &elapsed);
        if (elapsed.tv_sec > init_delay_sec)
            break;
        usleep(RTE_TIMER_INT);
    }

    /* start timer */
    for (i = 1; i < MAX_DELAY; i++) {
        timer = rte_zmalloc("timer", sizeof(struct dpvs_timer), 0);
        if (!timer) {
            fprintf(stderr, "no memory for timer\n");
            return 1;
        }
        memset(timer, 0, sizeof(*timer));
        delay.tv_sec = i;
        delay.tv_usec = 0;

        err = dpvs_timer_sched(timer, &delay, timeup, timer, true);
        if (err) {
            fprintf(stderr, "dpvs_timer_sched failed\n");
            return 1;
        }
    }

    /* wait for timeout */
    while (1) {
        rte_timer_manage();
        usleep(RTE_TIMER_INT);
    }

    return 0;
}
